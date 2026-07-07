<?php

namespace safeaccess;

class MachineCodeService
{
    /**
     * 获取服务器唯一编码
     *
     * @param boolean $isforce
     * @return string
     */
    public static function getcode($isforce = false)
    {
        $os = PHP_OS_FAMILY;
        $enkey = hash('sha256', 'hello world');
        $iv = substr($enkey, 0, 16);

        $cachePath = RUNTIME_PATH . md5($os . '_machine_code') . '.dat';
        $licenseDir = APP_PATH . 'common' . DS . 'license' . DS;
        $codeFile = $licenseDir . 'machine.id';
        $fingerprint = self::getMachineFingerprint($os);

        if (!$isforce) {
            $cache = self::readCache($cachePath, $enkey, $iv, $fingerprint);
            if ($cache) {
                if (!is_file($codeFile)) {
                    self::ensureLicenseDir($licenseDir);
                    @file_put_contents($codeFile, $cache['machine_id'], LOCK_EX);
                }

                return $cache['hash'];
            }
        }

        self::ensureLicenseDir($licenseDir);

        $raw = '';
        if (!$isforce && is_file($codeFile)) {
            $raw = trim((string) file_get_contents($codeFile));
        }

        if (!self::isValidMachineId($raw)) {
            $raw = self::createMachineId($os);
            if (file_put_contents($codeFile, $raw, LOCK_EX) === false) {
                throw new \Exception('写入机器码文件失败，请检查授权目录权限');
            }
        }

        $code = strtolower($os) . '-' . hash('sha256', $raw . '|' . $fingerprint);
        self::writeCache($cachePath, $enkey, $iv, $code, $raw, $fingerprint);

        return $code;
    }

    /**
     * 读取有效缓存
     *
     * @param string $cachePath
     * @param string $enkey
     * @param string $iv
     * @param string $fingerprint
     * @return array|null
     */
    protected static function readCache($cachePath, $enkey, $iv, $fingerprint)
    {
        if (!is_file($cachePath)) {
            return null;
        }

        $cachedata = file_get_contents($cachePath);
        if ($cachedata === false) {
            return null;
        }

        $encryData = openssl_decrypt($cachedata, 'AES-256-CBC', $enkey, 0, $iv);
        $cache = json_decode($encryData, true);
        if (!is_array($cache) || empty($cache['exp']) || $cache['exp'] <= time()) {
            return null;
        }

        $cacheCode = $cache['hash'] ?? ($cache['code'] ?? '');
        $cacheMachineId = $cache['machine_id'] ?? '';
        $cacheFingerprint = $cache['fingerprint'] ?? '';

        if ($cacheCode === '' || $cacheFingerprint === '') {
            return null;
        }

        if (!hash_equals($cacheFingerprint, $fingerprint) || !self::isValidMachineId($cacheMachineId)) {
            return null;
        }

        return [
            'hash' => $cacheCode,
            'machine_id' => $cacheMachineId,
        ];
    }

    /**
     * 写入机器码缓存
     *
     * @param string $cachePath
     * @param string $enkey
     * @param string $iv
     * @param string $code
     * @param string $machineId
     * @param string $fingerprint
     * @return void
     */
    protected static function writeCache($cachePath, $enkey, $iv, $code, $machineId, $fingerprint)
    {
        if (!is_dir(RUNTIME_PATH)) {
            @mkdir(RUNTIME_PATH, 0755, true);
        }

        $encryData = openssl_encrypt(json_encode([
            'exp' => time() + 86400 * 7,
            'hash' => $code,
            'machine_id' => $machineId,
            'fingerprint' => $fingerprint,
        ]), 'AES-256-CBC', $enkey, 0, $iv);

        if ($encryData !== false) {
            @file_put_contents($cachePath, $encryData, LOCK_EX);
        }
    }

    /**
     * 确保授权目录存在
     *
     * @param string $licenseDir
     * @return void
     */
    protected static function ensureLicenseDir($licenseDir)
    {
        if (!is_dir($licenseDir) && !@mkdir($licenseDir, 0755, true)) {
            throw new \Exception('创建授权目录失败，请检查目录权限');
        }
    }

    /**
     * 生成机器 ID
     *
     * Linux 下优先使用可安全读取的 machine-id 生成 hid；
     * 读取不到时再生成随机 mid，保证受限环境兼容。
     *
     * @param string $os
     * @return string
     */
    protected static function createMachineId($os)
    {
        $systemIdentity = self::getSystemMachineIdentity($os);
        if ($systemIdentity !== '') {
            return 'hid-' . hash('sha256', $systemIdentity);
        }

        try {
            $random = bin2hex(random_bytes(16));
        } catch (\Throwable $th) {
            $random = md5(uniqid('', true) . mt_rand());
        }

        return 'mid-' . $random;
    }

    /**
     * 判断机器 ID 是否有效
     *
     * @param string $value
     * @return bool
     */
    protected static function isValidMachineId($value)
    {
        $value = trim((string) $value);
        return strpos($value, 'mid-') === 0 || strpos($value, 'hid-') === 0;
    }

    /**
     * 获取额外环境指纹项
     *
     * @param string $os
     * @return array
     */
    protected static function getFingerprintItems($os)
    {
        $items = [];

        if ($os === 'Linux') {
            foreach (
                [
                    '/sys/class/dmi/id/product_uuid',
                    '/sys/class/dmi/id/board_serial',
                    '/sys/class/dmi/id/product_serial',
                ] as $file
            ) {
                if (!self::isPathAllowedByOpenBasedir($file) || !@is_file($file) || !@is_readable($file)) {
                    continue;
                }

                $value = @file_get_contents($file);
                if ($value !== false) {
                    $items[] = $value;
                }
            }
        }

        if ($os === 'Windows') {
            $items[] = getenv('COMPUTERNAME');
            $items[] = getenv('PROCESSOR_IDENTIFIER');
            $items[] = getenv('PROCESSOR_ARCHITECTURE');
        }

        return $items;
    }

    /**
     * 获取服务器环境指纹
     *
     * @param string $os
     * @return string
     */
    protected static function getMachineFingerprint($os)
    {
        $items = self::normalizeIdentityItems(array_merge([
            (string) $os,
            (string) gethostname(),
        ], self::getFingerprintItems($os)));

        if (empty($items)) {
            throw new \Exception('获取服务器指纹失败，请确认服务器环境信息可读');
        }

        return hash('sha256', implode('|', $items));
    }

    /**
     * 获取可恢复的系统机器标识
     *
     * @param string $os
     * @return string
     */
    protected static function getSystemMachineIdentity($os)
    {
        if ($os !== 'Linux') {
            return '';
        }

        foreach (['/etc/machine-id', '/var/lib/dbus/machine-id'] as $file) {
            if (!self::isPathAllowedByOpenBasedir($file) || !@is_file($file) || !@is_readable($file)) {
                continue;
            }

            $value = @file_get_contents($file);
            $items = self::normalizeIdentityItems([
                $value === false ? '' : $value,
            ]);

            if (!empty($items)) {
                return $items[0];
            }
        }

        return '';
    }

    /**
     * 归一化标识项
     *
     * @param array $items
     * @return array
     */
    protected static function normalizeIdentityItems(array $items)
    {
        $items = array_filter(array_map(function ($value) {
            $value = strtolower(trim((string) $value));
            return preg_replace('/\s+/', ' ', $value);
        }, $items), function ($value) {
            return !in_array($value, [
                '',
                'none',
                'null',
                'nil',
                'n/a',
                'na',
                'unknown',
                'undefined',
                'default',
                'default string',
                '00000000-0000-0000-0000-000000000000',
                'ffffffff-ffff-ffff-ffff-ffffffffffff',
            ], true);
        });

        $items = array_values(array_unique($items));
        sort($items);

        return $items;
    }

    /**
     * 判断路径是否在 open_basedir 允许范围内
     *
     * @param string $path
     * @return bool
     */
    protected static function isPathAllowedByOpenBasedir($path)
    {
        $openBasedir = trim((string) ini_get('open_basedir'));
        if ($openBasedir === '') {
            return true;
        }

        // 统一路径格式，避免 open_basedir 比对时受斜杠和相对路径影响。
        $normalizePath = function ($path) {
            $path = str_replace('\\', '/', trim((string) $path));
            if ($path === '') {
                return '';
            }

            if (!isset($path[0]) || ($path[0] !== '/' && !preg_match('#^[a-z]:/#i', $path) && strpos($path, '//') !== 0)) {
                $path = rtrim(str_replace('\\', '/', (string) getcwd()), '/') . '/' . $path;
            }

            $path = preg_replace('#/+#', '/', $path);
            if (PHP_OS_FAMILY === 'Windows') {
                $path = strtolower($path);
            }

            if ($path !== '/' && !preg_match('#^[a-z]:/$#i', $path)) {
                $path = rtrim($path, '/');
            }

            return $path;
        };

        $path = $normalizePath($path);
        foreach (explode(PATH_SEPARATOR, $openBasedir) as $baseDir) {
            $baseDir = trim((string) $baseDir);
            if ($baseDir === '') {
                continue;
            }

            if ($baseDir === '.') {
                $baseDir = (string) getcwd();
            }

            $baseDir = $normalizePath($baseDir);
            if ($baseDir === '') {
                continue;
            }

            if ($baseDir === '/' || $path === $baseDir || strpos($path, rtrim($baseDir, '/') . '/') === 0) {
                return true;
            }
        }

        return false;
    }
}
