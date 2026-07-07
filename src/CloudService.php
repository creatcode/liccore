<?php

namespace safeaccess;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\TransferException;
use think\Config;
use think\Db;

class CloudService
{
    protected static $instance = null;

    protected $cloudconfig;

    protected static $authpath    = APP_PATH . "common/license/register.lock";
    protected static $licensepath = APP_PATH . "common/license/license.lic";

    protected static $error = null;

    protected function __construct()
    {
        $this->cloudconfig = Config::get('cloud');
    }

    /**
     * 初始化
     *
     * @return self
     */
    public static function init()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 站点注册
     */
    public function register(string $name)
    {
        $response = $this->sendRequest(
            "/api/index/site_reg",
            [
                'name'    => $name,
                'code'    => $this->getcode(),
                'url'     => request()->domain(true),
                'version' => $this->cloudconfig['version'] ?? '1.0.0',
            ],
            'post',
            false
        );

        if (!$response || ($response['code'] ?? 0) == 0) {
            throw new \Exception($response['msg'] ?? '云端服务异常');
        }

        $data = is_array($response['data'] ?? null) ? $response['data'] : [];
        $secretKey = trim((string) ($data['secret_key'] ?? ''));
        $license = trim((string) ($data['license'] ?? ''));
        $licenseDir = dirname(self::$authpath);

        if ($secretKey === '') {
            throw new \Exception('云端返回的授权信息不完整');
        }

        if (!is_dir($licenseDir) && !@mkdir($licenseDir, 0755, true)) {
            throw new \Exception('创建授权目录失败，请检查目录权限');
        }

        if (file_put_contents(self::$authpath, $secretKey, LOCK_EX) === false) {
            throw new \Exception('保存授权锁文件失败');
        }

        // license 文件不是必需项，只有云端返回内容时才落盘
        if ($license !== '' && file_put_contents(self::$licensepath, $license, LOCK_EX) === false) {
            throw new \Exception('保存授权文件失败');
        }
    }

    /**
     * 授权检测
     */
    public function checkAuth()
    {
        $env = $this->cloudconfig['env'] ?? '';
        switch ($env) {
            case 'local':
                // 授权文件检测
                $license = $this->checklicense();
                if ($license === false) {
                    abort(403, self::getError() ?? '当前未授权,暂无法运行~');
                }
                break;
            case 'online':
                // 远程检测
                $baseurl = trim($this->cloudconfig['url'] ?? '');
                if ($baseurl === '') {
                    abort(403, '请先配置云端地址');
                }

                if (!preg_match('/^https?:\/\//i', $baseurl)) {
                    $baseurl = 'http://' . $baseurl;
                }
                try {
                    $client = new Client([
                        'timeout'         => 2,
                        'connect_timeout' => 2,
                        'http_errors'     => false,
                    ]);
                    $type = trim((string) ($this->cloudconfig['type'] ?? ''));
                    if ($type === '') {
                        abort(403, '请先配置 cloud.type');
                    }

                    $response = $client->post(rtrim($baseurl, '/') . '/api/index/checkauth', [
                        'form_params' => [
                            'code' => $this->getcode(),
                            'type' => $type,
                        ],
                    ]);
                    $body    = $response->getBody();
                    $content = $body->getContents();
                    $json    = (array) json_decode($content, true);
                } catch (\Throwable $th) {
                    abort(403, '云端授权检测失败，请联系服务商');
                }
                if (empty($json)) {
                    abort(403, '云端授权异常:授权检测失败');
                }
                if ($json['code'] != 1) {
                    abort(403, $json['msg'] ?? '授权检测失败');
                }
                $license = is_array($json['data'] ?? null) ? $json['data'] : [];
                break;
            default:
                abort(403, '运行环境异常，请确认云端配置文件正常');
        }
        $this->checkdev($license['devnum'] ?? 0);
        return $license;
    }

    /**
     * 获取服务器唯一编码
     *
     * @param boolean $isforce
     * @return string
     */
    public function getcode($isforce = false)
    {
        return MachineCodeService::getcode($isforce);
    }

    /**
     * 授权文件验证
     */
    public function checklicense()
    {
        try {
            $licPath = self::$licensepath;
            $pemFile = APP_PATH . "common" . DS . "license" . DS . "public.pem";

            if (!is_file($licPath) || !is_readable($licPath)) {
                return self::setError('授权文件不存在或不可读，请联系服务商~');
            }

            if (!is_file($pemFile) || !is_readable($pemFile)) {
                return self::setError('公钥不存在或不可读，请联系服务商~');
            }

            $licenseContent = trim((string) file_get_contents($licPath));
            $pemContent     = trim((string) file_get_contents($pemFile));

            if ($licenseContent === '' || $pemContent === '') {
                return self::setError('授权文件或公钥内容为空~');
            }

            $licenseJson = base64_decode($licenseContent, true);
            if ($licenseJson === false) {
                return self::setError('授权文件编码错误~');
            }

            $license = json_decode($licenseJson, true);
            if (!is_array($license) || empty($license['data']) || empty($license['sign'])) {
                return self::setError('授权文件格式错误~');
            }

            $base64Data = (string) $license['data'];
            $signature  = base64_decode((string) $license['sign'], true);
            if ($signature === false || $signature === '') {
                return self::setError('授权签名格式错误~');
            }

            $publicKey = openssl_pkey_get_public($pemContent);
            if (!$publicKey) {
                return self::setError('公钥加载失败~');
            }

            $verify = openssl_verify($base64Data, $signature, $publicKey, OPENSSL_ALGO_SHA256);

            // PHP 8 下 openssl_pkey_get_public 返回对象，不需要强制释放；保留资源类型兼容旧版本
            if (is_resource($publicKey)) {
                openssl_free_key($publicKey);
            }

            if ($verify !== 1) {
                return self::setError('授权签名验证失败~');
            }

            $json = base64_decode($base64Data, true);
            if ($json === false) {
                return self::setError('授权数据编码错误~');
            }

            $data = json_decode($json, true);
            if (!is_array($data)) {
                return self::setError('授权数据格式错误~');
            }

            $uuid   = trim((string) ($data['uuid'] ?? ''));
            $expiry = $data['expiry'] ?? '';
            $system = trim((string) ($data['system'] ?? ''));

            if ($uuid === '' || $expiry === '' || $system === '') {
                return self::setError('授权数据不完整~');
            }

            $localUuid = md5($this->getcode());
            if (!hash_equals($localUuid, $uuid)) {
                return self::setError('授权无效：授权码异常~');
            }

            $configType = trim((string) ($this->cloudconfig['type'] ?? ''));
            if ($configType === '' || !hash_equals($configType, $system)) {
                return self::setError('授权无效：系统类型异常~');
            }

            // 兼容时间戳和日期字符串两种授权过期时间格式
            $expiryTime = is_numeric($expiry) ? (int) $expiry : strtotime((string) $expiry);
            if (!$expiryTime) {
                return self::setError('授权有效期格式错误~');
            }

            if ($expiryTime < time()) {
                return self::setError('授权已过期，请联系服务商~');
            }

            $data['expiry'] = $expiryTime;
            return $data;
        } catch (\Throwable $th) {
            return self::setError('授权验证出错~');
        }
    }

    /**
     * 检测授权设备数量
     */
    public function checkdev($allownum)
    {
        $path = request()->path();
        if ($path == 'product/device/add/source/sub' || stripos($path, 'device/add/source/sub') !== false) {
            $totalNum = Db::name('device')->where('node_type', '<>', 1)->count();
            if ($allownum >= 0 && $totalNum >= $allownum) {
                throw new \Exception("当前设备数量已达到授权上限[{$allownum}],无法继续添加");
            }
        }
    }

    /**
     * 发送请求
     */
    public function sendRequest($url, $params = [], $method = 'post', $auth = true)
    {
        $baseurl = trim($this->cloudconfig['url'] ?? '');
        if (empty($baseurl)) {
            throw new \Exception('请先配置云端地址');
        }

        if (!preg_match('/^https?:\/\//i', $baseurl)) {
            $baseurl = 'http://' . $baseurl;
        }

        $token = '';
        if ($auth) {
            if (!is_file(self::$authpath) || !$token = file_get_contents(self::$authpath)) {
                throw new \Exception('接口token异常，请重新获取');
            }
        }

        $json = [];
        try {
            $options = [
                'timeout'         => 3,
                'connect_timeout' => 3,
                'verify'          => false,
                'http_errors'     => false,
                'headers'         => [
                    'Referer'    => dirname(request()->root(true)),
                    'User-Agent' => 'HYIOT',
                ],
            ];
            $client = new Client($options);
            $method = strtolower($method);

            $params['token'] = $token;
            $options         = $method == 'post' ? ['form_params' => $params] : ['query' => $params];

            // 统一处理斜杠，避免 baseurl 带 / 或 url 不带 / 时拼接异常
            $requestUrl = rtrim($baseurl, '/') . '/' . ltrim($url, '/');
            $response   = $client->request($method, $requestUrl, $options);

            $body    = $response->getBody();
            $content = $body->getContents();
            $json    = $content;
            if ($method == 'post') {
                $json = (array) json_decode($content, true);
            }
        } catch (TransferException $e) {
            throw new \Exception('网络异常~');
        } catch (\Exception $e) {
            throw new \Exception('请求异常' . $e->getMessage());
        }

        return $json;
    }

    /**
     * 设置错误信息
     * @param string|null $error
     * @return bool
     */
    protected static function setError(?string $error = null)
    {
        self::$error = $error ?: '未知错误';
        return false;
    }

    /**
     * 获取错误信息
     * @return string
     */
    public static function getError()
    {
        $error       = self::$error;
        self::$error = null;
        return $error;
    }
}
