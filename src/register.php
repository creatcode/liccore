<?php
defined('DS') or define('DS', DIRECTORY_SEPARATOR);

$publicPath = dirname($_SERVER['SCRIPT_FILENAME']) . DS;

defined('ROOT_PATH') or define('ROOT_PATH', dirname($publicPath) . DS);
defined('APP_PATH') or define('APP_PATH', ROOT_PATH . 'application' . DS);
defined('RUNTIME_PATH') or define('RUNTIME_PATH', ROOT_PATH . 'runtime' . DS);

require_once "../vendor/creatcode/liccore/src/MachineCodeService.php";
require_once "../vendor/creatcode/liccore/src/CloudService.php";
require_once "../thinkphp/library/think/Config.php";

/**
 * 统一返回 JSON 响应
 *
 * @param int $code 状态码
 * @param string $msg 提示信息
 * @param array $data 附加数据
 * @return void
 */
function json_response(int $code, string $msg, array $data = []): void
{
    header('Content-Type: application/json; charset=utf-8');
    exit(json_encode([
        'code' => $code,
        'msg'  => $msg,
        'data' => $data,
    ], JSON_UNESCAPED_UNICODE));
}

/**
 * 输出全屏错误提示并终止
 *
 * @param string $message 错误信息
 * @return void
 */
function render_block_message(string $message): void
{
    $message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

    echo <<<HTML
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <title>站点注册</title>
    <style>
        body {
            margin: 0;
            font-family: "Microsoft YaHei", "PingFang SC", Arial, sans-serif;
            background: rgba(15, 23, 42, 0.92);
        }
        .fullscreen-mask {
            position: fixed;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .mask-message {
            max-width: 640px;
            padding: 20px 28px;
            border-radius: 12px;
            background: #fff;
            color: #111827;
            font-size: 16px;
            line-height: 1.7;
            box-shadow: 0 16px 48px rgba(0, 0, 0, 0.22);
        }
    </style>
</head>
<body>
    <div class="fullscreen-mask">
        <div class="mask-message">{$message}</div>
    </div>
</body>
</html>
HTML;
    exit;
}

/**
 * 发送 CURL 请求
 *
 * @param string $url 请求地址
 * @param array $params 请求参数
 * @param string $method 请求方法
 * @param int $timeout 超时时间
 * @return string
 * @throws Exception
 */
function curl_request(string $url, array $params = [], string $method = 'POST', int $timeout = 10): string
{
    $method = strtoupper($method);
    $ch = curl_init();

    if ($ch === false) {
        throw new Exception('初始化 CURL 失败');
    }

    if ($method === 'GET' && !empty($params)) {
        $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($params);
    }

    $headers = [
        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
        'User-Agent: SiteAuthorization',
    ];

    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => $headers,
    ]);

    if ($method !== 'GET') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    }

    $response = curl_exec($ch);
    $error = curl_error($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false) {
        throw new Exception('请求授权服务失败：' . ($error ?: '网络异常'));
    }

    if ($statusCode < 200 || $statusCode >= 300) {
        throw new Exception('授权服务响应异常，HTTP 状态码：' . $statusCode);
    }

    return $response;
}

/**
 * 加载云端配置
 * 优先读取业务配置，不存在时回退到 liccore 默认配置
 *
 * @return array
 * @throws Exception
 */
function load_cloud_config(): array
{
    $configPath = "../application/extra/cloud.php";

    if (!is_file($configPath)) {
        throw new Exception('未找到云端配置文件：application/extra/cloud.php');
    }

    $config = include $configPath;

    if (!is_array($config)) {
        throw new Exception('云端配置文件格式错误');
    }

    return $config;
}

/**
 * 保存云端配置到业务目录
 *
 * @param array $cloudConfig 配置内容
 * @return void
 * @throws Exception
 */
function save_cloud_config(array $cloudConfig): void
{
    $configDir = "../application/extra";
    $configPath = $configDir . "/cloud.php";

    if (!is_dir($configDir) && !mkdir($configDir, 0755, true) && !is_dir($configDir)) {
        throw new Exception('创建配置目录失败：' . $configDir);
    }

    $content = "<?php\n\nreturn " . var_export($cloudConfig, true) . ";\n";
    if (file_put_contents($configPath, $content) === false) {
        throw new Exception('保存云端配置失败：' . $configPath);
    }
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$licenseDir = "../application/common/license";
$lockFile = $licenseDir . "/register.lock";
$licenseFile = $licenseDir . "/license.lic";
$pemFile = $licenseDir . "/public.pem";

if (!is_dir($licenseDir) && !mkdir($licenseDir, 0755, true) && !is_dir($licenseDir)) {
    render_block_message('授权目录创建失败，请检查 application/common/license 的写入权限。');
}

if (is_file($lockFile)) {
    exit('<title>站点注册</title><div style="text-align:center;margin-top:300px;font-size:20px;">此站点已注册</div>');
}

try {
    $config = load_cloud_config();
} catch (\Throwable $e) {
    render_block_message($e->getMessage());
}

$cloudUrl = trim((string) ($config['url'] ?? ''));
if ($cloudUrl !== '' && !preg_match('/^https?:\/\//i', $cloudUrl)) {
    $cloudUrl = 'http://' . $cloudUrl;
}
$cloudUrl = rtrim($cloudUrl, '/');

$requiredConfig = ['url', 'version'];
foreach ($requiredConfig as $key) {
    if (empty($config[$key])) {
        render_block_message('请先在 application/extra/cloud.php 中填写完整的配置后再继续操作。');
    }
}

if ($method === 'POST') {
    try {
        // 清理机器码缓存，避免读取旧值
        $os = PHP_OS_FAMILY;
        $filename = md5("{$os}_machine_code") . ".dat";
        $cachePath = RUNTIME_PATH . $filename;
        is_file($cachePath) && @unlink($cachePath);

        $name = trim((string) ($_POST['name'] ?? ''));
        $authCheck = isset($_POST['auth_check']) && (int) $_POST['auth_check'] === 1 ? 1 : 0;
        $period = trim((string) ($_POST['period'] ?? ''));
        $env = trim((string) ($_POST['env'] ?? ($config['env'] ?? 'local')));
        $projectId = trim((string) ($_POST['project_id'] ?? ''));
        $devnum = trim((string) ($_POST['devnum'] ?? '-1'));

        if ($name === '') {
            throw new Exception('请输入站点名称');
        }

        if ($projectId === '') {
            throw new Exception('请选择项目类型');
        }

        $env = in_array($env, ['local', 'online'], true) ? $env : 'local';

        if ($authCheck === 1) {
            if ($period === '') {
                throw new Exception('请选择授权有效期');
            }

            // 原生 date 只提交日期，这里统一补齐到当天结束时间
            $periodValue = $period . ' 23:59:59';
        } else {
            $periodValue = '2999-12-31 23:59:59';
        }

        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        if ($host === '') {
            throw new Exception('无法获取当前站点域名');
        }

        $machineCode = \safeaccess\CloudService::init()->getcode();
        if (empty($machineCode)) {
            throw new Exception('获取设备编码失败');
        }

        $params = [
            'name'       => $name,
            'auth_check' => $authCheck,
            'period'     => $periodValue,
            'devnum'     => $devnum,
            'version'    => (string) $config['version'],
            'project_id' => $projectId,
            'type'       => $env,
            'url'        => $protocol . '://' . $host,
            'code'       => $machineCode,
        ];

        $url = $cloudUrl . '/api/index/site_reg';
        $responseBody = curl_request($url, $params, 'POST');
        $response = json_decode($responseBody, true);

        if (json_last_error() !== JSON_ERROR_NONE || !is_array($response)) {
            throw new Exception('授权服务返回格式异常');
        }

        if ((int) ($response['code'] ?? 0) !== 1) {
            throw new Exception('授权失败：' . ($response['msg'] ?? '未知错误'));
        }

        $data = $response['data'] ?? [];
        if (empty($data['project_type'])) {
            throw new Exception('授权服务未返回项目类型');
        }

        if ($authCheck === 1) {
            if (empty($data['secret_key']) || empty($data['license']) || empty($data['pem'])) {
                throw new Exception('授权服务返回数据不完整');
            }

            // 启用授权校验时，写入授权文件
            file_put_contents($lockFile, $data['secret_key']);
            file_put_contents($licenseFile, $data['license']);
            file_put_contents($pemFile, $data['pem']);
        } else {
            // 关闭授权校验时，仅写入注册标记，避免重复进入注册页
            file_put_contents(
                $lockFile,
                !empty($data['secret_key']) ? $data['secret_key'] : 'auth_check_disabled-' . uniqid('', true)
            );
            is_file($licenseFile) && @unlink($licenseFile);
            is_file($pemFile) && @unlink($pemFile);
        }

        // 保存云端确认后的项目类型、运行环境和授权校验开关
        $cloudConfig = $config;
        $cloudConfig['type'] = $data['project_type'];
        $cloudConfig['env'] = $env;
        $cloudConfig['auth_check'] = $authCheck;
        save_cloud_config($cloudConfig);

        // 删除当前安装脚本
        @unlink(__FILE__);

        json_response(1, '注册成功');
    } catch (\Throwable $e) {
        json_response(0, $e->getMessage());
    }
}
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>站点注册</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, minimum-scale=1">
    <meta name="renderer" content="webkit">
    <script src="./assets/libs/jquery/dist/jquery.min.js"></script>
    <style>
    :root {
        --bg-top: #f3fbff;
        --bg-bottom: #eef6ff;
        --panel: rgba(255, 255, 255, 0.92);
        --panel-strong: #ffffff;
        --line: #d8e8f7;
        --line-strong: #bfd9ef;
        --text: #17324d;
        --text-soft: #5f7892;
        --title: #0f2740;
        --primary: #1f8fcb;
        --primary-dark: #146d9c;
        --primary-soft: rgba(31, 143, 203, 0.12);
        --secondary: #eaf6ff;
        --success: #1f9d68;
        --success-bg: #e8f8f0;
        --success-line: #b8e7d0;
        --danger: #c94d5d;
        --danger-bg: #fff1f3;
        --danger-line: #f5c7cf;
        --shadow-lg: 0 28px 80px rgba(58, 105, 145, 0.16);
        --shadow-md: 0 16px 42px rgba(68, 111, 150, 0.12);
        --shadow-sm: 0 10px 24px rgba(94, 127, 159, 0.10);
        --radius-xl: 28px;
        --radius-lg: 20px;
        --radius-md: 14px;
        --radius-sm: 12px;
    }

    * {
        box-sizing: border-box;
    }

    html {
        min-height: 100%;
    }

    body {
        min-height: 100vh;
        margin: 0;
        padding: 40px 16px;
        color: var(--text);
        line-height: 1.5;
        background:
            radial-gradient(circle at 0% 0%, rgba(143, 211, 255, 0.45), transparent 28%),
            radial-gradient(circle at 100% 12%, rgba(196, 233, 255, 0.72), transparent 24%),
            radial-gradient(circle at 20% 100%, rgba(217, 242, 255, 0.78), transparent 26%),
            linear-gradient(180deg, var(--bg-top) 0%, var(--bg-bottom) 100%);
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }

    body,
    input,
    select,
    button {
        font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
        font-size: 14px;
    }

    a {
        color: var(--primary);
        text-decoration: none;
    }

    a:hover {
        text-decoration: none;
    }

    .container {
        position: relative;
        width: 100%;
        max-width: 580px;
        margin: 0 auto;
        padding: 18px;
        border-radius: 32px;
        background: rgba(255, 255, 255, 0.38);
        box-shadow: var(--shadow-lg);
        backdrop-filter: blur(12px);
    }

    .container::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: 32px;
        padding: 1px;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(191, 217, 239, 0.55));
        -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        pointer-events: none;
    }

    .register-card {
        position: relative;
        overflow: hidden;
        border-radius: var(--radius-xl);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(250, 253, 255, 0.98));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.88);
    }

    .register-card::before {
        content: "";
        position: absolute;
        top: -120px;
        right: -90px;
        width: 220px;
        height: 220px;
        border-radius: 999px;
        background: radial-gradient(circle, rgba(139, 218, 255, 0.36), transparent 70%);
        pointer-events: none;
    }

    .register-header {
        position: relative;
        padding: 34px 34px 20px;
        text-align: center;
    }

    .register-badge {
        width: 84px;
        height: 84px;
        margin: 0 auto 18px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 26px;
        background: linear-gradient(180deg, #ffffff 0%, #edf9ff 100%);
        border: 1px solid rgba(202, 230, 246, 0.92);
        box-shadow: var(--shadow-md);
    }

    .register-badge svg {
        width: 58px;
        height: 58px;
    }

    .register-eyebrow {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 30px;
        padding: 0 14px;
        margin-bottom: 12px;
        border: 1px solid #d7ebfa;
        border-radius: 999px;
        color: #4d86ab;
        background: #f4fbff;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1px;
    }

    .register-title {
        margin: 0;
        color: var(--title);
        font-size: 31px;
        font-weight: 700;
        letter-spacing: 0.5px;
    }

    .page-desc {
        max-width: 420px;
        margin: 12px auto 0;
        color: var(--text-soft);
        font-size: 14px;
        line-height: 1.75;
    }

    .register-body {
        padding: 6px 34px 34px;
    }

    form {
        margin: 0;
        text-align: left;
    }

    .form-panel {
        padding: 24px;
        border: 1px solid #e4f0fa;
        border-radius: 22px;
        background: linear-gradient(180deg, rgba(247, 252, 255, 0.92), rgba(255, 255, 255, 0.98));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.84);
    }

    .form-group {
        margin-bottom: 18px;
    }

    .form-group:last-of-type {
        margin-bottom: 0;
    }

    .form-field {
        position: relative;
    }

    .form-field label {
        display: block;
        margin-bottom: 9px;
        color: #23415f;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.2px;
    }

    .form-field input,
    .custom-select {
        width: 100%;
        height: 52px;
        margin: 0;
        padding: 0 16px;
        color: var(--text);
        border: 1px solid var(--line);
        border-radius: var(--radius-sm);
        background: var(--panel-strong);
        outline: none;
        transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s, transform 0.2s;
    }

    .form-field input::placeholder {
        color: #95aabd;
    }

    .form-field input:hover,
    .custom-select:hover {
        border-color: var(--line-strong);
        background: #fcfeff;
    }

    .form-field input:focus,
    .custom-select:focus {
        border-color: var(--primary);
        box-shadow: 0 0 0 4px var(--primary-soft);
        background: #ffffff;
    }

    .custom-select {
        padding-right: 46px;
        cursor: pointer;
        appearance: none;
        -webkit-appearance: none;
        -moz-appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg width='14' height='14' viewBox='0 0 14 14' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M3.2 5.1L7 8.9l3.8-3.8' fill='none' stroke='%231f8fcb' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 16px center;
        background-size: 14px;
    }

    .form-field span {
        display: inline-block;
        margin-top: 8px;
        color: var(--text-soft);
        font-size: 12px;
        line-height: 1.6;
    }

    .date-row {
        display: flex;
        gap: 10px;
    }

    .date-row input {
        flex: 1;
    }

    #error,
    #success {
        margin-bottom: 18px;
        padding: 14px 16px;
        border-radius: 14px;
        line-height: 1.7;
        font-size: 13px;
    }

    #error {
        color: var(--danger);
        border: 1px solid var(--danger-line);
        background: var(--danger-bg);
        box-shadow: 0 10px 20px rgba(201, 77, 93, 0.08);
    }

    #success {
        color: var(--success);
        border: 1px solid var(--success-line);
        background: var(--success-bg);
        box-shadow: 0 10px 20px rgba(31, 157, 104, 0.08);
    }

    .form-buttons {
        margin-top: 24px;
        min-height: 54px;
        line-height: normal;
    }

    button,
    .btn {
        width: 100%;
        min-height: 54px;
        padding: 0 28px;
        color: #ffffff;
        border: 0;
        border-radius: 14px;
        cursor: pointer;
        font-weight: 700;
        letter-spacing: 0.8px;
        background: linear-gradient(135deg, #2899d4 0%, #54b5e3 100%);
        box-shadow: 0 18px 34px rgba(40, 153, 212, 0.24);
        transition: transform 0.2s, box-shadow 0.2s, opacity 0.2s, filter 0.2s;
        -webkit-appearance: none;
    }

    button:hover,
    .btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 22px 38px rgba(40, 153, 212, 0.28);
        filter: saturate(1.02);
    }

    button:focus-visible,
    .btn:focus-visible {
        outline: 3px solid rgba(31, 143, 203, 0.22);
        outline-offset: 3px;
    }

    button[disabled] {
        cursor: not-allowed;
        opacity: 0.66;
        transform: none;
        box-shadow: none;
        filter: none;
    }

    .permanent-btn {
        width: 96px;
        min-height: 52px;
        padding: 0;
        flex: 0 0 96px;
        color: var(--primary-dark);
        background: linear-gradient(180deg, #f6fbff 0%, #e8f4fc 100%);
        border: 1px solid #d0e5f5;
        box-shadow: none;
    }

    .permanent-btn:hover {
        box-shadow: none;
        background: linear-gradient(180deg, #fafdff 0%, #e1f0fb 100%);
    }

    #back-home {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        min-height: 54px;
        margin-top: 6px;
        color: #ffffff;
        border-radius: 14px;
        background: linear-gradient(135deg, #2899d4 0%, #54b5e3 100%) !important;
        box-shadow: 0 18px 34px rgba(40, 153, 212, 0.24);
    }

    #back-home:hover {
        color: #ffffff;
    }

    @media (max-width: 640px) {
        body {
            padding: 20px 12px;
        }

        .container {
            padding: 12px;
            border-radius: 24px;
        }

        .register-header {
            padding: 26px 22px 16px;
        }

        .register-body {
            padding: 0 22px 24px;
        }

        .form-panel {
            padding: 18px;
            border-radius: 18px;
        }

        .register-title {
            font-size: 26px;
        }

        .page-desc {
            font-size: 13px;
        }

        .date-row {
            flex-direction: column;
        }

        .permanent-btn {
            width: 100%;
            flex-basis: auto;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        *,
        *::before,
        *::after {
            transition: none !important;
            animation: none !important;
            scroll-behavior: auto !important;
        }
    }
</style>
</head>

<body>
    <div class="container">
    <div class="register-card">
        <div class="register-header">
            <!-- <div class="register-eyebrow">LICENSE CENTER</div> -->
            <h2 class="register-title">站点注册</h2>
            <p class="page-desc">填写基础信息后完成当前站点授权注册</p>
        </div>

        <div class="register-body">
            <form method="post" id="register-form">
                <div id="error" style="display:none"></div>
                <div id="success" style="display:none"></div>

                <div class="form-panel">
                    <div class="form-group">
                        <div class="form-field">
                            <label for="make">项目类型</label>
                            <select name="project_id" class="custom-select" required id="make">
                                <option value="">----- 请选择项目类型 -----</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="form-field">
                            <label for="env">运行环境</label>
                            <select name="env" class="custom-select" required id="env">
                                <option value="local">本地</option>
                                <option value="online">线上</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="form-field">
                            <label for="name">站点名称</label>
                            <input type="text" name="name" value="" required id="name">
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="form-field">
                            <label for="auth-check">授权校验</label>
                            <select name="auth_check" class="custom-select" required id="auth-check">
                                <option value="1">启用授权校验</option>
                                <option value="0" selected>关闭授权校验</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group" id="period-group" style="display:none">
                        <div class="form-field">
                            <label for="period">授权有效期</label>
                            <div class="date-row">
                                <input type="date" name="period" value="" required id="period" max="2999-12-31">
                                <button type="button" class="permanent-btn" id="set-permanent">永久</button>
                            </div>
                        </div>
                    </div>

                    <div class="form-group" id="devnum-group" style="display:none">
                        <div class="form-field">
                            <label for="devnum">授权设备数</label>
                            <input type="text" name="devnum" value="-1" id="devnum">
                            <span>tips：`-1` 表示不限制</span>
                        </div>
                    </div>
                </div>

                <div class="form-buttons">
                    <button type="submit" id="submit-btn">提交</button>
                </div>
            </form>
        </div>
    </div>
</div>

    <script>
        var baseurl = "<?php echo htmlspecialchars($cloudUrl, ENT_QUOTES, 'UTF-8'); ?>";

        // 获取项目类型数据
        function callback(data) {
            if (!$.isArray(data) || data.length === 0) {
                $('#error').show().text('获取项目类型失败，请检查云端地址配置');
                return;
            }

            data.forEach(function(item) {
                $('#make').append(
                    '<option value="' + item.type + '" data-type="' + item.type + '">' + item.name + '</option>'
                );
            });

            $('#error').hide();
            $('#make').trigger('change');
        }

        // 拉取项目类型列表
        $.ajax({
            url: baseurl + '/api/index/getproject',
            type: 'GET',
            dataType: 'jsonp',
            jsonpCallback: 'callback',
            timeout: 5000,
            error: function() {
                $('#error').show().text('获取项目类型失败，请检查云端地址或网络连接');
            }
        });

        $(function() {
            $('#name').trigger('focus');

            // 切换授权有效期输入框
            function togglePeriod() {
                var isAuthCheck = $('#auth-check').val() === '1';
                var $period = $('#period');

                if (isAuthCheck) {
                    $('#period-group').show();
                    $period.prop('required', true);

                    // 重新启用授权校验时，清理永久日期占位值
                    if ($period.val() === '2999-12-31') {
                        $period.val('');
                    }
                } else {
                    $('#period-group').hide();
                    $period.prop('required', false).val('');
                }
            }

            // 按项目类型切换设备数输入框
            function toggleDevnum() {
                var projectType = $('#make option:selected').data('type');
                var isIotadmin = projectType === 'iotadmin';

                $('#devnum-group').toggle(isIotadmin);
                $('#devnum').prop('required', isIotadmin);
            }

            $('#auth-check').on('change', togglePeriod);
            $('#make').on('change', toggleDevnum);

            $('#set-permanent').on('click', function() {
                // 原生 date 只保存日期，后端会补齐为 2999-12-31 23:59:59
                $('#period').val('2999-12-31');
            });

            togglePeriod();
            toggleDevnum();

            $('#register-form').on('submit', function(e) {
                e.preventDefault();

                var form = this;
                var $error = $('#error');
                var $success = $('#success');
                var $button = $('#submit-btn');
                var $subButtons = $('.form-buttons', form);

                $error.hide().text('');
                $success.hide().text('');
                $button.text('提交中...').prop('disabled', true);

                $.ajax({
                    url: '',
                    type: 'POST',
                    dataType: 'json',
                    data: $(form).serialize(),
                    success: function(ret) {
                        if (ret.code === 1) {
                            $error.hide();
                            $('.form-group', form).remove();
                            $button.remove();
                            $success.text(ret.msg).show();
                            $("<a class='btn' id='back-home' href='/'>返回首页</a>").appendTo($subButtons);
                            return;
                        }

                        $error.show().text(ret.msg || '提交失败');
                        $button.prop('disabled', false).text('重新提交');
                        $('html,body').animate({ scrollTop: 0 }, 300);
                    },
                    error: function(xhr) {
                        var message = '提交失败，请稍后重试';
                        if (xhr.responseJSON && xhr.responseJSON.msg) {
                            message = xhr.responseJSON.msg;
                        } else if (xhr.responseText) {
                            message = xhr.responseText;
                        }

                        $error.show().text(message);
                        $button.prop('disabled', false).text('重新提交');
                        $('html,body').animate({ scrollTop: 0 }, 300);
                    }
                });

                return false;
            });
        });
    </script>
</body>
</html>