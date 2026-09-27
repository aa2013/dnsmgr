<?php

namespace app\lib\deploy;

use app\lib\DeployInterface;
use Exception;

class nzcdn implements DeployInterface
{
    // 接口基址，裸域 nzcdn.com 会 301 跳转到 www，固定带 www
    private const BASE_URL = 'https://www.nzcdn.com';

    private const TIMEOUT = 60;
    // 域名列表单页拉取数量
    private const PAGE_SIZE = 100;
    // 删除证书接口成功状态码，204 无内容属正常响应
    private const DELETE_SUCCESS_CODES = [200, 204];
    // 证书名称随机后缀长度
    private const NAME_SUFFIX_LENGTH = 6;
    // 请求头标识，与 http_request 保持一致
    private const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';

    private $logger;
    private $username;
    private $password;
    private $proxy;
    private $cookie = '';

    public function __construct($config)
    {
        $this->username = trim($config['username'] ?? '');
        $this->password = $config['password'] ?? '';
        $this->proxy = ($config['proxy'] ?? 0) == 1;
    }

    public function check()
    {
        if ($this->username === '' || $this->password === '') {
            throw new Exception('请填写哪吒CDN的账号和密码');
        }
        $this->login();
    }

    public function deploy($fullchain, $privatekey, $config, &$info)
    {
        if (trim($fullchain) === '' || trim($privatekey) === '') {
            throw new Exception('证书或私钥内容为空');
        }

        // 本任务上次部署时创建的证书，部署成功后按开关清理，避免后台堆积
        $oldCertId = intval($config['cert_id'] ?? 0);

        $domains = $this->resolveDomains($config);
        $this->log('待部署域名：' . implode('、', $domains));

        $this->login();

        $domainMap = $this->fetchDomainMap();
        $this->log('获取域名列表成功，共' . count($domainMap) . '个域名配置');

        // 同一个域名可能在远端同时存在 domain 与 ascii 索引，此处按首次出现保留
        $targets = [];
        $missing = [];
        foreach ($domains as $domain) {
            $key = strtolower($domain);
            if (isset($domainMap[$key])) {
                $targets[$key] = $domainMap[$key];
            } else {
                $missing[] = $domain;
            }
        }
        if (empty($targets)) {
            throw new Exception('要部署的域名不存在：' . implode('、', $missing));
        }
        if (!empty($missing)) {
            $this->log('以下域名不存在，已跳过：' . implode('、', $missing));
        }

        $newCertId = $this->uploadCert(array_key_first($targets), $fullchain, $privatekey);
        $this->log('证书上传成功，证书ID：' . $newCertId);

        $success = 0;
        $errmsg = null;
        foreach ($targets as $domain => $domainId) {
            try {
                $this->bindCert($domainId, $newCertId);
                $this->log("域名 {$domain} 证书部署成功");
                $success++;
            } catch (Exception $e) {
                $errmsg = $e->getMessage();
                $this->log("域名 {$domain} 证书部署失败：" . $errmsg);
            }
        }
        if ($success == 0) {
            throw new Exception($errmsg ? $errmsg : '证书部署失败');
        }

        // 新证书已生效，此时清理旧证书即使失败也不影响本次部署结果
        if (!empty($config['delete_old_cert'])) {
            if ($oldCertId > 0 && $oldCertId != $newCertId) {
                try {
                    $this->deleteCert($oldCertId);
                    $this->log('旧证书 ' . $oldCertId . ' 已删除');
                } catch (Exception $e) {
                    $this->log('旧证书 ' . $oldCertId . ' 删除失败：' . $e->getMessage());
                }
            } else {
                $this->log('没有需要删除的旧证书');
            }
        }

        $info['config']['cert_id'] = $newCertId;
    }

    /**
     * 登录太虚云控制台，登录成功后以响应头 Set-Cookie 作为后续请求的身份凭证
     *
     * 服务端在登录失败时同样会下发 SmartWebSID 会话 Cookie，因此不能只凭是否
     * 收到 Cookie 判断成功，必须同时校验状态码。
     *
     * @throws Exception
     */
    private function login()
    {
        $params = [
            'username' => $this->username,
            // 接口要求提交密码的 MD5 值，账户配置中保存的是真实密码
            'password' => md5($this->password),
        ];
        $response = $this->request('/api/website/v1/account/auth/login', $params, 'POST');
        if ($response['code'] != 200) {
            throw new Exception('登录失败，' . $this->errorMessage($response));
        }
    }

    /**
     * 确定本次要绑定的域名
     *
     * 任务中手填的域名优先，未填写时回退为证书订单包含的全部域名
     */
    private function resolveDomains($config): array
    {
        $domains = [];
        $input = trim($config['domain'] ?? '');
        if ($input !== '') {
            $domains = preg_split('/[,，\r\n]+/u', $input);
        } elseif (!empty($config['domainList']) && is_array($config['domainList'])) {
            $domains = $config['domainList'];
        }

        $result = [];
        foreach ($domains as $domain) {
            $domain = trim(strtolower($domain));
            if ($domain !== '' && !in_array($domain, $result, true)) {
                $result[] = $domain;
            }
        }
        if (empty($result)) {
            throw new Exception('没有要部署的域名');
        }
        return $result;
    }

    /**
     * 拉取太虚云域名列表，返回 域名 => 域名配置ID 的映射
     *
     * 列表接口分页返回，按 total 持续翻页直到取完。
     * 泛解析与国际化域名可能只有 ascii 字段有值，故两个字段都建立索引。
     *
     * @throws Exception
     */
    private function fetchDomainMap(): array
    {
        $map = [];
        $start = 0;
        $total = 0;
        do {
            $response = $this->request('/api/website/v1/domain/list', [
                'page' => ['start' => $start, 'num' => self::PAGE_SIZE],
                'area' => '',
            ], 'POST');
            if ($response['code'] != 200) {
                throw new Exception('获取域名列表失败，' . $this->errorMessage($response));
            }
            $result = json_decode($response['body'] ?? '', true);
            $rows = is_array($result) ? ($result['data'] ?? null) : null;
            if (!is_array($rows)) {
                throw new Exception('获取域名列表失败，返回数据格式异常');
            }
            foreach ($rows as $row) {
                if (!is_array($row) || empty($row['id'])) continue;
                foreach ([$row['domain'] ?? '', $row['ascii'] ?? ''] as $name) {
                    $name = strtolower(trim($name));
                    if ($name !== '' && !isset($map[$name])) {
                        $map[$name] = intval($row['id']);
                    }
                }
            }
            $total = is_array($result) ? intval($result['total'] ?? 0) : 0;
            $start += self::PAGE_SIZE;
            // 单页取空时立即终止，避免 total 异常导致死循环
            if (empty($rows)) break;
        } while ($start < $total);

        if (empty($map)) {
            throw new Exception('太虚云账号下没有查询到任何域名');
        }
        return $map;
    }

    /**
     * 上传证书，返回证书ID
     *
     * @throws Exception
     */
    private function uploadCert($domain, $fullchain, $privatekey): int
    {
        $params = [
            'name' => $this->buildCertName($domain),
            'pem' => $fullchain,
            'key' => $privatekey,
        ];
        $response = $this->request('/api/website/v1/ca/add', $params, 'POST');
        $result = json_decode($response['body'] ?? '', true);
        $certId = is_array($result) ? intval($result['id'] ?? 0) : 0;
        if ($response['code'] != 200 || $certId <= 0) {
            throw new Exception('证书上传失败，' . $this->errorMessage($response));
        }
        return $certId;
    }

    /**
     * 将证书绑定到指定的域名配置
     *
     * 该接口成功时响应体为空，仅能依据状态码判断结果
     *
     * @throws Exception
     */
    private function bindCert($domainId, $certId)
    {
        $path = '/api/website/v1/domain/' . intval($domainId) . '/configuration';
        $params = ['https' => ['cert' => intval($certId)]];
        $response = $this->request($path, $params, 'PATCH');
        if ($response['code'] != 200) {
            throw new Exception('域名配置ID:' . intval($domainId) . '更新失败，' . $this->errorMessage($response));
        }
    }

    /**
     * 删除太虚云上已失效的旧证书
     *
     * @throws Exception
     */
    private function deleteCert($certId)
    {
        $path = '/api/website/v1/ca/' . intval($certId);
        $response = $this->request($path, null, 'DELETE');
        if (!in_array($response['code'], self::DELETE_SUCCESS_CODES, true)) {
            throw new Exception('证书ID:' . intval($certId) . '删除失败，' . $this->errorMessage($response));
        }
    }

    /**
     * 证书名称由域名与随机字符拼凑
     */
    private function buildCertName($domain): string
    {
        // 泛解析域名去掉通配符，并清理可能残留的首尾点号
        $name = trim(str_replace('*', '', $domain), '.');
        // 过长域名截断
        if (strlen($name) > 40) {
            $name = substr($name, 0, 40);
        }
        return $name . '-' . substr(getSid(), 0, self::NAME_SUFFIX_LENGTH);
    }

    /**
     * 从响应头中提取并合并登录 Cookie
     *
     * 服务端主动失效（空值或 deleted）的项则移除。
     */
    private function mergeCookies($headers): void
    {
        $cookies = [];
        foreach ($this->cookie !== '' ? array_map('trim', explode('; ', $this->cookie)) : [] as $pair) {
            $pos = strpos($pair, '=');
            if ($pos !== false) {
                $cookies[substr($pair, 0, $pos)] = substr($pair, $pos + 1);
            }
        }

        $updated = false;
        foreach ((array)$headers as $name => $values) {
            if (strcasecmp($name, 'Set-Cookie') !== 0) {
                continue;
            }
            foreach ((array)$values as $value) {
                // 仅取 name=value 部分，剔除 Path/HttpOnly 等属性
                $pair = trim(explode(';', $value, 2)[0]);
                $pos = strpos($pair, '=');
                if ($pos === false) continue;
                $key = substr($pair, 0, $pos);
                $val = substr($pair, $pos + 1);
                if ($val === '' || $val === 'deleted') {
                    unset($cookies[$key]);
                } else {
                    $cookies[$key] = $val;
                }
                $updated = true;
            }
        }

        if ($updated) {
            $pairs = [];
            foreach ($cookies as $key => $val) {
                $pairs[] = $key . '=' . $val;
            }
            $this->cookie = implode('; ', $pairs);
        }
    }

    /**
     * 提取接口返回的错误信息
     */
    private function errorMessage($response): string
    {
        $result = json_decode($response['body'] ?? '', true);
        if (is_array($result)) {
            foreach (['message', 'msg', 'error', 'errmsg'] as $key) {
                if (!empty($result[$key])) {
                    return is_string($result[$key])
                        ? $result[$key]
                        : json_encode($result[$key], JSON_UNESCAPED_UNICODE);
                }
            }
        }
        $body = trim($response['body'] ?? '');
        if ($body !== '' && strlen($body) <= 200) {
            return $body;
        }
        return 'HTTP状态码 ' . ($response['code'] ?? '未知');
    }

    /**
     * 发送接口请求，自动附带并更新登录 Cookie
     *
     * 太虚云以非标准的 600 状态码表示业务失败（如账号不存在），Guzzle 的响应头
     * 解析只接受 100-599，遇到 600 会直接抛异常并丢失业务错误信息，
     * 故此处绕开 http_request 直接使用原生 cURL，保证任何 HTTP 响应都能取回。
     *
     * @return array 含 code / headers / body 的响应
     * @throws Exception 网络异常或未安装 cURL 扩展
     */
    private function request($path, $params = null, $method = 'POST'): array
    {
        if (!function_exists('curl_init')) {
            throw new Exception('太虚云接口请求失败，PHP 未安装 cURL 扩展');
        }

        $headers = ['Content-Type: application/json'];
        if ($this->cookie !== '') {
            $headers[] = 'Cookie: ' . $this->cookie;
        }

        $responseHeaders = [];
        $ch = curl_init(self::BASE_URL . $path);
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            // 接口不会重定向，跟随会导致凭据被带到跳转地址
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$responseHeaders) {
                $length = strlen($line);
                $pos = strpos($line, ':');
                // 状态行与空行没有冒号，跳过
                if ($pos !== false) {
                    $name = trim(substr($line, 0, $pos));
                    $responseHeaders[$name][] = trim(substr($line, $pos + 1));
                }
                return $length;
            },
        ];
        if ($params !== null) {
            $options[CURLOPT_POSTFIELDS] = json_encode($params, JSON_UNESCAPED_UNICODE);
        }
        if ($this->proxy) {
            curl_set_proxy($ch);
        }
        curl_setopt_array($ch, $options);

        $body = curl_exec($ch);
        if (curl_errno($ch) !== 0) {
            $errmsg = curl_error($ch);
            curl_close($ch);
            throw new Exception('太虚云接口请求失败，' . $errmsg);
        }

        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        $this->mergeCookies($responseHeaders);

        return [
            'code' => intval($code),
            'headers' => $responseHeaders,
            'body' => $body === false ? '' : $body,
        ];
    }

    public function setLogger($func)
    {
        $this->logger = $func;
    }

    private function log($txt)
    {
        if ($this->logger) {
            call_user_func($this->logger, $txt);
        }
    }
}
