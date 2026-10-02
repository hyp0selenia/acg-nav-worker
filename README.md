# 🕊️ 鸽子窝 导航

基于 Cloudflare Workers + KV 的轻量级个人导航页面。

支持后台增删改链接，密码鉴权。

## 一键部署到 Cloudflare（推荐）

1. Fork 或直接使用本仓库
2. 打开 [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **Create** → **Connect to Git**
3. 选择本仓库 → 框架预设选 **None** 或 **Workers**
4. 部署完成后，进入该 Worker 的 **Settings**：

### 必须手动配置的两项：

#### ① 绑定 KV
- 进入 **Variables and Secrets** → **KV Namespace Bindings**
- 变量名填写：`NAV`
- 选择或新建一个 KV Namespace

#### ② 设置管理密码
- 进入 **Variables and Secrets** → **Secrets**
- 添加 Secret：
  - 名称：`ADMIN_PASSWORD`
  - 值：你的密码（例如 `mypass123`）

> ⚠️ **此项现在是必填的。** 没有配置 `ADMIN_PASSWORD` 时，登录接口会直接返回
> 「未配置管理密码」并拒绝所有登录。这是刻意为之：旧版本在没有密码时会退回
> 一个写死在源码里的默认密码，而本仓库是公开的，等于没有锁。

完成后重新部署一次即可生效。

## 安全说明

- **登录方式**：`/admin` 是一个正常的登录表单页面（HTTP 200），不再使用浏览器
  原生 Basic Auth 弹窗。原因见下方「为什么不用弹窗」。
- **会话**：登录成功后签发 HMAC 签名的令牌，放在 `HttpOnly` + `SameSite=Strict`
  Cookie 里，有效 **30 天**。前端 JavaScript 接触不到密码或令牌，只在过期时
  重新登录一次。
- **防爆破**：同一 IP 连续输错 10 次密码后，会被限流 15 分钟（返回 `429`）。
  计数存在 KV 中，因此不会被分散请求绕过。
- **改密码即登出**：令牌用 `ADMIN_PASSWORD` 派生密钥签名，改密码会让所有
  已登录会话立即失效。
- **CSRF**：写接口只接受 `POST/PUT/DELETE` + JSON 请求体，且会话 Cookie 为
  `SameSite=Strict`，跨站表单无法携带会话。
- 仍然保留 HTTP Basic 鉴权，方便 `curl` 直接调用 API：
  ```bash
  curl -u admin:你的密码 -X POST https://你的域名/api/links \
       -H 'Content-Type: application/json' \
       -d '{"title":"新链接","url":"https://example.com"}'
  ```

### 为什么不用浏览器弹窗（Basic Auth）

| | 弹窗 Basic Auth（旧） | 页面登录（现在） |
|---|---|---|
| 密码暴露面 | 每个请求都带密码，日志/代理都可能记录 | 只在登录那一次提交 |
| XSS 窃取 | 页面 JS 可读到凭据 | 令牌是 `HttpOnly`，JS 读不到 |
| 退出登录 | 无法退出，只能关浏览器 | 提供「退出登录」按钮 |
| 改密码 | 旧凭据继续有效 | 立即失效所有会话 |
| 是否反复弹窗 | 浏览器清缓存后重新弹 | 30 天内不再询问 |
| 自定义 | 无法加限流、验证码等 | 可扩展 |

## 本地开发

```bash
npm install
npx wrangler dev
```

本地必须提供密码，否则登录会返回「未配置管理密码」（见上方说明）。新建一个
`.dev.vars`（已在 `.gitignore` 中忽略，不会被提交）：

```
ADMIN_PASSWORD=admin123
```

`wrangler dev` 会自动读取它。

> 本地跑在 `http://` 上时，会话 Cookie 的 `Secure` 标记会自动省略
> （代码里按请求协议判断），因此登录态在本地同样可用。

## 测试

```bash
node tests/worker.test.mjs   # 46 项，直接跑 Worker 逻辑，无需联网
node tests/live.test.mjs     # 需先 npx wrangler dev（默认 127.0.0.1:8787）
```
---
## AI
100% AI Generated
