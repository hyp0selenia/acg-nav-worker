# 🕊️ 鸽子窝 导航

基于 Cloudflare Workers + KV 的轻量级个人导航页面。

支持后台增删改链接、拖动排序，用户名 + 密码登录。

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

#### ② 设置登录账号
- 进入 **Variables and Secrets** → **Secrets**（密码）与 **Variables**（用户名）
- 添加：

| 名称 | 类型 | 说明 | 不填时 |
|---|---|---|---|
| `ADMIN_PASSWORD` | Secret | 登录密码 | **必填**，不填则拒绝所有登录 |
| `ADMIN_USERNAME` | Variable | 登录用户名 | 默认 `admin` |

> ⚠️ **`ADMIN_PASSWORD` 是必填的。** 没有配置时登录接口会直接返回「未配置管理密码」
> 并拒绝所有登录。这是刻意为之：旧版本在没有密码时会退回一个写死在源码里的默认
> 密码，而本仓库是公开的，等于没有锁。

完成后重新部署一次即可生效。

## 后台使用

- **改内容**：改完点该行的「保存」。
- **调顺序**：拖行首的 ⠿ 手柄，或用 ▲ / ▼ 按钮；也可以聚焦某行的输入框后按
  `Alt + ↑/↓`。顺序有改动时底部会出现「保存顺序」提示条，点它一次写入即可
  （也可以点「还原」放弃）。**不需要删除再重新添加**。
- **退出登录**：右上角按钮。服务端会立刻作废当前令牌（包括被复制走的 Cookie）。

首页与后台都按保存后的顺序渲染。

## 安全说明

- **登录方式**：`/admin` 是一个正常的登录表单页面（HTTP 200），填写用户名 +
  密码。不再使用浏览器原生 Basic Auth 弹窗，原因见下方小节。
- **会话**：登录成功后签发 HMAC 签名的令牌，放在 `HttpOnly` + `SameSite=Strict`
  Cookie 里，有效 **30 天**，并且每次打开后台或保存都会自动续期。前端 JavaScript
  接触不到密码，也读不到令牌。
- **退出登录真的会失效**：令牌里带一个「会话代数」，退出登录或重新登录都会让
  代数 +1，此前的令牌立即作废（包括被人复制走的 Cookie）。纯 HMAC 令牌本身是
  无状态的，只删浏览器 Cookie 是删不掉服务端有效性的。
- **防爆破**：同一 IP 连续输错 10 次后限流 15 分钟（返回 `429`，带 `Retry-After`）。
  计数存在 KV 中，因此不会被分散请求绕过。
- **改密码即登出**：令牌用 `ADMIN_PASSWORD` 派生密钥签名，改密码会让所有已登录
  会话立即失效；改 `ADMIN_USERNAME` 同理。
- **CSRF**：写接口只接受 JSON 请求体，且会话 Cookie 为 `SameSite=Strict`，跨站
  表单无法携带会话。

### 为什么不用浏览器弹窗（Basic Auth）

| | 弹窗 Basic Auth（旧） | 页面登录（现在） |
|---|---|---|
| 密码暴露面 | 每个请求都带密码，日志/代理都可能记录 | 只在登录那一次提交 |
| XSS 窃取 | 页面 JS 可读到凭据 | 令牌是 `HttpOnly`，JS 读不到 |
| 退出登录 | **做不到**：浏览器缓存凭据并自动重发 | 服务端作废令牌，真实生效 |
| 换账号 | **做不到**：永远发送旧账号 | 退出后即可换 |
| 改密码 | 旧凭据继续有效 | 立即失效所有会话 |
| 是否反复弹窗 | 浏览器清缓存后重新弹 | 30 天内不再询问 |
| 自定义 | 无法加限流、验证码等 | 可扩展 |

> 上一版曾保留 Basic 作为 API 兜底，这恰恰是这个 bug 的根源：浏览器把 Basic
> 凭据缓存起来并对同源请求自动重发，导致「退出退不掉、换账号登不进」。现已
> 完全移除，改脚本调用请用下方的一次性令牌。

### 脚本调用 API

`/api/login` 会返回会话 Cookie；也可以把令牌取出来放进 `X-Nav-Token` 头，
服务端不接受 HTTP Basic，因此不会有凭据被浏览器缓存的问题：

```bash
# 1) 登录并保存 Cookie
curl -s -c jar.txt -X POST https://你的域名/api/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"你的密码"}'

# 2) 带着 Cookie 调用写接口
curl -s -b jar.txt -X POST https://你的域名/api/links \
     -H 'Content-Type: application/json' \
     -d '{"title":"新链接","url":"https://example.com"}'
```

## 本地开发

```bash
npm install
npx wrangler dev
```

本地必须提供密码，否则登录会返回「未配置管理密码」（见上方说明）。复制仓库里的
模板并填上自己的值：

```bash
cp .dev.vars.example .dev.vars
```

```
ADMIN_PASSWORD=change-me
ADMIN_USERNAME=admin
```

`wrangler dev` 会自动读取 `.dev.vars`。该文件已在 `.gitignore` 中，**不会被提交**；
`.dev.vars.example` 只是模板，会随仓库一起提交。

> 本地跑在 `http://` 上时，会话 Cookie 的 `Secure` 标记会自动省略
> （代码里按请求协议判断），因此登录态在本地同样可用。

## 测试

```bash
node tests/worker.test.mjs   # 79 项，直接跑 Worker 逻辑，无需联网
node tests/live.test.mjs     # 39 项，需先 npx wrangler dev（默认 127.0.0.1:8787）
```
---
## AI
100% AI Generated
