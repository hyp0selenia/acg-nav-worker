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
  - 值：你的密码（例如 `mypassword123`）

完成后重新部署一次即可生效。

## 本地开发

```bash
npm install
npx wrangler login
npx wrangler dev
```
---
Powered by 🐋 DeepSeek v4
