export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // 路由
    if (path === "/admin" || path.startsWith("/admin/")) {
      return handleAdmin(request, env);
    }

    if (path === "/api/login") {
      return handleLogin(request, env);
    }

    if (path === "/api/logout") {
      return handleLogout();
    }

    if (path === "/api/links") {
      return handleApiLinks(request, env);
    }

    // 首页
    return handleHome(request, env);
  },
};

/* ==================== 配置检查 ==================== */

// KV 未绑定时给出明确提示，而不是抛异常变成 500
function kv(env) {
  const ns = env && env.NAV;
  if (!ns || typeof ns.get !== "function" || typeof ns.put !== "function") return null;
  return ns;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    },
  });
}

function kvMissingResponse() {
  return jsonResponse(
    {
      error: "KV 未绑定",
      hint: "请在 Cloudflare Dashboard → 该 Worker → Settings → 变量和绑定 中添加 KV 命名空间绑定，变量名必须是 NAV。",
    },
    500
  );
}

/* ==================== 会话令牌 ==================== */

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 天免登录
const encoder = new TextEncoder();

function b64urlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  return atob(s + "=".repeat((4 - (s.length % 4)) % 4));
}

function bytesToB64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return b64urlEncode(bin);
}

/* ==================== 密钥派生与比较 ==================== */

// 一切校验都基于 ADMIN_PASSWORD。以前这里有一个硬编码的兜底字符串，
// 那等于公开了签名密钥：本仓库是开源的，任何人都能据此伪造合法会话令牌、
// 完全绕过密码。所以没配密码时必须失败关闭，而不是退回默认值。
function secretFor(env) {
  const pw = env && env.ADMIN_PASSWORD;
  return typeof pw === "string" && pw.length > 0 ? pw : null;
}

// 从主密钥派生用途隔离的子密钥，避免同一把密钥到处复用
async function deriveKey(purpose, env) {
  const root = secretFor(env);
  if (!root) return null;
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(root),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", material, encoder.encode("anime-nav/" + purpose + "/v1"));
  return crypto.subtle.importKey("raw", mac, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

// 长度无关的定时安全比较：先各自 HMAC 成固定长度再逐字节比，
// 这样比较耗时既不暴露内容、也不暴露长度。
// 注意两侧必须签同一段明文（HMAC 的密钥已经起到了域隔离作用）。
async function safeEqual(a, b, env) {
  const key = await deriveKey("compare", env);
  if (!key) return false;
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign("HMAC", key, encoder.encode(String(a))),
    crypto.subtle.sign("HMAC", key, encoder.encode(String(b))),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
  return diff === 0;
}

// 未配置 ADMIN_PASSWORD 时的统一响应，不泄露任何校验细节
function noPasswordResponse() {
  return jsonResponse(
    {
      error: "未配置管理密码",
      hint: "请在 Cloudflare Dashboard → 该 Worker → Settings → 变量和密钥 中添加 Secret：名称 ADMIN_PASSWORD，值为你的密码。",
    },
    500
  );
}

/* ==================== 会话令牌 ==================== */

// 令牌 = 过期时间 + 用密码签名的 HMAC，服务端不需要额外存储
// 注意：签名与令牌都经过 base64url 编码，里面不可能再出现 "|"，
// 因此不能用 indexOf("|") 去编码后的字符串里找分隔符。
async function signSession(exp, env) {
  const key = await deriveKey("session", env);
  if (!key) return null;
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode("v1|" + exp));
  const sig = bytesToB64url(new Uint8Array(mac));
  return { sig: sig, token: b64urlEncode(exp + "|" + sig) };
}

async function verifySession(token, env) {
  if (typeof token !== "string" || !token) return false;
  let exp, sig;
  try {
    const raw = b64urlDecode(token);
    const i = raw.indexOf("|");
    if (i === -1) return false;
    exp = raw.slice(0, i);
    sig = raw.slice(i + 1);
  } catch (err) {
    return false;
  }
  if (!/^\d+$/.test(exp)) return false;
  if (Number(exp) < Date.now()) return false;
  const expected = await signSession(exp, env);
  if (!expected) return false;
  return safeEqual(sig, expected.sig, env);
}

async function checkAuth(request, env) {
  const header = request.headers.get("Authorization") || "";

  // 1) 会话令牌（管理后台经 Cookie 传递，也支持 Bearer 头）
  if (header.startsWith("Bearer ")) {
    if (await verifySession(header.slice(7).trim(), env)) return true;
  }

  const cookie = request.headers.get("Cookie") || "";
  const m = /(?:^|;\s*)nav_session=([^;]+)/.exec(cookie);
  if (m && (await verifySession(decodeURIComponent(m[1]), env))) return true;

  // 2) HTTP Basic（方便用 curl 等工具直接调用 API）
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice(6));
      const i = decoded.indexOf(":");
      if (i === -1) return false;
      return (
        (await safeEqual(decoded.slice(0, i), env.ADMIN_USERNAME || "admin", env)) &&
        (await safeEqual(decoded.slice(i + 1), secretFor(env) || "", env))
      );
    } catch (err) {
      return false;
    }
  }

  return false;
}

function sessionCookie(token, request) {
  // 仅在 HTTPS 下加 Secure，方便 wrangler dev 本地调试
  const secure = new URL(request.url).protocol === "https:" ? " Secure;" : "";
  return (
    "nav_session=" +
    encodeURIComponent(token) +
    "; Path=/; HttpOnly;" +
    secure +
    " SameSite=Strict; Max-Age=" +
    Math.floor(TOKEN_TTL_MS / 1000)
  );
}

function clearSessionCookie() {
  return "nav_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
}

/* ==================== 登录限流 ==================== */

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;

// 存 KV 而不是内存：Memory 里的计数只在单个 isolate 生效，攻击者换一个
// 边缘节点就绕过了。滚动窗口：每次失败都刷新过期时间，所以持续爆破会一直
// 被挡，停手 15 分钟后自动放行。
async function throttleState(env, ip, now) {
  const ns = kv(env);
  if (!ns || !ip) return { blocked: false, record: null, retryAfter: 0 };
  const key = "loginfail:" + ip;
  let count = 0;
  try {
    count = Number(await ns.get(key)) || 0;
  } catch (err) {
    // 读不到就不阻断正常登录
    return { blocked: false, record: null, retryAfter: 0 };
  }
  if (count >= MAX_FAILURES) {
    return { blocked: true, record: null, retryAfter: Math.ceil(WINDOW_MS / 1000) };
  }
  // 注意：这里必须给出 record，否则计数器永远不会增长（曾经就是这个 bug）
  return { blocked: false, record: { key: key, count: count + 1 }, retryAfter: 0 };
}

async function recordFailure(state, env) {
  const ns = kv(env);
  if (!ns || !state.record) return;
  try {
    await ns.put(state.record.key, String(state.record.count), {
      expirationTtl: Math.ceil(WINDOW_MS / 1000),
    });
  } catch (err) {
    // 限流记录失败不应阻断正常登录流程
  }
}

/* ==================== 登录 / 登出 ==================== */

async function handleLogin(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  // 没配 ADMIN_PASSWORD 时直接失败关闭，绝不退回默认密码
  if (!secretFor(env)) return noPasswordResponse();

  let body;
  try {
    body = await request.json();
  } catch (err) {
    return jsonResponse({ error: "请求格式错误" }, 400);
  }

  const username = String((body && body.username) || "admin");
  const password = String((body && body.password) || "");

  const ip = request.headers.get("CF-Connecting-IP") || "";
  const now = Date.now();
  const state = await throttleState(env, ip, now);
  if (state.blocked) {
    return new Response(
      JSON.stringify({ error: "尝试次数过多，请 " + Math.ceil(state.retryAfter / 60) + " 分钟后再试" }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(state.retryAfter),
          "Cache-Control": "no-store",
        },
      }
    );
  }

  const okUser = await safeEqual(username, env.ADMIN_USERNAME || "admin", env);
  const okPass = await safeEqual(password, secretFor(env), env);
  if (!okUser || !okPass) {
    await recordFailure(state, env);
    return jsonResponse({ error: "密码错误" }, 401);
  }

  const session = await signSession(String(Date.now() + TOKEN_TTL_MS), env);
  if (!session) return noPasswordResponse();
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookie(session.token, request),
      "Cache-Control": "no-store",
    },
  });
}

function handleLogout() {
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": clearSessionCookie(),
      "Cache-Control": "no-store",
    },
  });
}

/* ==================== 工具函数 ==================== */

async function getLinks(env) {
  const ns = kv(env);
  if (!ns) return null;

  const data = await ns.get("links", { type: "json" });
  if (Array.isArray(data)) return data;

  // 兼容 { links: [...] } 这种包装写法，避免误判成「配置丢了」
  if (data && Array.isArray(data.links)) return data.links;

  // 默认链接（首次运行自动写入）
  const defaultLinks = [
    {
      id: crypto.randomUUID(),
      title: "🕊️ 鸽子窝",
      url: "https://github.com/hyp0selenia/acg-nav-worker",
      desc: "咕咕咕",
      icon: "🕊️",
      color: "#000000",
    },
    {
      id: crypto.randomUUID(),
      title: "这是测试",
      url: "https://github.com/hyp0selenia/acg-nav-worker",
      desc: "这是描述",
      icon: "🔗",
      color: "#a78bfa",
    },
  ];
  await ns.put("links", JSON.stringify(defaultLinks));
  return defaultLinks;
}

async function saveLinks(env, links) {
  const ns = kv(env);
  if (!ns) return false;
  await ns.put("links", JSON.stringify(links));
  return true;
}

// <input type="color"> 只接受 #rrggbb，非法值会让保存时静默改色
function normalizeColor(value, fallback = "#a78bfa") {
  if (/^#[0-9a-fA-F]{6}$/.test(String(value || ""))) return String(value);
  // 传入的兜底值也可能是历史脏数据，兜不住就退回默认色
  if (/^#[0-9a-fA-F]{6}$/.test(String(fallback || ""))) return String(fallback);
  return "#a78bfa";
}

function str(value, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

/* ==================== API ==================== */

async function handleApiLinks(request, env) {
  if (!kv(env)) return kvMissingResponse();

  // 公开读取
  if (request.method === "GET") {
    const links = await getLinks(env);
    return jsonResponse(links || []);
  }

  // 写操作需要鉴权
  if (!(await checkAuth(request, env))) {
    return jsonResponse({ error: "登录已过期，请重新登录管理后台" }, 401);
  }

  if (request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (err) {
      return jsonResponse({ error: "请求格式错误" }, 400);
    }

    const links = await getLinks(env);
    const newLink = {
      id: crypto.randomUUID(),
      title: str(body.title) || "未命名",
      url: str(body.url) || "#",
      desc: str(body.desc),
      icon: str(body.icon) || "🔗",
      color: normalizeColor(body.color),
    };
    links.push(newLink);
    await saveLinks(env, links);
    return jsonResponse(newLink, 201);
  }

  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch (err) {
      return jsonResponse({ error: "请求格式错误" }, 400);
    }

    const links = await getLinks(env);
    const idx = links.findIndex((l) => l.id === body.id);
    if (idx === -1) return jsonResponse({ error: "链接不存在（可能已被删除）" }, 404);

    const patch = { ...body };
    delete patch.id;
    if (patch.color !== undefined) patch.color = normalizeColor(patch.color, links[idx].color);
    links[idx] = { ...links[idx], ...patch };
    await saveLinks(env, links);
    return jsonResponse(links[idx]);
  }

  if (request.method === "DELETE") {
    let body;
    try {
      body = await request.json();
    } catch (err) {
      return jsonResponse({ error: "请求格式错误" }, 400);
    }

    let links = await getLinks(env);
    links = links.filter((l) => l.id !== body.id);
    await saveLinks(env, links);
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: "Method not allowed" }, 405);
}

/* ==================== 首页 ==================== */

async function handleHome(request, env) {
  const links = (await getLinks(env)) || [];

  const cards = links
    .map(
      (l) => `
    <a href="${escapeHtml(l.url)}" target="_blank" rel="noopener" class="card" style="--accent:${escapeHtml(
        normalizeColor(l.color)
      )}">
      <div class="icon">${escapeHtml(l.icon || "🔗")}</div>
      <div class="info">
        <h3>${escapeHtml(l.title)}</h3>
        <p>${escapeHtml(l.desc || "")}</p>
      </div>
      <div class="arrow">→</div>
    </a>`
    )
    .join("");

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>🕊️ 鸽子窝</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg1: #fff0f5;
      --bg2: #f3e8ff;
      --card: rgba(255, 255, 255, 0.85);
      --text: #4a3f55;
      --muted: #8b7a9b;
      --pink: #f9a8d4;
      --purple: #c4b5fd;
      --shadow: 0 10px 30px -10px rgba(167, 139, 250, 0.35);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: "Noto Sans SC", system-ui, sans-serif;
      background: linear-gradient(135deg, var(--bg1), var(--bg2));
      min-height: 100vh;
      color: var(--text);
      overflow-x: hidden;
    }

    /* 背景装饰 */
    .bg-deco {
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 0;
      overflow: hidden;
    }
    .bg-deco span {
      position: absolute;
      font-size: 2.5rem;
      opacity: 0.12;
      animation: float 18s ease-in-out infinite;
    }
    .bg-deco span:nth-child(1) { top: 8%; left: 6%; animation-delay: 0s; }
    .bg-deco span:nth-child(2) { top: 25%; right: 10%; animation-delay: 3s; }
    .bg-deco span:nth-child(3) { bottom: 20%; left: 15%; animation-delay: 6s; }
    .bg-deco span:nth-child(4) { bottom: 12%; right: 8%; animation-delay: 9s; }
    .bg-deco span:nth-child(5) { top: 50%; left: 45%; animation-delay: 12s; }

    @keyframes float {
      0%, 100% { transform: translateY(0) rotate(0deg); }
      50% { transform: translateY(-25px) rotate(8deg); }
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 920px;
      margin: 0 auto;
      padding: 48px 20px 80px;
    }

    header {
      text-align: center;
      margin-bottom: 48px;
    }

    .avatar {
      width: 96px;
      height: 96px;
      border-radius: 50%;
      background: linear-gradient(135deg, #f9a8d4, #c4b5fd);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 3rem;
      margin: 0 auto 20px;
      box-shadow: var(--shadow);
      border: 4px solid white;
      animation: bounce 2.5s ease-in-out infinite;
    }

    @keyframes bounce {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }

    h1 {
      font-size: 2.1rem;
      font-weight: 700;
      background: linear-gradient(90deg, #ec4899, #8b5cf6);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }

    .subtitle {
      color: var(--muted);
      font-size: 1rem;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 22px;
    }

    .card {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 20px 22px;
      background: var(--card);
      border-radius: 20px;
      text-decoration: none;
      color: inherit;
      box-shadow: var(--shadow);
      border: 1px solid rgba(255,255,255,0.6);
      backdrop-filter: blur(12px);
      transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
      position: relative;
      overflow: hidden;
    }

    .card::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 5px;
      background: var(--accent);
      border-radius: 20px 0 0 20px;
    }

    .card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 0 20px 40px -12px rgba(167, 139, 250, 0.45);
    }

    .icon {
      font-size: 2.4rem;
      flex-shrink: 0;
      width: 56px;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #fce7f3, #ede9fe);
      border-radius: 16px;
    }

    .info {
      flex: 1;
      min-width: 0;
    }

    .info h3 {
      font-size: 1.15rem;
      font-weight: 600;
      margin-bottom: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .info p {
      font-size: 0.88rem;
      color: var(--muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .arrow {
      font-size: 1.3rem;
      color: var(--accent);
      opacity: 0.6;
      transition: all 0.3s;
    }

    .card:hover .arrow {
      opacity: 1;
      transform: translateX(4px);
    }

    footer {
      text-align: center;
      margin-top: 60px;
      color: var(--muted);
      font-size: 0.85rem;
    }

    footer a {
      color: #a78bfa;
      text-decoration: none;
    }

    @media (max-width: 600px) {
      h1 { font-size: 1.7rem; }
      .avatar { width: 80px; height: 80px; font-size: 2.5rem; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="bg-deco">
    <span>🍥</span><span>🏳️‍⚧️</span><span>🏳️‍🌈</span><span>⚧</span><span>💕</span>
  </div>

  <div class="container">
    <header>
      <div class="avatar">🍥</div>
      <h1>🕊️ 鸽子窝</h1>
      <p class="subtitle">点击卡片即可跳转 ~ (｡･ω･｡)ﾉ♡</p>
    </header>

    <div class="grid">
      ${cards || '<p class="empty">还没有链接，去 <a href="/admin">管理后台</a> 添加吧 ~</p>'}
    </div>

    <footer>
      Made with ❤ · <a href="/admin">管理后台</a>
    </footer>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ==================== 管理后台 ==================== */

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理登录 · 🕊️ 鸽子窝</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #fff0f5, #f3e8ff);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0;
      padding: 20px;
    }
    form {
      background: white;
      padding: 40px;
      border-radius: 24px;
      box-shadow: 0 20px 40px rgba(167,139,250,0.25);
      text-align: center;
      max-width: 360px;
      width: 100%;
    }
    h2 { margin: 0 0 8px; color: #7c3aed; }
    p.sub { color: #8b7a9b; margin: 0 0 24px; font-size: 0.95rem; }
    input {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e9d5ff;
      border-radius: 12px;
      font-size: 1rem;
      margin-bottom: 16px;
      outline: none;
    }
    input:focus { border-color: #a78bfa; }
    button {
      width: 100%;
      padding: 13px;
      background: linear-gradient(90deg, #ec4899, #8b5cf6);
      color: white;
      border: none;
      border-radius: 12px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: default; }
    .msg {
      min-height: 20px;
      margin-top: 14px;
      font-size: 0.88rem;
      color: #e11d48;
      white-space: pre-line;
    }
    .back { display: inline-block; margin-top: 18px; font-size: 0.85rem; color: #a78bfa; text-decoration: none; }
  </style>
</head>
<body>
  <form id="f">
    <h2>🔐 管理后台</h2>
    <p class="sub">请输入管理密码</p>
    <input type="password" id="pw" placeholder="密码" autocomplete="current-password" autofocus>
    <button type="submit" id="btn">登录</button>
    <div class="msg" id="msg"></div>
    <a class="back" href="/">← 返回首页</a>
  </form>
  <script>
    const f = document.getElementById("f");
    const pw = document.getElementById("pw");
    const btn = document.getElementById("btn");
    const msg = document.getElementById("msg");

    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.textContent = "";
      btn.disabled = true;
      btn.textContent = "登录中...";
      try {
        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: pw.value }),
        });
        if (res.ok) {
          location.replace("/admin");
          return;
        }
        let data = {};
        try { data = await res.json(); } catch (err) {}
        msg.textContent = res.status === 401
          ? "❌ 密码错误，请重试"
          : "❌ 登录失败：" + (data.error || res.status) + (data.hint ? "\\n" + data.hint : "");
      } catch (err) {
        msg.textContent = "❌ 网络错误：" + err;
      }
      btn.disabled = false;
      btn.textContent = "登录";
    });
  </script>
</body>
</html>`;

async function handleAdmin(request, env) {
  if (!(await checkAuth(request, env))) {
    // 这里故意返回 200 而不是 401：
    // 401 + WWW-Authenticate 会让浏览器接管响应、弹出原生登录框而不渲染本页面，
    // 且原生登录框的凭据不会被后续 fetch 写请求自动携带 —— 这正是之前保存失败的原因。
    return new Response(LOGIN_PAGE, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  const links = (await getLinks(env)) || [];

  const rows = links
    .map(
      (l) => `
    <tr data-id="${escapeHtml(l.id)}">
      <td><input type="text" value="${escapeHtml(l.icon || "🔗")}" class="icon-input" style="width:50px;text-align:center"></td>
      <td><input type="text" value="${escapeHtml(l.title)}" class="title-input"></td>
      <td><input type="text" value="${escapeHtml(l.url)}" class="url-input"></td>
      <td><input type="text" value="${escapeHtml(l.desc || "")}" class="desc-input"></td>
      <td><input type="color" value="${escapeHtml(normalizeColor(l.color))}" class="color-input"></td>
      <td>
        <button class="btn-save">保存</button>
        <button class="btn-del">删除</button>
      </td>
    </tr>`
    )
    .join("");

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理后台 · 🕊️ 鸽子窝</title>
  <style>
    :root {
      --primary: #8b5cf6;
      --pink: #ec4899;
    }
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #faf5ff;
      margin: 0;
      padding: 24px;
      color: #4c1d95;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      flex-wrap: wrap;
      gap: 12px;
    }
    h1 { margin: 0; font-size: 1.6rem; }
    .btn {
      padding: 10px 18px;
      border-radius: 10px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.95rem;
      text-decoration: none;
      display: inline-block;
    }
    .btn-primary {
      background: linear-gradient(90deg, var(--pink), var(--primary));
      color: white;
    }
    .btn-secondary {
      background: white;
      border: 2px solid #e9d5ff;
      color: var(--primary);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: white;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(139, 92, 246, 0.1);
    }
    th, td {
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid #f3e8ff;
    }
    th {
      background: #f5f3ff;
      font-size: 0.85rem;
      color: #6b21a8;
    }
    input[type="text"] {
      width: 100%;
      padding: 8px 10px;
      border: 1px solid #e9d5ff;
      border-radius: 8px;
      font-size: 0.9rem;
    }
    input[type="color"] {
      width: 40px;
      height: 36px;
      border: none;
      background: none;
      cursor: pointer;
    }
    .btn-save, .btn-del {
      padding: 6px 12px;
      border-radius: 8px;
      border: none;
      font-size: 0.85rem;
      cursor: pointer;
      margin-right: 6px;
    }
    .btn-save { background: #c4b5fd; color: #4c1d95; }
    .btn-del { background: #fecdd3; color: #9f1239; }
    .btn-save:disabled, .btn-del:disabled { opacity: 0.5; cursor: default; }
    .add-form {
      margin-top: 32px;
      background: white;
      padding: 24px;
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(139, 92, 246, 0.1);
    }
    .add-form h3 { margin-top: 0; }
    .form-row {
      display: grid;
      grid-template-columns: 60px 1fr 1.5fr 1fr 60px auto;
      gap: 12px;
      align-items: end;
    }
    .toast {
      position: fixed;
      left: 50%;
      bottom: 28px;
      transform: translateX(-50%) translateY(20px);
      background: #4c1d95;
      color: white;
      padding: 12px 22px;
      border-radius: 12px;
      font-size: 0.92rem;
      opacity: 0;
      transition: all 0.25s;
      pointer-events: none;
      max-width: 90vw;
    }
    .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
    .toast.error { background: #9f1239; }
    @media (max-width: 900px) {
      .form-row { grid-template-columns: 1fr 1fr; }
      table { font-size: 0.85rem; }
      th, td { padding: 8px; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🍥 链接管理</h1>
    <div>
      <a href="/" class="btn btn-secondary">← 返回首页</a>
      <button class="btn btn-secondary" id="btn-logout">退出登录</button>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>图标</th>
        <th>标题</th>
        <th>链接</th>
        <th>描述</th>
        <th>颜色</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody id="tbody">
      ${rows}
    </tbody>
  </table>

  <div class="add-form">
    <h3>➕ 添加新链接</h3>
    <div class="form-row">
      <div>
        <label>图标</label>
        <input type="text" id="new-icon" value="🔗" style="text-align:center">
      </div>
      <div>
        <label>标题</label>
        <input type="text" id="new-title" placeholder="网站名称">
      </div>
      <div>
        <label>链接</label>
        <input type="text" id="new-url" placeholder="https://...">
      </div>
      <div>
        <label>描述</label>
        <input type="text" id="new-desc" placeholder="简短描述">
      </div>
      <div>
        <label>颜色</label>
        <input type="color" id="new-color" value="#a78bfa">
      </div>
      <div>
        <button class="btn btn-primary" id="btn-add">添加</button>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const toastEl = document.getElementById("toast");
    let toastTimer = null;
    function toast(text, isError) {
      toastEl.textContent = text;
      toastEl.className = "toast show" + (isError ? " error" : "");
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toastEl.className = "toast"; }, 2600);
    }

    // 会话通过 HttpOnly Cookie 传递，前端不需要保存任何密码
    async function api(method, data) {
      let res;
      try {
        res = await fetch("/api/links", {
          method: method,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        });
      } catch (err) {
        throw new Error("网络错误：" + err.message);
      }
      if (res.status === 401) {
        toast("登录已过期，正在跳转登录页...", true);
        setTimeout(() => location.replace("/admin"), 900);
        throw new Error("unauthorized");
      }
      let body = null;
      try { body = await res.json(); } catch (err) {}
      if (!res.ok) {
        throw new Error((body && (body.error || body.hint)) || ("HTTP " + res.status));
      }
      return body;
    }

    // 保存
    document.querySelectorAll(".btn-save").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const tr = e.target.closest("tr");
        const data = {
          id: tr.dataset.id,
          icon: tr.querySelector(".icon-input").value,
          title: tr.querySelector(".title-input").value,
          url: tr.querySelector(".url-input").value,
          desc: tr.querySelector(".desc-input").value,
          color: tr.querySelector(".color-input").value,
        };
        e.target.disabled = true;
        try {
          await api("PUT", data);
          toast("✅ 已保存");
        } catch (err) {
          if (err.message !== "unauthorized") toast("❌ 保存失败：" + err.message, true);
        }
        e.target.disabled = false;
      });
    });

    // 删除
    document.querySelectorAll(".btn-del").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        if (!confirm("确定删除这个链接吗？")) return;
        const tr = e.target.closest("tr");
        e.target.disabled = true;
        try {
          await api("DELETE", { id: tr.dataset.id });
          tr.remove();
          toast("🗑️ 已删除");
        } catch (err) {
          if (err.message !== "unauthorized") toast("❌ 删除失败：" + err.message, true);
        }
        e.target.disabled = false;
      });
    });

    // 添加
    document.getElementById("btn-add").addEventListener("click", async (e) => {
      const data = {
        icon: document.getElementById("new-icon").value || "🔗",
        title: document.getElementById("new-title").value,
        url: document.getElementById("new-url").value,
        desc: document.getElementById("new-desc").value,
        color: document.getElementById("new-color").value,
      };
      if (!data.title || !data.url) {
        toast("标题和链接不能为空", true);
        return;
      }
      e.target.disabled = true;
      try {
        await api("POST", data);
        location.reload();
      } catch (err) {
        if (err.message !== "unauthorized") toast("❌ 添加失败：" + err.message, true);
        e.target.disabled = false;
      }
    });

    // 退出登录
    document.getElementById("btn-logout").addEventListener("click", async () => {
      try { await fetch("/api/logout", { method: "POST" }); } catch (err) {}
      location.replace("/admin");
    });
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
