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
          "Access-Control-Allow-Headers": "Content-Type, X-Nav-Token",
          "Access-Control-Max-Age": "86400",
          "Cache-Control": "no-store",
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
      return handleLogout(request, env);
    }

    if (path === "/api/me") {
      return handleMe(request, env);
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

// 令牌 = 会话代数 + 过期时间 + 用户名的 HMAC 签名。
// 注意：签名与令牌都经过 base64url 编码，里面不可能再出现分隔符 "|"，因此
// 不能用 indexOf("|") 去编码后的字符串里找分隔符（踩过这个坑）。
async function signSession(gen, exp, user, env) {
  const key = await deriveKey("session", env);
  if (!key) return null;
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode("v4|" + gen + "|" + exp + "|" + user));
  const sig = bytesToB64url(new Uint8Array(mac));
  return { sig: sig, token: b64urlEncode(gen + "|" + exp + "|" + sig) };
}

/* ---------- 会话代数（让「退出登录」真正生效） ---------- */

// 纯 HMAC 令牌是无状态的：删掉浏览器 Cookie 并不能让令牌本身失效，
// 谁把 Cookie 复制走，在有效期内照样能用 —— 「退出登录」形同虚设。
//
// 解法是给会话编号：每次登录或退出都把代数 +1，令牌里带着签发时的代数，
// 代数对不上就作废。用计数器而不是时间戳，是因为时间戳会撞在同一毫秒上
// （退出后紧接着登录就会把自己刚发的令牌判死）。
const GEN_KEY = "session:gen";

async function readGen(env) {
  const ns = kv(env);
  if (!ns) return 0;
  try {
    return Number(await ns.get(GEN_KEY)) || 0;
  } catch (err) {
    return 0;
  }
}

// 读-改-写由 KV 承担不了原子性，所以这里用「只许前进」的写法收尾：
// 并发时可能多加几次，最坏结果是刚登录的人要重新登录一次，不会放行旧会话。
async function bumpGen(env) {
  const ns = kv(env);
  if (!ns) return 0;
  try {
    const next = (await readGen(env)) + 1;
    await ns.put(GEN_KEY, String(next));
    return next;
  } catch (err) {
    return 0;
  }
}

async function verifySession(token, env) {
  if (typeof token !== "string" || !token) return null;
  let gen, exp, sig;
  try {
    const bits = b64urlDecode(token).split("|");
    if (bits.length !== 3) return null;
    gen = bits[0];
    exp = bits[1];
    sig = bits[2];
  } catch (err) {
    return null;
  }
  if (!/^\d+$/.test(gen) || !/^\d+$/.test(exp)) return null;
  if (Number(exp) < Date.now()) return null;
  // 令牌里写入签发时的用户名，校验时必须回代，否则改了 ADMIN_USERNAME 后
  // 旧令牌依然能用（等于换账号换不掉旧会话）。
  const user = env.ADMIN_USERNAME || "admin";
  const expected = await signSession(gen, exp, user, env);
  if (!expected) return null;
  if (!(await safeEqual(sig, expected.sig, env))) return null;
  // 代数必须与当前一致：退出登录或改密码后，旧令牌立即失效
  const currentGen = await readGen(env);
  if (Number(gen) !== currentGen) return null;
  return { user: user, gen: currentGen };
}

// 从 Cookie 或 X-Nav-Token 头取会话令牌。
//
// 这里刻意不支持 HTTP Basic：浏览器会把 Basic 凭据缓存起来并自动重发，
// 导致「退出登录退不掉、换账号也登不进去」——服务端永远收到旧凭据。
// 用自定义头就不会触发浏览器的凭据缓存。
function sessionTokenOf(request) {
  const header = request.headers.get("X-Nav-Token");
  if (header) return header.trim();
  const cookie = request.headers.get("Cookie") || "";
  const m = /(?:^|;\s*)nav_session=([^;]+)/.exec(cookie);
  return m ? decodeURIComponent(m[1]) : "";
}

async function checkAuth(request, env) {
  return (await verifySession(sessionTokenOf(request), env)) !== null;
}

// 已验证的会话，顺手做滑动续期：
// 打开管理页与每次写操作都会刷新有效期，所以经常使用的人不会被登出；
// 长期不来的会话仍会在 30 天后过期。
async function requireSession(request, env) {
  const session = await verifySession(sessionTokenOf(request), env);
  if (!session) return null;
  if (!wantsRenewal(request)) return { user: session.user, token: null };
  // 续期沿用同一个代数，否则每次续期都换号，等于把自己作废
  const fresh = await signSession(session.gen, String(Date.now() + TOKEN_TTL_MS), session.user, env);
  return { user: session.user, token: fresh ? fresh.token : null };
}

function wantsRenewal(request) {
  // 只对页面和写操作续期，静态或读取请求不必每次写 Cookie
  if (request.method !== "GET") return true;
  return new URL(request.url).pathname.startsWith("/admin");
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
  // 清 Cookie 时必须与下发时的属性一致，否则部分浏览器不会覆盖
  return "nav_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
}

function withHeaders(response, extra) {
  if (!extra || Object.keys(extra).length === 0) return response;
  const merged = new Headers(response.headers);
  for (const k of Object.keys(extra)) merged.set(k, extra[k]);
  return new Response(response.body, { status: response.status, headers: merged });
}

function noStoreHtml(body, status = 200, extraHeaders) {
  return new Response(body, {
    status: status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
      ...(extraHeaders || {}),
    },
  });
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

  // 注意：这里不能给用户名加任何默认值。否则用户填错用户名也会被
  // 「补」成正确值，等于用户名形同虚设。
  const username = String((body && body.username) || "");
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
    // 不区分「用户名错」和「密码错」，避免暴露账号是否存在
    return jsonResponse({ error: "用户名或密码错误" }, 401);
  }

  // 每次登录都换一个会话代数：重新登录会立刻作废之前所有旧会话
  const gen = await bumpGen(env);
  const session = await signSession(String(gen), String(Date.now() + TOKEN_TTL_MS), username, env);
  if (!session) return noPasswordResponse();
  return new Response(JSON.stringify({ success: true, username: username }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookie(session.token, request),
      "Cache-Control": "no-store",
    },
  });
}

async function handleLogout(request, env) {
  // 只要带着会话就推进代数，服务端立即作废这条令牌；
  // 匿名请求不写 KV，免得被人刷。
  if (sessionTokenOf(request)) {
    await bumpGen(env);
  }
  const headers = {
    "Content-Type": "application/json",
    "Set-Cookie": clearSessionCookie(),
    "Cache-Control": "no-store",
  };
  // 顺手清掉浏览器可能缓存的 Basic 凭据（老版本用过 Basic，缓存会一直粘着）
  try {
    if (new URL(request.url).protocol === "https:") headers["Clear-Site-Data"] = '"cache", "storage"';
  } catch (err) {
    // 忽略
  }
  return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

// 给前端确认「当前到底是谁」，也用于滑动续期
async function handleMe(request, env) {
  const session = await requireSession(request, env);
  if (!session) return jsonResponse({ error: "未登录" }, 401);
  const headers = {};
  if (session.token) headers["Set-Cookie"] = sessionCookie(session.token, request);
  return new Response(JSON.stringify({ username: session.user }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
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

  // 写操作需要鉴权（成功时顺手滑动续期）
  const session = await requireSession(request, env);
  if (!session) {
    return jsonResponse({ error: "登录已过期，请重新登录管理后台" }, 401);
  }
  const renewHeaders = session.token ? { "Set-Cookie": sessionCookie(session.token, request) } : {};

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
    return withHeaders(jsonResponse(newLink, 201), renewHeaders);
  }

  // 排序：只接收「id 顺序」数组，不重新上传链接内容
  if (request.method === "PATCH") {
    let body;
    try {
      body = await request.json();
    } catch (err) {
      return jsonResponse({ error: "请求格式错误" }, 400);
    }

    const order = body && body.order;
    if (!Array.isArray(order)) {
      return withHeaders(jsonResponse({ error: "order 必须是 id 数组" }, 400), renewHeaders);
    }

    const links = await getLinks(env);
    const byId = new Map(links.map((l) => [l.id, l]));

    // 必须与现有链接一一对应，否则宁可拒绝也不要把链接搞丢
    if (order.length !== links.length || new Set(order).size !== order.length) {
      return withHeaders(
        jsonResponse({ error: "排序数据与当前链接不一致，请刷新页面后重试" }, 409),
        renewHeaders
      );
    }
    const reordered = [];
    for (const id of order) {
      const l = byId.get(id);
      if (!l) {
        return withHeaders(
          jsonResponse({ error: "排序数据与当前链接不一致，请刷新页面后重试" }, 409),
          renewHeaders
        );
      }
      reordered.push(l);
    }

    await saveLinks(env, reordered);
    return withHeaders(jsonResponse({ success: true, order: order }), renewHeaders);
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
    if (idx === -1) return withHeaders(jsonResponse({ error: "链接不存在（可能已被删除）" }, 404), renewHeaders);

    const patch = { ...body };
    delete patch.id;
    if (patch.color !== undefined) patch.color = normalizeColor(patch.color, links[idx].color);
    links[idx] = { ...links[idx], ...patch };
    await saveLinks(env, links);
    return withHeaders(jsonResponse(links[idx]), renewHeaders);
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
    return withHeaders(jsonResponse({ success: true }), renewHeaders);
  }

  return jsonResponse({ error: "Method not allowed" }, 405);
}

/* ==================== 站点与样式 ==================== */

const SITE_NAME = "鸽子窝";

// 站点图标：直接用鸽子 emoji，不额外占一个静态文件。
//
// 两个容易踩的点，别删：
// 1) 必须保留 emoji 后面的变体选择符 U+FE0F。少了它浏览器会渲染成黑白线稿
//    （实测对比过：带 VS16 是彩色鸽子，不带是纯黑轮廓）。
// 2) 用 SVG 内嵌 emoji 文本，而不是把 emoji 直接塞进 data URI 裸文本里 ——
//    后者在部分浏览器会因为编码问题画不出来。
const FAVICON =
  "data:image/svg+xml," +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">` +
      `<text x="50" y="52" font-size="84" text-anchor="middle" dominant-baseline="central">🕊️</text>` +
      `</svg>`
  );

const FAVICON_LINK = `<link rel="icon" href="${FAVICON}">`;

// 全站共用的样式。手写 CSS + 设计变量，不引外部 UI 库也不拉远程字体。
// 全站共用的样式。手写 CSS + 设计变量，不引外部 UI 库也不拉远程字体。
// 配色走暖色 ACG 风：粉紫渐变 + 柔和圆角，但不堆砌动效。
const APP_CSS = `
:root {
  color-scheme: light;
  --bg1: #fff5f9;
  --bg2: #f6f0ff;
  --bg3: #eef3ff;
  --surface: rgba(255, 255, 255, .86);
  --surface-solid: #ffffff;
  --surface-2: #fbf2f9;
  --border: #f0dcec;
  --border-strong: #e3c4dd;
  --text: #46344c;
  --muted: #8b7893;
  --faint: #b3a2b9;
  --ink: #ec4899;
  --ink2: #8b5cf6;
  --accent: #a855f7;
  --accent-soft: #f6ecff;
  --danger: #c0392b;
  --danger-soft: #fdf1f0;
  --ok: #0f7a4d;
  --radius: 11px;
  --radius-lg: 18px;
  --shadow-sm: 0 1px 2px rgba(167, 139, 250, .10);
  --shadow: 0 2px 6px rgba(167, 139, 250, .10), 0 16px 32px -18px rgba(167, 139, 250, .45);
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  background: linear-gradient(158deg, var(--bg1) 0%, var(--bg2) 52%, var(--bg3) 100%);
  background-attachment: fixed;
  color: var(--text);
  font-family: var(--font);
  font-size: 15px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; }
h1, h2, h3 { margin: 0; font-weight: 700; letter-spacing: -.01em; line-height: 1.25; }
p { margin: 0; }
input, button, textarea { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 8px; }

.shell { position: relative; max-width: 900px; margin: 0 auto; padding: 0 24px 56px; }
main { padding-top: 30px; }

/* 顶栏 */
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  height: 60px; border-bottom: 1px solid var(--border);
}
.brand { display: inline-flex; align-items: center; gap: 9px; font-size: 14px; font-weight: 700; }
.brand-dot {
  width: 9px; height: 9px; border-radius: 50%;
  background: linear-gradient(135deg, var(--ink), var(--ink2));
  box-shadow: 0 0 0 3px rgba(236, 72, 153, .12);
}
.topbar-link, .topbar-user {
  font-size: 13px; color: var(--muted); text-decoration: none;
  padding: 5px 11px; border-radius: 999px; border: 1px solid transparent;
}
.topbar-link:hover { color: var(--text); background: rgba(255, 255, 255, .75); }
.topbar-user {
  display: inline-flex; align-items: center; gap: 7px;
  border-color: var(--border); background: var(--surface);
}
.topbar-user b { color: var(--text); font-weight: 700; }
.topbar-actions { display: flex; align-items: center; gap: 8px; }

/* 排版 */
.eyebrow {
  display: inline-block;
  font-size: 11.5px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
  color: var(--ink);
  background: rgba(255, 255, 255, .7);
  border: 1px solid var(--border);
  border-radius: 999px; padding: 3px 11px; margin-bottom: 12px;
}
.display {
  font-size: clamp(26px, 3.4vw, 33px);
  background: linear-gradient(92deg, var(--ink) 0%, var(--ink2) 100%);
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  /* 兜底：不支持 background-clip:text 的浏览器仍然看得见文字 */
  display: inline-block;
}
.lede { color: var(--muted); margin-top: 8px; max-width: 48ch; font-size: 14.5px; }

/* 头像与浮动装饰 */
.hero { display: flex; align-items: center; gap: 16px; }
.avatar {
  flex: none; width: 62px; height: 62px; border-radius: 50%;
  display: grid; place-items: center; font-size: 30px; line-height: 1;
  background: linear-gradient(135deg, #fbcfe8, #ddd6fe);
  border: 3px solid #fff;
  box-shadow: 0 10px 24px -12px rgba(167, 139, 250, .8);
  animation: bob 2.8s ease-in-out infinite;
}
@keyframes bob {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-6px); }
}
.bg-deco { position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; }
.bg-deco span {
  position: absolute; font-size: 2.3rem; opacity: .12;
  animation: float 20s ease-in-out infinite;
}
.bg-deco span:nth-child(1) { top: 10%; left: 5%; animation-delay: 0s; }
.bg-deco span:nth-child(2) { top: 28%; right: 8%; animation-delay: 4s; }
.bg-deco span:nth-child(3) { bottom: 22%; left: 12%; animation-delay: 8s; }
.bg-deco span:nth-child(4) { bottom: 10%; right: 10%; animation-delay: 12s; }
.bg-deco span:nth-child(5) { top: 52%; left: 46%; animation-delay: 16s; }
@keyframes float {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  50% { transform: translateY(-22px) rotate(7deg); }
}
@media (prefers-reduced-motion: reduce) {
  .avatar, .bg-deco span { animation: none; }
  * { transition: none !important; }
}

/* 卡片网格 */
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(272px, 1fr)); gap: 14px; margin-top: 26px; }
.card {
  position: relative; overflow: hidden;
  display: flex; align-items: center; gap: 12px;
  padding: 14px 15px;
  background: var(--surface); border: 1px solid rgba(255, 255, 255, .8);
  border-radius: var(--radius-lg);
  text-decoration: none;
  box-shadow: var(--shadow-sm);
  backdrop-filter: blur(10px);
  transition: transform .22s cubic-bezier(.34, 1.4, .64, 1), box-shadow .22s ease, border-color .22s ease;
}
.card::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
  background: var(--accent);
}
.card:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow);
  border-color: #fff;
}
.card:active { transform: translateY(-1px); }
.card-icon {
  flex: none; width: 40px; height: 40px; border-radius: 13px;
  display: grid; place-items: center; font-size: 20px; line-height: 1;
  background: color-mix(in srgb, var(--accent) 14%, #fff);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 24%, transparent);
}
.card-body { min-width: 0; flex: 1; display: flex; flex-direction: column; }
.card-title {
  font-size: 14.5px; font-weight: 700; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
.card-meta {
  font-size: 12.5px; color: var(--muted); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
.card-arrow { flex: none; width: 17px; height: 17px; color: var(--accent); opacity: .45; transition: transform .2s ease, opacity .2s ease; }
.card:hover .card-arrow { opacity: 1; transform: translateX(3px); }

/* 空状态 */
.empty {
  grid-column: 1 / -1; text-align: center; padding: 44px 24px;
  border: 1.5px dashed var(--border-strong); border-radius: var(--radius-lg);
  background: rgba(255, 255, 255, .6);
}
.empty-title { font-weight: 700; font-size: 14.5px; }
.empty-desc { color: var(--muted); font-size: 13px; margin-top: 3px; }
.empty-desc a { color: var(--ink); }

/* 页脚 */
.footer {
  display: flex; align-items: center; gap: 9px;
  margin-top: 52px; padding-top: 18px; border-top: 1px solid var(--border);
  font-size: 12.5px; color: var(--faint);
}
.footer-sep { width: 3px; height: 3px; border-radius: 50%; background: var(--border-strong); }

/* 表单 */
.field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.field label { font-size: 12px; font-weight: 600; color: var(--muted); }
.input {
  width: 100%; padding: 8px 11px; background: var(--surface-solid);
  border: 1px solid var(--border-strong); border-radius: var(--radius);
  font-size: 14px; transition: border-color .15s ease, box-shadow .15s ease;
}
.input::placeholder { color: var(--faint); }
.input:hover { border-color: var(--faint); }
.input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(168, 85, 247, .15); }

/* 按钮 */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  padding: 8px 14px; border-radius: 999px; border: 1px solid transparent;
  font-size: 13.5px; font-weight: 600; cursor: pointer; text-decoration: none;
  white-space: nowrap;
  transition: background .15s ease, border-color .15s ease, color .15s ease, opacity .15s ease, transform .15s ease;
}
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn-primary { background: linear-gradient(92deg, var(--ink), var(--ink2)); color: #fff; box-shadow: 0 8px 18px -10px rgba(167, 139, 250, .9); }
.btn-primary:hover:not(:disabled) { transform: translateY(-1px); }
.btn-ghost { background: rgba(255, 255, 255, .86); border-color: var(--border-strong); color: var(--muted); }
.btn-ghost:hover:not(:disabled) { color: var(--ink); border-color: var(--ink); background: #fff; }
.btn-quiet { background: transparent; color: var(--muted); padding: 6px 10px; font-size: 13px; }
.btn-quiet:hover:not(:disabled) { background: rgba(168, 85, 247, .10); color: var(--ink2); }
.btn-danger { background: transparent; color: var(--faint); padding: 6px 10px; font-size: 13px; }
.btn-danger:hover:not(:disabled) { background: var(--danger-soft); color: var(--danger); }
.btn-block { width: 100%; }

/* 提示条 */
.alert {
  display: none; gap: 8px; align-items: flex-start;
  padding: 9px 12px; border-radius: var(--radius); font-size: 13px; line-height: 1.5;
  background: var(--danger-soft); color: var(--danger); border: 1px solid #f6d5d0;
}
.alert.show { display: flex; }

/* toast */
.toast {
  position: fixed; left: 50%; bottom: 22px; z-index: 50;
  transform: translate(-50%, 10px);
  display: flex; align-items: center; gap: 8px;
  padding: 10px 16px; border-radius: 999px;
  background: linear-gradient(92deg, var(--ink), var(--ink2)); color: #fff; font-size: 13.5px;
  box-shadow: 0 12px 28px -12px rgba(167, 139, 250, .9); opacity: 0; pointer-events: none;
  transition: opacity .2s ease, transform .2s ease; max-width: min(90vw, 420px);
}
.toast.show { opacity: 1; transform: translate(-50%, 0); }
.toast-error { background: var(--danger); }
`;

/* ==================== 首页 ==================== */

// 把域名当作副标题，比 emoji + 大片渐变克制得多
function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch (err) {
    return "";
  }
}

async function handleHome(request, env) {
  const links = (await getLinks(env)) || [];

  const cards = links
    .map((l) => {
      const host = hostOf(l.url);
      return `
      <a class="card" href="${escapeHtml(l.url)}" target="_blank" rel="noopener noreferrer">
        <span class="card-icon" style="--accent:${escapeHtml(normalizeColor(l.color))}">${escapeHtml(
        l.icon || "🔗"
      )}</span>
        <span class="card-body">
          <span class="card-title">${escapeHtml(l.title)}</span>
          <span class="card-meta">${escapeHtml(l.desc || host || l.url)}</span>
        </span>
        <svg class="card-arrow" viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </a>`;
    })
    .join("");

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>${escapeHtml(SITE_NAME)}</title>
  ${FAVICON_LINK}
  <style>${APP_CSS}</style>
</head>
<body>
  <div class="bg-deco" aria-hidden="true">
    <span>🕊</span><span>💜</span><span>✨</span><span>🌸</span><span>⭐</span>
  </div>

  <div class="shell">
    <div class="topbar">
      <span class="brand"><span class="brand-dot" aria-hidden="true"></span>${escapeHtml(SITE_NAME)}</span>
      <a class="topbar-link" href="/admin">管理</a>
    </div>

    <main>
      <div class="hero">
        <div class="avatar" aria-hidden="true">🕊</div>
        <div>
          <h1 class="display">常用站点</h1>
          <p class="lede">点击卡片即可跳转 ~ (｡･ω･｡)ﾉ♡</p>
        </div>
      </div>

      <div class="grid">
        ${
          cards ||
          `<div class="empty">
            <p class="empty-title">还没有添加链接</p>
            <p class="empty-desc">到 <a href="/admin">管理后台</a> 添加第一条吧 ~</p>
          </div>`
        }
      </div>
    </main>

    <footer class="footer">
      <span>${escapeHtml(SITE_NAME)}</span>
      <span class="footer-sep" aria-hidden="true"></span>
      <span>${links.length} 个链接</span>
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

// 后台样式：同一套设计变量，桌面用表格、窄屏用卡片，避免横向滚动
const ADMIN_CSS = `
.panel {
  margin-top: 24px; background: var(--surface);
  border: 1px solid rgba(255, 255, 255, .85); border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm); overflow: hidden;
  backdrop-filter: blur(10px);
}
.panel-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 14px 18px; border-bottom: 1px solid var(--border);
}
.panel-head > div { min-width: 0; }
.panel-head h2 { font-size: 14.5px; }
.panel-head p { font-size: 12.5px; color: var(--muted); margin-top: 1px; }
.count {
  flex: none; white-space: nowrap;
  font-size: 12px; font-weight: 600; color: var(--ink2); background: var(--accent-soft);
  border: 1px solid var(--border); border-radius: 999px; padding: 2px 10px;
}
table { width: 100%; border-collapse: collapse; }
thead th {
  padding: 9px 14px; text-align: left; font-size: 11.5px; font-weight: 600;
  letter-spacing: .04em; text-transform: uppercase; color: var(--faint);
  background: var(--surface-2); border-bottom: 1px solid var(--border); white-space: nowrap;
}
tbody td { padding: 9px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #fffaff; }

/* 排序 */
.drag-cell { width: 108px; }
.drag-cell .row-actions { gap: 1px; }
.drag-handle {
  cursor: grab; user-select: none; color: var(--faint); font-size: 16px;
  line-height: 1; padding: 6px 5px; border-radius: 7px;
}
.drag-handle:hover { color: var(--accent); background: rgba(168, 85, 247, .1); }
.drag-handle:active { cursor: grabbing; }
.icon-btn {
  border: 0; background: transparent; cursor: pointer; line-height: 1;
  color: var(--muted); font-size: 11px; padding: 8px 9px; border-radius: 7px;
}
.icon-btn:hover:not(:disabled) { color: var(--ink); background: rgba(236, 72, 153, .12); }
.icon-btn:disabled { opacity: .22; cursor: not-allowed; }
tr.dragging { opacity: .45; }
tr.drop-above td { box-shadow: inset 0 2px 0 0 var(--accent); }
tr.drop-below td { box-shadow: inset 0 -2px 0 0 var(--accent); }

/* 排序未保存时的浮动提示条 */
.order-bar {
  position: fixed; left: 50%; bottom: 22px; z-index: 60;
  transform: translate(-50%, 12px);
  display: none; align-items: center; gap: 12px;
  padding: 10px 12px 10px 18px; border-radius: 999px;
  background: var(--surface-solid); border: 1px solid var(--border-strong);
  box-shadow: var(--shadow); font-size: 13.5px; color: var(--text);
  transition: opacity .2s ease, transform .2s ease;
}
.order-bar.show { display: flex; }
.order-bar b { color: var(--ink); }
.order-bar .btn { padding: 6px 14px; font-size: 13px; }
td.col-actions { white-space: nowrap; text-align: right; }
.cell-input { padding: 7px 9px; font-size: 13.5px; }
.icon-cell { width: 62px; }
.icon-cell .cell-input { text-align: center; padding: 7px 4px; font-size: 16px; }
.color-cell { width: 46px; }
input[type="color"] {
  width: 34px; height: 32px; padding: 2px; cursor: pointer;
  border: 1px solid var(--border-strong); border-radius: 9px; background: var(--surface-solid);
}
.row-actions { display: inline-flex; gap: 2px; }
.empty-row { padding: 34px 18px; text-align: center; color: var(--muted); font-size: 13.5px; }

.add-form { padding: 18px; border-top: 1px solid var(--border); background: rgba(251, 242, 249, .7); }
.add-grid { display: grid; grid-template-columns: 64px 1.1fr 1.4fr 1fr 52px auto; gap: 10px; align-items: end; }
.add-grid .field label { font-size: 11.5px; }

@media (max-width: 900px) {
  .add-grid { grid-template-columns: 1fr 1fr; }
  .add-grid .field-wide { grid-column: 1 / -1; }
}
@media (max-width: 760px) {
  .shell { padding: 0 16px 40px; }
  main { padding-top: 26px; }
  thead { display: none; }
  table, tbody { display: block; }
  tbody tr {
    display: grid; grid-template-columns: 1fr 1fr; gap: 11px 12px;
    padding: 14px 16px; border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child { border-bottom: 0; }
  tbody tr:hover { background: transparent; }
  tbody td { display: block; padding: 0; border: 0; min-width: 0; }
  tbody td::before {
    content: attr(data-label); display: block;
    font-size: 11px; letter-spacing: .04em; text-transform: uppercase;
    color: var(--faint); margin-bottom: 3px;
  }
  /* 图标做成小尺寸，和标题同一行，不会撑出一大块空白
     （只作用于表格行，新增表单里的图标框保持正常宽度） */
  .icon-cell { grid-column: 1 / -1; }
  .icon-cell::before { display: none; }
  tbody .icon-cell .cell-input {
    width: 46px; text-align: center; font-size: 15px; padding: 6px 4px;
  }
  .color-cell { grid-column: auto; }
  /* 排序独占一行，放在卡片顶部右侧好点按。
     必须清掉桌面端的固定宽度，否则这一格只有 108px 宽。 */
  .drag-cell { grid-column: 1 / -1; width: auto; }
  .drag-cell::before { display: none; }
  .drag-cell .row-actions { justify-content: flex-end; }
  .drag-handle { font-size: 18px; padding: 6px 8px; }
  .icon-btn { font-size: 13px; padding: 8px 12px; }
  .col-actions { grid-column: 1 / -1; padding-top: 3px; }
  .col-actions::before { display: none; }
  .row-actions { display: flex; gap: 8px; }
  .row-actions .btn {
    flex: 1; justify-content: center;
    border: 1px solid var(--border-strong); background: var(--surface); color: var(--muted);
  }
  .row-actions .btn-danger { color: var(--danger); border-color: #f0d2cd; }
  .add-grid { grid-template-columns: 1fr 1fr; }
  .add-grid .field-wide { grid-column: 1 / -1; }
  .topbar-user { display: none; }
  .display { font-size: 24px; }
  /* 窄屏放不下长说明，只留一句 */
  .panel-head p { display: none; }
}
`;

const ADMIN_JS = `
const toastEl = document.getElementById("toast");
let toastTimer = null;
function toast(text, isError) {
  toastEl.textContent = text;
  toastEl.className = "toast show" + (isError ? " toast-error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastEl.className = "toast"; }, 2600);
}

// 会话走 HttpOnly Cookie，前端不保存用户名或密码
async function api(method, data, path) {
  let res;
  try {
    res = await fetch(path || "/api/links", {
      method: method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      cache: "no-store",
    });
  } catch (err) {
    throw new Error("网络错误，请重试");
  }
  if (res.status === 401) {
    toast("登录已过期，正在跳转登录页…", true);
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

document.querySelectorAll(".btn-save").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const row = btn.closest("tr");
    btn.disabled = true;
    try {
      await api("PUT", {
        id: row.dataset.id,
        icon: row.querySelector(".icon-input").value,
        title: row.querySelector(".title-input").value,
        url: row.querySelector(".url-input").value,
        desc: row.querySelector(".desc-input").value,
        color: row.querySelector(".color-input").value,
      });
      toast("已保存");
    } catch (err) {
      if (err.message !== "unauthorized") toast("保存失败：" + err.message, true);
    }
    btn.disabled = false;
  });
});

document.querySelectorAll(".btn-del").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const row = btn.closest("tr");
    const title = row.querySelector(".title-input").value;
    if (!confirm("确定删除「" + title + "」？")) return;
    btn.disabled = true;
    try {
      await api("DELETE", { id: row.dataset.id });
      row.remove();
      toast("已删除");
    } catch (err) {
      if (err.message !== "unauthorized") toast("删除失败：" + err.message, true);
      btn.disabled = false;
    }
  });
});

const addBtn = document.getElementById("btn-add");
addBtn.addEventListener("click", async () => {
  const val = (id) => document.getElementById(id).value;
  const data = {
    icon: val("new-icon") || "🔗",
    title: val("new-title").trim(),
    url: val("new-url").trim(),
    desc: val("new-desc").trim(),
    color: val("new-color"),
  };
  if (!data.title || !data.url) {
    toast("标题和链接不能为空", true);
    return;
  }
  addBtn.disabled = true;
  try {
    await api("POST", data);
    location.reload();
  } catch (err) {
    if (err.message !== "unauthorized") toast("添加失败：" + err.message, true);
    addBtn.disabled = false;
  }
});

/* ==================== 排序（拖拽 / 上移下移） ==================== */

const tbody = document.getElementById("tbody");
const orderBar = document.getElementById("order-bar");
let orderDirty = false;

function rowsInOrder() {
  return [...tbody.querySelectorAll("tr[data-id]")];
}

function markOrderDirty() {
  orderDirty = true;
  orderBar.classList.add("show");
  syncMoveButtons();
}

function syncMoveButtons() {
  // 只按顺序控制按钮可用性，不改动行内容，避免覆盖用户正在编辑的输入
  const rows = rowsInOrder();
  rows.forEach((row, i) => {
    const up = row.querySelector(".btn-up");
    const down = row.querySelector(".btn-down");
    if (up) up.disabled = i === 0;
    if (down) down.disabled = i === rows.length - 1;
  });
}

function moveRow(row, delta) {
  const rows = rowsInOrder();
  const i = rows.indexOf(row);
  const j = i + delta;
  if (i === -1 || j < 0 || j >= rows.length) return;
  if (delta < 0) tbody.insertBefore(row, rows[j]);
  else tbody.insertBefore(rows[j], row);
  markOrderDirty();
  row.scrollIntoView({ block: "nearest" });
}

function currentOrder() {
  return rowsInOrder().map((r) => r.dataset.id);
}

async function saveOrder() {
  const btn = document.getElementById("btn-order-save");
  btn.disabled = true;
  try {
    await api("PATCH", { order: currentOrder() });
    orderDirty = false;
    orderBar.classList.remove("show");
    toast("顺序已保存");
  } catch (err) {
    if (err.message !== "unauthorized") toast("保存顺序失败：" + err.message, true);
  }
  btn.disabled = false;
  syncMoveButtons();
}

tbody.addEventListener("click", (e) => {
  const up = e.target.closest(".btn-up");
  const down = e.target.closest(".btn-down");
  if (up) moveRow(up.closest("tr"), -1);
  else if (down) moveRow(down.closest("tr"), 1);
});

document.getElementById("btn-order-save").addEventListener("click", saveOrder);
document.getElementById("btn-order-cancel").addEventListener("click", () => location.reload());

// 键盘也能排序：聚焦某行输入后按 Alt + ↑/↓
tbody.addEventListener("keydown", (e) => {
  if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
  const row = e.target.closest("tr");
  if (!row) return;
  e.preventDefault();
  moveRow(row, e.key === "ArrowUp" ? -1 : 1);
  // 移动后把焦点还给同一行里对应的输入框，方便连续调整
  const cls = [...e.target.classList].find((c) => c.endsWith("-input"));
  if (cls) {
    const again = row.querySelector("." + cls);
    if (again) again.focus();
  }
});

// 拖拽排序（鼠标）：用事件委托，行是渲染时生成的
let dragRow = null;
tbody.addEventListener("dragstart", (e) => {
  const handle = e.target.closest(".drag-handle");
  if (!handle) {
    e.preventDefault();
    return;
  }
  dragRow = handle.closest("tr");
  dragRow.classList.add("dragging");
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", dragRow.dataset.id || "");
  }
});
tbody.addEventListener("dragover", (e) => {
  if (!dragRow) return;
  const over = e.target.closest("tr");
  if (!over || over === dragRow) return;
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
  const rect = over.getBoundingClientRect();
  const after = e.clientY > rect.top + rect.height / 2;
  rowsInOrder().forEach((r) => r.classList.remove("drop-above", "drop-below"));
  over.classList.add(after ? "drop-below" : "drop-above");
});
tbody.addEventListener("drop", (e) => {
  if (!dragRow) return;
  const over = e.target.closest("tr");
  if (!over || over === dragRow) return;
  e.preventDefault();
  const rect = over.getBoundingClientRect();
  const after = e.clientY > rect.top + rect.height / 2;
  tbody.insertBefore(dragRow, after ? over.nextSibling : over);
  markOrderDirty();
});
tbody.addEventListener("dragend", () => {
  if (dragRow) dragRow.classList.remove("dragging");
  rowsInOrder().forEach((r) => r.classList.remove("drop-above", "drop-below"));
  dragRow = null;
});

syncMoveButtons();

document.getElementById("btn-logout").addEventListener("click", async () => {
  try {
    await fetch("/api/logout", { method: "POST", cache: "no-store" });
  } catch (err) {}
  location.replace("/admin");
});
`;

// 登录浮层专用样式：沿用同一套设计变量，保持全站观感一致
const AUTH_CSS = `
.auth-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.auth-card {
  width: 100%; max-width: 376px; background: var(--surface);
  border: 1px solid rgba(255, 255, 255, .9); border-radius: 22px;
  box-shadow: var(--shadow); padding: 28px;
  backdrop-filter: blur(12px);
}
.auth-head { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; }
.auth-mark {
  flex: none; width: 40px; height: 40px; border-radius: 13px;
  background: linear-gradient(135deg, #fbcfe8, #ddd6fe);
  display: grid; place-items: center; font-size: 20px; line-height: 1;
  border: 2px solid #fff;
  box-shadow: 0 8px 18px -10px rgba(167, 139, 250, .9);
}
.auth-head h1 {
  font-size: 16px;
  background: linear-gradient(92deg, var(--ink), var(--ink2));
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  display: inline-block;
}
.auth-head p { font-size: 12.5px; color: var(--muted); margin-top: 1px; }
.auth-form { display: flex; flex-direction: column; gap: 14px; }
.auth-foot {
  margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center;
  font-size: 12.5px; color: var(--faint);
}
.auth-foot a { color: var(--muted); text-decoration: none; }
.auth-foot a:hover { color: var(--ink); }
`;

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>登录 · ${SITE_NAME}</title>
  ${FAVICON_LINK}
  <meta name="robots" content="noindex">
  <style>${APP_CSS}${AUTH_CSS}</style>
</head>
<body>
  <div class="auth-wrap">
    <div class="auth-card">
      <div class="auth-head">
        <span class="auth-mark" aria-hidden="true">🕊</span>
        <div>
          <h1>登录管理后台</h1>
          <p>${SITE_NAME}</p>
        </div>
      </div>

      <form class="auth-form" id="f" novalidate>
        <div class="field">
          <label for="user">用户名</label>
          <input class="input" type="text" id="user" name="username" autocomplete="username"
                 placeholder="用户名" spellcheck="false" autocapitalize="off" autofocus>
        </div>
        <div class="field">
          <label for="pw">密码</label>
          <input class="input" type="password" id="pw" name="password" autocomplete="current-password" placeholder="密码">
        </div>
        <div class="alert" id="err" role="alert"></div>
        <button class="btn btn-primary btn-block" type="submit" id="btn">登录</button>
      </form>

      <div class="auth-foot">
        <a href="/">← 返回首页</a>
        <span id="tip"></span>
      </div>
    </div>
  </div>

  <script>
    const form = document.getElementById("f");
    const userEl = document.getElementById("user");
    const pwEl = document.getElementById("pw");
    const btn = document.getElementById("btn");
    const errEl = document.getElementById("err");

    function showError(text) {
      errEl.textContent = text;
      errEl.classList.add("show");
    }
    function clearError() {
      errEl.textContent = "";
      errEl.classList.remove("show");
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      clearError();

      const username = userEl.value.trim();
      const password = pwEl.value;
      if (!username || !password) {
        showError("请输入用户名和密码");
        (!username ? userEl : pwEl).focus();
        return;
      }

      btn.disabled = true;
      btn.textContent = "登录中…";
      try {
        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username, password: password }),
          cache: "no-store",
        });
        if (res.ok) {
          // 登录成功后整页跳转，确保拿到新会话而不是缓存页面
          location.replace("/admin");
          return;
        }
        let data = {};
        try { data = await res.json(); } catch (err) {}
        if (res.status === 401) {
          showError("用户名或密码错误");
          pwEl.value = "";
          pwEl.focus();
        } else if (res.status === 429) {
          showError(data.error || "尝试次数过多，请稍后再试");
        } else {
          showError((data.error || "登录失败") + (data.hint ? "：" + data.hint : ""));
        }
      } catch (err) {
        showError("网络错误，请检查连接后重试");
      }
      btn.disabled = false;
      btn.textContent = "登录";
    });
  </script>
</body>
</html>`;

async function handleAdmin(request, env) {
  const session = await requireSession(request, env);
  if (!session) {
    // 这里故意返回 200 而不是 401：
    // 401 + WWW-Authenticate 会让浏览器接管响应、弹出原生 Basic 登录框而不渲染
    // 本页面；而且浏览器的 Basic 凭据缓存会导致「退出退不掉、换账号登不进」。
    return noStoreHtml(LOGIN_PAGE);
  }
  // 打开管理页即刷新有效期（滑动续期）
  const renewHeaders = session.token ? { "Set-Cookie": sessionCookie(session.token, request) } : {};
  const username = session.user;

  const links = (await getLinks(env)) || [];

  const rows = links
    .map(
      (l, i) => `
        <tr data-id="${escapeHtml(l.id)}" draggable="false">
          <td class="drag-cell" data-label="排序">
            <span class="row-actions">
              <span class="drag-handle" draggable="true" title="拖动排序" aria-hidden="true">⠿</span>
              <button class="icon-btn btn-up" type="button" title="上移" aria-label="上移">▲</button>
              <button class="icon-btn btn-down" type="button" title="下移" aria-label="下移">▼</button>
            </span>
          </td>
          <td class="icon-cell" data-label="图标">
            <input class="input cell-input icon-input" type="text" value="${escapeHtml(l.icon || "🔗")}" aria-label="图标">
          </td>
          <td data-label="标题">
            <input class="input cell-input title-input" type="text" value="${escapeHtml(l.title)}" aria-label="标题">
          </td>
          <td data-label="链接">
            <input class="input cell-input url-input" type="text" value="${escapeHtml(l.url)}" aria-label="链接">
          </td>
          <td data-label="描述">
            <input class="input cell-input desc-input" type="text" value="${escapeHtml(l.desc || "")}" aria-label="描述">
          </td>
          <td class="color-cell" data-label="颜色">
            <input type="color" class="color-input" value="${escapeHtml(normalizeColor(l.color))}" aria-label="颜色">
          </td>
          <td class="col-actions" data-label="操作">
            <span class="row-actions">
              <button class="btn btn-quiet btn-save" type="button">保存</button>
              <button class="btn btn-danger btn-del" type="button">删除</button>
            </span>
          </td>
        </tr>`
    )
    .join("");

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>管理后台 · ${escapeHtml(SITE_NAME)}</title>
  ${FAVICON_LINK}
  <meta name="robots" content="noindex">
  <style>${APP_CSS}${ADMIN_CSS}</style>
</head>
<body>
  <div class="shell">
    <div class="topbar">
      <span class="brand"><span class="brand-dot" aria-hidden="true"></span>${escapeHtml(SITE_NAME)}</span>
      <span class="topbar-actions">
        <span class="topbar-user">已登录 <b>${escapeHtml(username)}</b></span>
        <button class="btn btn-ghost" type="button" id="btn-logout">退出登录</button>
      </span>
    </div>

    <main>
      <p class="eyebrow">管理</p>
      <h1 class="display">链接</h1>
      <p class="lede">改动保存后立即生效，首页与后台都会同步更新。</p>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>全部链接</h2>
            <p>改内容点该行的「保存」；调顺序拖左侧手柄，或用 ▲▼</p>
          </div>
          <span class="count">${links.length} 条</span>
        </div>

        <table>
          <thead>
            <tr>
              <th>排序</th><th>图标</th><th>标题</th><th>链接</th><th>描述</th><th>颜色</th><th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody id="tbody">
${rows || `<tr><td class="empty-row" colspan="7">还没有链接，用下面的表单添加第一条。</td></tr>`}
          </tbody>
        </table>

        <div class="add-form">
          <div class="add-grid">
            <div class="field">
              <label for="new-icon">图标</label>
              <input class="input" id="new-icon" type="text" value="🔗" style="text-align:center">
            </div>
            <div class="field">
              <label for="new-title">标题</label>
              <input class="input" id="new-title" type="text" placeholder="网站名称">
            </div>
            <div class="field field-wide">
              <label for="new-url">链接</label>
              <input class="input" id="new-url" type="text" placeholder="https://example.com" spellcheck="false">
            </div>
            <div class="field">
              <label for="new-desc">描述</label>
              <input class="input" id="new-desc" type="text" placeholder="可选">
            </div>
            <div class="field">
              <label for="new-color">颜色</label>
              <input type="color" id="new-color" value="#a78bfa">
            </div>
            <div class="field">
              <button class="btn btn-primary" type="button" id="btn-add">添加</button>
            </div>
          </div>
        </div>
      </section>
    </main>
  </div>

  <div class="order-bar" id="order-bar" role="status" aria-live="polite">
    <span>顺序已调整，<b>还没保存</b></span>
    <button class="btn btn-ghost" type="button" id="btn-order-cancel">还原</button>
    <button class="btn btn-primary" type="button" id="btn-order-save">保存顺序</button>
  </div>
  <div class="toast" id="toast" role="status" aria-live="polite"></div>
  <script>${ADMIN_JS}</script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      ...renewHeaders,
    },
  });
}
