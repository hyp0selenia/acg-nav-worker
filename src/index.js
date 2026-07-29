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
      return handleAdmin(request, env, path);
    }

    if (path === "/api/links") {
      return handleApiLinks(request, env);
    }

    // 首页
    return handleHome(request, env);
  },
};

/* ==================== 工具函数 ==================== */

async function getLinks(env) {
  const data = await env.NAV.get("links", { type: "json" });
  if (data && Array.isArray(data)) return data;

  // 默认链接（首次运行自动写入）
  const defaultLinks = [
    {
      id: crypto.randomUUID(),
      title: "🕊️ 鸽子窝",
      url: "https://hyposelenia.dpdns.org",
      desc: "咕咕咕",
      icon: "🕊️",
      color: "#000000",
    },
    {
      id: crypto.randomUUID(),
      title: "这是测试",
      url: "https://github.com/hyp0selenia/acg-nav-worker",
      desc: "这是描述",
      icon: "这是emoji",
      color: "#ffffff",
    },
  ];
  await env.NAV.put("links", JSON.stringify(defaultLinks));
  return defaultLinks;
}

async function saveLinks(env, links) {
  await env.NAV.put("links", JSON.stringify(links));
}

function checkAuth(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Basic ")) return false;
  try {
    const decoded = atob(auth.slice(6));
    const [user, pass] = decoded.split(":");
    // 用户名固定为 admin，密码用环境变量
    return user === "admin" && pass === (env.ADMIN_PASSWORD || "admin123");
  } catch {
    return false;
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

/* ==================== API ==================== */

async function handleApiLinks(request, env) {
  // 公开读取
  if (request.method === "GET") {
    const links = await getLinks(env);
    return jsonResponse(links);
  }

  // 写操作需要鉴权
  if (!checkAuth(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  if (request.method === "POST") {
    const body = await request.json();
    const links = await getLinks(env);
    const newLink = {
      id: crypto.randomUUID(),
      title: body.title || "未命名",
      url: body.url || "#",
      desc: body.desc || "",
      icon: body.icon || "🔗",
      color: body.color || "#a78bfa",
    };
    links.push(newLink);
    await saveLinks(env, links);
    return jsonResponse(newLink);
  }

  if (request.method === "PUT") {
    const body = await request.json();
    let links = await getLinks(env);
    const idx = links.findIndex((l) => l.id === body.id);
    if (idx === -1) return jsonResponse({ error: "Not found" }, 404);
    links[idx] = { ...links[idx], ...body };
    await saveLinks(env, links);
    return jsonResponse(links[idx]);
  }

  if (request.method === "DELETE") {
    const body = await request.json();
    let links = await getLinks(env);
    links = links.filter((l) => l.id !== body.id);
    await saveLinks(env, links);
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: "Method not allowed" }, 405);
}

/* ==================== 首页 ==================== */

async function handleHome(request, env) {
  const links = await getLinks(env);

  const cards = links
    .map(
      (l) => `
    <a href="${escapeHtml(l.url)}" target="_blank" rel="noopener" class="card" style="--accent:${l.color || "#a78bfa"}">
      <div class="icon">${l.icon || "🔗"}</div>
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
      ${cards}
    </div>

    <footer>
      Made with 💕 · <a href="/admin">管理后台</a>
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

async function handleAdmin(request, env, path) {
  // 登录页 / 鉴权检查
  if (!checkAuth(request, env)) {
    return new Response(
      `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理登录</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      background: linear-gradient(135deg, #fff0f5, #f3e8ff);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0;
    }
    .box {
      background: white;
      padding: 40px;
      border-radius: 24px;
      box-shadow: 0 20px 40px rgba(167,139,250,0.25);
      text-align: center;
      max-width: 360px;
      width: 90%;
    }
    h2 { margin: 0 0 8px; color: #7c3aed; }
    p { color: #8b7a9b; margin-bottom: 24px; font-size: 0.95rem; }
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
    button:hover { opacity: 0.95; }
  </style>
</head>
<body>
  <div class="box">
    <h2>🔐 管理后台</h2>
    <p>请使用浏览器弹出的登录框输入<br>用户名 <b>admin</b> + 你的密码</p>
    <p style="font-size:0.85rem;color:#a78bfa;">如果没有弹出登录框，请刷新页面</p>
  </div>
  <script>
    // 触发浏览器 Basic Auth 弹窗
    fetch(location.href, {
      headers: { Authorization: "Basic " + btoa("admin:") }
    }).then(r => {
      if (r.status === 401) location.reload();
    });
  </script>
</body>
</html>`,
      {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Admin"',
          "Content-Type": "text/html; charset=utf-8",
        },
      }
    );
  }

  // 已鉴权，返回管理页面
  const links = await getLinks(env);

  const rows = links
    .map(
      (l) => `
    <tr data-id="${l.id}">
      <td><input type="text" value="${escapeHtml(l.icon)}" class="icon-input" style="width:50px;text-align:center"></td>
      <td><input type="text" value="${escapeHtml(l.title)}" class="title-input"></td>
      <td><input type="text" value="${escapeHtml(l.url)}" class="url-input"></td>
      <td><input type="text" value="${escapeHtml(l.desc || "")}" class="desc-input"></td>
      <td><input type="color" value="${l.color || "#a78bfa"}" class="color-input"></td>
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

  <script>
    const authHeader = "Basic " + btoa("admin:" + prompt("请再次确认密码（仅本次会话）") || "");

    // 保存
    document.querySelectorAll(".btn-save").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const tr = e.target.closest("tr");
        const id = tr.dataset.id;
        const data = {
          id,
          icon: tr.querySelector(".icon-input").value,
          title: tr.querySelector(".title-input").value,
          url: tr.querySelector(".url-input").value,
          desc: tr.querySelector(".desc-input").value,
          color: tr.querySelector(".color-input").value,
        };
        const res = await fetch("/api/links", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "Authorization": authHeader
          },
          body: JSON.stringify(data)
        });
        if (res.ok) {
          alert("✅ 已保存");
        } else {
          alert("❌ 保存失败");
        }
      });
    });

    // 删除
    document.querySelectorAll(".btn-del").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        if (!confirm("确定删除这个链接吗？")) return;
        const tr = e.target.closest("tr");
        const id = tr.dataset.id;
        const res = await fetch("/api/links", {
          method: "DELETE",
          headers: {
            "Content-Type": "application/json",
            "Authorization": authHeader
          },
          body: JSON.stringify({ id })
        });
        if (res.ok) {
          tr.remove();
        } else {
          alert("删除失败");
        }
      });
    });

    // 添加
    document.getElementById("btn-add").addEventListener("click", async () => {
      const data = {
        icon: document.getElementById("new-icon").value || "🔗",
        title: document.getElementById("new-title").value,
        url: document.getElementById("new-url").value,
        desc: document.getElementById("new-desc").value,
        color: document.getElementById("new-color").value,
      };
      if (!data.title || !data.url) {
        alert("标题和链接不能为空");
        return;
      }
      const res = await fetch("/api/links", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": authHeader
        },
        body: JSON.stringify(data)
      });
      if (res.ok) {
        location.reload();
      } else {
        alert("添加失败");
      }
    });
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
