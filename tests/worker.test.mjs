/**
 * Verification harness for the "无法保存配置" bug in this Worker.
 *
 * Imports the real src/index.js, fakes the KV binding, then drives the HTTP
 * conversation a browser has with the Worker, carrying cookies across requests.
 */

const FIXED_NOW = Date.parse("2025-01-01T00:00:00Z");
const realNow = Date.now;
Date.now = () => FIXED_NOW;

const PASSWORD = "mypass123";
const ENV = { ADMIN_USERNAME: "admin", ADMIN_PASSWORD: PASSWORD };

const store = new Map();
ENV.NAV = {
  async get(key, opts) {
    const raw = store.get(key);
    if (raw === undefined) return null;
    return opts && opts.type === "json" ? JSON.parse(raw) : raw;
  },
  async put(key, value) {
    store.set(key, value);
  },
};

const worker = (await import("../src/index.js")).default;
const BASE = "https://nav.example.workers.dev";

/* ---------- tiny test framework ---------- */
const results = [];
function check(name, passed, detail) {
  results.push({ name, passed });
  console.log(`${passed ? "PASS" : "FAIL"}  ${name}${detail ? `\n        ${detail}` : ""}`);
}
function section(title) {
  console.log(`\n=== ${title} ===`);
}

/* ---------- browser-ish client with a cookie jar ---------- */
const jar = new Map();
function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function absorb(res) {
  const sc = res.headers.get("Set-Cookie");
  if (!sc) return;
  const [pair, ...attrs] = sc.split(";");
  const i = pair.indexOf("=");
  const name = pair.slice(0, i).trim();
  const value = pair.slice(i + 1).trim();
  const maxAge = attrs.map((a) => a.trim()).find((a) => /^max-age=/i.test(a));
  const expired = maxAge && Number(maxAge.split("=")[1]) <= 0;
  if (expired || value === "") jar.delete(name);
  else jar.set(name, value);
}
async function call(path, init = {}) {
  const headers = { ...(init.headers || {}) };
  const cookies = cookieHeader();
  if (cookies) headers.Cookie = cookies;
  const res = await worker.fetch(new Request(BASE + path, { ...init, headers }), ENV);
  absorb(res);
  return res;
}
async function json(res) {
  try {
    return await res.json();
  } catch (err) {
    return null;
  }
}
const post = (p, body, headers) =>
  call(p, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
const put = (p, body, headers) =>
  call(p, { method: "PUT", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
const del = (p, body, headers) =>
  call(p, { method: "DELETE", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });

/* =========================================================
   1. The reported bug
   ========================================================= */
section("1. 保存配置 (the reported bug)");

let res = await call("/admin");
const loginHtml = await res.text();
check(
  "GET /admin without credentials renders a login page (200, not 401)",
  res.status === 200 && /管理后台/.test(loginHtml),
  `status=${res.status}`
);
check(
  "no WWW-Authenticate header, so the browser never hijacks the page",
  res.headers.get("WWW-Authenticate") === null,
  `header=${JSON.stringify(res.headers.get("WWW-Authenticate"))}`
);
check(
  "the broken prompt()/btoa(\"admin:\") auth code is gone",
  !/prompt\(/.test(loginHtml) && !/Basic " \+ btoa/.test(loginHtml),
  null
);

res = await post("/api/login", { password: "wrong-password" });
check("login with a wrong password is rejected (401)", res.status === 401, `status=${res.status}`);

res = await post("/api/login", { password: PASSWORD });
check("login with the correct password succeeds", res.status === 200, `status=${res.status}`);
const setCookie = res.headers.get("Set-Cookie") || "";
check(
  "session cookie is HttpOnly + SameSite=Strict + Secure on https",
  /HttpOnly/.test(setCookie) && /SameSite=Strict/.test(setCookie) && /Secure/.test(setCookie),
  setCookie
);
check("cookie jar holds a session", jar.has("nav_session"), `cookies=[${[...jar.keys()]}]`);

res = await call("/admin");
const adminHtml = await res.text();
check(
  "GET /admin with the session renders the editor",
  res.status === 200 && /add-form/.test(adminHtml) && /btn-save/.test(adminHtml),
  `status=${res.status}`
);

const links = await json(await call("/api/links"));
const target = links[0];
const savedTitle = "改过的标题 ✅";

res = await put("/api/links", { ...target, title: savedTitle, color: "#ff00aa" });
const body = await json(res);
check(
  "PUT /api/links is accepted (this is the 保存 button)",
  res.status === 200,
  `status=${res.status} body=${JSON.stringify(body)}`
);

const after = await json(await call("/api/links"));
const persisted = after.find((l) => l.id === target.id);
check("the edit is actually persisted to KV", persisted && persisted.title === savedTitle, `stored=${JSON.stringify(persisted)}`);
check("saving does not silently change the colour", persisted && persisted.color === "#ff00aa", `stored color=${persisted && persisted.color}`);

const reloaded = await (await call("/admin")).text();
check("the reloaded admin page shows the saved title", reloaded.includes(savedTitle), null);
check("the home page shows the saved title", (await (await call("/")).text()).includes(savedTitle), null);

/* =========================================================
   2. Add / delete
   ========================================================= */
section("2. 添加 / 删除");

res = await post("/api/links", { title: "新链接", url: "https://example.com", desc: "测试", icon: "🆕", color: "#123456" });
const created = await json(res);
check("POST /api/links creates a link", res.status === 201 && created && created.id, `status=${res.status}`);

const listAfterAdd = await json(await call("/api/links"));
check("the new link is in the list", listAfterAdd.some((l) => l.id === created.id), `count=${listAfterAdd.length}`);

res = await del("/api/links", { id: created.id });
check("DELETE /api/links removes a link", res.status === 200, `status=${res.status}`);
check("the deleted link is gone from KV", !(await json(await call("/api/links"))).some((l) => l.id === created.id), null);

res = await put("/api/links", { id: "does-not-exist", title: "x" });
check("PUT for a missing id returns 404 with a readable message", res.status === 404, `status=${res.status} body=${JSON.stringify(await json(res))}`);

/* =========================================================
   3. Authorisation boundaries
   ========================================================= */
section("3. 鉴权边界");

res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: target.id, title: "hacked" }),
  }),
  ENV
);
check("PUT /api/links without any session is rejected (401)", res.status === 401, `status=${res.status}`);
check(
  "the rejected write did not change anything",
  (await json(await call("/api/links"))).find((l) => l.id === target.id).title === savedTitle,
  null
);

// A forged Bearer token alone (no cookie) must not authenticate.
res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer total-garbage" },
    body: JSON.stringify({ id: target.id, title: "x" }),
  }),
  ENV
);
check("a forged Bearer token with no session is rejected", res.status === 401, `status=${res.status}`);

// Tamper with the token payload inside the cookie.
const goodCookie = jar.get("nav_session");
const tampered = goodCookie.slice(0, 10) + (goodCookie[10] === "a" ? "b" : "a") + goodCookie.slice(11);
const tamperRes = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${tampered}` },
    body: JSON.stringify({ id: target.id, title: "tampered" }),
  }),
  ENV
);
check("a tampered session token is rejected", tamperRes.status === 401, `status=${tamperRes.status}`);

const decodedToken = Buffer.from(
  goodCookie.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (goodCookie.length % 4)) % 4),
  "base64"
).toString("utf8");
const SESSION_DAYS = 30;
const expPart = decodedToken.split("|")[0];
check(
  `the session token carries a ${SESSION_DAYS}-day expiry`,
  Number(expPart) === FIXED_NOW + SESSION_DAYS * 24 * 60 * 60 * 1000,
  `exp=${expPart} expected=${FIXED_NOW + SESSION_DAYS * 24 * 60 * 60 * 1000}`
);

// Still valid just before it lapses...
Date.now = () => FIXED_NOW + (SESSION_DAYS - 1) * 24 * 60 * 60 * 1000;
const stillValid = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${goodCookie}` },
    body: JSON.stringify({ id: target.id, title: savedTitle }),
  }),
  ENV
);
check("the session still works the day before it expires", stillValid.status === 200, `status=${stillValid.status}`);

Date.now = () => FIXED_NOW + (SESSION_DAYS + 1) * 24 * 60 * 60 * 1000;
const expiredRes = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${goodCookie}` },
    body: JSON.stringify({ id: target.id, title: "expired" }),
  }),
  ENV
);
check("an expired session token is rejected", expiredRes.status === 401, `status=${expiredRes.status}`);
Date.now = () => FIXED_NOW;

const rotatedEnv = { ...ENV, ADMIN_PASSWORD: "a-new-password" };
const rotatedRes = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${goodCookie}` },
    body: JSON.stringify({ id: target.id, title: "x" }),
  }),
  rotatedEnv
);
check("changing ADMIN_PASSWORD invalidates old sessions", rotatedRes.status === 401, `status=${rotatedRes.status}`);

const basic = "Basic " + Buffer.from(`admin:${PASSWORD}`).toString("base64");
res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: basic },
    body: JSON.stringify({ id: target.id, title: savedTitle }),
  }),
  ENV
);
check("curl-style HTTP Basic auth still works", res.status === 200, `status=${res.status}`);

res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Basic " + Buffer.from("admin:wrong").toString("base64"),
    },
    body: JSON.stringify({ id: target.id, title: "x" }),
  }),
  ENV
);
check("HTTP Basic with a wrong password is rejected", res.status === 401, `status=${res.status}`);

/* =========================================================
   4. Logout
   ========================================================= */
section("4. 退出登录");

res = await post("/api/logout", {});
check(
  "POST /api/logout clears the session cookie",
  /nav_session=;/.test(res.headers.get("Set-Cookie") || ""),
  res.headers.get("Set-Cookie")
);
check("the cookie jar no longer holds a session", !jar.has("nav_session"), `cookies=[${[...jar.keys()]}]`);
res = await put("/api/links", { id: target.id, title: "after logout" });
check("writes after logout are rejected", res.status === 401, `status=${res.status}`);

/* =========================================================
   5. Misconfiguration
   ========================================================= */
section("5. 配置缺失时的表现");

const noKv = { ADMIN_PASSWORD: PASSWORD };
res = await worker.fetch(new Request(BASE + "/api/links"), noKv);
const kvBody = await json(res);
check(
  "GET /api/links without the KV binding returns 500 + a hint",
  res.status === 500 && kvBody && kvBody.hint,
  `status=${res.status} body=${JSON.stringify(kvBody)}`
);

res = await worker.fetch(new Request(BASE + "/"), noKv);
check("GET / without the KV binding still renders a page instead of throwing", res.status === 200, `status=${res.status}`);

// 4 段已登出，这里重新登录，才能测到「带鉴权但请求体是坏的」这一层。
res = await post("/api/login", { password: PASSWORD });
check("re-login works after logout", res.status === 200 && jar.has("nav_session"), `status=${res.status}`);

res = await call("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{not json" });
check("malformed JSON body returns 400", res.status === 400, `status=${res.status}`);

/* =========================================================
   6. Data shape tolerance
   ========================================================= */
section("6. 存储数据格式");

await ENV.NAV.put(
  "links",
  JSON.stringify({ links: [{ id: "wrapped", title: "包装格式", url: "https://a.b", color: "#ffffff" }] })
);
const shaped = await json(await call("/api/links"));
check(
  "a { links: [...] } stored value is read instead of silently reset",
  Array.isArray(shaped) && shaped.some((l) => l.id === "wrapped"),
  `got=${JSON.stringify(shaped)}`
);

await ENV.NAV.put("links", JSON.stringify([{ id: "bad-color", title: "坏颜色", url: "https://a.b", color: "red" }]));
const badColorEdit = await json(await put("/api/links", { id: "bad-color", title: "坏颜色", url: "https://a.b", color: "not-a-color" }));
check(
  "an invalid colour is replaced by a usable hex value",
  badColorEdit && badColorEdit.color === "#a78bfa",
  `stored color=${JSON.stringify(badColorEdit && badColorEdit.color)}`
);

await ENV.NAV.put("links", JSON.stringify([{ id: "ok-color", title: "好颜色", url: "https://a.b", color: "#00ff00" }]));
const okColorEdit = await json(await put("/api/links", { id: "ok-color", title: "好颜色", url: "https://a.b", color: "garbage" }));
check(
  "an invalid colour keeps the existing colour instead of resetting it",
  okColorEdit && okColorEdit.color === "#00ff00",
  `stored color=${JSON.stringify(okColorEdit && okColorEdit.color)}`
);

/* =========================================================
   7. Security regression tests for the fixes in this round:
      - no hard-coded fallback signing key
      - length-independent password comparison
      - login brute-force throttling
   ========================================================= */
section("7. 安全回归");

// (a) With no ADMIN_PASSWORD the Worker must fail closed. Previously the
// signing key fell back to a hard-coded literal published in this repo, so
// anyone could mint a valid session token without knowing any password.
const NO_PW = { ADMIN_USERNAME: "admin", NAV: ENV.NAV };

res = await worker.fetch(
  new Request(BASE + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: "admin123" }),
  }),
  NO_PW
);
check(
  "no ADMIN_PASSWORD: the old default password no longer logs you in",
  res.status === 500,
  `status=${res.status} body=${await res.text()}`
);

res = await worker.fetch(
  new Request(BASE + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: "anime-nav-insecure-default" }),
  }),
  NO_PW
);
check("no ADMIN_PASSWORD: the old hard-coded secret does not log you in either", res.status === 500, `status=${res.status}`);

// Forge a token exactly as the leaked fallback key would have produced it.
async function forgeToken(secret, exp) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode("anime-nav:" + secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode("v1|" + exp));
  const b64url = (s) => Buffer.from(s, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sig = b64url(String.fromCharCode(...new Uint8Array(mac)));
  return b64url(exp + "|" + sig);
}
const forged = await forgeToken("anime-nav-insecure-default", String(Date.now() + 86400000));
res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${forged}` },
    body: JSON.stringify({ id: target.id, title: "forged" }),
  }),
  NO_PW
);
check("a token forged from the old published secret is rejected", res.status === 401, `status=${res.status}`);

res = await worker.fetch(
  new Request(BASE + "/api/links", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: `nav_session=${forged}` },
    body: JSON.stringify({ id: target.id, title: "forged" }),
  }),
  ENV
);
check("...and is also rejected when a real password IS configured", res.status === 401, `status=${res.status}`);

// (b) The password comparison must not leak length. Measure the two paths and
// make sure a very long wrong password does not cost noticeably more than a
// short one (the old loop ran max(len) times).
async function timeLogin(pw, ip) {
  const req = new Request(BASE + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
    body: JSON.stringify({ password: pw }),
  });
  const t0 = performance.now();
  await worker.fetch(req, ENV);
  return performance.now() - t0;
}
// Warm up so JIT/import cost does not dominate.
await timeLogin("warmup", "10.0.0.99");
const shortTimes = [];
const longTimes = [];
for (let i = 0; i < 12; i++) {
  shortTimes.push(await timeLogin("x", `10.0.1.${i}`));
  longTimes.push(await timeLogin("x".repeat(4000), `10.0.2.${i}`));
}
const avg = (a) => a.reduce((s, v) => s + v, 0) / a.length;
const shortAvg = avg(shortTimes);
const longAvg = avg(longTimes);
const ratio = longAvg / shortAvg;
check(
  "wrong-password timing does not grow with password length",
  ratio < 3,
  `short=${shortAvg.toFixed(2)}ms long=${longAvg.toFixed(2)}ms ratio=${ratio.toFixed(2)}x`
);

// (c) Brute force must be throttled.
let sawThrottle = false;
let lastStatus = 0;
for (let i = 0; i < 14; i++) {
  const r = await worker.fetch(
    new Request(BASE + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7" },
      body: JSON.stringify({ password: "guess-" + i }),
    }),
    ENV
  );
  lastStatus = r.status;
  if (r.status === 429) {
    sawThrottle = true;
    check("throttled responses carry Retry-After", Number(r.headers.get("Retry-After")) > 0, `Retry-After=${r.headers.get("Retry-After")}`);
    break;
  }
}
check("repeated wrong passwords get throttled (429)", sawThrottle, `last status=${lastStatus}`);

// Throttling must not lock out the correct password from a different address.
res = await worker.fetch(
  new Request(BASE + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.5" },
    body: JSON.stringify({ password: PASSWORD }),
  }),
  ENV
);
check("throttling a bad actor does not block a legitimate login", res.status === 200, `status=${res.status}`);

/* ---------- summary ---------- */
const failed = results.filter((r) => !r.passed);
console.log(`\n=== Summary ===\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("\nFailing:");
  for (const f of failed) console.log("  - " + f.name);
}
Date.now = realNow;
process.exitCode = failed.length ? 1 : 0;
