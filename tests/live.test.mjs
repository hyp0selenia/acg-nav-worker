/**
 * Integration test against the real workerd runtime (wrangler dev on :8787).
 * Uses the built-in fetch and maintains its own cookie jar.
 */

const BASE = "http://127.0.0.1:8787";
const PASSWORD = "admin123"; // default when ADMIN_PASSWORD is not set

const results = [];
function check(name, passed, detail) {
  results.push({ name, passed });
  console.log(`${passed ? "PASS" : "FAIL"}  ${name}${detail ? `\n        ${detail}` : ""}`);
}
function section(t) {
  console.log(`\n=== ${t} ===`);
}

const jar = new Map();
function absorb(res) {
  const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")].filter(Boolean);
  for (const one of sc) {
    const [pair, ...attrs] = one.split(";");
    const i = pair.indexOf("=");
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1).trim();
    const maxAge = attrs.map((a) => a.trim()).find((a) => /^max-age=/i.test(a));
    if ((maxAge && Number(maxAge.split("=")[1]) <= 0) || value === "") jar.delete(name);
    else jar.set(name, value);
  }
}
async function call(path, init = {}) {
  const headers = { ...(init.headers || {}) };
  if (jar.size) headers.Cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const res = await fetch(BASE + path, { ...init, headers, redirect: "manual" });
  absorb(res);
  return res;
}
const jsonOf = async (r) => {
  try {
    return await r.json();
  } catch {
    return null;
  }
};
const postJson = (p, b) => call(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
const putJson = (p, b) => call(p, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });

/* ---------- 1. login page ---------- */
section("1. 登录页");
let res = await call("/admin");
let html = await res.text();
check("GET /admin returns 200 and a login form", res.status === 200 && html.includes('id="pw"'), `status=${res.status}`);
check("no WWW-Authenticate (browser will not hijack the page)", res.headers.get("www-authenticate") === null, null);

res = await postJson("/api/login", { password: "definitely-wrong" });
check("wrong password rejected", res.status === 401, `status=${res.status}`);

res = await postJson("/api/login", { password: PASSWORD });
check("correct password accepted", res.status === 200, `status=${res.status}`);
const cookie = res.headers.get("set-cookie") || "";
check("session cookie set (HttpOnly, SameSite=Strict)", /HttpOnly/.test(cookie) && /SameSite=Strict/.test(cookie), cookie);

/* ---------- 2. the reported bug: save ---------- */
section("2. 保存配置");
res = await call("/admin");
html = await res.text();
check("admin editor renders when logged in", res.status === 200 && html.includes("btn-save"), `status=${res.status}`);

let links = await jsonOf(await call("/api/links"));
check("GET /api/links returns the seeded defaults", Array.isArray(links) && links.length === 2, `count=${links && links.length}`);

const target = links[0];
const NEW_TITLE = "用真实运行时保存的标题 ✅";
res = await putJson("/api/links", { ...target, title: NEW_TITLE, color: "#ff00aa", icon: "🎯" });
const putBody = await jsonOf(res);
check("PUT /api/links (保存按钮) succeeds", res.status === 200, `status=${res.status} body=${JSON.stringify(putBody)}`);

links = await jsonOf(await call("/api/links"));
const stored = links.find((l) => l.id === target.id);
check("the change is persisted in KV", stored && stored.title === NEW_TITLE, `stored=${JSON.stringify(stored)}`);
check("colour and icon persisted too", stored && stored.color === "#ff00aa" && stored.icon === "🎯", `color=${stored && stored.color} icon=${stored && stored.icon}`);

html = await (await call("/admin")).text();
check("reloading /admin shows the new title", html.includes(NEW_TITLE), null);
const home = await (await call("/")).text();
check("the home page shows the new title", home.includes(NEW_TITLE), null);

/* ---------- 3. add / delete ---------- */
section("3. 添加 / 删除");
res = await postJson("/api/links", { title: "真实运行时新增", url: "https://example.com", desc: "d", icon: "✨", color: "#00ff00" });
const created = await jsonOf(res);
check("POST /api/links succeeds", res.status === 201 && created && created.id, `status=${res.status}`);
check("new link appears in the list", (await jsonOf(await call("/api/links"))).some((l) => l.id === created.id), null);

res = await call("/api/links", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: created.id }) });
check("DELETE /api/links succeeds", res.status === 200, `status=${res.status}`);
check("deleted link is gone", !(await jsonOf(await call("/api/links"))).some((l) => l.id === created.id), null);

/* ---------- 4. unauthenticated writes ---------- */
section("4. 未登录写入");
const anon = await fetch(BASE + "/api/links", {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ id: target.id, title: "hacked" }),
});
check("anonymous PUT is rejected", anon.status === 401, `status=${anon.status}`);
const afterAnon = await jsonOf(await call("/api/links"));
check("the anonymous write changed nothing", afterAnon.find((l) => l.id === target.id).title === NEW_TITLE, null);

/* ---------- 5. logout ---------- */
section("5. 退出登录");
res = await postJson("/api/logout", {});
check("logout clears the cookie", /nav_session=;/.test(res.headers.get("set-cookie") || ""), res.headers.get("set-cookie"));
res = await putJson("/api/links", { id: target.id, title: "x" });
check("writes after logout are rejected", res.status === 401, `status=${res.status}`);
res = await call("/admin");
check("admin shows the login form again", (await res.text()).includes('id="pw"'), `status=${res.status}`);

/* ---------- 6. 不再反复要密码 ---------- */
section("6. 连续保存不需要再输密码");
res = await postJson("/api/login", { password: PASSWORD });
const cookie2 = res.headers.get("set-cookie") || "";
check("session cookie lives 30 days", /Max-Age=2592000/.test(cookie2), cookie2);

let editsOk = 0;
for (let i = 1; i <= 5; i++) {
  const r = await putJson("/api/links", { ...target, title: `连续第 ${i} 次保存` });
  if (r.status === 200) editsOk++;
}
check("5 consecutive saves all succeed without re-entering the password", editsOk === 5, `${editsOk}/5 succeeded`);

// A fresh GET of /admin must NOT contain any password prompt logic.
const editor = await (await call("/admin")).text();
check("the editor page contains no prompt()/btoa password code", !/prompt\(/.test(editor) && !/btoa\(/.test(editor), null);
check("the editor page sends no Authorization header built from a password", !/"Authorization"/.test(editor), null);

/* ---------- 7. 防爆破限流 ---------- */
section("7. 防爆破限流");
let throttled = false;
let attempts = 0;
for (let i = 0; i < 14; i++) {
  attempts++;
  const r = await fetch(BASE + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.99" },
    body: JSON.stringify({ password: "guess-" + i }),
  });
  if (r.status === 429) {
    throttled = true;
    check("throttled response carries Retry-After", Number(r.headers.get("retry-after")) > 0, `Retry-After=${r.headers.get("retry-after")}`);
    break;
  }
}
check("brute force gets throttled on the real runtime", throttled, `${attempts} attempts before 429`);

// The correct password from the already-authenticated session must still work.
res = await putJson("/api/links", { ...target, title: "限流期间仍可保存" });
check("an existing session keeps working while an attacker is throttled", res.status === 200, `status=${res.status}`);

const failed = results.filter((r) => !r.passed);
console.log(`\n=== Summary (real workerd) ===\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) for (const f of failed) console.log("  - " + f.name);
process.exitCode = failed.length ? 1 : 0;
