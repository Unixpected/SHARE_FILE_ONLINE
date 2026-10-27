import { AwsClient } from "aws4fetch";

// ---------------------------------------------------------------------------
// Defaults. The admin page can change maxMB and logDays (stored in D1).
// ---------------------------------------------------------------------------
const DEFAULTS = { maxMB: 200, logDays: 30 };
const LIMITS = { maxMB: [1, 5000], logDays: [1, 365] }; // 5000 MB = S3 single-PUT ceiling
const TTL_MS = 60 * 60 * 1000; // files live 1 hour
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;

const cors = (env) => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  Vary: "Origin",
});
const json = (env, data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors(env) },
  });

const client = (env) =>
  new AwsClient({
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APP_KEY,
    service: "s3",
    region: env.B2_REGION,
  });

const objUrl = (env, key = "") =>
  `https://${env.B2_ENDPOINT}/${env.B2_BUCKET}/${key.split("/").map(encodeURIComponent).join("/")}`;

async function presign(env, method, key, seconds, extra = {}) {
  const u = new URL(objUrl(env, key));
  u.searchParams.set("X-Amz-Expires", String(seconds));
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
  const signed = await client(env).sign(new Request(u, { method }), { aws: { signQuery: true } });
  return signed.url;
}

const randomId = () => {
  const b = crypto.getRandomValues(new Uint8Array(15));
  return [...b].map((x) => x.toString(36).padStart(2, "0")).join("").slice(0, 20);
};
const cleanName = (n) =>
  (String(n || "file").replace(/[^\w.\- ]/g, "_").replace(/^\.+/, "").slice(0, 100)) || "file";

// ---------------------------------------------------------------------------
// Settings (stored in D1 table `settings`)
// ---------------------------------------------------------------------------
async function getSettings(env) {
  const s = { ...DEFAULTS };
  if (!env.DB) return s;
  try {
    const { results } = await env.DB.prepare("SELECT key, value FROM settings").all();
    for (const r of results) {
      const n = Number(r.value);
      if (r.key in s && Number.isFinite(n)) s[r.key] = n;
    }
  } catch {
    /* table not created yet -> use defaults */
  }
  return s;
}

// ---------------------------------------------------------------------------
// Extra allowed websites, editable on the admin page (settings key "domains").
// The ALLOWED_ORIGIN variable in wrangler.toml is the permanent base list.
// ---------------------------------------------------------------------------
const DOMAIN_RX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:\d{1,5})?$/;
const parseDomains = (text) => [
  ...new Set(
    String(text || "")
      .split(/[\s,;]+/)
      .map((s) => s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""))
      .filter(Boolean)
  ),
];
async function getDomainList(env) {
  if (!env.DB) return [];
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'domains'").first();
    return parseDomains(row?.value);
  } catch {
    return [];
  }
}
let domainCache = { t: 0, list: [] }; // cached 60 s per worker instance
async function getExtraOrigins(env) {
  if (Date.now() - domainCache.t < 60000) return domainCache.list;
  const list = (await getDomainList(env)).flatMap((d) => [`https://${d}`, `http://${d}`]);
  domainCache = { t: Date.now(), list };
  return list;
}

// ---------------------------------------------------------------------------
// Activity log (stored in D1 table `logs`)
// ---------------------------------------------------------------------------
const who = (req) => ({
  ip: req.headers.get("CF-Connecting-IP") || "unknown",
  country: req.cf?.country || null,
  city: req.cf?.city || null,
  ua: (req.headers.get("User-Agent") || "").slice(0, 200),
});

function log(env, ctx, req, event, detail = {}) {
  if (!env.DB) return;
  const w = who(req);
  const p = env.DB
    .prepare("INSERT INTO logs (ts, event, ip, country, city, ua, detail) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(Date.now(), event, w.ip, w.country, w.city, w.ua, JSON.stringify(detail).slice(0, 1000))
    .run()
    .catch((e) => console.log("LOG_FAILED", e.message));
  ctx?.waitUntil(p);
}

// ---------------------------------------------------------------------------
// Admin auth: password -> signed 12h token (HMAC-SHA256, key = ADMIN_PASSWORD)
// ---------------------------------------------------------------------------
const enc = new TextEncoder();
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function checkPassword(env, pw) {
  // Hash both sides first so comparison time does not depend on the password length
  const a = await hmacHex("pw-check", String(pw || ""));
  const b = await hmacHex("pw-check", env.ADMIN_PASSWORD);
  return safeEq(a, b);
}
async function makeToken(env) {
  const exp = Date.now() + ADMIN_SESSION_MS;
  return `${exp}.${await hmacHex(env.ADMIN_PASSWORD, "admin." + exp)}`;
}
async function isAdmin(env, req) {
  const m = /^Bearer (\d+)\.([0-9a-f]{64})$/.exec(req.headers.get("Authorization") || "");
  if (!m || !Number.isFinite(Number(m[1])) || Number(m[1]) < Date.now()) return false;
  return safeEq(m[2], await hmacHex(env.ADMIN_PASSWORD, "admin." + m[1]));
}

const validKey = (key) => typeof key === "string" && key.split("/").length === 2 && key.length < 300;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    // Which website may call us? Base list from wrangler.toml + domains added on the admin page.
    const base = env.ALLOWED_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean);
    const origin = req.headers.get("Origin");
    let allow;
    if (url.pathname.startsWith("/admin/") && origin) {
      // Admin calls are protected by the password / bearer token (no cookies), so CORS adds no
      // protection here. Allowing any origin means /admin.html still works on a brand-new domain,
      // which is how you add that domain without any command line.
      allow = origin;
    } else {
      let list = base;
      if (origin && !base.includes(origin)) list = base.concat(await getExtraOrigins(env));
      allow = list.includes(origin) ? origin : base[0];
    }
    env = { ...env, ALLOWED_ORIGIN: allow };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(env) });

    try {
      // Public: current upload limit, so the page always shows the right number
      if (url.pathname === "/config" && req.method === "GET") {
        const cfg = await getSettings(env);
        return json(env, { maxMB: cfg.maxMB });
      }

      // 1) Browser asks for an upload URL
      if (url.pathname === "/init" && req.method === "POST") {
        if (env.RATE_LIMITER) {
          const ip = req.headers.get("CF-Connecting-IP") || "unknown";
          const { success } = await env.RATE_LIMITER.limit({ key: ip });
          if (!success) {
            log(env, ctx, req, "rate_limited", { route: "upload" });
            return json(env, { error: "Too many uploads. Please wait a minute and try again." }, 429);
          }
        }
        const cfg = await getSettings(env);
        const maxBytes = cfg.maxMB * 1024 * 1024;
        const { name, size } = await req.json().catch(() => ({}));
        if (!Number.isFinite(size) || size <= 0) return json(env, { error: "Invalid size" }, 400);
        if (size > maxBytes) return json(env, { error: `File exceeds ${cfg.maxMB}MB` }, 413);
        const id = randomId();
        const key = `${id}/${cleanName(name)}`;
        // Allow slow connections: assume at least ~150 KB/s, minimum 15 min, maximum 6 h
        const seconds = Math.min(6 * 3600, Math.max(900, Math.ceil(size / (150 * 1024))));
        const uploadUrl = await presign(env, "PUT", key, seconds);
        log(env, ctx, req, "upload_start", { name: cleanName(name), size, key });
        return json(env, { key, uploadUrl });
      }

      // 2) Browser says upload finished -> verify size, return share link
      if (url.pathname === "/done" && req.method === "POST") {
        const { key } = await req.json().catch(() => ({}));
        if (!validKey(key)) return json(env, { error: "Bad key" }, 400);
        let head;
        for (let i = 0; i < 4; i++) {
          head = await client(env).fetch(objUrl(env, key), { method: "HEAD" });
          if (head.ok || head.status === 403) break; // 403 = config/signature problem, retrying won't help
          await new Promise((r) => setTimeout(r, 500 * (i + 1)));
        }
        if (!head.ok) {
          console.log("DONE_HEAD_FAILED", head.status, key); // view with: npx wrangler tail
          return json(env, { error: `Upload not found (storage returned ${head.status}). Please try again.` }, head.status === 404 ? 404 : 502);
        }
        const size = Number(head.headers.get("content-length"));
        const cfg = await getSettings(env);
        if (size > cfg.maxMB * 1024 * 1024) {
          await client(env).fetch(objUrl(env, key), { method: "DELETE" });
          log(env, ctx, req, "upload_rejected", { key, size, reason: "over limit" });
          return json(env, { error: `File exceeds ${cfg.maxMB}MB` }, 413);
        }
        const link = `${url.origin}/d/${key.split("/").map(encodeURIComponent).join("/")}`;
        log(env, ctx, req, "upload_done", { name: key.split("/")[1], size, key });
        return json(env, { link, expiresInMinutes: 60 });
      }

      // 3) Download link -> checks age -> redirects to short-lived signed URL
      if (url.pathname.startsWith("/d/") && req.method === "GET") {
        const key = decodeURIComponent(url.pathname.slice(3));
        if (!validKey(key)) return new Response("Not found", { status: 404 });
        const head = await client(env).fetch(objUrl(env, key), { method: "HEAD" });
        if (!head.ok) return new Response("This file has expired or does not exist.", { status: 404 });
        const age = Date.now() - new Date(head.headers.get("last-modified")).getTime();
        if (age > TTL_MS) {
          await client(env).fetch(objUrl(env, key), { method: "DELETE" });
          return new Response("This link has expired.", { status: 410 });
        }
        const fname = key.split("/")[1];
        const signed = await presign(env, "GET", key, 300, {
          "response-content-disposition": `attachment; filename="${fname}"`,
        });
        log(env, ctx, req, "download", { name: fname, key });
        return Response.redirect(signed, 302);
      }

      // ===== Public comments =====
      if (url.pathname === "/comments" && req.method === "GET") {
        if (!env.DB) return json(env, { error: "Comments are not set up yet." }, 503);
        const { results } = await env.DB
          .prepare(
            "WITH top AS (SELECT id FROM comments WHERE parent_id IS NULL ORDER BY created_at DESC LIMIT 50) " +
            "SELECT id, name, text, created_at, likes, stars, parent_id FROM comments " +
            "WHERE id IN (SELECT id FROM top) OR parent_id IN (SELECT id FROM top) ORDER BY created_at ASC"
          )
          .all();
        return json(env, { comments: results });
      }

      if (url.pathname === "/comments" && req.method === "POST") {
        if (!env.DB) return json(env, { error: "Comments are not set up yet." }, 503);
        const ip = req.headers.get("CF-Connecting-IP") || "unknown";
        if (env.RATE_LIMITER) {
          const { success } = await env.RATE_LIMITER.limit({ key: "c:" + ip });
          if (!success) {
            log(env, ctx, req, "rate_limited", { route: "comment" });
            return json(env, { error: "Too many requests. Please wait a minute." }, 429);
          }
        }
        const body = await req.json().catch(() => ({}));
        const text = String(body.text || "").trim().slice(0, 500);
        const name = String(body.name || "").trim().slice(0, 40) || "Anonymous";
        if (!text) return json(env, { error: "Please write a comment." }, 400);
        // Replies: one level only. Replying to a reply attaches to the original comment.
        let parent_id = null;
        if (body.parent_id) {
          const par = await env.DB
            .prepare("SELECT id, parent_id FROM comments WHERE id = ?")
            .bind(String(body.parent_id).slice(0, 40))
            .first();
          if (!par) return json(env, { error: "The comment you are replying to no longer exists." }, 404);
          parent_id = par.parent_id || par.id;
        }
        const id = randomId();
        const created_at = Date.now();
        try {
          await env.DB
            .prepare("INSERT INTO comments (id, name, text, created_at, likes, stars, parent_id, ip) VALUES (?, ?, ?, ?, 0, 0, ?, ?)")
            .bind(id, name, text, created_at, parent_id, ip)
            .run();
        } catch {
          // `ip` column missing (migration not run yet): still accept the comment
          await env.DB
            .prepare("INSERT INTO comments (id, name, text, created_at, likes, stars, parent_id) VALUES (?, ?, ?, ?, 0, 0, ?)")
            .bind(id, name, text, created_at, parent_id)
            .run();
        }
        log(env, ctx, req, parent_id ? "reply" : "comment", { id, name, preview: text.slice(0, 120) });
        return json(env, { comment: { id, name, text, created_at, likes: 0, stars: 0, parent_id } }, 201);
      }

      // POST /comments/<id>/<like|unlike|star|unstar>
      const rx = /^\/comments\/([\w-]{1,40})\/(like|unlike|star|unstar)$/.exec(url.pathname);
      if (rx && req.method === "POST") {
        if (!env.DB) return json(env, { error: "Comments are not set up yet." }, 503);
        if (env.RATE_LIMITER_REACT) {
          const ip = req.headers.get("CF-Connecting-IP") || "unknown";
          const { success } = await env.RATE_LIMITER_REACT.limit({ key: "r:" + ip });
          if (!success) return json(env, { error: "Too many requests. Please wait a minute." }, 429);
        }
        const [, id, action] = rx;
        const sql = {
          like:   "UPDATE comments SET likes = likes + 1 WHERE id = ?",
          unlike: "UPDATE comments SET likes = MAX(likes - 1, 0) WHERE id = ?",
          star:   "UPDATE comments SET stars = stars + 1 WHERE id = ?",
          unstar: "UPDATE comments SET stars = MAX(stars - 1, 0) WHERE id = ?",
        }[action];
        await env.DB.prepare(sql).bind(id).run();
        const row = await env.DB.prepare("SELECT likes, stars FROM comments WHERE id = ?").bind(id).first();
        if (!row) return json(env, { error: "Comment not found" }, 404);
        return json(env, row);
      }

      // ===== Admin =====
      if (url.pathname.startsWith("/admin/")) {
        if (!env.ADMIN_PASSWORD) {
          return json(env, { error: "Admin is not set up. Run: npx wrangler secret put ADMIN_PASSWORD" }, 503);
        }
        if (!env.DB) return json(env, { error: "Database is not set up." }, 503);

        if (url.pathname === "/admin/login" && req.method === "POST") {
          const limiter = env.RATE_LIMITER_ADMIN || env.RATE_LIMITER;
          const ip = req.headers.get("CF-Connecting-IP") || "unknown";
          if (limiter) {
            const { success } = await limiter.limit({ key: "a:" + ip });
            if (!success) return json(env, { error: "Too many attempts. Wait a minute." }, 429);
          }
          const { password } = await req.json().catch(() => ({}));
          if (!(await checkPassword(env, password))) {
            log(env, ctx, req, "admin_login_failed");
            return json(env, { error: "Wrong password." }, 401);
          }
          log(env, ctx, req, "admin_login");
          return json(env, { token: await makeToken(env), expiresInHours: ADMIN_SESSION_MS / 3600000 });
        }

        if (!(await isAdmin(env, req))) return json(env, { error: "Please sign in again." }, 401);

        // Overview: settings + a few counts
        if (url.pathname === "/admin/overview" && req.method === "GET") {
          const since = Date.now() - 24 * 3600 * 1000;
          const one = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).first()) || {};
          const up = await one("SELECT COUNT(*) AS n FROM logs WHERE event = 'upload_done' AND ts > ?", since);
          const vis = await one("SELECT COUNT(DISTINCT ip) AS n FROM logs WHERE ts > ?", since);
          const com = await one("SELECT COUNT(*) AS n FROM comments");
          return json(env, { settings: await getSettings(env), domains: await getDomainList(env), limits: LIMITS, stats: { uploads24h: up.n, visitors24h: vis.n, comments: com.n } });
        }

        // Activity log with filters + cursor paging
        if (url.pathname === "/admin/logs" && req.method === "GET") {
          const p = url.searchParams;
          const limit = Math.min(Math.max(Number(p.get("limit")) || 50, 1), 200);
          let sql = "SELECT id, ts, event, ip, country, city, ua, detail FROM logs WHERE 1=1";
          const b = [];
          if (p.get("event")) { sql += " AND event = ?"; b.push(p.get("event")); }
          if (p.get("q")) { sql += " AND (ip LIKE ? OR detail LIKE ?)"; const q = `%${p.get("q").slice(0, 80)}%`; b.push(q, q); }
          if (Number(p.get("before"))) { sql += " AND id < ?"; b.push(Number(p.get("before"))); }
          sql += " ORDER BY id DESC LIMIT ?"; b.push(limit + 1);
          const { results } = await env.DB.prepare(sql).bind(...b).all();
          const more = results.length > limit;
          return json(env, { logs: results.slice(0, limit), more });
        }

        // All comments incl. IP, newest first
        if (url.pathname === "/admin/comments" && req.method === "GET") {
          const p = url.searchParams;
          const limit = Math.min(Math.max(Number(p.get("limit")) || 50, 1), 200);
          const before = Number(p.get("before")) || Date.now() + 1;
          const { results } = await env.DB
            .prepare("SELECT id, name, text, created_at, likes, stars, parent_id, ip FROM comments WHERE created_at < ? ORDER BY created_at DESC LIMIT ?")
            .bind(before, limit + 1)
            .all();
          return json(env, { comments: results.slice(0, limit), more: results.length > limit });
        }

        // Delete a comment (and its replies, if it is a top-level comment)
        if (url.pathname === "/admin/comments/delete" && req.method === "POST") {
          const { id } = await req.json().catch(() => ({}));
          if (!id) return json(env, { error: "Missing id" }, 400);
          const row = await env.DB.prepare("SELECT id, name, text, ip FROM comments WHERE id = ?").bind(String(id)).first();
          if (!row) return json(env, { error: "Comment not found" }, 404);
          const rep = await env.DB.prepare("DELETE FROM comments WHERE parent_id = ?").bind(row.id).run();
          await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(row.id).run();
          log(env, ctx, req, "comment_deleted", {
            id: row.id, author: row.name, author_ip: row.ip, preview: String(row.text).slice(0, 120),
            replies_deleted: rep.meta?.changes ?? 0,
          });
          return json(env, { ok: true, repliesDeleted: rep.meta?.changes ?? 0 });
        }

        // Delete an uploaded file right now (abuse handling)
        if (url.pathname === "/admin/files/delete" && req.method === "POST") {
          const { key } = await req.json().catch(() => ({}));
          if (!validKey(key)) return json(env, { error: "Bad key" }, 400);
          const r = await client(env).fetch(objUrl(env, key), { method: "DELETE" });
          if (!r.ok && r.status !== 404) return json(env, { error: `Storage returned ${r.status}` }, 502);
          log(env, ctx, req, "file_deleted", { key });
          return json(env, { ok: true });
        }

        // Change settings
        if (url.pathname === "/admin/settings" && req.method === "POST") {
          const body = await req.json().catch(() => ({}));
          const writes = [];
          const upsert = (k, v) =>
            env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(k, String(v));
          for (const k of Object.keys(LIMITS)) {
            if (body[k] === undefined) continue;
            const n = Math.round(Number(body[k]));
            const [lo, hi] = LIMITS[k];
            if (!Number.isFinite(n) || n < lo || n > hi) return json(env, { error: `${k} must be between ${lo} and ${hi}.` }, 400);
            writes.push(upsert(k, n));
          }
          if (body.domains !== undefined) {
            const list = parseDomains(body.domains);
            if (list.length > 20) return json(env, { error: "Too many domains (maximum 20)." }, 400);
            const bad = list.find((d) => !DOMAIN_RX.test(d));
            if (bad) return json(env, { error: `"${bad}" is not a valid domain. Use letters, numbers, dots and hyphens only (no underscores), for example files.example.com` }, 400);
            writes.push(upsert("domains", list.join(",")));
          }
          if (!writes.length) return json(env, { error: "Nothing to change." }, 400);
          await env.DB.batch(writes);
          domainCache = { t: 0, list: [] };
          const settings = await getSettings(env);
          const domains = await getDomainList(env);
          log(env, ctx, req, "settings_changed", { ...settings, domains: domains.join(",") });
          return json(env, { settings, domains });
        }

        return json(env, { error: "Not found" }, 404);
      }
    } catch (e) {
      console.log("WORKER_ERROR", url.pathname, e.message);
      const hint = /no such (table|column)/i.test(e.message) ? " Run migrate.sql on your D1 database." : "";
      return json(env, { error: "Server error." + hint }, 500);
    }

    return new Response("OK");
  },

  // Cron: delete files older than 1 hour, and old log rows
  async scheduled(_evt, env) {
    let token = "";
    do {
      const u = new URL(`https://${env.B2_ENDPOINT}/${env.B2_BUCKET}`);
      u.searchParams.set("list-type", "2");
      if (token) u.searchParams.set("continuation-token", token);
      const xml = await (await client(env).fetch(u)).text();
      for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
        const key = /<Key>([\s\S]*?)<\/Key>/.exec(m[1])?.[1]
          ?.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
          .replace(/&quot;/g, '"').replace(/&apos;/g, "'");
        const mod = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(m[1])?.[1];
        if (key && mod && Date.now() - new Date(mod).getTime() > TTL_MS) {
          await client(env).fetch(objUrl(env, key), { method: "DELETE" });
        }
      }
      token = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)?.[1] || "";
    } while (token);

    if (env.DB) {
      try {
        const { logDays } = await getSettings(env);
        await env.DB.prepare("DELETE FROM logs WHERE ts < ?").bind(Date.now() - logDays * 86400000).run();
      } catch (e) {
        console.log("LOG_PURGE_FAILED", e.message);
      }
    }
  },
};
