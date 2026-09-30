import { AwsClient } from "aws4fetch";

const MAX_BYTES = 200 * 1024 * 1024;
const TTL_MS = 60 * 60 * 1000; // 1 hour

const cors = (env) => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
});
const json = (env, data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...cors(env) },
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

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    // ALLOWED_ORIGIN may be a comma-separated list (GitHub Pages + your domain)
    const allowed = env.ALLOWED_ORIGIN.split(",").map((s) => s.trim());
    const origin = req.headers.get("Origin");
    env = { ...env, ALLOWED_ORIGIN: allowed.includes(origin) ? origin : allowed[0] };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(env) });

    // 1) Browser asks for an upload URL
    if (url.pathname === "/init" && req.method === "POST") {
      // Abuse protection: per-IP rate limit (binding defined in wrangler.toml)
      if (env.RATE_LIMITER) {
        const ip = req.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.RATE_LIMITER.limit({ key: ip });
        if (!success) return json(env, { error: "Too many uploads. Please wait a minute and try again." }, 429);
      }
      const { name, size } = await req.json().catch(() => ({}));
      if (!Number.isFinite(size) || size <= 0) return json(env, { error: "Invalid size" }, 400);
      if (size > MAX_BYTES) return json(env, { error: "File exceeds 200MB" }, 413);
      const id = randomId();
      const key = `${id}/${cleanName(name)}`;
      const uploadUrl = await presign(env, "PUT", key, 900);
      return json(env, { key, uploadUrl });
    }

    // 2) Browser says upload finished -> verify size, return share link
    if (url.pathname === "/done" && req.method === "POST") {
      const { key } = await req.json().catch(() => ({}));
      if (!key || key.split("/").length !== 2) return json(env, { error: "Bad key" }, 400);
      // Retry a few times: the object may not be visible instantly, and B2 can return transient errors
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
      if (size > MAX_BYTES) {
        await client(env).fetch(objUrl(env, key), { method: "DELETE" });
        return json(env, { error: "File exceeds 200MB" }, 413);
      }
      const link = `${url.origin}/d/${key.split("/").map(encodeURIComponent).join("/")}`;
      return json(env, { link, expiresInMinutes: 60 });
    }

    // 3) Download link -> checks age -> redirects to short-lived signed URL
    if (url.pathname.startsWith("/d/") && req.method === "GET") {
      const key = decodeURIComponent(url.pathname.slice(3));
      if (key.split("/").length !== 2) return new Response("Not found", { status: 404 });
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
      return Response.redirect(signed, 302);
    }

    // ===== Public comments (stored in D1 database bound as env.DB) =====
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
      if (env.RATE_LIMITER) {
        const ip = req.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.RATE_LIMITER.limit({ key: "c:" + ip });
        if (!success) return json(env, { error: "Too many requests. Please wait a minute." }, 429);
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
      await env.DB
        .prepare("INSERT INTO comments (id, name, text, created_at, likes, stars, parent_id) VALUES (?, ?, ?, ?, 0, 0, ?)")
        .bind(id, name, text, created_at, parent_id)
        .run();
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

    return new Response("OK");
  },

  // Cron: delete everything older than 1 hour
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
  },
};
