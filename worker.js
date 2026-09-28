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
      const head = await client(env).fetch(objUrl(env, key), { method: "HEAD" });
      if (!head.ok) return json(env, { error: "Upload not found" }, 404);
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
