# Moving to a new domain (no command line needed)

Your index.html and admin.html never contain the domain (they talk to the workers.dev
address, which does not change). The domain only matters in these places:

| Where                  | What to do                                          |
|------------------------|-----------------------------------------------------|
| Admin page > Settings  | add the new domain to "Allowed websites"            |
| Domain registrar (DNS) | point the new name at GitHub                        |
| GitHub > Settings > Pages | set the new custom domain, tick Enforce HTTPS    |
| Adsterra               | add the new domain (new ad code only if they give it) |

Backblaze needs nothing if its CORS rule is "share with every origin".

## Steps (about 15 minutes, plus waiting for DNS)

1. Buy the new domain a few weeks before the old one expires.

2. Open your CURRENT site's /admin.html, sign in, go to Settings.
   In "Allowed websites" type the new domain on its own line, e.g.  files.NEWDOMAIN.com
   Click Save settings. (Do this first, so nothing breaks at the moment of switching.)

3. At the registrar, add a DNS record for the new domain:
   - Subdomain (easiest):  CNAME   host: files   value: unixpected.github.io.
   - Bare domain instead:  four A records on @ :
       185.199.108.153  185.199.109.153  185.199.110.153  185.199.111.153

4. GitHub repo > Settings > Pages > Custom domain: type the new domain and Save.
   Wait for "DNS check successful", then tick "Enforce HTTPS" when it becomes available
   (up to ~15 minutes). From now on the old domain stops serving the site.

5. Open the new address, press Ctrl+Shift+R, and test a comment, an upload and /admin.html.
   (If you forgot step 2, /admin.html on the new domain still lets you sign in, so you can
   add the domain there and refresh.)

6. Adsterra: add the new domain as a site and wait for approval. If they give you new code,
   replace the <script src="...invoke.js"> line and the container id in index.html (both
   contain the same long id) and upload index.html to GitHub.

7. Later, you can delete the old domain from your Adsterra account and registrar.

## Changing the admin password without a command line
Cloudflare dashboard > Workers & Pages > share-file-online > Settings >
Variables and Secrets > ADMIN_PASSWORD > Edit. (Menu names can change slightly.)

## Updating the worker without a command line (one-time setup)
Cloudflare dashboard > Workers & Pages > share-file-online > Settings > Builds > Connect,
choose your GitHub repo and branch (main). The worker name must stay "share-file-online".
After that, every time you upload worker.js or wrangler.toml to GitHub, Cloudflare redeploys
the worker by itself. Check the Builds tab if something looks wrong.

## Keep safe (you cannot read these back from Cloudflare)
Save in a password manager: ADMIN_PASSWORD, B2_KEY_ID, B2_APP_KEY, your Cloudflare,
Backblaze, GitHub and registrar logins. Your database id is already in wrangler.toml.

## Setting up from nothing on a new Cloudflare account (needs the command line once)
   npm install
   npx wrangler login
   npx wrangler d1 create share-comments       (put the id into wrangler.toml)
   npx wrangler d1 execute share-comments --remote --file=schema.sql
   npx wrangler secret put B2_KEY_ID
   npx wrangler secret put B2_APP_KEY
   npx wrangler secret put ADMIN_PASSWORD
   npx wrangler deploy
