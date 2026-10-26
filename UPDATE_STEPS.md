# Update steps (do these in order)

1. **Database** (once). Open a terminal in the project folder:
   npx wrangler d1 execute share-comments --remote --file=migrate.sql

2. **Admin password** (pick a long one):
   npx wrangler secret put ADMIN_PASSWORD

3. **Deploy the worker**:
   npx wrangler deploy
   (Keep your real database_id in wrangler.toml. The one in this zip is a placeholder.)

4. **Upload the site files to GitHub**: index.html, admin.html, privacy.html, terms.html,
   and the whole fonts/ folder.

5. Open /admin.html on your site and sign in.

## Ads
The ad code is unchanged. See the notes in the chat about why it was not showing
(underscore in the domain, Brave Shields, Adsterra site approval).
