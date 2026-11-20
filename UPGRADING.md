# Upgrading AuthWAPI

## How an upgrade works

Stop the container, start the new image on the same data folder. On boot, AuthWAPI applies any new migrations
from `migrations/` before it serves a request:

1. **Backup first.** If the database already has migrations and new ones are pending, it copies the database and
   the secret to `backups/before-<first pending migration>-<timestamp>.db` and `.secret`, and logs
   `backed up database before migrating`. A brand-new data folder has nothing to back up.
2. **All or nothing.** Every pending migration runs in one transaction. If one fails, the whole upgrade is rolled
   back and the container refuses to start:

   ```
   AuthWAPI failed to start: Migration <name> failed, so the whole upgrade was rolled back; the database is unchanged. A backup from before the upgrade is at <data>/backups/before-<...>.db.
     cause: <the SQLite error>
   ```

   The database is left as it was, so the previous image still runs on it. Report the error before retrying.
3. After a successful upgrade, `migrations/` in the data folder holds a copy of every applied migration and
   `schema.sql` is rewritten.

**Never run an older image on a newer data folder.** If the database has a migration the image doesn't know,
the container refuses to start:

```
AuthWAPI failed to start: Database has migration <name>, which this image doesn't know: it was made by a newer AuthWAPI.
```

To go back to an older version after an upgrade, stop the container and restore the backup: copy
`backups/before-<...>.db` over `authwapi.db` and `backups/before-<...>.secret` over `secret`, delete the copies
of the newer migrations from `migrations/`, then start the older image. Anything written since the upgrade is
lost.

## 0.2.0 → 0.3.0

**Migrations** (applied on boot, after the backup above): `0004_admin_mcp` (admin MCP keys), `0005_signin_methods`
(2FA and passkeys), `0006_orgs_admin` (organizations, roles, bans, impersonation). An image older than 0.3.0 won't
start on the upgraded folder; restore the backup to go back.

**New, all optional:** `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET`
turn on "Continue with Google/GitHub". Set both of a pair or neither: half a pair stops the server. See the README
for the redirect URIs.

**What changes for an operator:**

- **Admin MCP at `BASE_URL/mcp`.** The first 0.3.0 boot writes a one-time `bootstrap-admin-key` (mode 0600, valid
  24 hours) into the data folder. Use it to mint a write key, or ignore it. If it's lost or expired:
  `docker exec -u 1000 authwapi node src/cli.ts bootstrap-key`. Admin calls are logged to `logs/audit.jsonl`.
- **New CLI commands:** `bootstrap-key`, `export <dir>` / `import <dir>` (move a data folder), and
  `resource add|link|unlink` (protect your own MCP servers).
- **Two-factor authentication** is opt-in per user. On an account that has it, every first step (password, magic
  link, Google, GitHub) needs the second factor before any session, consent or authorization code; API clients that
  sign users in must handle `{"twoFactorRedirect": true}`. Turning it on signs out the user's other sessions,
  revokes their refresh tokens and removes their passkeys.
- **Passkeys** need `BASE_URL` on a hostname: `http://localhost:4000` works, `http://127.0.0.1:4000` doesn't.
- **Organizations** can't be created over HTTP; only the `create_org` MCP tool creates one. Apps can ask for the
  new `organization` scope.
- **Pages CSP** is now `frame-ancestors 'none'; script-src 'self'; base-uri 'none'`. If a proxy injects inline
  scripts into AuthWAPI's pages, they'll be blocked.

SSO lands in a later section.
