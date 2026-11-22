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

## 0.3.0 → 0.3.1

0.3.1 changes how the hosted pages look. It has no migrations and no API, protocol, email or dependency changes.
Going back to 0.3.0 needs no backup: stop 0.3.1 and start 0.3.0 on the same data folder (tested).

**What changes for an operator:**

- **New look.** Every hosted page has new markup, class names and styles. If a reverse proxy injects CSS into the
  pages, or a script reads them, check it again: the markup is not an API and can change in any release.
- **Some forms start collapsed.** On `/sign-in`, SSO and the magic link are each behind a disclosure (`<details>`:
  "Sign in with SSO", "Email me a sign-in link"). On `/two-factor`, the backup code form is behind "Use a backup
  code". A disclosure is open when the page comes back from its own form. Browser automation that fills those fields
  must open the disclosure first.
- **The home page's title** is "Welcome" when signed out and "Your account" when signed in (it was "AuthWAPI").
- **Accessibility:** links inside text are underlined, field borders and the dark-mode link and focus colors meet
  WCAG AA contrast, a focused field has a solid outline, and the passkey status line is announced by screen
  readers.

## 0.2.0 → 0.3.0

0.3.0 is the first published image (`ghcr.io/anmolnoor/authwapi:0.3.0`). 0.2.0 was never tagged or published, so
this section is for a data folder made by an image built from source while `package.json` said 0.2.0. Those builds
span several snapshots: later ones already have some of the migrations and features below. Boot applies only the
migrations a folder is missing, and keeps any admin keys and roles it already has.

**Migrations** (each applied on boot if the folder doesn't have it yet, after the backup above): `0004_admin_mcp` (admin MCP keys), `0005_signin_methods`
(2FA and passkeys), `0006_orgs_admin` (organizations, roles, bans, impersonation), `0007_sso` (SSO providers),
`0008_sso_needs_owner` (triggers that keep an owner on every organization with SSO providers) and
`0009_totp_last_used_step` (the last TOTP step used, so a code works once). An image older
than 0.3.0 won't start on the upgraded folder; restore the backup to go back.

**New, all optional:** `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET`
turn on "Continue with Google/GitHub". Set both of a pair or neither: half a pair stops the server. See the README
for the redirect URIs. A Google or GitHub sign-in joins an existing account with the same email only
if the provider says the email is verified and the AuthWAPI account's email is verified too; otherwise it's refused.

**What changes for an operator:**

- **Admin MCP at `BASE_URL/mcp`.** If the folder never had a bootstrap key (a build from before the admin MCP), the
  first boot writes a one-time `bootstrap-admin-key` (mode 0600, valid 24 hours) into the data folder. Use it to mint a write key, or ignore it. If it's lost or expired:
  `docker exec -u 1000 authwapi node src/cli.ts bootstrap-key`. Admin calls are logged to `logs/audit.jsonl`.
  `/mcp` is served wherever `BASE_URL` is reachable: block it at your reverse proxy if you don't use it.
- **Site admins.** On a folder from before admin roles, no user is an admin after the upgrade; the `set_role` MCP
  tool (write key) makes one. An admin
  uses Better Auth's routes under `/api/auth/admin/` to ban users (a banned user can't sign in), impersonate (never
  an admin or an organization owner or admin; written to `logs/audit.jsonl`), set passwords, revoke sessions and
  remove users.
- **New CLI commands:** `bootstrap-key`, `export <dir>` / `import <dir>` (move a data folder), and
  `resource add|link|unlink` (protect your own MCP servers).
- **Two-factor authentication** is opt-in per user. On an account that has it, every first step (password, magic
  link, Google, GitHub, SSO) needs the second factor before any session, consent or authorization code; API clients that
  sign users in must handle `{"twoFactorRedirect": true}`. Turning it on signs out the user's other sessions,
  revokes their refresh tokens and removes their passkeys. A TOTP code works once, counted from the first code accepted after the
  upgrade: reusing a code, or sending one from an earlier 30-second step than the last code accepted, is refused
  (the API answers `401 TOTP_CODE_ALREADY_USED`; the hosted form says the code was already used). That includes the
  code that turned 2FA on, and a right code refused for another reason (unless the sign-in is out of attempts or
  expired). A sign-in keeps its challenge, so waiting for the next code and entering it on the same form works.
- **Passkeys** need `BASE_URL` on a hostname: `http://localhost:4000` works, `http://127.0.0.1:4000` doesn't.
- **Organizations** can't be created over HTTP; only the `create_org` MCP tool creates one. Apps can ask for the
  new `organization` scope.
- **Pages CSP** is now `frame-ancestors 'none'; script-src 'self'; base-uri 'none'`. If a proxy injects inline
  scripts into AuthWAPI's pages, they'll be blocked.
- **Error page.** Better Auth's default error destination for a browser is now the hosted `/error?error=<code>`
  (HTTP 400; before: Better Auth's own page at `/api/auth/error`, or `/?error=` in production), and
  `/api/auth/error` redirects there. Hosted Google, GitHub and SSO sign-ins still return errors to `/sign-in`. The
  page shows only codes it knows and never `error_description`, so an app can't rely on that text reaching the
  person.
- **Logout pages.** The RP-initiated logout pages of `/api/auth/oauth2/end-session` are AuthWAPI pages now; Better
  Auth's markup (its `data-oidc-logout-*` attributes) no longer reaches the browser. Status codes, cookies, JSON
  answers and redirects are unchanged.
- **Hosted pages.** `/two-factor/setup` shows a QR code (new dependency `lean-qr`), `/sign-in` names the app
  during an app's sign-in, a signed-out invitee is offered sign-up as well as sign-in, and links are readable in
  dark mode.

**SSO per organization (OIDC and SAML).** New dependencies: `@better-auth/sso`, plus `samlify` and
`@xmldom/xmldom` for SAML. Setup and the full rules are in the README and the site's SSO page.

- Providers are registered and deleted only with the MCP tools `register_sso_provider` / `list_sso_providers` /
  `delete_sso_provider` or the CLI `sso register|bind|list|delete`, as the organization's owner, whose email must be
  verified. Better Auth's HTTP routes that change providers answer 404. To change a provider, delete it and
  register it again.
- OIDC endpoints must be `https://` and publicly routable. A SAML IdP's SSO URL must be `https://` (plain `http`
  only for a loopback test IdP on a trusted origin), and registering a SAML provider needs an `https` `BASE_URL`
  unless `BASE_URL` is loopback (`saml_needs_https` otherwise).
- The SAML ACS route (`/api/auth/sso/saml2/sp/acs/<providerId>`) accepts a browser POST from the IdP's origin;
  every other route still refuses an Origin that isn't `BASE_URL`'s or in `ALLOWED_HOSTS`.
- Client secrets and SAML configuration are stored unencrypted in the database, like the rest of the data folder.

**Behavior changes that come with SSO:**

- An organization owner needs a verified email: an unverified user can't be made one (`create_org`, a role change
  to `owner`).
- An organization with SSO providers can't lose its last owner (remove, leave or demote is refused; the database
  enforces it). It can't be deleted, nor can the user who registered its providers, until the providers are deleted.
- The first proof that someone holds an unverified account's mailbox (a magic link, a password reset, the verify
  page, or an admin setting `emailVerified: true`) removes, in the same transaction, everything set up before it:
  linked sign-ins (SSO, Google/GitHub, any other password), sessions, 2FA, passkeys, OAuth tokens and consents,
  unused authorization codes and organization memberships, except a sole owner's membership in an organization
  that has SSO providers, so it keeps an owner. This matters most for accounts SSO created, whose email
  stays unverified.
- `/admin/update-user` refuses an `emailVerified` that isn't `true` or `false` (`INVALID_EMAIL_VERIFIED`).
