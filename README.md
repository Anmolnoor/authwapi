# AuthWAPI

> WorkOS-style auth for localhost: one `docker run`, one data folder you can move anywhere, MCP built in.

**Status: early (M1, slice 3 of the [plan](.solofounder/flow.md)).** Works today: hosted sign-in and sign-up
pages, email + password with verification, magic links, password reset, sessions, apps signing users in through
AuthWAPI (OAuth 2.1 / OpenID Connect), the data folder with export/import, migrations and Docker. **Not built yet:** the admin MCP
server, the no-human agent test. Don't put real users on it yet.

The earlier Express + MongoDB learning version is preserved at the `v0.1-learning` tag.

## Quick start

```bash
docker build -t authwapi .
docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" authwapi
curl http://localhost:4000/health        # {"status":"ok"}
open http://localhost:4000               # sign-up / sign-in pages
```

- **Rootless podman** (podman refuses a missing folder; `keep-id` makes the container user you; `:Z` is for SELinux):
  `mkdir -p authwapi-data && podman run -d --name authwapi --userns=keep-id -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data:Z" authwapi`
- **Linux with a different user ID than 1000:** add `-e PUID=$(id -u) -e PGID=$(id -g)`.
- **A different port:** set `BASE_URL` to match, e.g. `-p 127.0.0.1:8080:4000 -e BASE_URL=http://localhost:8080`.
  A request for a host that isn't `BASE_URL` (or `ALLOWED_HOSTS`) gets `421 unknown_host`.
- **SELinux (Fedora, RHEL):** add `:Z` to the volume. Without it the server stops with a "not writable" error.
- Docker and podman follow a symlink you pass as the host folder (`-v link:/data`); AuthWAPI can only refuse
  symlinks inside the folder it sees.

The port is published on `127.0.0.1` only. Exposing AuthWAPI beyond your machine needs HTTPS and Resend; that
setup isn't documented yet.

## The data folder

Everything AuthWAPI keeps is in the folder you mount at `/data`:

| Path | What |
| --- | --- |
| `authwapi.db` | SQLite database (journal mode `DELETE`, safe on Docker Desktop bind mounts) |
| `secret` | Instance secret, created on first boot, mode 0600. Keep it with the database. |
| `schema.sql` | The current schema, rewritten on every boot |
| `migrations/` | Copies of the migrations applied to this database |
| `backups/` | A copy of the database and secret taken before each upgrade migration |
| `logs/app.jsonl` | JSON-lines log. Never contains tokens or sign-in links. |
| `outbox/` | Emails, when Resend isn't configured (see below). 0600 files, deleted after 24 hours. |

**To move it**, see [Moving the data folder](#moving-the-data-folder).

## Moving the data folder

Never copy `authwapi.db` while the server runs: a copy taken mid-write can be corrupt. Two safe ways:

**Stop, copy, start.** Stop the container, copy the whole folder (`cp -a`, keeping file modes), start a container
on the new folder.

**Export, then import** (no downtime for the old instance). `export` copies the database through SQLite's online
backup API, one consistent snapshot, plus the `secret`, into a new or empty folder (0700, files 0600). It works
while the server runs:

```bash
docker exec authwapi node src/cli.ts export /data/export-$(date +%Y%m%d)
mv authwapi-data/export-$(date +%Y%m%d) ./authwapi-export    # it lands inside the mounted folder; move it out
```

`import` restores an export into a data folder that has no database yet, after checking
`PRAGMA integrity_check`; run it before the new server starts, then start the server on that folder (it applies
any newer migrations on boot):

```bash
mkdir -p new-data
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/new-data:/data" -v "$PWD/authwapi-export:/import:ro" \
  --entrypoint node authwapi src/cli.ts import /import
docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/new-data:/data" authwapi
```

Rootless podman: use `--userns=keep-id` instead of `--user`, and add `:Z` to both volumes on SELinux. Without
Docker: `DATA_DIR=./authwapi-data node src/cli.ts export ./authwapi-export`, and
`DATA_DIR=./new-data node src/cli.ts import ./authwapi-export`.

An export holds only `authwapi.db` and `secret`, which is everything the new folder needs, and the secret
means it must be kept as private as the data folder. Left behind: `schema.sql` and `migrations/` (rebuilt on
boot), `backups/` (this instance's pre-upgrade copies), `logs/` (this instance's history) and `outbox/` (sign-in
links that expire; an export shouldn't carry working credentials). Import refuses a folder that already has a
database or secret, so it never overwrites data or runs under a live server.

## Email

| Setting | Result |
| --- | --- |
| `RESEND_API_KEY` + `EMAIL_FROM` set | Sent through [Resend](https://resend.com). Until you verify a domain in Resend, it only delivers to your own Resend account's address. |
| Neither set, `BASE_URL` is localhost | Written to `outbox/` (open the JSON file to get the link) |
| Neither set, `BASE_URL` is not localhost | The server refuses to start |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `BASE_URL` | `http://localhost:4000` | The address people and apps use. Links, cookies and the Host check all come from it. Origin only, no path. |
| `ALLOWED_HOSTS` | — | Extra Host names to accept, comma-separated, e.g. `authwapi` or `host.docker.internal` for an agent in another container |
| `RESEND_API_KEY`, `EMAIL_FROM` | — | Resend delivery (both needed) |
| `PUID`, `PGID` | `1000` | User the server runs as; the entrypoint gives `/data` to this user |
| `PORT` | `4000` | Port inside the container |
| `DATA_DIR` | `/data` | Data folder inside the container |

## Pages

Server-rendered, no JavaScript: `/` · `/sign-in` (password or "email me a link") · `/sign-up` · `/forgot-password`
· `/reset-password` · `/consent` (an app asking for access) · `/signed-out`.

- **Verifying an email asks for the password you chose at sign-up.** Opening the link only shows that form, so
  someone who signed up with *your* address can't get in when you click it: you won't know their password, and
  "Forgot password?" replaces it and ends every session.
- **A magic link asks "Sign in as you@example.com?"** before it signs you in, so an email scanner that opens
  links can't use it up, and a link someone else sent you can't sign you in without you seeing whose it is.

## Apps (OAuth 2.1 / OpenID Connect)

AuthWAPI is the identity provider. Issuer: your `BASE_URL`. Discovery:
`BASE_URL/.well-known/openid-configuration` (keys at `/api/auth/jwks`).

```bash
docker exec authwapi node src/cli.ts clients create --name "My app" --redirect-uri https://myapp.example/callback [--resource https://api.myapp.example]
docker exec authwapi node src/cli.ts clients list
```
The client secret is printed once and stored hashed. Plain `http://` redirect URIs are allowed only on loopback.

- Authorization code flow with PKCE (S256, required). Scopes: `openid`, `email`, `offline_access`.
- ID token: `aud` = your client ID; `sub`, plus `email` and `email_verified` when you asked for `email`.
- Access tokens last 15 minutes. Pass `resource=<api>` on authorize and token to get a JWT with `aud` = that
  API (the client must be registered for it); verify signature, `iss` and `aud` against the JWKS. Refresh tokens
  rotate.
- A JWT stays valid until it expires even after sign-out; use the introspection endpoint when revocation must be
  instant (it reports tokens issued before the revocation inactive; so does userinfo). Signing out, ending the
  session through the OIDC end-session endpoint (`id_token_hint` works for CLI clients), revoking sessions,
  changing the password with `revokeOtherSessions`, or resetting the password revokes every refresh token the
  user has, for every app.
- Send `resource` on the token request only if it was on the authorization request (`invalid_target` otherwise).
  A `claims` request may name `email`/`email_verified` only with the `email` scope.

## API

Auth routes are [Better Auth](https://better-auth.com)'s, under `/api/auth`: `POST /sign-up/email`,
`POST /sign-in/email`, `POST /sign-out`, `GET /get-session`, `POST /request-password-reset`,
`POST /reset-password`, `POST /sign-in/magic-link`, and the OAuth endpoints under `/oauth2/`. The links in
emails (`/api/auth/verify-email`, `/api/auth/magic-link/verify`) are pages: GET shows a form, POST acts.
Browser-style requests must send an `Origin` equal to `BASE_URL`.

**Magic links** (`POST /api/auth/sign-in/magic-link` with `{"email", "callbackURL"}`): sign in an existing
account only, never create one. The link works once, for 5 minutes, and is stored hashed. For an email with no
account the answer is the same but nothing is sent, and one address gets at most one link a minute. A magic link
also verifies the email; any password set before it was verified is removed (use password reset to set one).
`callbackURL` (and `newUserCallbackURL`, `errorCallbackURL`) must be on `BASE_URL` or an `ALLOWED_HOSTS` name.

**Email delivery** runs in the background, so a request never waits on the mail provider, and the answer is the
same whether or not the account exists. A failed send is written to `logs/app.jsonl`.


## Development

Node 22.18+ runs the TypeScript directly; there's no build step. On a Linux machine without a C++ compiler,
`npm ci` fails building better-sqlite3 even though it ships a ready-made binary: use `npm ci --ignore-scripts`
(the Docker image is unaffected).

```bash
npm install
npm test            # node --test: everything, against real servers on temp folders
scripts/container-check.sh   # Linux: builds the image, checks rootful/rootless, SELinux, refusals, 50 kill cycles
npm run typecheck   # tsc, type check only
DATA_DIR=./.data BASE_URL=http://localhost:4000 HOST=127.0.0.1 npm start
```

**Schema changes:** change the Better Auth config in `src/auth.ts`, then run
`node scripts/new-migration.ts <name>`. It applies the existing migrations to a fresh database and writes
whatever Better Auth still needs as the next `migrations/NNNN_<name>.sql`. A test fails if the committed
migrations don't match the config.

## License

MIT
