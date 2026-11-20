---
title: Configuration
description: Environment variables, the data folder, email delivery, Host and Origin checks, and running on podman, SELinux or another port.
---

Every setting is an environment variable, checked once at boot. A bad value stops the server with a message that
says what to fix.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `BASE_URL` | `http://localhost:4000` | The address people and apps use. Links in emails, cookies, the OAuth issuer and the Host check all come from it. An origin only: no path, query or fragment. |
| `ALLOWED_HOSTS` | none | Extra Host names to accept, comma-separated, such as `authwapi` or `host.docker.internal` for an agent in another container. A name without a port means the listening port. |
| `RESEND_API_KEY`, `EMAIL_FROM` | none | Send email through Resend. Both are needed. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | none | Turns on "Continue with Google". Both are needed. In Google Cloud, create a "Web application" OAuth client with the redirect URI `BASE_URL/api/auth/callback/google`. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | none | Turns on "Continue with GitHub". Both are needed. In GitHub's Developer settings, create an OAuth App with the callback URL `BASE_URL/api/auth/callback/github`. |
| `PUID`, `PGID` | `1000` | The user the server runs as. The container's entrypoint gives `/data` to this user. |
| `PORT` | `4000` | Port inside the container. |
| `DATA_DIR` | `/data` | Data folder inside the container. |

Pass them with `-e`, for example `docker run -e BASE_URL=http://localhost:8080 …`.

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
| `outbox/` | Emails, when Resend isn't configured. 0600 files, deleted once they are 24 hours old (checked hourly). |

**To move it:** stop the container, copy the folder, start a container on the new folder. Or, while the server
runs, `docker exec -u 1000 authwapi node src/cli.ts export /data/export-<date>` and `import` it into the new folder before
its server starts (see the README's
[Moving the data folder](https://github.com/Anmolnoor/authwapi#moving-the-data-folder)). Never copy the database
while the server runs.

**Upgrades:** on boot, AuthWAPI applies any new migrations in one transaction, after backing up the database and
secret to `backups/`. If a migration fails, nothing changes and the server stops. A database made by a newer
AuthWAPI is refused.

## Email

| Settings | Result |
| --- | --- |
| `RESEND_API_KEY` and `EMAIL_FROM` set | Sent through [Resend](https://resend.com). Until you verify a domain in Resend, it only delivers to your own Resend account's address. |
| Neither set, `BASE_URL` is localhost | Written to `outbox/`. Open the JSON file to get the link. |
| Neither set, `BASE_URL` is not localhost | The server refuses to start. |

Emails are sent after the response, so a request never waits on the mail provider and the answer is the same
whether or not the account exists. A failed send is written to `logs/app.jsonl`.

## Host and Origin checks

- **Host.** Every request (except `GET /health`) must have a `Host` header equal to `BASE_URL`'s host or a name in
  `ALLOWED_HOSTS`. Anything else gets
  `421 {"error":"unknown_host","host":"…","hint":"Set BASE_URL to the address you use, or add the name to ALLOWED_HOSTS."}`.
  This blocks DNS rebinding, and a port mapping that doesn't match `BASE_URL` fails loudly instead of producing
  broken links.
- **Origin.** A request that sends an `Origin` header must send `BASE_URL`'s origin (or an `ALLOWED_HOSTS` name
  with the same scheme). Anything else gets `403 {"error":"untrusted_origin","origin":"…"}`.
- **Origin with a session cookie.** A `POST` to a Better Auth route under `/api/auth` (not the email-link
  pages) that sends any cookie, such as the session cookie, must send that `Origin`; without it,
  Better Auth answers `403 {"code":"MISSING_OR_NULL_ORIGIN"}` and does nothing. Browsers send it on their own;
  from curl or a script, add `-H 'origin: http://localhost:4000'`. Requests without a cookie (sign-up, sign-in,
  OAuth token calls) don't need one.
- **Network.** Inside the container the server listens on all interfaces. What keeps it on your machine is
  publishing the port on `127.0.0.1` (`-p 127.0.0.1:4000:4000`), as every example here does. Plain `-p 4000:4000`
  listens on every interface and, on Linux, bypasses ufw and firewalld. (Docker Engine before 28.0 also let other
  machines on the same network reach ports published on `127.0.0.1`; use 28.0 or later.)

## Rate limits

Routes under `/api/auth`, and the hosted page forms that call them, are rate-limited per client IP, taken from the
TCP connection. `X-Forwarded-For` is ignored. Too many API requests get `429` with an `X-Retry-After` header in
seconds; the hosted forms show an error page instead. Limits reset when the server restarts. `/health` and pages
you only open (GET) aren't limited.

| Routes (under `/api/auth`) | Limit per IP |
| --- | --- |
| `/sign-in/email`, `/sign-up/email`, `/change-password` | 3 per 10 seconds |
| `/sign-in/magic-link`, `/magic-link/verify` | 5 per minute |
| `/request-password-reset`, `/send-verification-email` | 3 per minute |
| `/oauth2/token` | 20 per minute |
| `/oauth2/authorize` | 30 per minute |
| `/oauth2/revoke` | 30 per minute |
| `/oauth2/userinfo` | 60 per minute |
| `/oauth2/introspect` | 100 per minute |
| Everything else | 100 per 10 seconds |

The email verification form (`POST /api/auth/verify-email`) has its own limits: 20 tries per IP and 5 per account
every 5 minutes. It answers an HTML page with status 429 and no `X-Retry-After`.

## Running on other setups

- **Rootless podman.** Build with `podman build -t authwapi .`. Podman refuses a missing folder, `keep-id` makes the
  container user you, and `:Z` is for SELinux:
  ```bash
  mkdir -p authwapi-data
  podman run -d --name authwapi --userns=keep-id -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data:Z" authwapi
  ```
- **Linux with a user ID other than 1000:** add `-e PUID=$(id -u) -e PGID=$(id -g)`.
- **A different port:** set `BASE_URL` to match, for example
  `-p 127.0.0.1:8080:4000 -e BASE_URL=http://localhost:8080`.
- **SELinux (Fedora, RHEL):** add `:Z` to the volume. Without it the server stops with a "not writable" error.
- **An agent or app in another container:** on Docker Desktop, reach the server at `host.docker.internal:4000`
  and start it with `-e ALLOWED_HOSTS=host.docker.internal`. On Linux, a port published on 127.0.0.1 can't be
  reached from a container, so put both containers on one network
  (`docker network create authwapi-net`, then `--network authwapi-net` on both) and use `http://authwapi:4000`
  with `-e ALLOWED_HOSTS=authwapi`.
- Docker and podman follow a symlink you pass as the host folder (`-v link:/data`); AuthWAPI can only refuse
  symlinks inside the folder it sees.

Exposing AuthWAPI beyond your machine needs HTTPS and Resend. That setup isn't documented yet.
