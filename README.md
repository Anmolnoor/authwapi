# AuthWAPI

> WorkOS-style auth for localhost: one `docker run`, one data folder you can move anywhere, MCP built in.

**Status: early (M1, slice 1 of the [plan](.solofounder/flow.md)).** Works today: email + password
sign-up with email verification, sign-in, sign-out, password reset, sessions, the data folder, migrations
and Docker. **Not built yet:** magic links, hosted login pages, the OAuth/OIDC provider for apps, the
admin MCP server, export/import. Don't put real users on it yet.

The earlier Express + MongoDB learning version is preserved at the `v0.1-learning` tag.

## Quick start

```bash
docker build -t authwapi .
docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" authwapi
curl http://localhost:4000/health        # {"status":"ok"}
```

- **Rootless podman** (podman refuses a missing folder; `keep-id` makes the container user you; `:Z` is for SELinux):
  `mkdir -p authwapi-data && podman run -d --name authwapi --userns=keep-id -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data:Z" authwapi`
- **Linux with a different user ID than 1000:** add `-e PUID=$(id -u) -e PGID=$(id -g)`.
- **A different port:** set `BASE_URL` to match, e.g. `-p 127.0.0.1:8080:4000 -e BASE_URL=http://localhost:8080`.
  A request for a host that isn't `BASE_URL` (or `ALLOWED_HOSTS`) gets `421 unknown_host`.

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

**To move it:** stop the container, copy the folder, start a container on the new folder. Never copy the
database while the server runs.

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

## API

Auth routes are [Better Auth](https://better-auth.com)'s, under `/api/auth`:
`POST /sign-up/email`, `POST /sign-in/email`, `POST /sign-out`, `GET /get-session`, `GET /verify-email`,
`POST /request-password-reset`, `POST /reset-password`. Browser-style requests must send an `Origin` equal to
`BASE_URL`.

## Development

Node 22.18+ runs the TypeScript directly; there's no build step.

```bash
npm install
npm test            # node --test: config, migrations, and the full email flow against a real server
npm run typecheck   # tsc, type check only
DATA_DIR=./.data BASE_URL=http://localhost:4000 HOST=127.0.0.1 npm start
```

**Schema changes:** change the Better Auth config in `src/auth.ts`, then run
`node scripts/new-migration.ts <name>`. It applies the existing migrations to a fresh database and writes
whatever Better Auth still needs as the next `migrations/NNNN_<name>.sql`. A test fails if the committed
migrations don't match the config.

## License

MIT
