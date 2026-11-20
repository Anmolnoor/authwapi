# Flow: AuthWAPI → "WorkOS for localhost" (rev 5, 2026-11-19)

## Context
- Domain: software product (pivot of an existing learning project)
- Project: AuthWAPI, Express 4 + Mongo, ~1.3k LOC. Bugs 1–5 from `gap-analysis.md` fixed on branch `workos-project-gap-analysis` with 10 regression tests (uncommitted).
- User's goal: one `docker run` gives an AI agent or developer a local auth server with login/register, magic links via Resend, SSO and other WorkOS-style features, plus MCP built in. Everything it keeps (SQLite database, logs, schema) sits in one folder they can move anywhere.
- Facts checked live on 2026-11-19 (sources in "Evidence").
- Rev 5 applies council round 4 (plan: Opus 8.5, Sol 8, Terra 9; fixes: Opus 9, Sol 10, Terra 10). Rev 4 applied council round 3 (plan: Opus 7.5, Sol 7, Terra 8). Rev 3 applied round 2 (Opus 8, Sol 7.5, Terra 7). Rev 2 applied council round 1. Scores for the plan: Claude Opus 5.5 6/10, GPT-6.2 Sol 5.5/10, GPT-6.1 Terra 6/10. All three said the demand gate came too late and before the differentiator. They also flagged four gaps: no app-integration contract, the log email mode leaking credentials, the server listening on all interfaces, and no upgrade path before the first public image.

## Product in one paragraph
```
docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" ghcr.io/anmolnoor/authwapi
```
That command starts an auth server with no other setup. `./authwapi-data` holds:
- `authwapi.db` (SQLite)
- `logs/app.jsonl` and `logs/audit.jsonl` (no tokens or links, ever)
- `outbox/` (local-mode emails)
- `schema.sql` (current schema, generated)
- `migrations/` (applied history)
- `secret` (generated on first boot)
- `bootstrap-admin-key` (one-time, expires)

Apps sign users in through AuthWAPI as an OAuth 2.1 / OIDC provider (authorization code + PKCE, hosted login pages), and verify tokens through JWKS. AI agents administer it through a built-in MCP server. Later, users' own MCP servers can use the same OAuth provider.

## Key decisions (defaults; user can override)
| # | Decision | Default | Why |
|---|---|---|---|
| D1 | Core | **Better Auth 1.7.x** (MIT), versions pinned exactly | It ships the login methods, SSO and OAuth provider. A hand-built core produced 10 bugs in 1.3k lines. Our value is packaging plus the agent experience. |
| D2 | Web framework | **Hono** on `@hono/node-server` | Better Auth and MCP SDK v2 both take web-standard Requests, so there's no body-parser ordering trap. |
| D3 | Runtime | **Node 26 LTS**, TypeScript, ESM | Active LTS since 2026-10-28; Better Auth is ESM-only. |
| D4 | SQLite driver | **better-sqlite3** | Better Auth's recommended driver; `node:sqlite` is still a release candidate in Node 26. |
| D5 | Journal mode | **`journal_mode=DELETE`**, one writer process | WAL needs shared memory on one host and has corrupted databases on macOS Docker Desktop bind mounts. Auth write volume is low. |
| D6 | Where the data lives | **Bind-mounted host folder** (the user's ask), plus `authwapi export <dir>` / `import <dir>` using SQLite's backup API | The council split: Opus preferred a named volume plus export, Sol a bind mount. A bind mount matches "a folder I can move". DELETE journal removes the WAL risk. Export/import is the safe way to move data while the server runs. The rule: stop the container or use export, never copy a live database. |
| D7 | Network exposure | Quick start publishes **`127.0.0.1:4000` only**. `BASE_URL` defaults to `http://localhost:4000` and is the one source for links, cookies, issuer and passkey RP ID. Host and Origin are validated against it, plus an explicit `ALLOWED_HOSTS` list. **Agents inside a container:** on Docker Desktop they use `host.docker.internal:4000` with `ALLOWED_HOSTS=host.docker.internal`. On Linux, a port published on 127.0.0.1 can't be reached from the bridge, so both containers join a user-defined network (`--network authwapi-net`). The quick start names the server container `authwapi`, so the agent reaches `http://authwapi:4000` with `ALLOWED_HOSTS=authwapi`. | Docker's `-p 4000:4000` listens on every interface and bypasses ufw/firewalld on Linux. Exposing AuthWAPI beyond localhost is a separate, documented HTTPS profile. |
| D8 | Email | `RESEND_API_KEY` set → **Resend** (any `BASE_URL`, so localhost can test real delivery). Not set and loopback `BASE_URL` → **outbox** `/data/outbox/` (0600, deleted after 24h, never in logs or MCP). Not set and non-loopback → boot fails. The chosen mode is logged at boot. | Verification, reset and magic links are credentials. Resend's test domain only delivers to your own account address, so a real second user needs a verified domain. |
| D9 | App integration | M1 makes AuthWAPI an **OAuth 2.1 / OIDC provider** (`@better-auth/oauth-provider` + `jwt`). Contract: issuer = `BASE_URL`. **ID token:** `aud` = client ID; the app checks it once at sign-in. **Access token (JWT):** `aud` = the resource (API) it's for; APIs verify signature + `aud` through JWKS. A JWT stays valid until it expires (15 min) even after sign-out, so APIs that need instant revocation use the introspection endpoint. Sign-out revokes the session **and explicitly revokes every refresh token for that user and client, including `offline_access` ones** (Better Auth's built-in sign-out leaves those valid). The `jwt` plugin runs in OAuth-provider mode from M1, with session-JWT issuance turned off as the docs require. M1 claims: `sub`, `email`, `email_verified`; `org_id`/`roles` arrive in M3. | Without this, no app can receive the signed-in user. `@better-auth/mcp` builds on the same provider (the docs say not to register both), so the M5 MCP OAuth work extends it rather than adding a second provider. |
| D10 | Admin trust | The bootstrap key (file in `/data`, 24h expiry) is accepted by exactly one MCP tool, `mint_agent_key(scope)`. It is consumed on first success. A write-scoped agent key can also call that tool. The new key is returned once in that tool's result and stored only as a hash. Agent keys are `read` or `write` scoped and revocable; every admin call writes an audit line. MCP tool output is treated as data, never as instructions. | The admin MCP is a remote control for the whole auth server. Logs contain attacker-controlled strings (names, user agents) that could prompt-inject an agent. |
| D13 | Data folder ownership | **Rootful Docker / Docker Desktop:** the entrypoint starts as root only to create `/data` and `chown` it to `PUID:PGID` (default 1000:1000), then drops to that user with `setpriv` before Node starts. **Rootless podman:** documented command `mkdir -p authwapi-data && podman run --userns=keep-id -v "$PWD/authwapi-data:/data:Z" …` (`:Z` relabels the folder for SELinux on Fedora) (podman rejects a missing bind folder, and `keep-id` makes the container user the host user). **Started as non-root:** the entrypoint skips `chown`, checks `/data` is writable, and stops with a clear message if not. | Rootful Docker creates a missing bind folder as root, and Docker Desktop maps ownership to the host user. Under rootless podman, container UID 1000 maps to a subordinate host UID, so without `keep-id` the host couldn't read the 0600 outbox. |
| D14 | Migrations | Each release generates its migration (`node scripts/new-migration.ts <name>`, which calls Better Auth's `getMigrations`, the function behind `auth generate`): apply migrations `0001…N-1` to a fresh SQLite, diff against *that* database, and commit the SQL as `migrations/NNNN_name.sql`. CI also checks that a fresh install and an upgrade from every earlier release end at the same schema. Our runner applies the files in order, each in a transaction, after a backup. It records each one in `_authwapi_migrations` and copies the file to `/data/migrations/`. | `auth generate` diffs against the connected database, so it must start from the previous release's schema. Generating against an empty database emits create-table SQL that fails on upgrade. |
| D11 | Legacy code | Commit the bug fixes, tag `v0.1-learning`, then replace `src/` on a pivot branch | Keeps the learning history; no dual codebase. |
| D12 | Postgres / MySQL | **Not now.** `schema.sql` comes from the `auth` CLI, so a later move is possible | Build it when someone asks. |

## Competition (corrected)
- **Pocket ID** (10.4k, BSD) and **Rauthy** (1.5k, Apache) already ship as single-container identity providers on SQLite / embedded SQLite. "One container, one SQLite file" is **not** an edge.
- **Casdoor** (14.9k) markets itself as an "agent-first IAM / MCP gateway". Also in the field: Logto (15.0k), Hanko (9.1k, "alternative to WorkOS"), Zitadel, Keycloak.
- **Better Auth Infrastructure** (paid, by the Better Auth team) adds a dashboard, audit logs, email and SSO onboarding.
- **Our only edge:** agent-first operation. An agent deploys it, bootstraps it and administers it over MCP with no human, on a TypeScript/Better Auth core. The plan tests this first.

## The team
- **Auth security engineer:** sessions, tokens, OAuth provider, SSO; reviews every auth diff.
- **Platform engineer (TypeScript / Better Auth / Hono):** builds the core.
- **Agent-experience engineer:** MCP tool design, `AGENTS.md`, `/llms.txt`, the no-human deploy test.
- **Packaging / SRE:** Docker image, `/data` layout, non-root writes, migrations, export/import, upgrades.
- **Frontend engineer:** hosted pages (sign-in, sign-up, verify, reset, magic link, OAuth consent). Better Auth has none built in, so this is real work.
- **QA tester who uses a real browser:** clicks through hosted pages and email links and counts for themselves.

## Stages

### Stage 0: Close out the learning version (done)
- Bugs 1–5 are fixed with 10 regression tests. Revocation uses a per-user `tokenVersion` with optimistic concurrency (round 1 found a 1-second window in the timestamp check; round 2 found a race between concurrent password saves). The compiled production build was smoke-tested live.
- Fixed in PR #43 and tagged `v0.1-learning`.

### Stage 1: Thin release (M1)
**Progress:** slice 1 built on branch `m1-foundation` (config, data folder, SQLite, migrations runner, Better Auth email + password with verification and reset, outbox/Resend, Host check, Docker entrypoint, 13 tests, container run and 10-cycle kill test). Slice 2 (magic links) built: 5-minute single-use links, stored hashed, existing accounts only (Better Auth would email any address; we skip unknown ones), callbackURL limited to BASE_URL. Review fixes (2 rounds): every email is sent after the response via `setImmediate`, including Better Auth's resend-verification route, which awaits its callback; refused callback values are blanked in the log and other URLs cut to their origin; the outbox uses non-blocking file calls; logging never throws; (same answer and timing for known and unknown accounts; failures logged), links go to the stored address, one link per address per minute, Better Auth's warnings/errors go to app.jsonl. Slice 3 built by three parallel lanes (Opus 5.5; lane C on Fedora): OAuth 2.1/OIDC provider with a client CLI (issuer = BASE_URL, PKCE required, 15-min access tokens, sign-out/end-session/reset revoke every refresh token); hosted pages with the Risk 8 fix enforced at the verification link (password required, GET verifies nothing) and a magic-link confirm step (GET consumes nothing); `scripts/container-check.sh` passing on Fedora (rootful docker, rootless podman + keep-id + :Z, refusals, 50/50 kill cycles). 71 tests. Follow-ups: magic link isn't offered during an OAuth sign-in (the emailed link would have to carry the OAuth request); `/change-password` with `revokeOtherSessions` doesn't revoke OAuth refresh tokens. Next slices: admin MCP → export/import → agent test.

**Goal:** the smallest thing that proves the agent-first idea. An agent starts AuthWAPI, administers it over MCP, and a real app signs a user in.

**Scope**
- Hono + Better Auth + better-sqlite3 (DELETE journal).
- **Sign-in methods:** email + password with verification, and magic link (`storeToken: "hashed"`, 5-minute links, sign-up via magic link off by default).
- **Hosted pages:** sign in, sign up, verify, reset, magic-link landing, OAuth consent.
- **OAuth 2.1 / OIDC provider** per D9; JWKS.
- **Email:** D8 transport (outbox or Resend).
- **Thin admin MCP** at `/mcp`: MCP SDK v2, spec 2026-07-28, `allowedHosts` set. Five tools: `mint_agent_key` (bootstrap or write key, per D10), `get_status`, `list_users`, `create_user` (write scope), `read_audit`.
- **Data and operations:**
  - JSON logs plus an audit log
  - numbered migrations (D14) applied on boot, with a database + secret backup taken before each one
  - `export` / `import`
  - `/health`
  - Dockerfile on `node:26-slim`, running as a non-root user that owns `/data`
- `AGENTS.md`, `/llms.txt`, and a quick start that documents the Resend test-domain limit.

**Completion checklist** (status 2026-11-20: 8 of 10 met; the evidence follows each item)
- [x] **No-human agent test.** A fresh agent session given only the repository docs (README and site docs; amended 2026-11-20, as the docs site came later) runs the container and connects to `/mcp` with the bootstrap key. It mints a scoped key, creates a user, and reads the audit entry. The run is recorded. It is done twice: once from the host, and once from an agent inside a container (Docker Desktop: `host.docker.internal`; Linux: shared network `authwapi-net`, per D7). *Met:* host run (macOS, Docker Desktop) and container run (Fedora, podman, the client in a second container on a shared podman network), both recorded in `.solofounder/agent-tests/`.
- [x] **Real app integration.** A sample app on a *different hostname* (not just another localhost port, since cookies are shared across localhost ports) signs a user in through the OAuth provider. A validly signed access token for the wrong audience is rejected, and so is a browser session cookie presented to the API. After sign-out, introspection reports the token inactive, and refresh tokens no longer work, including `offline_access` ones. *Met:* `scripts/app-check.sh` (sample app on `app.localhost`, AuthWAPI on `authwapi.localhost`), run in CI's container job.
- [x] **Data.** After a restart, users and sessions are kept. Export → import into a fresh folder on a different host path restores everything, including the secret. Starting from a folder that doesn't exist yet, non-root writes work on rootful Linux Docker, rootless podman (with the D13 command) and macOS Docker Desktop, and the host user can read the outbox. *Met:* restart in `scripts/upgrade-check.sh`. Export → import at another path restores the database and the secret, which is all an export holds (README), in `test/export-import.test.ts` and by hand on Docker Desktop and Fedora (PR #48). Non-root writes and an outbox the host user reads: `scripts/container-check.sh` checks 1 and 2 (rootful Docker, rootless podman), and a run on Docker Desktop 29.5.3 on 2026-11-20 (fresh folder; every file owned by the host user, who read an outbox mail directly).
- [x] **Durability.** 50 kill-during-write cycles on a bind mount, each followed by `PRAGMA integrity_check` = ok. *Met:* `scripts/container-check.sh` check 5, run in CI.
- [x] **Upgrades.** Upgrading from the previous build keeps the users, accounts, OAuth clients, sessions and secret. A failed migration rolls back the whole upgrade, keeps the pre-migration backup, and the container refuses to start with a clear message that names it. (Amended 2026-11-20: no image has been published yet, and rolling back replaced restoring the backup; see `UPGRADING.md`.) *Met:* `scripts/upgrade-check.sh`, run in CI, upgrades the build from just before the newest migration to the current one, then checks that a broken migration rolls back and the container refuses to start, naming the backup.
- [ ] **Security.** *Partly met:* the first four items are tested in `test/admin-mcp.test.ts` lines 63 and 87 (once, expiry), 126, 135 and 160. For the last, the test at line 234 greps `logs/`, the database and MCP output for the bootstrap key, agent keys, a password, and a magic link and its token. Other tests grep only the logs, each in one flow: verification links (`test/flow.test.ts:115`), session, OAuth access and refresh tokens presented to `/mcp` (`test/oauth.test.ts:280`), and magic-link tokens and client secrets (`test/magic-link.test.ts`, `test/oauth.test.ts`). MCP output isn't grepped for session or OAuth tokens.
  - The bootstrap key works once, then fails, and fails after expiry.
  - A revoked agent key fails.
  - A `read` key can't call `create_user`.
  - A wrong Host or Origin is rejected.
  - No token, link or key appears in `logs/` or in MCP output, except the one-time result of `mint_agent_key` (a test greps for them).
- [x] **Config.** A non-loopback `BASE_URL` without Resend config fails at boot with a clear message. With `RESEND_API_KEY` set on localhost, a real email reaches the account's own address. *Met:* the boot refusal is tested in `test/config.test.ts`; a real verification email reached the Resend account owner's inbox on 2026-11-20 (`.solofounder/live-checks/2026-11-20.md`).
- [x] **Risk 8 closed:** the `todo` test "someone who signed up with your email loses access once you verify it" passes. Nothing is tagged or merged to `main` before this. *Met:* `test/flow.test.ts` runs it as a normal test (no longer `todo`) and it passes.
- [x] Browser QA clicks through every hosted page and email link. *Met:* every hosted page and every email link (verification, magic link, reset, invitation) clicked through in a browser on 2026-11-20, `.solofounder/live-checks/2026-11-20.md`. It found a TOTP code that works twice in its window and five smaller issues, recorded there.
- [ ] Council review passes. *Not met as worded:* the M1 lane PRs (#48, #49, #50 and #52) each ended with sol-loop and council rounds (final scores 8–9/10), but the last round's items were fixed afterwards without a passing re-review, and no M1-wide council round has run.

### Gate G1: Demand check (right after M1)
- Publish the M1 image. Ask outside developers to put their agent through the no-human test and sign in to their own app. Post where agent builders are.
- **Pass:** at least 3 developers outside this project each complete both the no-human agent test and a sign-in to their own app, confirmed by their report or recording.
- **Fail:** fewer than 3 within 4 weeks of publishing.
- **Override:** the owner may continue after a fail. That is recorded as "override, demand not shown", never as a pass.
- Feedback picks the order of the next stages. No stage below is committed before G1.

### After G1 (order set by feedback)
- **M2, more sign-in methods:**
  - Google/GitHub OAuth, TOTP with backup codes, passkeys (`rpID` from `BASE_URL`).
  - Better Auth's 2FA only challenges password/username/phone sign-in by default, so the rule for magic link and social logins must be decided and tested. Switching sign-in method must not bypass 2FA.
- **M3, organizations and admin:**
  - Organizations, invitations and roles; `org_id`/`roles` claims.
  - Admin ban (revokes sessions). Impersonation with an audit entry.
  - More MCP write tools, each with an audit line and scope.
- **M4a, OIDC SSO:**
  - Per organization, via `@better-auth/sso`.
  - **Identity binding:** an SSO identity is bound to (org, issuer, subject). The email domain only routes the user to the right provider; it never decides who the user is. Linking an SSO identity to an existing account, or joining an org through it, needs an explicit policy.
  - **Domain proof:** for v1, an org admin asserts the domain (DNS TXT proves nothing on localhost).
  - **Hardening:** validate callback URLs (open-redirect risk); only org admins may register providers.
  - **Tests:** cross-org denial, unverified email, replay, wrong audience, invalid signature. A security review before external use.
- **M4b, SAML** (its own gate, after M4a):
  - Uses samlify through `@better-auth/sso`. Require signed assertions; keep IdP-initiated sign-in off unless an org opts in.
  - Document that SAML keys sit unencrypted in SQLite.
  - Round trip against a real IdP container in CI, plus negative tests.
- **M5, MCP OAuth for users' MCP servers:**
  - `@better-auth/mcp` + `@better-auth/cimd`, on the D9 provider (OAuth-provider mode is already on from M1).
  - Tested against a separate resource server that publishes its own discovery metadata and checks that tokens are bound to it.
- **M6, release hardening:** multi-arch image (amd64/arm64) on GHCR, CI on Linux and macOS, semantic versions, upgrade notes. M1 already covers migrations, backup and export.

### Rev 8 execution (2026-11-20): finish M1, then M2 → M6
Rev 9 applies council round 3 (Opus 8, Sol 7, Terra 7) as implementation notes; rev 8 applied round 2 (Opus 7, Sol 7, Terra 7); rev 7 applied round 1 on rev 6 (Opus 6, Sol 6, Terra 6).
Where this section and the older milestone bullets above disagree (IdP-initiated SAML opt-in, `@better-auth/mcp`),
this section wins.

**G1 result: override, demand not shown.** On 2026-11-20 the owner asked for M2–M6 to be built now, before
publishing M1. Not a pass. Per the owner: M6 adds the release workflows but publishes no image or tag; quality
beats the clock (each milestone is reviewed and merged before the next depends on it).

**How the work runs.** One PR per lane, merged to `main` in this order, each after sol-loop (GPT-6.2 Sol) and a
council round: **M6a → M1-A, M1-B → M1-C → M2 → M3 → M4a → M4b → M5 → M6b.** Lanes may be coded in parallel
when their files don't overlap, but merge in that order. Coders work on the Mac in their own worktrees and push
a branch; the full container check (needs enforcing SELinux) runs on Fedora.

**Migrations are numbered in merge order**, not reserved: a lane rebases onto `main` right before merge, deletes
its provisional SQL, and regenerates with `scripts/new-migration.ts` (next free number). Our own tables are
declared through a plugin `schema` (as `tokensRevokedAt` is in `src/oauth.ts`) so the generator and the existing
schema-drift test cover them.

| Lane | Branch | Depends on |
|---|---|---|
| M6a CI (Linux + macOS tests; container checks 1, 2, 4, 5) | `m6-ci` | — |
| M1-A admin MCP (5 tools, agent keys, `logs/audit.jsonl`) | `m1-admin-mcp` | — |
| M1-B `export` / `import` | `m1-export-import` | — |
| M1-C M1 exit: `AGENTS.md`, `/llms.txt`, sample app on another hostname, upgrade test, browser QA, the no-human agent test run twice (host; container on Fedora's `authwapi-net`) | `m1-exit` | M1-A, M1-B |
| M2 sign-in methods | `m2-signin-methods` | M6a |
| M3 organizations and admin | `m3-orgs-admin` | M1-A, M2 |
| M4a OIDC SSO | `m4a-oidc-sso` | M3 |
| M4b SAML | `m4b-saml` | M4a |
| M5 MCP OAuth for users' MCP servers | `m5-mcp-oauth` | M3 |
| M6b release: multi-arch build on tags (never triggered), semver, `UPGRADING.md` | `m6-release` | all |

Each lane pins any new `@better-auth/*` package at the core's exact version and confirms the options it relies on
(by test or source citation) before building on them.

**Decisions per milestone:**
- **M2, MFA is enforced on the server.** No usable session, consent or authorization code exists before the
  second factor, for every first factor: password (Better Auth's built-in challenge), magic-link verify and social
  callback (our hook turns the new session into a 2FA challenge before the response), and later SSO callbacks
  (M4). **Mechanism:** one after-hook, in a plugin registered *before* `oauthProvider` (as is `twoFactor`), fires on
  a response that *creates a new session by a first factor* (not renewals: `/get-session`, `/update-user` etc. also
  set the cookie) for a user with 2FA on, and turns it into the challenge exactly as `twoFactor` does (session row
  deleted, `newSession` cleared, response replaced, its `two_factor` challenge cookie minted), so the provider's
  after-hook never sees a session and mints no code. `/sign-in/email|username|phone-number` stay with the built-in
  hook. Allow-list: the
  `/two-factor/verify-*` endpoints, passkey sign-in with user verification, admin impersonation. Tested per path,
  including direct API calls. `twoFactor` with `allowPasswordless: true` and backup codes. **Trusted devices off:**
  1.7.26 has no switch, so a before-hook rejects `trustDevice: true` on `/two-factor/*` and incoming trust cookies
  are ignored; enabling 2FA revokes other sessions and refresh tokens. A passkey sign-in counts as both
  factors only with `authenticatorSelection.userVerification: "required"` checked on the server; adding a passkey to
  an account with 2FA needs a fresh 2FA check. The signed OAuth request survives the social redirect, the 2FA page
  and the passkey ceremony (this also closes the M1 follow-up: offer magic link during an OAuth sign-in).
- **M2, account linking**, `trustedProviders` empty: a provider account links only when the provider asserts a
  verified email *and* the local email is verified (1.7.26's default `requireLocalEmailVerified: true` for implicit
  linking; our check adds it for explicit linking). An unverified local account (possibly pre-registered, Risk 8) is
  refused, and the page points to magic link, which already does the verified takeover. Google/GitHub are on
  only when their credentials are set. Passkeys need a small client script and a CSP change on hosted pages. Tests
  use an in-process mock OAuth server and a software WebAuthn authenticator.
- **M3, one ban operation** for HTTP and MCP: revokes sessions and refresh tokens, and the provider rejects refresh
  and code exchange for banned users (ban and issuance are serialized: issuance re-checks the ban after its token write and revokes what it just
  wrote if a ban landed, tested with a ban between the user read and the write);
  `/admin/update-user` ban fields go through the same operation; introspection reports their tokens inactive (a JWKS-only API keeps the
  15-minute window, documented). Tested against a concurrent ban. `/admin/revoke-user-session(s)`,
  `/admin/set-user-password` and `/admin/remove-user` also revoke refresh tokens. The first admin is set with a
  `set_role` MCP tool (write scope). **Impersonation:** short, audited, can't target admins or org owners/admins,
  and an impersonated session gets no consent write and no authorization code (enforced at the provider's shared authorization step, so
  `/oauth2/authorize`, `/oauth2/consent` and `/oauth2/continue` are all covered) and can't change credentials.
  **Org claims** (`org_id`, `roles`) sit behind an `organization` scope, in the **access token and userinfo only**
  (`customAccessTokenClaims` gets the grant's `referenceId` and runs again on refresh; userinfo copies them from the
  validated access-token payload; ID-token claims can't see the grant in 1.7.26, so ID tokens carry none). The org is bound to the grant at sign-in (provider `postLogin` +
  `consentReferenceId`) and shown at consent, never read from the live session; refresh re-checks membership and
  role, and leaves the claims out when there's no authorized org. Tested: org switch before consent and before
  refresh. A hosted page accepts invitations. MCP: `list_orgs` (read), `create_org`,
  `invite_member`, `ban_user`, `unban_user`, `set_role` (write), all audited.
- **M4a, SSO trust.** Providers are registered only by a write MCP tool `register_sso_provider` (org-scoped) or the
  CLI, which call Better Auth as the org's owner. The HTTP routes are closed with `disabledPaths` (`/sso/register`,
  `/sso/update-provider`, `/sso/delete-provider`, `/sso/request-domain-verification`, `/sso/verify-domain`);
  `providersLimit` stays above 0 because 0 also blocks server-side calls. Provider IDs get their own prefix. Explicit endpoints (`skipDiscovery`); the test IdP's origin is trusted
  only in test fixtures. **No linking by email or domain:** domains only route users to their org's provider, are unique
  across orgs, and are never "verified" (Better Auth would then link any verified user by email). An SSO identity
  resolves only through its (org, issuer, subject) binding. An existing account is linked only by a pre-provisioned
  subject binding (operator) or explicit linking while freshly signed in; org membership alone isn't enough. SSO
  sign-in provisions new users as members of the provider's org. **Reverse pre-hijack:** an SSO-created user's email
  is stored unverified; the mailbox owner recovers it through magic link only, which atomically clears pre-proof
  credentials, MFA and passkey enrollments, SSO bindings, sessions and grants (the Risk 8 rule, extended). Deleting a provider revokes its users' sessions and tokens.
  Local 2FA applies after SSO sign-in. Tests: an org claiming `gmail.com` gets no one else's account, existing or future, cross-org,
  unverified email, replay, wrong audience, bad signature. IdP in tests: a second AuthWAPI instance.
- **M4b, SAML.** IdP-initiated sign-in stays off (Better Auth's switch is global). `wantAssertionsSigned: true` on every
  provider's `samlConfig` (it's per provider), `requireTimestamps: true`, `algorithms.onDeprecated: "reject"`, InResponseTo and replay checks on. Document that
  SAML keys sit unencrypted in SQLite. Round trip against a real IdP container on Fedora/CI, plus negative tests
  (unsigned, wrong audience, replay, another provider's assertion).
- **M5, users' MCP servers on the current provider:** `cimd()` plus the provider's resource registry; not
  `@better-auth/mcp`, which would replace the provider. The operator registers each MCP server as a resource
  (`authwapi resource add`) and links clients to it (`authwapi resource link <client_id> <resource>`, which also takes a
  CIMD client's URL); the CLI resolves a CIMD URL into its client row first (the link is a foreign key). Per-client enforcement stays
  on, so a client gets no token *for a resource it isn't linked to*, and every resource server rejects tokens whose
  `aud` isn't itself, including tokens with no `aud`; `isMetadataDocumentUrlAllowed` policy and
  the bundled SSRF-safe fetch; the consent page shows the `client_id` host (a client name is self-asserted). Refresh
  rotation stays strict. Tested with two external MCP resources through discovery, code exchange and refresh: a
  token for one is rejected by the other, and a client can't get a token for a resource that exists but isn't linked to it. OAuth
  tokens are never accepted by the admin MCP.
- **M6.** M6a above. M6b: tag-triggered multi-arch (amd64/arm64) GHCR workflow that this plan never triggers;
  semantic versions; `UPGRADING.md`.

### Stage 7: Learn
Retrospective and cross-project learning (`solofounder:conversation-analysis`).

## Out of scope until a user asks
- Postgres/MySQL
- SCIM directory sync
- web admin dashboard (MCP + API first)
- raw log reading or key rotation over MCP
- Radar-style fraud detection beyond rate limits
- Vault/BYOK
- per-org branding
- SMS
- multi-instance / high availability
- DNS domain verification

## Risks
1. **Better Auth ships its own server image, or Pocket ID / Casdoor add an MCP admin surface.** Mitigation was G1 before the expensive work; the owner overrode it on 2026-11-20, so this risk is accepted.
2. **OAuth provider and SSO correctness.** This is where auth bugs become breaches. Mitigation: the contract in D9, negative tests, and a security review round per milestone.
3. **SQLite durability on bind mounts.** Mitigation: DELETE journal, single writer, the 50-cycle kill test, export/import, backup before every migration.
4. **Better Auth churn** (the `@better-auth/cli` → `auth` rename already happened). Mitigation: exact pins; CI checks that the generated `schema.sql` matches the committed one.
5. **Scope.** "WorkOS" is 30+ products. Mitigation: the out-of-scope list holds and every council round fights additions (G1 was overridden on 2026-11-20).
6. **Sign-in racing a password reset** (council M1 slice 1, GPT-6.2 Sol): a sign-in that verified the old password just before a reset commits can still create a session. It lives inside Better Auth's sign-in, needs the old password, and the window is the ~100ms hash check. Accepted for now; revisit with an upstream fix or a credential-version check in a session-create hook if M2/M3 touch this path.
7. **Magic-link login CSRF** (M1 slice 2): someone can request a link for *their own* account and get a victim to open it, signing the victim's browser into the attacker's account. Inherent to links that work on any device; hosted pages (slice 3) could add a "you're signing in as X, continue?" confirmation step. Accepted for now.
8. **Account pre-hijack through the verification link** (found during M1 slice 2 review, confirmed live): someone signs up with *your* email and their password; if you click "Verify your email", their password works on what is now your verified account. Mitigation now: the email says not to open the link if you didn't sign up, and a `todo` test records the gap. **Fix in slice 3 (high priority):** verification requires the sign-up password **at the verification endpoint itself** (council: a hosted page alone could be bypassed by opening the link directly); whoever doesn't know it gets "forgot password", which replaces it and ends every session. Magic-link sign-in already locks the attacker out (tested). **Blocks any release or real-user deployment**, and the `todo` test passing is an M1 exit criterion. Unauthenticated `/send-verification-email` lets an attacker re-send the email to the victim (rate-limited per IP), which raises the odds of a click.

9. **Known small windows in OAuth revocation** (council slice 3, accepted): a code exchange that passes the session check just before a password reset deletes sessions but writes its token after `onPasswordReset` (milliseconds); a JWT minted in the same second just after a revocation reads as revoked until refreshed (1-second `iat`); a valid `id_token_hint` whose session is already gone revokes nothing. If pairwise subject identifiers are ever enabled, the userinfo hook's `token.sub !== result.sub` check must change or every pairwise client gets 401.

10. **Better Auth's own 2FA writes aren't atomic** (council M2 round 2, accepted upstream risk): turning 2FA on (set the flag, create a session, delete the old one, mark the secret verified) and similar rotations are separate writes in Better Auth 1.7.26, so a crash between them can leave a half-rotated session; AuthWAPI sweeps before and after enabling and changes nothing upstream.

## Evidence (fetched 2026-11-19)
- Better Auth: better-auth.com/docs/adapters/sqlite, /docs/concepts/cli, /docs/integrations/{hono,express}, /docs/plugins/{magic-link,sso,sso/saml,organization,admin,api-key,mcp,oauth-provider,jwt,2fa,passkey,agent-auth}, /blog/1-7; npm `better-auth`@1.7.26, `auth`@1.7.26
- Node 26 LTS and `node:sqlite` RC: github.com/nodejs/Release, nodejs.org/api/sqlite.html
- Resend: resend.com/docs/send-with-nodejs (`resend`@6.39.0), resend.com/docs/knowledge-base/403-error-resend-dev-domain
- MCP SDK v2 and spec 2026-07-28: github.com/modelcontextprotocol/typescript-sdk, ts.sdk.modelcontextprotocol.io/v2/serving/hono.html, modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- SQLite: sqlite.org/wal.html, sqlite.org/backup.html; Docker: docs.docker.com/engine/network/port-publishing/, docs.docker.com/engine/storage/bind-mounts/
- Competition: github.com/pocket-id/pocket-id, github.com/sebadob/rauthy, github.com/casdoor/casdoor, logto-io/logto, teamhanko/hanko, better-auth.com/products?tab=infrastructure
