# M1 slice 3 spec: OAuth/OIDC provider, hosted pages, Risk 8 fix

Base commit: `m1-foundation` after "Slice 3 foundation". Read `.solofounder/flow.md` (decisions D1–D14, Stage 1,
Risks 6–8) and `README.md` first. Stack: Node runs `.ts` directly (type stripping: no enums, no JSX, no
parameter properties), Hono 4.13, Better Auth 1.7.26, `@better-auth/oauth-provider` 1.7.26 (installed),
better-sqlite3, `node --test`. Read Better Auth's types in `node_modules` rather than guessing APIs.

## Rules for every lane
- **Touch only the files your lane owns.** Need a change elsewhere? Stop and report it; the lead makes it.
- Every behaviour gets a test in your test file; every security check is **mutation-verified** (remove the
  guard, watch the test fail, restore it — restore from a copy in a `trap`, then grep that the guard is back).
- `npm test` and `npx tsc` must pass. Never weaken an existing test.
- Iron laws: no fallbacks, no silent failures, every error actionable. Nothing secret in logs.
- Commit on your branch with a clear message ending in `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Do not push (Mac lanes) unless told. Report: branch, commit SHA, what you built, test count, mutation checks,
  anything you could not do, and any change you need in a file you don't own.

## Shared wiring (lead, done)
- `src/app.ts`: `createApp({ auth, config, db, log })`. Exposes `AuthCall = (c, request) => Promise<Response>`:
  forwards a request to Better Auth with the client-IP header set from the TCP peer. Use it to call Better Auth
  endpoints internally (build a `Request` to `${config.baseUrl.origin}/api/auth/...`, copy the client's
  `cookie` and set `origin: config.baseUrl.origin`; pass Better Auth's `set-cookie` back to the browser).
- Mount order: `/health` → Host check → Origin check → `wellKnownRoutes` (A) → `pageRoutes` (B) → `/api/auth/*`.
  B's routes run before the catch-all, so B can intercept Better Auth paths.
- `src/auth.ts`: `plugins: [magicLink(...), ...oauthPlugins(deps)]`.

## Lane A — OAuth 2.1 / OIDC provider (Mac)
Owns: `src/oauth.ts`, `src/cli.ts` (new), `test/oauth.test.ts` (new), `migrations/0002_oauth.sql` (generate with
`node scripts/new-migration.ts oauth`; never hand-edit).

Contract (plan D9):
- `oauthProvider` + `jwt` plugins. `loginPage: '/sign-in'`, `consentPage: '/consent'` (B builds these pages).
- Issuer = `BASE_URL` origin. Discovery at `BASE_URL/.well-known/openid-configuration` (serve it from
  `wellKnownRoutes` if Better Auth only serves it under `/api/auth`); JWKS reachable from the discovery doc.
- ID token `aud` = client ID. Access tokens are JWTs whose `aud` is the requested resource; 15-minute lifetime.
- Refresh tokens rotate. **Sign-out revokes the session and every refresh token for that user**, including
  `offline_access` ones (Better Auth's built-in sign-out does not; do it yourself, e.g. a hook on sign-out).
- JWT plugin in OAuth-provider mode with session-JWT issuance off, as Better Auth's jwt docs require.
- Dynamic client registration **off**. Clients are registered with a CLI:
  `node src/cli.ts clients create --name <n> --redirect-uri <uri> [--redirect-uri ...]` (inside the container:
  `docker exec authwapi node src/cli.ts ...`). It opens the same data folder (`DATA_DIR`), prints client ID and
  secret **once** to stdout (never to the log), stores the secret hashed. Also `clients list`.
  Exit non-zero with a clear message on bad input.
- Claims in M1: `sub`, `email`, `email_verified` (org/roles come in M3).

Tests (`test/oauth.test.ts`, against a real server via `test/helpers.ts`; drive the flow with HTTP calls —
sign in via `/api/auth/sign-in/email` for a cookie, `GET /api/auth/oauth2/authorize`, follow to `/consent?...`,
accept via Better Auth's consent endpoint — so you don't depend on B's HTML):
1. Full authorization-code + PKCE flow for a client registered with the CLI; the relying party is on a
   **different hostname** than the server (e.g. server `127.0.0.1`, redirect URI on `localhost`).
2. ID token verifies against the JWKS from discovery; `iss`, `aud`, `sub`, `email`, `email_verified` correct.
3. A validly signed access token for a different audience is rejected by a verifier checking `aud`.
4. A browser session cookie presented to the userinfo endpoint (without a bearer token) is rejected.
5. After sign-out: introspection says the access token is inactive, and the refresh token no longer works
   (also an `offline_access` refresh token).
6. Refresh-token rotation: the old refresh token stops working after use.
7. CLI: create prints ID+secret once and stores the secret hashed (not in plain text in the database, not in
   `logs/app.jsonl`); bad input exits non-zero; list shows the client without the secret.
8. PKCE is required (a request without `code_challenge` is refused); an unregistered redirect URI is refused.

## Lane B — hosted pages + Risk 8 fix (Mac)
Owns: `src/pages.ts`, `test/pages.test.ts` (new), and in `test/flow.test.ts` **only** the `todo` test for
Risk 8 (remove its `todo` option so it must pass; adjust it to go through the new verification step).

Pages are server-rendered HTML with `hono/html` (no JSX, no client framework, no external assets; inline CSS
is fine, keep it small and accessible: labels, focus order, errors announced). Every form POSTs to our own
route with the same origin. Show Better Auth errors as readable messages, never raw JSON.

Routes:
- `GET/POST /sign-in` (password + "email me a link" magic-link option), `GET/POST /sign-up`,
  `GET/POST /forgot-password`, `GET/POST /reset-password` (token from the reset link), `GET /signed-out`.
  `/sign-in` must work as the OAuth `loginPage`: Better Auth redirects there with signed OAuth query params;
  after sign-in the OAuth flow must continue (find out how in the oauth-provider types/docs: e.g. passing
  the original query back, or `/oauth2/continue`). Lane A tests the API-level flow; you test the page flow.
- `GET/POST /consent`: shows the client's name and the requested scopes in plain words; Accept / Deny POST to
  Better Auth's consent endpoint and redirect to the result. Lane A configures `consentPage: '/consent'`.
- **Risk 8 fix, enforced at the link itself:** intercept `GET /api/auth/verify-email` (the link in the
  verification email). Do **not** verify on GET. Show a page: "Enter the password you chose when you signed
  up". `POST` checks that password against the account's credential (constant-time, rate-limited via
  `callAuth` to Better Auth or your own limit) and only then completes verification (call Better Auth's
  verify-email through `callAuth`). Wrong password: say so and offer "Forgot password?" (reset replaces the
  password and ends all sessions; after reset the user verifies with the new password). There must be **no**
  route left that verifies an email from the token alone. Accounts without a password credential (none exist
  in M1; magic link can't sign up) must fail closed with a clear message.
- **Magic-link confirm step (Risk 7, and stops email scanners from burning single-use links):** intercept
  `GET /api/auth/magic-link/verify`. Do not consume the token on GET. Show "Sign in as <stored email>?" with a
  Continue button; `POST` consumes the token via Better Auth and sets the session.
- `GET /` : a tiny landing page linking to sign-in/sign-up and showing the signed-in email if any.

Tests (`test/pages.test.ts`): each page renders (200, has its form), each form's happy path and main error
path, the OAuth `loginPage` continuation, consent accept and deny, and:
1. Risk 8: the attacker-signs-up-with-your-email scenario ends with the attacker's password **failing**
   (that's the `todo` test in `flow.test.ts`, now required to pass).
2. A GET to the verification link verifies nothing and consumes nothing; verification needs the password.
3. A GET to a magic link consumes nothing (the link still works after the GET); POST signs in once.
4. No page reflects user input unescaped (XSS: put `<script>` in a name and an error path).
5. Forms reject a cross-site POST (Origin check already exists; prove it covers the page routes).

## Lane C — Linux container checks (Fedora)
Owns: `scripts/container-check.sh` (new) and a short "Linux" note in your report (the lead edits README).
Works from `origin/m1-foundation` at the slice 2 commit (421497a); no app code changes.
- Write `scripts/container-check.sh`: builds the image, then runs each check, prints PASS/FAIL per check, exits
  non-zero on any failure, cleans up containers and temp folders (trap), uses unique container names and a
  non-default port, never touches `$HOME` data.
- Checks: (1) start from a **missing** bind folder (rootful docker if available, else rootful podman); files
  owned by the host user, dirs 0700 / files 0600; health ok; sign-up writes an outbox file the host user can
  read. (2) Rootless podman with `--userns=keep-id -v ...:/data:Z` from a folder created with `mkdir -p`.
  (3) SELinux enforcing: without `:Z` it fails with a clear error; with `:Z` it works. (4) `PUID=00` and a
  symlinked data folder are refused. (5) **50 kill-during-write cycles** on a bind mount, each followed by
  `PRAGMA integrity_check` = ok (run the check with the image's node + better-sqlite3).
- Run it on Fedora, report results per check, and push your branch `m1-linux-checks` to origin.
- Fleet rule: one full test/container run at a time on this machine.
