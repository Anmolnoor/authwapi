# AuthWAPI vs WorkOS: gap analysis (rev 2, 2026-11-19)

## Flow used
1. Evidence: read all of `src/` (22 files, ~1.3k LOC); ran the app live twice (Mongo 7 in Docker, NODE_ENV=development and production).
2. Research: WorkOS product pages, docs index, pricing (fetched 2026-11-19).
3. Draft gap matrix + recommendation.
4. Council (3x Claude Opus 5.5, read-only), 2 rounds. Round 1: code truth 7, WorkOS accuracy 7, strategy 4. Round 2: 8.5, 8, 8. All round-2 corrections applied; new bug claims re-run live where possible (marked ✔ vs ◇).

## What AuthWAPI is today
Express 4 + TypeScript + MongoDB, ~1.3k LOC, 18 commits, 1 GitHub star, zero tests, no CI.

| Route | Does |
|---|---|
| GET  /api/test | hello |
| POST /api/v1/auth/register | create user, set JWT cookie |
| POST /api/v1/auth/login | email-or-username + password, JWT cookie (HS256; cookie fixed at 30d). Token is **not** in the response body, despite README:50 |
| GET  /api/v1/auth/logout | overwrite cookie (no server-side revocation) |
| POST /api/v1/auth/forget-password | emails a SHA-256-hashed, 10-min reset token |
| PATCH /api/v1/auth/reset-password/:token | consume token, set password, log in |
| GET  /api/v1/user/me | profile (also leaks `resetToken` hash, stale `.select()`) |
| POST /api/v1/user/update-password | change password, re-issue JWT |
| POST /api/v1/user/upload-image | avatar → Sharp → S3 |

Infra: helmet, `cors()` wildcard with no credentials, and the cookie is `sameSite: strict` (jwt.ts:43), so cross-site browser login can't work for two separate reasons, 500 req/IP/hour global limit, Winston, graceful shutdown, Dockerfile. `xss-clean` is mounted before `express.json()`, so it never sees bodies (no-op).

## Bugs, ranked (✔ = reproduced live; ◇ = from code, not run)
| # | Sev | Bug | Where |
|---|---|---|---|
| 1 | High ✔ | **NoSQL injection in login and forget-password**: `{"username":{"$regex":"^o"}}` → 500 if any user matches, 401 if not; `{"email":{"$regex":"^a"}}` on forget-password → 500 vs 404, no password needed. Enumerates every email/username char by char. (Narrow variant, from code: omitting `username` makes the filter `{username:null}`, matching the one user registered without a username.) | auth.controller.ts:70-83, :134 (raw body into the query) |
| 2 | Med ✔ | **Password hash returned** in register / login / reset responses (plus reset-token hash), to a client that just sent the plaintext; risk is the hash landing in client logs, analytics or proxies | auth.controller.ts:63, :87, :213; no `select:false`/toJSON |
| 3 | High ✔ | **Old JWTs survive password change *and* reset** (so account recovery doesn't evict an attacker); README claims otherwise | auth.controller.ts:288 typo `passwordChangedAT` |
| 4 | High ◇ | **Reset-link poisoning**: link built from `req.protocol`; with `trust proxy 1` an attacker sets `X-Forwarded-Proto: https://evil/?t=` and the victim's email points at the attacker. Applies when clients reach Express directly (the shipped Dockerfile, `EXPOSE 8000`) or via a proxy that passes the header through; not behind one that overwrites it | auth.controller.ts:155, app.ts:28 |
| 5 | Med ✔ | **Won't boot from `.env`**: `dotenv.config()` runs after imports that read `JWT_SECRET`; `.env.example` doesn't exist | app.ts:23, jwt.ts:4 |
| 6 | Med ◇ | Rate limit bypass via spoofed `X-Forwarded-For` (same `trust proxy`, same deployment condition as 4); no stricter limit on login/reset | app.ts:28, :55 |
| 7 | Med ✔ | Account-existence leaks: forget-password 404; missing password on known user → 500 vs 401; duplicate email → 500 | auth.controller.ts:137 etc. |
| 8 | Med ✔ | Emails > 32 chars can't register (production shows generic 500) | user.model.ts:37 |
| 9 | Med ◇ | Second signup without username fails (unique, not sparse) | user.model.ts:27-32 |
| 10 | Low | Email not lowercased; password `trim`+maxlength 32; soft-delete filter on `active` not `isActive`; client can set `image`; upload 500s on missing field; `image/heic` rejected | various |

## Gap matrix vs WorkOS
Legend: ✅ have · 🟡 partial/broken · ❌ missing. Sizes are for one developer on this codebase.

| Area | WorkOS | AuthWAPI | Size |
|---|---|---|---|
| Email + password | ✅ | 🟡 bugs 1–10 | S |
| Email verification | ✅ | ❌ | S |
| Magic link / email codes | ✅ | ❌ | S |
| Social login ("all major providers") | ✅ | ❌ | M |
| MFA (TOTP via widgets) + per-org "MFA required" | ✅ | ❌ | M |
| Passkeys | ✅ | ❌ | M |
| Sessions: refresh rotation, list/revoke | ✅ | ❌ 30-day bearer only | M |
| Organizations, memberships, invites | ✅ | ❌ | M |
| Per-org auth policies (MFA required for non-SSO members, SSO-only enforcement) | ✅ | ❌ | M (needs orgs) |
| RBAC: org-scoped roles, perms in token, IdP group → role sync | ✅ | ❌ `restrictTo` commented out | M (sync: L) |
| FGA (resource-scoped extension of RBAC) | ✅ | ❌ | L |
| Enterprise SSO: any SAML/OIDC IdP, JIT ($125/$100/$80/$65 per connection, 101+ custom) | ✅ | ❌ | L |
| Directory Sync / SCIM (same pricing) | ✅ | ❌ | L |
| Domain verification (DNS TXT) | ✅ | ❌ | S |
| Admin Portal (customer IT self-serve) | ✅ | ❌ | L |
| Audit log collection + CSV export | ✅ | ❌ | S |
| Audit log SIEM streaming ($125/mo/connection) | ✅ | ❌ | M |
| Webhooks / events API, data sync | ✅ | ❌ | M |
| Radar: bots incl. AI agents, brute force, impossible travel, repeat sign-up, disposable email, stale accounts, unknown devices, country allow/block, email challenge (SMS on sign-up) | ✅ | 🟡 one spoofable IP limit | L (basic lockout + HIBP: M) |
| Hosted login UI (branding, 90 languages), custom domain $99/mo | ✅ | ❌ API only | L |
| Drop-in React widgets | ✅ | ❌ | M |
| Impersonation | ✅ | ❌ | S (after RBAC + audit) |
| API keys | ✅ | ❌ | S |
| MCP / AI-agent auth (needs an OAuth 2.1 authorization server) | ✅ | ❌ no OAuth server | L |
| Vault: EKM, BYOK (docs: AWS/GCP/Azure; marketing also says HSM, HashiCorp), per-org keys | ✅ | ❌ | L |
| Feature flags + entitlements | ✅ | ❌ | M |
| Pipes (users connect third-party accounts) | ✅ | ❌ | L |
| Migration tooling (Auth0, Clerk, Firebase, Cognito, Supabase, Stytch, Descope, Better Auth; bcrypt/scrypt/pbkdf2/argon2 hash import) | ✅ | ❌ | M |
| Transactional email delivery | ✅ | 🟡 raw SMTP | S |
| SDKs: 10 server, 7 framework, iOS + Android; OpenAPI | ✅ | ❌ | OpenAPI + 1 client: M |
| Dashboard | ✅ | ❌ | L |
| Staging/prod environments | ✅ free staging | n/a self-hosted | — |
| SOC 2 Type 2, GDPR, CCPA, HIPAA BAA (enterprise); 99.99% SLA (annual/enterprise plans only) | ✅ | ❌ | n/a |
| Deployment | SaaS only (the on-prem guide is for your app calling WorkOS cloud; air-gapped unsupported) | ✅ self-host, MIT, free, works air-gapped | — real edge vs WorkOS, but shared with every open-source competitor |

## Better Auth check (fetched 2026-11-19, npm `better-auth@1.7.26`, MIT)
All first-party, none labelled experimental/beta: MongoDB adapter (`@better-auth/mongo-adapter`), Express via `better-auth/node`, organizations, 2FA/TOTP, passkeys (`@better-auth/passkey`), magic link, JWT + JWKS, API keys, OAuth 2.1/OIDC provider (`@better-auth/oauth-provider`), MCP (`@better-auth/mcp`), SSO OIDC + SAML (`@better-auth/sso`), SCIM (`@better-auth/scim`, needs an adapter with interactive transactions).
Caveats: **ESM only, CommonJS not supported**, and AuthWAPI compiles to CommonJS (tsconfig), so the spike includes an ESM switch. Self-service SSO setup UI is in their paid "Infrastructure" product; the SSO plugin itself is in the library.
Sources: better-auth.com/docs/plugins, /docs/adapters/mongo, /docs/integrations/express, /docs/plugins/{organization,2fa,passkey,magic-link,jwt,api-key,oauth-provider,mcp,sso,scim}.

## Recommendation (rev 2, after council)
The draft's first recommendation was wrong. It named Better Auth / Ory / Keycloak / Logto / Zitadel as the real competitors, then planned to hand-build their features. Better Auth alone is MIT, TypeScript, has a MongoDB adapter, and ships 2FA, passkeys, magic link, JWT/JWKS, organizations, API keys, an OAuth 2.1 provider, MCP and SSO as plugins. "Self-hosted + MIT" is not an edge; every one of them has it. And ten bugs in 1.3k lines is evidence that hand-rolling sessions, WebAuthn and SAML would be worse.

Order:
1. **Today:** fix bugs 1, 3, 4, 5 (security / can't boot), then 2, with one regression test each (bug 4's test is its proof, since it wasn't run live). Bugs 4 and 6 share one root cause, `trust proxy 1` at app.ts:28, so one commit fixes both. Correct the README's false claims (token invalidation, bearer token in body, `.env.example`).
2. **Decide in one line:** learning project or product. If product, name one real user who'd pick it over `npm i better-auth`.
3. **Product only, one-day spike:** on a branch, switch the build to ESM and replace `auth.controller.ts` with Better Auth + Mongo adapter, keeping Docker. Better Auth mounts its own handler, so either drop the old `/api/v1/auth/*` paths or count the shim's lines in the "lines deleted vs features gained" comparison.
4. **Pick:**
   - Product with a named user → a narrow, honest niche ("one-command Docker auth server for Express + Mongo, on Better Auth").
   - Product with no named user → archive, README points to Better Auth, keep the bug write-up as the lesson.
   - Learning → keep hand-building (sessions, passkeys, orgs are the point); README says "learning project, not for production".
5. **Nothing else until a real user asks** (product path). No SSO, SCIM, audit logs or agent auth on spec.
