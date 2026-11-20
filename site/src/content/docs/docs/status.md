---
title: Status and roadmap
description: What AuthWAPI does today (M1, M2 sign-in methods and M3 organizations), what is still being built, and where the earlier version went.
---

AuthWAPI is early. It is the first milestone (M1) of a rewrite as a self-hosted auth server built on
[Better Auth](https://better-auth.com), [Hono](https://hono.dev) and SQLite. **Don't put real users on it yet.**

## Works today

- Email and password sign-up with email verification (the link asks for the sign-up password)
- Sign-in, sessions, sign-out, password reset
- Magic links: one use, 5 minutes, existing accounts only, with a confirm step
- Google and GitHub sign-in, each on when its client ID and secret are set; accounts join by email only when both the
  provider and the existing account have verified it
- TOTP two-factor authentication with backup codes, enforced on the server after every first step (password, magic
  link, Google, GitHub); no trusted devices
- Passkeys with user verification required; a passkey sign-in counts as both factors
- Organizations with `owner`, `admin` and `member` roles, emailed invitations, and `org_id`/`roles` claims for apps
  that ask for the `organization` scope
- Admin ban (ends sessions and revokes OAuth tokens) and short, audited impersonation
- Hosted pages: sign-in, sign-up, reset, verification, magic link, OAuth consent, 2FA, TOTP setup, passkeys,
  organization pick, invitations. Every
  sign-in method works during an app's sign-in
- OAuth 2.1 / OpenID Connect provider: authorization code + PKCE, ID tokens, JWT access tokens per API, JWKS,
  introspection, userinfo, refresh-token rotation, RP-initiated logout; sign-out revokes refresh tokens for every app
- Operator CLI for OAuth clients
- **Admin MCP server** at `/mcp`: an agent bootstraps it with a one-time key, mints scoped, revocable keys, lists
  and creates users, manages organizations, bans users, sets the first admin, and reads an audit log
- Email through Resend, or an outbox folder on localhost
- One data folder: SQLite, migrations with a backup before each upgrade, JSON logs with no tokens or links
- `export` / `import` of the data folder, safe while the server runs (SQLite's online backup API)
- Docker image running as a non-root user; checked on rootful Docker, rootless podman and SELinux

## Still to build in M1

- **The no-human agent test:** a fresh agent, given only the docs, runs the container and administers it over MCP

## After M1

M2 (Google and GitHub sign-in, TOTP and passkeys) and M3 (organizations and admin) are built. Next: SSO (OIDC, then SAML);
OAuth for your own MCP servers; a multi-arch image on GHCR.

## The earlier version

Before M1, AuthWAPI was a learning project: an Express + MongoDB API with JWT cookies and S3 avatar upload. It is
preserved at the [`v0.1-learning`](https://github.com/Anmolnoor/authwapi/tree/v0.1-learning) tag. These docs don't
cover it.
