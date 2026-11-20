---
title: Status and roadmap
description: What AuthWAPI does today (M1 through M6, from sign-in methods to OIDC and SAML SSO and OAuth for MCP servers), what is left before the first release, and where the earlier version went.
---

AuthWAPI is early. It is a rewrite as a self-hosted auth server built on [Better Auth](https://better-auth.com),
[Hono](https://hono.dev) and SQLite, and no release has been published yet. **Don't put real users on it yet.**

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
- OIDC SSO per organization: providers registered over MCP or the CLI, identities bound to (provider, subject),
  never joined by email
- SAML SSO per organization, under the same rules: signed assertions only (RSA-SHA256 or stronger), started from
  AuthWAPI (identity-provider-initiated sign-in is refused)
- Hosted pages: sign-in, sign-up, reset, verification, magic link, OAuth consent, 2FA, TOTP setup, passkeys,
  organization pick, invitations. Every
  sign-in method works during an app's sign-in
- OAuth 2.1 / OpenID Connect provider: authorization code + PKCE, ID tokens, JWT access tokens per API, JWKS,
  introspection, userinfo, refresh-token rotation, RP-initiated logout; sign-out revokes refresh tokens for every app
- Operator CLI for OAuth clients
- OAuth for your own MCP servers: MCP clients identify themselves with Client ID Metadata Documents, and the operator
  links each one to the MCP servers (resources) it may get tokens for
- **Admin MCP server** at `/mcp`: an agent bootstraps it with a one-time key, mints scoped, revocable keys, lists
  and creates users, manages organizations, bans users, sets the first admin, and reads an audit log
- Email through Resend, or an outbox folder on localhost
- One data folder: SQLite, migrations with a backup before each upgrade, JSON logs with no tokens or links
- `export` / `import` of the data folder, safe while the server runs (SQLite's online backup API)
- Docker image running as a non-root user; checked on rootful Docker, rootless podman and SELinux
- The no-human agent test: a fresh agent, given only the docs, ran the container and administered it over MCP,
  from the host and from another container
  ([runs](https://github.com/Anmolnoor/authwapi/tree/main/.solofounder/agent-tests))

## Milestones

M1 (the core server, admin MCP and export/import), M2 (Google and GitHub sign-in, TOTP and passkeys), M3
(organizations and admin), M4a (OIDC SSO), M4b (SAML SSO), M5 (OAuth for your own MCP servers) and M6 (CI on Linux
and macOS, and a release workflow) are built. The release workflow builds a multi-arch (amd64/arm64) image for GHCR
from a version tag, and [UPGRADING.md](https://github.com/Anmolnoor/authwapi/blob/main/UPGRADING.md) holds the
upgrade notes. No release tag (`vX.Y.Z`) has been pushed yet, so there is no published image: build it from source
as the quick start shows.

## The earlier version

Before M1, AuthWAPI was a learning project: an Express + MongoDB API with JWT cookies and S3 avatar upload. It is
preserved at the [`v0.1-learning`](https://github.com/Anmolnoor/authwapi/tree/v0.1-learning) tag. These docs don't
cover it.
