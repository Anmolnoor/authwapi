---
title: Status and roadmap
description: What AuthWAPI M1 does today, what is still being built, and where the earlier version went.
---

AuthWAPI is early. It is the first milestone (M1) of a rewrite as a self-hosted auth server built on
[Better Auth](https://better-auth.com), [Hono](https://hono.dev) and SQLite. **Don't put real users on it yet.**

## Works today

- Email and password sign-up with email verification (the link asks for the sign-up password)
- Sign-in, sessions, sign-out, password reset
- Magic links: one use, 5 minutes, existing accounts only, with a confirm step
- Hosted pages: sign-in, sign-up, reset, verification, magic link, OAuth consent
- OAuth 2.1 / OpenID Connect provider: authorization code + PKCE, ID tokens, JWT access tokens per API, JWKS,
  introspection, userinfo, refresh-token rotation, RP-initiated logout; sign-out revokes refresh tokens for every app
- Operator CLI for OAuth clients
- **Admin MCP server** at `/mcp`: an agent bootstraps it with a one-time key, mints scoped, revocable keys, lists
  and creates users and reads an audit log
- Email through Resend, or an outbox folder on localhost
- One data folder: SQLite, migrations with a backup before each upgrade, JSON logs with no tokens or links
- `export` / `import` of the data folder, safe while the server runs (SQLite's online backup API)
- Docker image running as a non-root user; checked on rootful Docker, rootless podman and SELinux

## Still to build in M1

- **The no-human agent test:** a fresh agent, given only the docs, runs the container and administers it over MCP

## After M1

What comes next depends on feedback from developers who try M1. Candidates: Google and GitHub sign-in, TOTP and
passkeys; organizations and roles; SSO (OIDC, then SAML); OAuth for your own MCP servers; a multi-arch image on
GHCR.

## The earlier version

Before M1, AuthWAPI was a learning project: an Express + MongoDB API with JWT cookies and S3 avatar upload. It is
preserved at the [`v0.1-learning`](https://github.com/Anmolnoor/authwapi/tree/v0.1-learning) tag. These docs don't
cover it.
