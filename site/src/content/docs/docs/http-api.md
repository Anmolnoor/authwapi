---
title: HTTP API (sessions)
description: Sign up, sign in, magic links, password reset and sessions over HTTP, with the session cookie. Errors and request rules.
---

AuthWAPI's account routes are [Better Auth](https://better-auth.com)'s, served under `BASE_URL/api/auth`. They
use a session **cookie**, so they suit a web app served from AuthWAPI's own origin, scripts and tests. For an app
on another origin, or an API that needs tokens, use [OAuth / OIDC](/docs/integrate-an-app/) instead.

Every route with its request and response schema is in the [API reference](/api/), and as a file in
[`/openapi.json`](/openapi.json).

## Rules for every request

- **Host** must be `BASE_URL`'s host or a name in `ALLOWED_HOSTS`, else `421 unknown_host`.
- **Origin**, if sent, must be `BASE_URL`'s origin, else `403 untrusted_origin`. Browsers always send it on
  `POST`; curl doesn't.
- **Bodies** are JSON (`content-type: application/json`).
- **Rate limits** apply per IP; see [Configuration](/docs/configuration/#rate-limits).
- **Errors** from account routes look like `{"message":"Email not verified","code":"EMAIL_NOT_VERIFIED"}`.
  OAuth routes answer `{"error":"invalid_grant","error_description":"…"}`.

## Sessions

Sign-in sets the `better-auth.session_token` cookie (`HttpOnly`, `SameSite=Lax`, 7 days; named
`__Secure-better-auth.session_token` when `BASE_URL` is https). Send it back on every call.

| Route | What it does |
| --- | --- |
| `POST /sign-up/email` `{name, email, password}` | Creates the account and emails a verification link. The answer looks the same whether or not the address already has an account. |
| `POST /sign-in/email` `{email, password}` | Sets the session cookie. `403 EMAIL_NOT_VERIFIED` until the email is verified. |
| `GET /get-session` | The session and user, or `null`. |
| `POST /sign-out` | Ends the session and revokes the user's OAuth refresh tokens. |
| `GET /list-sessions` | The user's sessions. |
| `POST /revoke-session` `{token}`, `/revoke-sessions`, `/revoke-other-sessions` | End sessions. Each also revokes the user's OAuth refresh tokens. |
| `POST /change-password` `{currentPassword, newPassword, revokeOtherSessions?}` | Changes the password. |
| `POST /send-verification-email` `{email}` | Sends the verification email again. |

```bash
curl -c jar -X POST http://localhost:4000/api/auth/sign-in/email \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'
curl -b jar http://localhost:4000/api/auth/get-session
curl -b jar -X POST http://localhost:4000/api/auth/sign-out    # {"success":true}
```

## Magic links

```bash
curl -X POST http://localhost:4000/api/auth/sign-in/magic-link \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","callbackURL":"/"}'
# {"status":true}
```

- Signs in an existing account only; it never creates one.
- The link works once, for 5 minutes, and is stored hashed.
- For an address with no account the answer is the same, but nothing is sent. One address gets at most one link a
  minute.
- A magic link also verifies the email. Any password set before the email was verified is removed (use password
  reset to set one).
- `callbackURL` (and `newUserCallbackURL`, `errorCallbackURL`) must be on `BASE_URL` or an `ALLOWED_HOSTS` name.

The emailed link (`/api/auth/magic-link/verify?token=…`) is a page: opening it asks "Sign in as
ada@example.com?" and only the **Continue** button signs in.

## Password reset

```bash
curl -X POST http://localhost:4000/api/auth/request-password-reset \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","redirectTo":"/reset-password"}'
# {"status":true,"message":"If this email exists in our system, check your email for the reset link"}
```

The email's link is `BASE_URL/api/auth/reset-password/<token>?callbackURL=…`. Opening it redirects to the hosted
reset page. To finish over the API, take the token from the link's path:

```bash
curl -X POST http://localhost:4000/api/auth/reset-password \
  -H 'content-type: application/json' \
  -d '{"token":"<token>","newPassword":"new-password-456"}'
# {"status":true}
```

A reset ends every session and revokes every OAuth refresh token the user has.

## Other Better Auth routes

Better Auth mounts more routes under `/api/auth` (updating the user, changing the email, social sign-in, client
administration). AuthWAPI M1 doesn't configure, test or support them, so they're left out of these docs and the
API reference.
