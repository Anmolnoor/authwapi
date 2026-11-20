---
title: Integrate an app (OAuth / OIDC)
description: Register a client, run the authorization code flow with PKCE, verify ID and access tokens, refresh, and handle sign-out and revocation.
---

AuthWAPI is an OAuth 2.1 / OpenID Connect provider. Your app sends the user to AuthWAPI's hosted sign-in page and
gets back an ID token (who the user is) and, if it asks, an access token for your API. Any standard OIDC client
library works: point it at the discovery document and use the authorization code flow with PKCE. Your app is a
confidential client: run the flow on your backend, and keep the client secret, `state` and PKCE verifier there.

| | |
| --- | --- |
| Issuer | your `BASE_URL`, e.g. `http://localhost:4000` |
| Discovery | `BASE_URL/.well-known/openid-configuration` |
| Keys (JWKS) | `BASE_URL/api/auth/jwks` (EdDSA) |
| Flow | Authorization code, PKCE with `S256` required |
| Scopes | `openid`, `email`, `offline_access`, `organization` |
| Client authentication | `client_secret_basic` (HTTP Basic) only. Discovery also lists other methods; clients made with the CLI can't use them. |

## 1. Register your app

Clients are created on the server with the CLI; there is no registration over HTTP.

```bash
docker exec -u 1000 authwapi node src/cli.ts clients create \
  --name "My app" \
  --redirect-uri http://127.0.0.1:3000/callback \
  --resource http://localhost:5000/api
```

```text
Created client "My app". The secret is shown only this once; store it now.
client_id:     wuyyoKxNToKVnVCFaSDwUJhLsKxIDuIc
client_secret: ZeEDjEUqUDBhRuzrVKfoQMlGlMRYsHzn
resources:     http://localhost:5000/api
```

- `--redirect-uri` can be repeated. Plain `http://` is allowed only for loopback addresses (`localhost`,
  `127.0.0.1`, `[::1]`, `*.localhost`); anything else needs `https://`.
- `--resource` (optional, repeatable) names an API your app may request access tokens for. Leave it out if your
  app only needs to know who signed in.
- The secret is printed once and stored hashed. `docker exec -u 1000 authwapi node src/cli.ts clients list` shows
  the clients, never secrets.
- `-u 1000` runs the CLI as the user the server runs as. If you set `PUID` or `PGID`, use `-u <PUID>:<PGID>`, with
  `1000` for the one you didn't set.

## 2. Send the user to sign in

Create a PKCE verifier and challenge, then redirect the browser to the authorization endpoint:

```text
http://localhost:4000/api/auth/oauth2/authorize
  ?response_type=code
  &client_id=wuyyoKxNToKVnVCFaSDwUJhLsKxIDuIc
  &redirect_uri=http://127.0.0.1:3000/callback
  &scope=openid email offline_access
  &state=<random>
  &code_challenge=<BASE64URL(SHA256(verifier))>
  &code_challenge_method=S256
  &resource=http://localhost:5000/api
```

(URL-encode the values.) If the user isn't signed in, AuthWAPI shows its sign-in page. The first time, the consent
page lists what your app asked for, in plain words, and the user picks **Allow** or **Deny**. AuthWAPI redirects
back:

```text
http://127.0.0.1:3000/callback?code=8BF356YxVkm1oEn9ozUpBhugS0WjxCoZ&state=xyz&iss=http%3A%2F%2Flocalhost%3A4000
```

Check that `state` is the one you sent and `iss` is your issuer.

- Ask for `email` to get `email` and `email_verified`. Ask for `offline_access` to get a refresh token.
- Ask for `organization` to learn which organization the user signs in for: AuthWAPI asks them to pick one of theirs
  (or none), shows it on the consent page, and puts `org_id` and `roles` in the access token and userinfo (never the
  ID token). The organization is fixed for the grant; each refresh re-checks that the user is still a member and
  updates `roles`, and leaves both claims out once they aren't.
- Pass `resource` only if your app needs an access token for that API. The client must have been registered with it.

## 3. Exchange the code

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -X POST http://localhost:4000/api/auth/oauth2/token \
  -d grant_type=authorization_code \
  -d code=8BF356YxVkm1oEn9ozUpBhugS0WjxCoZ \
  -d redirect_uri=http://127.0.0.1:3000/callback \
  -d code_verifier="$VERIFIER" \
  -d resource=http://localhost:5000/api
```

```json
{
  "access_token": "eyJ0eXAiOiJhdCtqd3Qi…",
  "expires_in": 900,
  "expires_at": 1795154799,
  "token_type": "Bearer",
  "refresh_token": "dbrwRfEjWYPeRnTgMYlxbFJLBhlrEmPH",
  "scope": "openid email offline_access",
  "id_token": "eyJhbGciOiJFZERTQSIs…"
}
```

Send `resource` here only if it was on the authorization request; otherwise the answer is `invalid_target`.

## 4. Read the ID token

The ID token tells your app who signed in. Let your OIDC library validate it: signature against the JWKS
(EdDSA), `iss` = your issuer, `aud` = your client ID, `exp`, and `nonce` if you sent one. It looks like this:

```json
{
  "iss": "http://localhost:4000",
  "sub": "dNSJ48si6OD0IFPmTkMfQOLbhNIgdEep",
  "aud": "wuyyoKxNToKVnVCFaSDwUJhLsKxIDuIc",
  "email": "ada@example.com",
  "email_verified": true,
  "sid": "e0AzUQ3zpUNiPDimjvMTERwcmEtxb9xS",
  "auth_time": 1795153881,
  "iat": 1795153899,
  "exp": 1795189899
}
```

Use `sub` as the user's ID. `email` and `email_verified` are present only when you asked for the `email` scope.

## 5. Verify access tokens in your API

Access tokens requested with `resource` are JWTs (`typ: at+jwt`) whose `aud` includes that resource. They last 15
minutes. Your API checks the signature, `typ`, `iss`, `aud` and `exp`. With [jose](https://github.com/panva/jose)
in Node:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const AUTHWAPI = 'http://localhost:4000';
const jwks = createRemoteJWKSet(new URL(`${AUTHWAPI}/api/auth/jwks`));

export async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: AUTHWAPI,
    audience: 'http://localhost:5000/api',
    typ: 'at+jwt',
    requiredClaims: ['exp'],
  });
  return payload; // payload.sub is the user, payload.scope the granted scopes
}
```

A browser session cookie is not an access token: your API should accept only bearer JWTs it can verify like this.

## 6. Refresh

With `offline_access`, trade the refresh token for new tokens. Each refresh token works once; use the new one it
returns. Using an old one again revokes every refresh token the user has for your app, and their opaque access
tokens (JWT access tokens stay valid until they expire), so never refresh twice at once with the same token.

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -X POST http://localhost:4000/api/auth/oauth2/token \
  -d grant_type=refresh_token -d refresh_token="$REFRESH_TOKEN" -d resource=http://localhost:5000/api
```

Using an old refresh token again returns `{"error":"invalid_grant","error_description":"invalid refresh token"}`.

## Sign-out and revocation

These revoke **every** refresh token the user has, for every app, `offline_access` ones included:

- signing out (`POST /api/auth/sign-out`, or the hosted sign-out)
- RP-initiated logout through `end_session_endpoint` (`/api/auth/oauth2/end-session`; `id_token_hint` works for
  clients made with the CLI), when it ends a live session
- revoking sessions (`/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`)
- changing the password with `revokeOtherSessions: true`
- resetting the password
- an admin banning the user, revoking their sessions, setting their password or removing them

A banned user's refresh tokens and unused authorization codes are refused, and introspection and userinfo report
their tokens inactive.

**A JWT access token stays valid until it expires (at most 15 minutes), even after sign-out.** If your API needs
revocation to take effect at once, ask the introspection endpoint instead of only checking the signature:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -X POST http://localhost:4000/api/auth/oauth2/introspect -d token="$ACCESS_TOKEN"
```

Accept the token only if the answer has `"active": true` and its `aud` includes your API. After sign-out it
returns `{"active":false}`, and userinfo (`GET /api/auth/oauth2/userinfo` with `Authorization: Bearer <token>`)
answers `401 invalid_token`. Introspection is limited to 100 requests a minute per IP. If a busy API caches
answers, revocation reaches it only when the cached answer expires: keep the cache short and never past the
token's `exp`.

## Other endpoints

All are in the discovery document and the [API reference](/api/):

- `userinfo_endpoint`: `/api/auth/oauth2/userinfo`, returns `sub`, plus `email` and `email_verified` when the
  token has the `email` scope, and `org_id` and `roles` when it has `organization` and the user is still a member.
- `revocation_endpoint`: `/api/auth/oauth2/revoke`, revokes a refresh token or an opaque access token. A JWT
  access token can't be revoked; it expires.
- A `claims` request may name `email` or `email_verified` only together with the `email` scope.

## Things to know

- Browsers share cookies across ports of one host, so an app on `localhost:3000` would receive AuthWAPI's cookies
  from `localhost:4000`. That's why these examples put the app on `127.0.0.1`. Test a real integration with the app
  on a different hostname.
- Magic-link sign-in isn't offered during an OAuth sign-in yet; the user signs in with their password.
