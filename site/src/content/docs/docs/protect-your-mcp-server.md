---
title: Protect your MCP server with AuthWAPI
description: Use AuthWAPI as the authorization server for your own MCP servers. Register each server as a resource, link the MCP clients allowed to use it, and check tokens in the server.
---

Your MCP server can use AuthWAPI as its authorization server. An MCP client finds AuthWAPI from your server's
metadata, signs the user in through AuthWAPI's hosted pages, and gets an access token that only your server accepts.
This is separate from AuthWAPI's own admin MCP at `BASE_URL/mcp`, which never accepts OAuth tokens.

| | |
| --- | --- |
| Authorization server metadata | `BASE_URL/.well-known/oauth-authorization-server` (also `openid-configuration`) |
| Keys (JWKS) | `BASE_URL/api/auth/jwks` |
| Client registration | [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (`client_id_metadata_document_supported: true`); dynamic client registration is off |
| Flow | Authorization code, PKCE with `S256` required, `resource` = your MCP server's URL |
| Scopes | `offline_access` for refresh tokens; `openid` and `email` if the client wants them |

## 1. Register your MCP server and the clients allowed to use it

The resource is your MCP server's URL, exactly as clients send it in `resource=` (for example
`https://mcp.example.com/mcp`):

```bash
docker exec -u 1000 authwapi node src/cli.ts resource add https://mcp.example.com/mcp
```

A client gets no token for a resource it isn't linked to, so link each MCP client you allow. An MCP client's
`client_id` is the `https` URL of its metadata document:

```bash
docker exec -u 1000 authwapi node src/cli.ts resource link https://client.example/oauth/metadata.json https://mcp.example.com/mcp
```

Linking fetches nothing. AuthWAPI uses a client's metadata document only while the client is linked to at least
one resource: it fetches the document when a user signs in through the client, and refuses any other `client_id`
URL without a request going out. The URL must be `https` on a public host, with a path and no fragment or
credentials; loopback and private addresses are always refused. The fetch resolves DNS once, refuses private
addresses, follows no redirects, gives up after 5 seconds and accepts at most 5 KB of JSON.

To take a client's access away, unlink it. A client linked to no resource is refused at once, even if its document
is cached: no new sign-in, and its refresh tokens stop working. Access tokens it already holds last until they
expire (15 minutes).

```bash
docker exec -u 1000 authwapi node src/cli.ts resource unlink https://client.example/oauth/metadata.json https://mcp.example.com/mcp
```

The consent page leads with the host of the metadata URL, which is where the client really comes from, and then
the name the document gives itself: *client.example (calls itself "Example MCP Client") wants to…*

### The metadata document

The client serves it as JSON (`Content-Type: application/json`) at its `client_id` URL:

```json
{
  "client_id": "https://client.example/oauth/metadata.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://localhost:33418/callback", "https://client.example/oauth/callback"],
  "token_endpoint_auth_method": "none"
}
```

- `client_id`: exactly the URL the document is served from.
- `client_name`: required, non-empty.
- `redirect_uris`: required, non-empty. Each one must be on the `client_id`'s origin, on a loopback host
  (`localhost`, `127.0.0.1`, `[::1]`), or a native app's private-use scheme (`com.example.app:/callback`). A
  document can't move its callbacks to another origin. `post_logout_redirect_uris` follow the same rule, and
  `client_uri` must be on the `client_id`'s origin.
- `token_endpoint_auth_method`: `none` (the default; a public client using PKCE) or `private_key_jwt`. A shared
  secret (`client_secret_*`, `client_secret`) is refused.
- `private_key_jwt` needs the client's public keys: either `jwks` inline (public keys only) or `jwks_uri`. A
  `jwks_uri` must be `https`, on the `client_id`'s origin (or on AuthWAPI's own `BASE_URL` / `ALLOWED_HOSTS`
  origins), and is fetched only for a linked client, through the same SSRF-safe fetch as the document.

### Clients without a metadata document

A client on `localhost` can't publish a metadata document AuthWAPI will fetch. If it runs on a server that can keep
a secret, register it with `clients create` instead: that makes a confidential client that authenticates with a
client secret (`client_secret_basic`), as described in [Integrate an app](/docs/integrate-an-app/). Then
`resource link <its client_id> <resource>` links it the same way. Don't use this for a desktop or CLI app that
would have to ship the secret.

## 2. Publish your server's metadata

Serve [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected-resource metadata, and point at it from every
401:

```http
GET /.well-known/oauth-protected-resource

{"resource": "https://mcp.example.com/mcp", "authorization_servers": ["http://localhost:4000"]}
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

`resource` must equal the identifier you registered, and `authorization_servers` holds your `BASE_URL`.

## 3. Check every token

Access tokens are JWTs (`typ: at+jwt`) that last 15 minutes. Your server must check the signature, `iss`, `exp`
and that `aud` includes **its own** URL. A token minted for another resource, or with no `aud` at all, must be
refused: that is what stops a token for one MCP server working on another. A token with a `cnf` claim is bound to
a key (DPoP) and is valid only with a proof from that key; a server that takes plain bearer tokens must refuse it.
With
[jose](https://github.com/panva/jose):

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const AUTHWAPI = 'http://localhost:4000';
const jwks = createRemoteJWKSet(new URL(`${AUTHWAPI}/api/auth/jwks`));

export async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: AUTHWAPI,
    audience: 'https://mcp.example.com/mcp', // this server; a token without aud fails too
    typ: 'at+jwt',
    requiredClaims: ['exp'],
  });
  if (payload.cnf !== undefined) throw new Error('DPoP-bound token: this server accepts bearer tokens only');
  return payload; // payload.sub is the user, payload.scope the granted scopes
}
```

Don't pass the token on to other APIs: it is for your server only. A JWT stays valid until it expires (15 minutes),
even after the user signs out.

## Refresh

Refresh tokens rotate on every use, with no grace window: presenting a used refresh token fails with
`invalid_grant` and revokes the rest of that client's refresh tokens for the user.
