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

Linking fetches nothing. AuthWAPI fetches a client's metadata document only when a user signs in through that
client, and only if the operator linked its URL: any other `client_id` URL is refused without a request going out.
The URL must be `https` on a public host, with a path and no fragment or credentials; loopback and private
addresses are always refused, and the fetch resolves DNS once, refuses private addresses, and follows no
redirects. The document must name the client (`client_name`), list its `redirect_uris`, and use
`token_endpoint_auth_method` `none` or `private_key_jwt`.

An MCP client without a metadata document (one on `localhost`, say) can use a client made with
`clients create` instead: `resource link <its client_id> <resource>` links it the same way.

The consent page shows the client's name and the host of its metadata URL. The name is whatever the document says;
the host is where the client really comes from.

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
refused: that is what stops a token for one MCP server working on another. With
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
  return payload; // payload.sub is the user, payload.scope the granted scopes
}
```

Don't pass the token on to other APIs: it is for your server only. A JWT stays valid until it expires (15 minutes),
even after the user signs out.

## Refresh

Refresh tokens rotate on every use, with no grace window: presenting a used refresh token fails with
`invalid_grant` and revokes the rest of that client's refresh tokens for the user.
