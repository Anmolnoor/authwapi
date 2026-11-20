---
title: SSO for your organization
description: Let an organization sign its people in with its own OpenID Connect identity provider, registered by an agent over MCP or by the operator CLI, with identities that are never joined by email.
---

An organization can sign its people in with its own OpenID Connect (OIDC) identity provider: Okta, Entra ID,
Google Workspace, Keycloak, or another AuthWAPI. AuthWAPI uses
[Better Auth's SSO plugin](https://better-auth.com/docs/plugins/sso). SAML isn't supported yet.

## Set it up (agent or operator)

You need an organization (`create_org`; its owner's email must be verified, and only a verified user can be made an
owner) and, from the identity provider, an app for AuthWAPI.

1. **Pick a slug** for the provider, such as `acme`. Its ID is `sso-acme`.
2. **At the identity provider**, create a web app (authorization code flow) with:
   - redirect URI `BASE_URL/api/auth/sso/callback/sso-acme`, e.g. `https://auth.example.com/api/auth/sso/callback/sso-acme`
   - scopes `openid email`

   Note its client ID and secret, its issuer (the `iss` in its ID tokens), and its authorization, token and JWKS
   URLs (all listed in its `/.well-known/openid-configuration`).
3. **Register it** over the admin MCP with a write key:

   ```json
   {
     "name": "register_sso_provider",
     "arguments": {
       "organizationId": "<organization id>",
       "slug": "acme",
       "domain": "acme.com",
       "issuer": "https://idp.acme.com",
       "clientId": "<client id>",
       "clientSecret": "<client secret>",
       "authorizationEndpoint": "https://idp.acme.com/authorize",
       "tokenEndpoint": "https://idp.acme.com/token",
       "jwksEndpoint": "https://idp.acme.com/jwks"
     }
   }
   ```

   The result is `{"provider": {"providerId", "organizationId", "domain", "issuer", "redirectUri"}}`. The secret is
   never returned or logged. Or, as the operator, with the secret on stdin:

   ```bash
   printf %s "$CLIENT_SECRET" | docker exec -i -u 1000 authwapi node src/cli.ts sso register --org <organization id> \
     --slug acme --domain acme.com --issuer https://idp.acme.com --client-id <client id> \
     --authorization-endpoint https://idp.acme.com/authorize --token-endpoint https://idp.acme.com/token \
     --jwks-endpoint https://idp.acme.com/jwks
   ```

Both run as the organization's owner and write an audit line in the same transaction. Refusals: `domain_taken`
(another provider has the domain), `insecure_endpoint` (the issuer or an endpoint isn't `https://`),
`organization_not_found`, `owner_email_not_verified`, and Better Auth's own (the ID is taken; an endpoint isn't publicly routable).

| MCP tool | CLI | What |
| --- | --- | --- |
| `register_sso_provider` (write) | `sso register ...` | Add a provider for an organization |
| `list_sso_providers` (read) | `sso list` | Providers with their organization, domain, issuer and redirect URI |
| `delete_sso_provider` (write) | `sso delete <providerId>` | Remove a provider: its bindings go, and its users' sessions and OAuth tokens are revoked |
| — | `sso bind --provider <id> --subject <sub> --user <userId>` | Let an existing, verified account sign in through a provider |

To change a provider, delete it and register it again. Better Auth's HTTP routes for registering, updating,
deleting and domain-verifying providers are turned off (404).

## Signing in

- On the hosted `/sign-in` page: "Sign in with SSO", then the email. Its domain picks the provider. This works during
  an app's sign-in too: the app's request carries on to consent afterwards.
- From code: `POST /api/auth/sign-in/sso` with `{"email": "ada@acme.com", "callbackURL": "/"}` (or `"providerId"`
  instead of the email) returns `{"url"}`; send the browser there. The identity provider sends it back to the
  redirect URI, which signs the user in and redirects to `callbackURL`. A refused sign-in redirects to
  `errorCallbackURL` (or `callbackURL`) with `?error=`.

| `error` | Why |
| --- | --- |
| `account_exists` | An account with this email already exists. SSO doesn't join it; see "Existing accounts" below |
| `email_not_verified` | The identity provider didn't say the email is verified |
| `invalid_provider` | The ID token was refused (signature, issuer, audience or expiry), or the token request failed |
| `invalid_state` | The callback was used already, or doesn't belong to this browser |

## Who someone is

- **An SSO identity is the provider plus the ID token's `sub`.** A provider belongs to one organization and has one
  issuer, so this binds the identity to (organization, issuer, subject). The email domain only picks the provider;
  each domain belongs to one provider, and it is never "verified" to mean more.
- **The first sign-in creates a new user**, a `member` of the provider's organization. Their email is stored
  **unverified**: the organization vouches for it, not the mailbox. Later sign-ins don't touch membership: someone
  the organization removed isn't added back.
- **An existing account is never joined by email**, not even a verified one with the same address. The operator
  binds it to its subject with `sso bind` (the account's email must be verified), which also makes it a member;
  after that, SSO signs in as it.
- **Another organization's provider can't sign in to an identity bound to this one**, even with the same identity
  provider and the same `sub`.

## If an organization claims an address that isn't theirs

An organization could register `gmail.com`, or have its identity provider assert any email. It still gets nobody
else's account: existing accounts aren't joined by email, and an account it creates stays unverified. The real
owner of the address takes it back with "Email me a link" on `/sign-in` (which also verifies the email), or with
"Forgot password?" and then the verification link with the new password. The first proof that someone holds the
mailbox (a magic link, a reset, the verification link) removes, in the same transaction, everything set up before:
SSO bindings, Google/GitHub links, any password but the one just checked, sessions, 2FA, passkeys, OAuth tokens,
consents, unused authorization codes and organization memberships. An admin marking the email verified
(`/admin/update-user` with `emailVerified: true`) does the same. A proof that fails part-way changes nothing, and
the same link works again. The organization's provider can't sign in to it afterwards. (The verification
email that AuthWAPI sends a new SSO user can't verify the account on its own: it has no password.)

This is also what happens if an SSO user signs in by magic link or resets their password themselves: their address
becomes verified and their SSO binding and membership go. The operator can bind it again with `sso bind`.

## Also

- **2FA still applies.** A user who turned on TOTP is asked for a code after the SSO sign-in, before any session.
- **Deleting a provider** ends its users' sessions and revokes their OAuth tokens, in the same transaction. An
  organization with SSO providers can't be deleted, nor the user who registered them, until the providers are (the
  database enforces it too). It always keeps an owner: removing, leaving or demoting its last owner is refused (the database enforces
  it).
- **Client secrets** are stored unencrypted in SQLite, like everything else in the data folder: keep it private.
- **Endpoints must be `https://` and publicly routable** (no `localhost`, private or link-local addresses), and they
  are given explicitly: AuthWAPI doesn't fetch the discovery document.
