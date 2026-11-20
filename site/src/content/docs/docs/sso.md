---
title: SSO for your organization
description: Let an organization sign its people in with its own OpenID Connect or SAML identity provider, registered by an agent over MCP or by the operator CLI, with identities that are never joined by email.
---

An organization can sign its people in with its own identity provider, over OpenID Connect (OIDC) or
[SAML 2.0](#saml): Okta, Entra ID, Google Workspace, Keycloak, or another AuthWAPI. AuthWAPI uses
[Better Auth's SSO plugin](https://better-auth.com/docs/plugins/sso). Everything on this page applies to both,
except where a section says OIDC or SAML.

## Set it up with OIDC (agent or operator)

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

   The result is `{"provider": {"providerId", "organizationId", "domain", "issuer", "protocol": "oidc", "redirectUri"}}`. The secret is
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
| `list_sso_providers` (read) | `sso list` | Providers with their organization, domain, protocol, issuer, and redirect URI (OIDC) or ACS URL and SP entity ID (SAML) |
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

- **An SSO identity is the provider plus the ID token's `sub`** (SAML: the assertion's NameID). A provider belongs
  to one organization and has one issuer, so this binds the identity to (organization, issuer, subject). The email domain only picks the provider;
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
  organization with SSO providers can't be deleted, nor the user who registered them, until the providers are. It
  always keeps an owner: removing, leaving or demoting its last owner is refused. The database enforces both.
- **Client secrets** and SAML configuration are stored unencrypted in SQLite, like everything else in the data
  folder: keep it private (see [SAML keys](#saml-keys-and-what-is-stored)).
- **OIDC endpoints must be `https://` and publicly routable** (no `localhost`, private or link-local addresses), and
  they are given explicitly: AuthWAPI doesn't fetch the discovery document.

## SAML

SAML providers sign in through the same plugin (it uses [samlify](https://github.com/tngan/samlify)), with the
same rules as OIDC: registered only over MCP or the CLI, routed by email domain, bound to their organization, never
joined by email, new users unverified, 2FA after sign-in, deleted with their sessions.

### Set it up

1. **Pick a slug**, such as `acme` (provider ID `sso-acme`). The two values the identity provider needs are:
   - **ACS URL** (reply URL, single sign-on URL): `BASE_URL/api/auth/sso/saml2/sp/acs/sso-acme`
   - **SP entity ID** (audience URI, identifier): `BASE_URL/api/auth/sso/saml2/sp/metadata?providerId=sso-acme`.
     That URL also serves the SP metadata, if the identity provider imports metadata.
2. **At the identity provider**, create a SAML app with those values, and set:
   - **Name ID format: persistent**, with a value that never changes and is never reused (an internal user ID).
   - **An attribute named `email`** with the user's email address.
   - **Signed assertions**, RSA-SHA256 or stronger. Signing the response as well is fine; signing only the
     response is refused. Don't encrypt the assertion: TLS protects it.
   - SP-initiated sign-in. Sign-in started from the identity provider's dashboard (IdP-initiated) is refused.
3. **Register it**, with the identity provider's metadata XML:

   ```json
   {
     "name": "register_sso_provider",
     "arguments": {
       "protocol": "saml",
       "organizationId": "<organization id>",
       "slug": "acme",
       "domain": "acme.com",
       "idpMetadata": "<?xml version=\"1.0\"?><EntityDescriptor ...>...</EntityDescriptor>"
     }
   }
   ```

   or, without metadata, its entity ID, SSO URL (HTTP-Redirect binding) and signing certificate:
   `"idpEntityId"`, `"idpSsoUrl"`, `"idpSigningCert"` (PEM) in place of `"idpMetadata"`. The result is
   `{"provider": {"providerId", "organizationId", "domain", "issuer", "protocol": "saml", "acsUrl", "spEntityId"}}`,
   where `issuer` is the identity provider's entity ID. As the operator, the metadata (or, with `--idp-entity-id`
   and `--idp-sso-url`, the certificate) goes on stdin:

   ```bash
   docker exec -i -u 1000 authwapi node src/cli.ts sso register --protocol saml --org <organization id> \
     --slug acme --domain acme.com < idp-metadata.xml
   ```

Refusals, besides OIDC's: `invalid_idp_metadata`, `insecure_endpoint` and `idp_signing_cert_missing` (the
metadata must have an `https` HTTP-Redirect SSO URL and a signing certificate), `invalid_idp_signing_cert`, and
input errors (both metadata and the manual fields, or OIDC fields on a SAML provider). Plain `http` is accepted only
for a loopback SSO URL whose origin AuthWAPI trusts (`BASE_URL` or `ALLOWED_HOSTS`): a test IdP on your machine.
`scripts/saml-idp-check.sh` runs a full sign-in against a SimpleSAMLphp IdP that way.

### What a sign-in must pass

AuthWAPI sends a SAML AuthnRequest asking for a persistent NameID, and the identity provider posts its response to
the ACS URL. The response is refused, and the browser sent to `errorCallbackURL` with `?error=`, unless:

| Check | `error` when it fails |
| --- | --- |
| The assertion is signed by the certificate registered for this provider (a signature on the response alone isn't enough) | `saml_error` or `invalid_saml_response` |
| Its audience is this provider's SP entity ID, and its recipient this provider's ACS URL | `saml_error` or `invalid_saml_response` |
| It answers an AuthnRequest AuthWAPI sent, for this provider, in the last 5 minutes, that wasn't answered before | `invalid_saml_response` |
| It answers an AuthnRequest at all (no IdP-initiated responses) | `unsolicited_response` |
| Its `Conditions` carry `NotBefore`/`NotOnOrAfter`, and now is inside them (5 minutes' clock skew) | `saml_error` |
| Its ID wasn't used before | `replay_detected` |
| Signatures and digests are SHA-256 or stronger (SHA-1 is refused) | `saml_deprecated_algorithm` |
| The NameID's format is `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | `nameid_not_persistent` |
| An `email` attribute holds an email address | `email_missing` |
| No other account has that email (see [Who someone is](#who-someone-is)) | `account_exists` |

The identity is (provider, NameID). The email attribute only fills in the new user's address: a later sign-in with
the same NameID is the same user even if the email changed. Transient NameIDs would make a new user at every
sign-in, and email-format ones would follow an address that can be renamed or reassigned, so both are refused.
`sso bind --subject` takes the NameID for a SAML provider.

### Okta, Entra ID, Google Workspace

- **Okta**: create an app integration, SAML 2.0. Single sign-on URL: the ACS URL (also the recipient and
  destination). Audience URI: the SP entity ID. Name ID format: Persistent. Application username: one that never
  changes, e.g. a custom `user.getInternalProperty("id")` (the Okta user ID). Attribute statement: `email` =
  `user.email`. Keep the assertion signed, RSA-SHA256. Then download the IdP metadata from the app's Sign On tab.
- **Entra ID**: Enterprise applications → New application → your own → Single sign-on → SAML. Identifier (Entity
  ID): the SP entity ID. Reply URL: the ACS URL. Attributes & Claims: set the Unique User Identifier (Name ID) to
  format Persistent, source `user.objectid`, and add a claim named `email` (no namespace) from `user.mail`. SAML
  Signing Certificate: signing option "Sign SAML assertion" (or response and assertion), SHA-256. Then download the
  Federation Metadata XML.
- **Google Workspace**: Admin console → Apps → Web and mobile apps → Add custom SAML app. Download the IdP
  metadata. ACS URL and Entity ID: the two values above. Name ID format: PERSISTENT. Attribute mapping: Primary
  email → `email`. Google's Name ID can only be a directory field such as the primary email: if a user's address is
  renamed, AuthWAPI sees a new identity, refused with `account_exists`, until the operator binds the new NameID with
  `sso bind`.

### SAML keys and what is stored

AuthWAPI holds no SAML private key: AuthnRequests aren't signed and assertions aren't encrypted. Each provider's
identity provider metadata (or entity ID, SSO URL and signing certificate) is stored **unencrypted in SQLite**, in
the data folder, like OIDC client secrets. The certificate is public, but it is what AuthWAPI trusts: anyone who
can write to the data folder can replace it and sign in as that organization's users (they could also change any
account directly). Keep the data folder private and its backups as safe as the server.
