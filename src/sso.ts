// M4a OIDC SSO per organization (plan flow.md, M4a in "Rev 9 execution"): @better-auth/sso, and the policy around it.
// - Providers are registered and deleted only in-process (admin MCP tools, operator CLI), as the organization's owner;
//   the HTTP routes that change providers are off (SSO_DISABLED_PATHS). Providers are never updated in place.
// - An SSO identity is its account row (providerId, accountId = the ID token's sub). A provider belongs to one
//   organization and has one issuer, so that row is the (org, issuer, subject) binding. resolveUser signs in through
//   a binding or creates a new user; an email or domain never picks an existing account.
// - SSO-created users keep an unverified email (trustEmailVerified stays off). Their mailbox owner takes the address
//   over by magic link (recoverByMagicLink), which clears everything set up before that proof.
// - Deleting a provider ends its users' sessions and OAuth tokens (guardProviderMutation, inside Better Auth's delete).
import { createHash } from 'node:crypto';
import { sso, type SSOOptions } from '@better-auth/sso';
import { defineRequestState, getCurrentAdapter, runWithTransaction } from '@better-auth/core/context';
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware } from 'better-auth/api';
import * as z from 'zod';
import { revokeUserTokens } from './oauth.ts';
import { asUser } from './orgs.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];

/** Every SSO provider ID starts with this, so it can't collide with credential, google, github... account rows. */
export const SSO_PROVIDER_PREFIX = 'sso-';

/** Better Auth's provider-changing routes, closed over HTTP. Server-side calls still reach them (src/admin.ts, src/cli.ts). */
export const SSO_DISABLED_PATHS = ['/sso/register', '/sso/update-provider', '/sso/delete-provider', '/sso/request-domain-verification', '/sso/verify-domain'];

/** Where the IdP sends the browser back (Better Auth's per-provider callback): register this redirect URI with the IdP. */
const ssoRedirectUri = (context: AuthContext, providerId: string) => `${context.baseURL}/sso/callback/${providerId}`;

/** Called inside Better Auth's delete transaction, after the revocations: a caller's audit line, so a delete that can't be audited is rolled back. */
const providerDeleted = defineRequestState<(() => void) | undefined>(() => undefined);

const reject = (code: string, message: string) => ({ action: 'reject' as const, code, message });

/**
 * Runs inside Better Auth's sign-in transaction, after the ID token's signature, issuer, audience and expiry are
 * checked. A bound subject signs in as its user; an unbound one becomes a new user, unless an account already has
 * that email (it is never linked by email: the operator binds it with `sso bind`).
 */
const resolveUser: NonNullable<SSOOptions['resolveUser']> = async (input, { database }) => {
  if (input.protocol !== 'oidc') return reject('sso_protocol_not_supported', 'Only OIDC providers are supported.');
  // The claims the profile came from (the verified ID token: providers have no userinfo endpoint here).
  if (input.providerClaims.email_verified !== true) return reject('email_not_verified', "The identity provider didn't confirm this email address.");
  const binding = [
    { field: 'providerId', value: input.providerId },
    { field: 'accountId', value: input.accountKey.accountId },
  ];
  if (await database.findOne({ model: 'account', where: binding })) return { action: 'continue' };
  if (await database.findOne({ model: 'user', where: [{ field: 'email', value: input.providerUser.email.toLowerCase() }] })) {
    return reject('account_exists', 'An account with this email already exists. Ask the operator to bind it to this sign-in.');
  }
  return { action: 'continue' };
};

/**
 * Runs inside Better Auth's provider delete, after the row is locked and before the provider and its bindings go:
 * every user signed in through it loses their sessions and OAuth tokens. Updates are refused (none are exposed).
 */
const guardProviderMutation: NonNullable<SSOOptions['guardProviderMutation']> = async (input, { database }) => {
  if (input.action !== 'delete') throw new Error('SSO providers are not updated in place: delete and register again.');
  const bindings = await database.findMany<{ userId: string }>({ model: 'account', where: [{ field: 'providerId', value: input.provider.providerId }] });
  for (const userId of new Set(bindings.map((b) => b.userId))) {
    await database.deleteMany({ model: 'session', where: [{ field: 'userId', value: userId }] });
    await revokeUserTokens({ adapter: database as never }, userId);
  }
  (await providerDeleted.get())?.();
};

const b64sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');

/**
 * A magic link to an account whose email isn't verified yet is its mailbox owner's first proof. Before Better Auth
 * signs them in, one transaction removes everything that whoever set the account up could still use: every linked
 * account (password, SSO bindings, Google/GitHub), sessions, 2FA, passkeys, OAuth tokens and consents; then the email
 * counts as verified. (Better Auth alone would remove only accounts and sessions, one by one.)
 */
function recoverByMagicLink(): BetterAuthPlugin {
  return {
    id: 'authwapi-sso',
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === '/magic-link/verify',
          handler: createAuthMiddleware(async (ctx) => {
            const token = ctx.query?.token;
            if (typeof token !== 'string' || !token) return;
            // Better Auth's own lookup (storeToken: 'hashed'); it consumes the token after this hook.
            const pending = await ctx.context.internalAdapter.findVerificationValue(`magic-link:${b64sha256(token)}`);
            if (!pending || pending.expiresAt <= new Date()) return;
            const email = (JSON.parse(pending.value) as { email?: unknown }).email;
            const found = typeof email === 'string' ? await ctx.context.internalAdapter.findUserByEmail(email) : null;
            if (!found || found.user.emailVerified) return;
            const userId = found.user.id;
            await runWithTransaction(ctx.context.adapter, async () => {
              const db = await getCurrentAdapter(ctx.context.adapter);
              const where = [{ field: 'userId', value: userId }];
              for (const model of ['account', 'session', 'twoFactor', 'passkey', 'oauthConsent']) await db.deleteMany({ model, where });
              await revokeUserTokens(ctx.context, userId);
              await db.update({ model: 'user', where: [{ field: 'id', value: userId }], update: { emailVerified: true, twoFactorEnabled: false } });
            });
          }),
        },
      ],
    },
  };
}

/** The SSO plugin and the recovery hook. Added to authOptions().plugins, after the organization plugin. */
export function ssoPlugins(): Plugin[] {
  return [
    sso({
      resolveUser,
      guardProviderMutation,
      // providersLimit: Better Auth's default (10 per registering owner). 0 would also refuse our own server-side calls.
      // organizationProvisioning: Better Auth's default, members of the provider's organization (role member).
    }),
    recoverByMagicLink(),
  ];
}

const url = z.url({ protocol: /^https?$/ }).max(2048);
/** What registering an OIDC provider takes (admin MCP register_sso_provider, CLI `sso register`). Endpoints are explicit: no discovery. */
export const ssoProviderInput = z.object({
  organizationId: z.string().min(1).max(200),
  slug: z.string().max(48).regex(/^[a-z0-9]+(-[a-z0-9]+)*$/), // the provider ID is sso-<slug>
  domain: z.string().max(253).regex(/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/), // routes sign-ins only
  issuer: url,
  clientId: z.string().min(1).max(500),
  clientSecret: z.string().min(1).max(2000),
  authorizationEndpoint: url,
  tokenEndpoint: url,
  jwksEndpoint: url,
});
export type SsoProviderInput = z.infer<typeof ssoProviderInput>;

/** What callers see of a provider: never the client secret. */
export interface SsoProviderSummary {
  providerId: string;
  organizationId: string;
  domain: string;
  issuer: string;
  redirectUri: string;
}

/** The SSO plugin's endpoints, called in-process (authOptions() is typed as plain BetterAuthOptions, so auth.api doesn't list them). */
interface SsoEndpoints {
  registerSSOProvider: (input: { body: object; headers: Headers }) => Promise<unknown>;
  deleteSSOProvider: (input: { body: { providerId: string }; headers: Headers }) => Promise<unknown>;
}

export class SsoRefusal extends Error {}

/** The organization's first owner, whom Better Auth's register and delete run as. */
async function ownerOf(context: AuthContext, organizationId: string): Promise<string> {
  const members = await context.adapter.findMany<{ userId: string; role: string; createdAt: Date }>({
    model: 'member',
    where: [{ field: 'organizationId', value: organizationId }],
  });
  const owners = members.filter((m) => m.role.split(',').map((r) => r.trim()).includes('owner'));
  owners.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  if (!owners[0]) throw new SsoRefusal('organization_not_found');
  return owners[0].userId;
}

const providerWithDomain = (context: AuthContext, domain: string) =>
  context.adapter.findMany<{ providerId: string }>({ model: 'ssoProvider', where: [{ field: 'domain', value: domain }] });

/**
 * Registers an OIDC provider for an organization, through Better Auth's /sso/register run as the organization's
 * owner (it checks the owner role, reserved and taken IDs, and that endpoints aren't private hosts). A domain belongs
 * to one provider. `audit` writes the caller's line; if it can't, the provider is deleted again.
 */
export async function registerSsoProvider(context: AuthContext, api: unknown, input: SsoProviderInput, audit: (providerId: string) => void): Promise<SsoProviderSummary> {
  const endpoints = api as SsoEndpoints;
  const providerId = `${SSO_PROVIDER_PREFIX}${input.slug}`;
  const owner = await ownerOf(context, input.organizationId);
  if ((await providerWithDomain(context, input.domain)).length > 0) throw new SsoRefusal('domain_taken');
  // Bindings left by a provider that went without Better Auth's delete (its registering owner was deleted, say) would
  // sign their subjects in through a new provider with this ID.
  if (await context.adapter.findOne({ model: 'account', where: [{ field: 'providerId', value: providerId }] })) throw new SsoRefusal('provider_id_taken');
  await asUser(owner, () =>
    endpoints.registerSSOProvider({
      headers: new Headers(),
      body: {
        providerId,
        issuer: input.issuer,
        domain: input.domain,
        organizationId: input.organizationId,
        oidcConfig: {
          clientId: input.clientId,
          clientSecret: input.clientSecret,
          authorizationEndpoint: input.authorizationEndpoint,
          tokenEndpoint: input.tokenEndpoint,
          jwksEndpoint: input.jwksEndpoint,
          tokenEndpointAuthentication: 'client_secret_basic',
          scopes: ['openid', 'email'],
          pkce: true,
          skipDiscovery: true,
        },
      },
    })
  );
  try {
    // Two registrations of one domain at once: the check above passed for both, so neither keeps it.
    if ((await providerWithDomain(context, input.domain)).length > 1) throw new SsoRefusal('domain_taken');
    audit(providerId);
  } catch (err) {
    await deleteSsoProvider(context, api, providerId, () => {});
    throw err;
  }
  return { providerId, organizationId: input.organizationId, domain: input.domain, issuer: input.issuer, redirectUri: ssoRedirectUri(context, providerId) };
}

/**
 * Deletes a provider and its bindings through Better Auth's /sso/delete-provider, run as the organization's owner; its
 * users lose their sessions and OAuth tokens (guardProviderMutation). `audit` runs inside that transaction.
 */
export async function deleteSsoProvider(context: AuthContext, api: unknown, providerId: string, audit: () => void): Promise<void> {
  const endpoints = api as SsoEndpoints;
  const provider = await context.adapter.findOne<{ organizationId: string }>({ model: 'ssoProvider', where: [{ field: 'providerId', value: providerId }] });
  if (!provider) throw new SsoRefusal('provider_not_found');
  await asUser(await ownerOf(context, provider.organizationId), async () => {
    await providerDeleted.set(audit);
    await endpoints.deleteSSOProvider({ headers: new Headers(), body: { providerId } });
  });
}

/** Every provider, oldest first, or one organization's. */
export async function listSsoProviders(context: AuthContext, organizationId?: string): Promise<SsoProviderSummary[]> {
  const rows = await context.adapter.findMany<{ providerId: string; organizationId: string; domain: string; issuer: string }>({
    model: 'ssoProvider',
    where: organizationId ? [{ field: 'organizationId', value: organizationId }] : [],
    sortBy: { field: 'providerId', direction: 'asc' },
  });
  return rows.map(({ providerId, organizationId: org, domain, issuer }) => ({ providerId, organizationId: org, domain, issuer, redirectUri: ssoRedirectUri(context, providerId) }));
}

/**
 * The operator's pre-provisioned binding (CLI `sso bind`): the subject `sub` at this provider signs in as an existing
 * user. The user's email must be verified (an unverified account may be someone else's pre-registration).
 */
export async function bindSsoIdentity(context: AuthContext, providerId: string, subject: string, userId: string, audit: () => void): Promise<void> {
  await runWithTransaction(context.adapter, async () => {
    const db = await getCurrentAdapter(context.adapter);
    if (!(await db.findOne({ model: 'ssoProvider', where: [{ field: 'providerId', value: providerId }] }))) throw new SsoRefusal('provider_not_found');
    const user = await db.findOne<{ emailVerified: boolean }>({ model: 'user', where: [{ field: 'id', value: userId }] });
    if (!user) throw new SsoRefusal('user_not_found');
    if (!user.emailVerified) throw new SsoRefusal('email_not_verified');
    const binding = [{ field: 'providerId', value: providerId }, { field: 'accountId', value: subject }];
    if (await db.findOne({ model: 'account', where: binding })) throw new SsoRefusal('subject_already_bound');
    if (await db.findOne({ model: 'account', where: [{ field: 'providerId', value: providerId }, { field: 'userId', value: userId }] })) throw new SsoRefusal('user_already_bound');
    const now = new Date();
    await db.create({ model: 'account', data: { providerId, accountId: subject, userId, createdAt: now, updatedAt: now } });
    audit();
  });
}
