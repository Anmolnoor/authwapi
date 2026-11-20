// M4a OIDC SSO per organization (plan flow.md, M4a in "Rev 9 execution"): @better-auth/sso, and the policy around it.
// - Providers are registered and deleted only in-process (admin MCP tools, operator CLI), as the organization's owner;
//   the HTTP routes that change providers are off (SSO_DISABLED_PATHS). Providers are never updated in place.
// - An SSO identity is its account row (providerId, accountId = the ID token's sub). A provider belongs to one
//   organization and has one issuer, so that row is the (org, issuer, subject) binding. resolveUser signs in through
//   a binding or creates a new user; an email or domain never picks an existing account.
// - SSO-created users keep an unverified email (trustEmailVerified stays off) and become members of the provider's
//   organization (only then, in the sign-in transaction: account.create hook). Their mailbox owner takes the address
//   over by magic link, password reset or the verify page; each first mailbox proof clears everything set up before it
//   (purgeUnproven), and so does an admin marking the email verified.
// - Deleting a provider ends its users' sessions and OAuth tokens (guardProviderMutation, inside Better Auth's delete).
//   The owner who registered a provider, and its organization, can't be deleted while it exists (ON DELETE RESTRICT,
//   with friendlier checks in front).
import { createHash } from 'node:crypto';
import { sso, type SSOOptions } from '@better-auth/sso';
import { defineRequestState, getCurrentAdapter, runWithTransaction } from '@better-auth/core/context';
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from 'better-auth';
import type Database from 'better-sqlite3';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import * as z from 'zod';
import { isLoopback } from './config.ts';
import { revokeUserTokens } from './oauth.ts';
import { asUser, deletePendingCodes } from './orgs.ts';

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
 * The first proof that someone controls the account's mailbox, on an account whose email isn't verified yet (a magic
 * link, a password reset, the verify page; or an admin marking it verified) removes everything whoever set the account
 * up could still use: every linked account (SSO bindings, Google/GitHub, and the password unless `keepCredential`:
 * the one just checked), sessions, 2FA, passkeys, OAuth tokens, consents and unused authorization codes, and
 * organization memberships. `verify` also marks the email verified. (Better Auth alone removes only accounts and
 * sessions, one by one, and only on a magic link.)
 * Plain SQL, synchronous, and no transaction of its own: callers run it inside theirs (a Kysely transaction on this
 * same connection includes it), so it commits or rolls back with the proof.
 */
export function purgeUnproven(db: Database.Database, userId: string, { keepCredential, verify }: { keepCredential: boolean; verify: boolean }): void {
  const now = new Date().toISOString();
  db.prepare(`DELETE FROM account WHERE userId = ?${keepCredential ? " AND providerId != 'credential'" : ''}`).run(userId);
  for (const table of ['session', 'twoFactor', 'passkey', 'oauthConsent', 'member']) db.prepare(`DELETE FROM "${table}" WHERE userId = ?`).run(userId);
  // What revokeUserTokens (src/oauth.ts) does, in SQL.
  db.prepare('UPDATE oauthRefreshToken SET revoked = ? WHERE userId = ?').run(now, userId);
  db.prepare('UPDATE oauthAccessToken SET revoked = ? WHERE userId = ?').run(now, userId);
  deletePendingCodes({ options: { database: db } } as never, userId);
  db.prepare(`UPDATE "user" SET twoFactorEnabled = 0, tokensRevokedAt = ?, updatedAt = ?${verify ? ', emailVerified = 1' : ''} WHERE id = ?`).run(now, now, userId);
}

type HookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];

/** The unverified user a magic link or password reset is for, if its token is live (Better Auth's own lookups). */
async function unprovenUser(ctx: HookContext): Promise<string | undefined> {
  let userId: unknown;
  if (ctx.path === '/magic-link/verify') {
    const token = ctx.query?.token;
    if (typeof token !== 'string' || !token) return undefined;
    const pending = await ctx.context.internalAdapter.findVerificationValue(`magic-link:${b64sha256(token)}`); // storeToken: 'hashed'
    if (!pending || pending.expiresAt <= new Date()) return undefined;
    const email = (JSON.parse(pending.value) as { email?: unknown }).email;
    userId = typeof email === 'string' ? (await ctx.context.internalAdapter.findUserByEmail(email))?.user.id : undefined;
  } else {
    const token = ctx.body?.token || ctx.query?.token; // Better Auth's precedence
    const password = ctx.body?.newPassword;
    const { minPasswordLength, maxPasswordLength } = ctx.context.password.config;
    // A password Better Auth will refuse changes nothing, so it proves nothing here either.
    if (typeof token !== 'string' || !token || typeof password !== 'string' || password.length < minPasswordLength || password.length > maxPasswordLength) return undefined;
    const pending = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
    if (!pending || pending.expiresAt <= new Date()) return undefined;
    userId = pending.value;
  }
  const user = typeof userId === 'string' ? await ctx.context.internalAdapter.findUserById(userId) : null;
  return user && !user.emailVerified ? user.id : undefined;
}

const isSsoProviderId = (providerId: unknown) => typeof providerId === 'string' && providerId.startsWith(SSO_PROVIDER_PREFIX);

function ssoGlue(db: Database.Database): BetterAuthPlugin {
  return {
    id: 'authwapi-sso',
    // Neither the user who registered a provider nor its organization can be deleted while it exists: their rows would
    // otherwise take it (or leave it) without guardProviderMutation. Replaces the SSO plugin's userId (cascade) and
    // organizationId (no reference) fields.
    schema: {
      ssoProvider: {
        fields: {
          userId: { type: 'string', required: true, references: { model: 'user', field: 'id', onDelete: 'restrict' } },
          organizationId: { type: 'string', required: false, references: { model: 'organization', field: 'id', onDelete: 'restrict' } },
        },
      },
    },
    init: (context) => ({
      options: {
        databaseHooks: {
          account: {
            create: {
              // Inside Better Auth's SSO sign-in transaction (an SSO account is created only with its new user: SSO never
              // links one to an existing user, and `sso bind` writes its own): the member commits with the user.
              before: async (account) => {
                if (!isSsoProviderId(account.providerId)) return;
                const trx = await getCurrentAdapter(context.adapter);
                const provider = await trx.findOne<{ organizationId: string | null }>({ model: 'ssoProvider', where: [{ field: 'providerId', value: account.providerId }] });
                if (!provider?.organizationId) return;
                await trx.create({ model: 'member', data: { organizationId: provider.organizationId, userId: account.userId, role: 'member', createdAt: new Date() } });
              },
            },
          },
          user: {
            update: {
              // An admin marking an unverified email verified (/admin/update-user, inside its transaction): the same purge,
              // keeping the password. The hook gets no user id, so it comes from the request.
              before: async (data, ctx) => {
                if (data.emailVerified !== true || ctx?.path !== '/admin/update-user' || typeof ctx.body?.userId !== 'string') return;
                const user = db.prepare('SELECT emailVerified FROM "user" WHERE id = ?').get(ctx.body.userId) as { emailVerified: number } | undefined;
                if (user && !user.emailVerified) purgeUnproven(db, ctx.body.userId, { keepCredential: true, verify: false });
              },
            },
          },
        },
      },
    }),
    hooks: {
      before: [
        {
          // Runs before Better Auth consumes the token and signs in or sets the password.
          matcher: (ctx) => ctx.path === '/magic-link/verify' || ctx.path === '/reset-password',
          handler: createAuthMiddleware(async (ctx) => {
            const userId = await unprovenUser(ctx);
            if (!userId) return;
            // A Kysely transaction holds the connection, so no other request's transaction can contain this one.
            await runWithTransaction(ctx.context.adapter, async () =>
              purgeUnproven(db, userId, { keepCredential: false, verify: ctx.path === '/magic-link/verify' })
            );
          }),
        },
        {
          matcher: (ctx) => ctx.path === '/admin/remove-user',
          handler: createAuthMiddleware(async (ctx) => {
            const userId = ctx.body?.userId;
            if (typeof userId !== 'string') return;
            if (await ctx.context.adapter.findOne({ model: 'ssoProvider', where: [{ field: 'userId', value: userId }] })) {
              throw new APIError('BAD_REQUEST', { code: 'USER_REGISTERED_SSO_PROVIDERS', message: 'This user registered SSO providers: delete those SSO providers first.' });
            }
          }),
        },
      ],
    },
  };
}

/** The SSO plugin and the recovery hook. Added to authOptions().plugins, after the organization plugin. */
export function ssoPlugins(db: Database.Database): Plugin[] {
  return [
    sso({
      resolveUser,
      guardProviderMutation,
      // providersLimit: Better Auth's default (10 per registering owner). 0 would also refuse our own server-side calls.
      // Better Auth's provisioning would (re)add the member on every sign-in, after the sign-in commits. Only users SSO
      // creates join, in the same transaction (ssoGlue's account hook); `sso bind` adds the member it binds.
      organizationProvisioning: { disabled: true },
    }),
    ssoGlue(db),
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

const providerWithDomain = async (context: AuthContext, domain: string) =>
  (await getCurrentAdapter(context.adapter)).findMany<{ providerId: string }>({ model: 'ssoProvider', where: [{ field: 'domain', value: domain }] });

/**
 * Registers an OIDC provider for an organization, through Better Auth's /sso/register run as the organization's
 * owner (it checks the owner role, reserved and taken IDs, and that endpoints aren't private hosts). A domain belongs
 * to one provider. `audit` writes the caller's line; if it can't, the provider is deleted again.
 */
export async function registerSsoProvider(context: AuthContext, api: unknown, input: SsoProviderInput, audit: (providerId: string) => void): Promise<SsoProviderSummary> {
  const endpoints = api as SsoEndpoints;
  const providerId = `${SSO_PROVIDER_PREFIX}${input.slug}`;
  // https only; plain http just for a loopback origin the operator listed as trusted (ALLOWED_HOSTS; the test IdP).
  for (const raw of [input.issuer, input.authorizationEndpoint, input.tokenEndpoint, input.jwksEndpoint]) {
    const u = new URL(raw);
    if (u.protocol !== 'https:' && !(isLoopback(u) && context.isTrustedOrigin(u.href))) throw new SsoRefusal('insecure_endpoint');
  }
  const owner = await ownerOf(context, input.organizationId);
  // An unverified owner's first mailbox proof would purge their membership, leaving a provider nobody can delete.
  if (!(await context.internalAdapter.findUserById(owner))?.emailVerified) throw new SsoRefusal('owner_email_not_verified');
  // One transaction with the caller's audit line: a provider that can't be audited is never registered. Better Auth's
  // endpoint joins it (the owner-session hook in src/orgs.ts hands it the transaction's adapter). SQLite runs one
  // transaction at a time, so the domain check can't race another registration.
  return runWithTransaction(context.adapter, async () => {
    if ((await providerWithDomain(context, input.domain)).length > 0) throw new SsoRefusal('domain_taken');
    // Bindings left by a provider that went without Better Auth's delete would sign their subjects in through a new
    // provider with this ID.
    if (await (await getCurrentAdapter(context.adapter)).findOne({ model: 'account', where: [{ field: 'providerId', value: providerId }] })) throw new SsoRefusal('provider_id_taken');
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
    audit(providerId);
    return { providerId, organizationId: input.organizationId, domain: input.domain, issuer: input.issuer, redirectUri: ssoRedirectUri(context, providerId) };
  });
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
    const provider = await db.findOne<{ organizationId: string }>({ model: 'ssoProvider', where: [{ field: 'providerId', value: providerId }] });
    if (!provider) throw new SsoRefusal('provider_not_found');
    const user = await db.findOne<{ emailVerified: boolean }>({ model: 'user', where: [{ field: 'id', value: userId }] });
    if (!user) throw new SsoRefusal('user_not_found');
    if (!user.emailVerified) throw new SsoRefusal('email_not_verified');
    const binding = [{ field: 'providerId', value: providerId }, { field: 'accountId', value: subject }];
    if (await db.findOne({ model: 'account', where: binding })) throw new SsoRefusal('subject_already_bound');
    if (await db.findOne({ model: 'account', where: [{ field: 'providerId', value: providerId }, { field: 'userId', value: userId }] })) throw new SsoRefusal('user_already_bound');
    const now = new Date();
    await db.create({ model: 'account', data: { providerId, accountId: subject, userId, createdAt: now, updatedAt: now } });
    // The operator's bind is the decision to join the organization (SSO sign-in adds no member for existing users).
    const membership = [{ field: 'organizationId', value: provider.organizationId }, { field: 'userId', value: userId }];
    if (!(await db.findOne({ model: 'member', where: membership }))) {
      await db.create({ model: 'member', data: { organizationId: provider.organizationId, userId, role: 'member', createdAt: now } });
    }
    audit();
  });
}
