// OAuth 2.1 / OIDC provider for apps (plan D9). Better Auth's oauthProvider + jwt plugins, configured so that:
// - the issuer is BASE_URL, ID tokens have aud = client ID, access tokens requested with `resource` are JWTs with
//   aud = that resource and live 15 minutes;
// - clients are created only by the operator CLI (src/cli.ts), never over HTTP;
// - sign-out revokes the session and every refresh and opaque access token the user holds;
// - (M3) a banned user gets no tokens, even when the ban races the issuance, and their tokens introspect inactive;
// - (M3) org claims (org_id, roles) come with the organization scope, in access tokens and userinfo only, for the
//   organization picked at sign-in (SELECT_ORG_PAGE), bound to the grant and re-checked whenever tokens are issued.
import { randomUUID } from 'node:crypto';
import { defineRequestState } from '@better-auth/core/context';
import { getOAuthProviderApi, oauthProvider } from '@better-auth/oauth-provider';
import { getCurrentAdapter, type AuthContext, type BetterAuthOptions, type BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware, isAPIError } from 'better-auth/api';
import { parseAccessTokenAuthorization } from 'better-auth/oauth2';
import { jwt } from 'better-auth/plugins';
import { Hono } from 'hono';
import type { AuthDeps } from './auth.ts';
import type { AuthCall } from './app.ts';
import { isLoopback, type Config } from './config.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

/** What an authorization request without `scope` gets (M1's scopes; `organization` must be asked for). */
const DEFAULT_SCOPE = 'openid email offline_access';

/** The provider's postLogin page: the user picks the organization an app's organization scope is for. */
export const SELECT_ORG_PAGE = '/select-org';

/**
 * Better Auth's client and resource admin endpoints require a signed-in session. The CLI has none, so calls it
 * makes in-process (no HTTP request; these endpoints are server-only anyway) run as this operator session, and
 * clientPrivileges/resourcePrivileges accept only it. The id is random per process, so no real session matches.
 */
const OPERATOR_ID = `operator-${randomUUID()}`;
const operatorSession = () => {
  const now = new Date();
  return {
    session: { id: OPERATOR_ID, token: OPERATOR_ID, userId: OPERATOR_ID, createdAt: now, updatedAt: now, expiresAt: new Date(now.getTime() + 60_000) },
    user: { id: OPERATOR_ID, email: 'operator@authwapi.invalid', emailVerified: true, name: 'AuthWAPI CLI', createdAt: now, updatedAt: now },
  };
};
const isOperator = ({ session }: { session?: { id: string } }) => session?.id === OPERATOR_ID;

type HookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type ProviderOptions = Parameters<typeof oauthProvider>[0];

/**
 * Revokes every refresh and opaque access token the user holds, for every client (offline_access ones included),
 * and records when, so introspection can report older JWT access tokens inactive too (see introspectionGuard).
 */
export async function revokeUserTokens(context: Pick<AuthContext, 'adapter'>, userId: string): Promise<void> {
  const now = new Date();
  // Inside a transaction (an end-session delete may run in one) queries outside it would wait forever.
  const adapter = await getCurrentAdapter(context.adapter);
  const where = [{ field: 'userId', value: userId }];
  await adapter.updateMany({ model: 'oauthRefreshToken', where, update: { revoked: now } });
  await adapter.updateMany({ model: 'oauthAccessToken', where, update: { revoked: now } });
  await adapter.update({ model: 'user', where: [{ field: 'id', value: userId }], update: { tokensRevokedAt: now } });
}

/**
 * Requests that end the user's sessions (or reset the password). Each one revokes the user's tokens BEFORE Better
 * Auth runs it, once per request, whether or not any session row is left to delete (an expired session may already
 * have been cleared). If revoking fails, the request fails and its sessions stay: /sign-out would otherwise swallow
 * the error and report success. A request Better Auth then refuses (wrong current password, say) has still revoked
 * the tokens: only someone holding the user's session or reset token can cause that.
 * Clearing an expired session is not on this list: offline_access tokens outlive the browser session.
 * An impersonated session (M3) ending itself or the target's sessions revokes none of the target's tokens.
 */
const SIGN_OUT_PATHS = new Set(['/sign-out', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions', '/change-password', '/reset-password']);

async function userEndingSessions(ctx: HookContext): Promise<string | undefined> {
  if (ctx.path === '/reset-password') {
    const token = ctx.body?.token || ctx.query?.token; // Better Auth's precedence: an empty body token falls through
    if (typeof token !== 'string' || !token) return undefined; // Better Auth refuses it
    // The same lookup Better Auth makes; it hashes the identifier (verification.storeIdentifier: 'hashed').
    const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
    return verification && verification.expiresAt > new Date() ? verification.value : undefined;
  }
  if (ctx.path === '/change-password' && ctx.body?.revokeOtherSessions !== true) return undefined;
  // The session the cookie names, expired or not, exactly as /sign-out finds it.
  const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
  if (!token) return undefined;
  const session = (await ctx.context.internalAdapter.findSession(token))?.session as { userId: string; impersonatedBy?: string | null } | undefined;
  return session?.impersonatedBy ? undefined : session?.userId;
}

/** Each auth instance's context, by the deps it was built from, for revokeTokensAfterPasswordReset. */
const authContexts = new WeakMap<AuthDeps, AuthContext>();

/**
 * For emailAndPassword.onPasswordReset, which Better Auth calls once the new password is saved and the sessions are
 * deleted. The reset's before-hook revoked the tokens already, but while the password was being hashed a session
 * could still mint new ones (an authorization code exchanged in that window); revoking again here catches them.
 */
export async function revokeTokensAfterPasswordReset(deps: AuthDeps, userId: string): Promise<void> {
  const context = authContexts.get(deps);
  if (!context) throw new Error('revokeTokensAfterPasswordReset: no auth instance was built from these deps');
  await revokeUserTokens(context, userId);
}

/**
 * RP-initiated logout deletes a session only after Better Auth has verified the id_token_hint or the user's
 * confirmation, and it fails the request if the delete (so this hook) fails. Revoking on that row's deletion
 * reuses its checks. A hint whose session is already gone revokes nothing (the app can revoke its own token).
 */
const END_SESSION_PATHS = new Set(['/oauth2/end-session', '/oauth2/end-session/confirm']);

const invalidTarget = () =>
  new APIError('BAD_REQUEST', { error: 'invalid_target', error_description: 'resource was not part of the authorization request' });

/**
 * Better Auth checks a token request's `resource` against the grant only when the grant named resources; a grant
 * without any would accept any registered resource. Here an authorization without `resource` grants none.
 */
async function rejectResourceNotGranted(ctx: HookContext, opts: ProviderOptions): Promise<void> {
  const requested = [ctx.body?.resource].flat().filter(Boolean);
  if (requested.length === 0) return;
  const { hashToken } = getOAuthProviderApi(ctx, opts);
  // The hook sees the raw body; Better Auth's schema trims grant_type before dispatching on it.
  const grantType = typeof ctx.body.grant_type === 'string' ? ctx.body.grant_type.trim() : undefined;
  if (grantType === 'authorization_code' && typeof ctx.body.code === 'string') {
    const verification = await ctx.context.internalAdapter.findVerificationValue(await hashToken(ctx.body.code, 'authorization_code'));
    if (!verification) return; // unknown code: Better Auth refuses it
    const grant = JSON.parse(verification.value) as { resource?: unknown; query?: { resource?: unknown } };
    if ([grant.resource ?? grant.query?.resource].flat().filter(Boolean).length === 0) throw invalidTarget();
  } else if (grantType === 'refresh_token' && typeof ctx.body.refresh_token === 'string') {
    const stored = await ctx.context.adapter.findOne<{ resources?: string[] | null }>({
      model: 'oauthRefreshToken',
      where: [{ field: 'token', value: await hashToken(ctx.body.refresh_token, 'refresh_token') }],
    });
    if (stored && !stored.resources?.length) throw invalidTarget();
  }
}

/** Claims a `claims` request may name only when the user granted the scope behind them (M1: email). */
const CLAIM_SCOPE: Record<string, string> = { email: 'email', email_verified: 'email' };

/**
 * Better Auth releases a claim named in the `claims` parameter whatever the scopes, so `scope=openid` plus
 * claims.userinfo.email would hand over the email without the consent page asking for it. Refuse such requests.
 */
function rejectClaimsOutsideScope(ctx: HookContext, claims: unknown, scope: string | null | undefined): void {
  if (claims === undefined || claims === null || scope === undefined || scope === null) return; // no scope: all are requested
  let request: { userinfo?: object; id_token?: object };
  try {
    request = typeof claims === 'string' ? JSON.parse(claims) : claims;
  } catch {
    return; // not JSON: Better Auth refuses it as an invalid claims request
  }
  const granted = new Set(scope.split(' '));
  const names = [...Object.keys(request?.userinfo ?? {}), ...Object.keys(request?.id_token ?? {})];
  const missing = [...new Set(names.filter((n) => CLAIM_SCOPE[n] !== undefined && !granted.has(CLAIM_SCOPE[n])))];
  if (missing.length === 0) return;
  const description = `claims ${missing.join(', ')} need the ${[...new Set(missing.map((n) => CLAIM_SCOPE[n]))].join(', ')} scope`;
  if (ctx.path === '/oauth2/authorize') {
    // The redirect URI isn't validated yet, so the error goes to AuthWAPI's own error page, like invalid_redirect.
    throw ctx.redirect(`${ctx.context.baseURL}/error?${new URLSearchParams({ error: 'invalid_request', error_description: description })}`);
  }
  throw new APIError('BAD_REQUEST', { error: 'invalid_request', error_description: description });
}

/** A ban (admin plugin fields) that hasn't expired. */
export const isBanned = (user: unknown): boolean => {
  const u = user as { banned?: unknown; banExpires?: Date | string | null } | null | undefined;
  return Boolean(u?.banned) && !(u!.banExpires && new Date(u!.banExpires).getTime() <= Date.now());
};

/** Whether a token issued at `iat` (seconds) is revoked: its user is gone or banned, or it predates their last revocation. */
async function tokenRevoked(ctx: HookContext, userId: string, iat: number): Promise<boolean> {
  const user = await ctx.context.adapter.findOne<{ tokensRevokedAt?: Date | null }>({ model: 'user', where: [{ field: 'id', value: userId }] });
  if (!user || isBanned(user)) return true;
  // Known limit, kept on purpose (the safe direction): iat has 1s resolution, so a token minted within the same
  // second just after a revocation also reads revoked until the app refreshes it. ponytail: record a token id per
  // revocation if that ever bites.
  return Boolean(user?.tokensRevokedAt && iat * 1000 < new Date(user.tokensRevokedAt).getTime());
}

/**
 * The user a token request is for (its code's or refresh token's) and their last revocation time as the request
 * began, from the before-hook to the after-hook.
 */
const tokenUser = defineRequestState<{ id: string; revokedAt: number } | undefined>(() => undefined);
type RevocationState = { tokensRevokedAt?: Date | string | null; banned?: unknown; banExpires?: Date | string | null };
const findRevocationState = (ctx: HookContext, userId: string) =>
  ctx.context.adapter.findOne<RevocationState>({ model: 'user', where: [{ field: 'id', value: userId }] });
const revokedAtMs = (user: RevocationState | null) => (user?.tokensRevokedAt ? new Date(user.tokensRevokedAt).getTime() : 0);

async function tokenRequestUser(ctx: HookContext, opts: ProviderOptions): Promise<string | undefined> {
  const { hashToken } = getOAuthProviderApi(ctx, opts);
  const grantType = typeof ctx.body?.grant_type === 'string' ? ctx.body.grant_type.trim() : undefined;
  if (grantType === 'authorization_code' && typeof ctx.body.code === 'string') {
    const verification = await ctx.context.internalAdapter.findVerificationValue(await hashToken(ctx.body.code, 'authorization_code'));
    const userId = verification ? (JSON.parse(verification.value) as { userId?: unknown }).userId : undefined;
    return typeof userId === 'string' ? userId : undefined;
  }
  if (grantType === 'refresh_token' && typeof ctx.body.refresh_token === 'string') {
    const stored = await ctx.context.adapter.findOne<{ userId: string }>({
      model: 'oauthRefreshToken',
      where: [{ field: 'token', value: await hashToken(ctx.body.refresh_token, 'refresh_token') }],
    });
    return stored?.userId;
  }
  return undefined;
}

const userBanned = () => new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: 'the user is banned' });
const tokensRevoked = () => new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: "the user's tokens were revoked" });

function authwapiOAuthGlue(opts: ProviderOptions, deps: AuthDeps): BetterAuthPlugin {
  return {
    id: 'authwapi-oauth',
    schema: {
      // When the user's tokens were last revoked: JWT access tokens issued before it introspect as inactive.
      user: { fields: { tokensRevokedAt: { type: 'date', required: false, input: false, returned: false } } },
      // The organization picked on SELECT_ORG_PAGE for the authorization in progress (M3); see postLogin below.
      session: { fields: { oauthOrgId: { type: 'string', required: false, input: false } } },
    },
    init: (context) => {
      authContexts.set(deps, context);
      return {
        options: {
          databaseHooks: {
            session: {
              delete: {
                before: async (session, ctx) => {
                  const impersonated = (session as { impersonatedBy?: string | null }).impersonatedBy;
                  if (ctx?.path && END_SESSION_PATHS.has(ctx.path) && !impersonated) await revokeUserTokens(ctx.context, session.userId);
                },
              },
            },
          },
        },
      };
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path?.startsWith('/admin/oauth2/') === true && ctx.request === undefined,
          handler: createAuthMiddleware(async () => ({ context: { context: { session: operatorSession() } } })),
        },
        {
          matcher: (ctx) => ctx.path !== undefined && SIGN_OUT_PATHS.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const userId = await userEndingSessions(ctx);
            if (userId) await revokeUserTokens(ctx.context, userId);
          }),
        },
        {
          matcher: (ctx) => ctx.path === '/oauth2/token',
          handler: createAuthMiddleware((ctx) => rejectResourceNotGranted(ctx, opts)),
        },
        {
          // A banned user's code or refresh token gets nothing. The after-hook below checks again once tokens exist.
          matcher: (ctx) => ctx.path === '/oauth2/token',
          handler: createAuthMiddleware(async (ctx) => {
            const userId = await tokenRequestUser(ctx, opts);
            if (!userId) return;
            const user = await findRevocationState(ctx, userId);
            await tokenUser.set({ id: userId, revokedAt: revokedAtMs(user) });
            if (isBanned(user)) throw userBanned();
          }),
        },
        {
          matcher: (ctx) => ctx.path === '/oauth2/authorize',
          handler: createAuthMiddleware(async (ctx) => {
            // Better Auth reads a POSTed authorization request from the body, otherwise from the query.
            const post = ctx.request?.method === 'POST';
            const params = (post ? ctx.body : ctx.query) ?? {};
            // Without `scope` Better Auth grants every configured scope; here it means the M1 ones, so the organization
            // step and org claims come only when an app asks for `organization`.
            const scope = params.scope === undefined || params.scope === '' ? DEFAULT_SCOPE : params.scope;
            rejectClaimsOutsideScope(ctx, params.claims, scope);
            if (scope !== params.scope) return { context: post ? { body: { ...params, scope } } : { query: { ...params, scope } } };
          }),
        },
        {
          matcher: (ctx) => ctx.path === '/oauth2/consent',
          handler: createAuthMiddleware(async (ctx) => {
            // What would be granted: the scopes and claims accepted here, else those in the (signed) original request.
            const original = new URLSearchParams(typeof ctx.body?.oauth_query === 'string' ? ctx.body.oauth_query : '');
            rejectClaimsOutsideScope(ctx, ctx.body?.claims ?? original.get('claims') ?? undefined, ctx.body?.scope ?? original.get('scope'));
          }),
        },
      ],
      after: [
        {
          // Issuance and ban are serialized by order: a ban writes `banned` and then revokes (src/orgs.ts banUser); this
          // reads the user after the provider has written its tokens. A ban that landed after the check above is seen
          // here, and so is a revocation (tokensRevokedAt moved) even if its ban was already lifted again: what was
          // just written is revoked (with everything else of the user's) before anyone sees it.
          matcher: (ctx) => ctx.path === '/oauth2/token',
          handler: createAuthMiddleware(async (ctx) => {
            const started = await tokenUser.get();
            if (!started || isAPIError(ctx.context.returned)) return;
            const user = await findRevocationState(ctx, started.id);
            const banned = isBanned(user);
            if (!banned && revokedAtMs(user) === started.revokedAt) return;
            await revokeUserTokens(ctx.context, started.id);
            throw banned ? userBanned() : tokensRevoked();
          }),
        },
        {
          // A JWT access token stays valid until it expires (D9), but introspection is where APIs ask for instant
          // revocation: one issued before the user's tokens were last revoked is inactive. Better Auth only cuts
          // off JWTs whose session (sid) is gone, and an offline refresh after the session ended mints JWTs with none.
          matcher: (ctx) => ctx.path === '/oauth2/introspect',
          handler: createAuthMiddleware(async (ctx) => {
            const result = ctx.context.returned as { active?: unknown; sub?: unknown; iat?: unknown } | undefined;
            if (result?.active !== true || typeof result.sub !== 'string' || typeof result.iat !== 'number') return;
            if (await tokenRevoked(ctx, result.sub, result.iat)) return ctx.json({ active: false });
          }),
        },
        {
          // Userinfo, our own API, answers the same way, and releases only the claims the token's scopes cover:
          // Better Auth also releases claims named in the original `claims` request, and a refresh carries those
          // into tokens whose scopes no longer include them.
          matcher: (ctx) => ctx.path === '/oauth2/userinfo',
          handler: createAuthMiddleware(async (ctx) => {
            const result = ctx.context.returned as Record<string, unknown> | undefined;
            if (typeof result?.sub !== 'string') return; // Better Auth refused the request
            // The token Better Auth read (its getUserInfoAccessToken): the Authorization header with any scheme or
            // none, else a POSTed access_token. Then its scopes and iat from Better Auth's own validator.
            const sent = parseAccessTokenAuthorization(ctx.headers?.get('authorization'))?.token ?? (ctx.request?.method === 'POST' ? ctx.body?.access_token : undefined);
            const validate = async (t: unknown) => (typeof t === 'string' ? getOAuthProviderApi(ctx, opts).validateAccessToken(t) : undefined);
            const token = await validate(sent).catch(() => undefined);
            // Fail closed: a token we can't read back as the same active token, or one issued before a revocation.
            if (token?.active !== true || token.sub !== result.sub || typeof token.iat !== 'number' || (await tokenRevoked(ctx, result.sub, token.iat))) {
              throw new APIError('UNAUTHORIZED', { error: 'invalid_token', error_description: 'the access token was revoked' });
            }
            const scopes = new Set(typeof token.scope === 'string' ? token.scope.split(' ') : []);
            const outside = Object.keys(result).filter((n) => CLAIM_SCOPE[n] !== undefined && !scopes.has(CLAIM_SCOPE[n]));
            // Org claims are copied from the validated token (customAccessTokenClaims made them for its grant).
            const org = scopes.has('organization') && typeof token.org_id === 'string' ? { org_id: token.org_id, roles: token.roles } : undefined;
            if (outside.length > 0 || org) return ctx.json({ ...Object.fromEntries(Object.entries(result).filter(([n]) => !outside.includes(n))), ...org });
          }),
        },
      ],
    },
  };
}

/**
 * The jwt plugin, in OAuth-provider mode: no JWT on get-session (disableSettingJwtHeader) and no GET /token, which
 * would mint a session JWT signed with the same keys as access tokens. Its JWKS endpoint stays.
 */
function jwtForOAuth(issuer: string): BetterAuthPlugin {
  const plugin = jwt({ jwt: { issuer }, disableSettingJwtHeader: true });
  const { getToken: _sessionJwt, ...endpoints } = plugin.endpoints;
  return { ...plugin, endpoints } as BetterAuthPlugin;
}

/** Better Auth plugins for the OAuth/OIDC provider (oauthProvider + jwt). Added to authOptions().plugins. */
export function oauthPlugins(deps: AuthDeps): Plugin[] {
  const { config, db } = deps;
  // Prepared when used: scripts/new-migration.ts builds these options before the tables exist.
  /** The user's roles in the organization now, or undefined if they aren't a member. */
  const rolesIn = (userId: string, organizationId: string) => {
    const role = db.prepare('SELECT role FROM member WHERE userId = ? AND organizationId = ?').pluck().get(userId, organizationId) as string | undefined;
    return role === undefined ? undefined : role.split(',').map((r) => r.trim());
  };
  const opts: ProviderOptions = {
    loginPage: '/sign-in',
    consentPage: '/consent',
    scopes: ['openid', 'email', 'offline_access', 'organization'], // claims: sub, email, email_verified; org_id, roles (M3)
    grantTypes: ['authorization_code', 'refresh_token'],
    accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
    // Better Auth puts scope claims only in userinfo; apps read email from the ID token at sign-in (D9).
    customIdTokenClaims: ({ user, scopes }) =>
      scopes.includes('email') ? { email: user.email, email_verified: user.emailVerified } : {},
    // The grant's organization (its referenceId, from consentReferenceId below). Runs at every issuance, refresh too
    // (and when an opaque token is introspected), so membership and role are current; no membership, no claims.
    customAccessTokenClaims: ({ user, referenceId, scopes }) => {
      const roles = user && referenceId && scopes.includes('organization') ? rolesIn(user.id, referenceId) : undefined;
      return roles ? { org_id: referenceId, roles } : {};
    },
    postLogin: {
      page: SELECT_ORG_PAGE,
      // Every authorization with the organization scope picks its organization afresh on SELECT_ORG_PAGE, which
      // records the pick on the session (oauthOrgId) and continues. A continuation that skipped the page has no pick.
      shouldRedirect: ({ session, scopes, isContinuation }) => {
        if (!scopes.includes('organization') || isContinuation) return false;
        db.prepare('UPDATE session SET oauthOrgId = NULL WHERE id = ?').run(session.id);
        return true;
      },
      // The provider's shared authorization step: /oauth2/authorize, /oauth2/consent (before it writes consent) and
      // /oauth2/continue all call this before a consent write or an authorization code. Its value becomes the grant's
      // referenceId (consent, code, refresh tokens); the session's active organization is never read.
      consentReferenceId: ({ user, session, scopes }) => {
        if (session.impersonatedBy) {
          throw new APIError('FORBIDDEN', { error: 'access_denied', error_description: "An impersonated session can't authorize apps." });
        }
        const picked = session.oauthOrgId;
        return scopes.includes('organization') && typeof picked === 'string' && rolesIn(user.id, picked) ? picked : undefined;
      },
    },
    allowDynamicClientRegistration: false,
    clientPrivileges: isOperator,
    resourcePrivileges: isOperator,
    clientReference: () => 'authwapi-cli', // clients belong to the instance, not to a user
    // Apps on this machine run on http://localhost:<port>. Plain http stays refused for any other host.
    allowInsecureRedirectUri: isLoopback,
  };
  const provider = oauthProvider(opts);
  // The glue calls Better Auth's helpers with the provider's resolved options (defaults filled in), as it does.
  return [jwtForOAuth(config.baseUrl.origin), provider, authwapiOAuthGlue(provider.options, deps)];
}

/**
 * BASE_URL/.well-known/openid-configuration and /.well-known/oauth-authorization-server (issuer = BASE_URL).
 * Better Auth serves them from its own handler when the request path matches the issuer, so they're forwarded.
 */
export function wellKnownRoutes({ callAuth }: { callAuth: AuthCall; config: Config }): Hono {
  const app = new Hono();
  app.get('/.well-known/openid-configuration', (c) => callAuth(c, c.req.raw));
  app.get('/.well-known/oauth-authorization-server', (c) => callAuth(c, c.req.raw));
  return app;
}
