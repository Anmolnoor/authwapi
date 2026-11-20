// OAuth 2.1 / OIDC provider for apps (plan D9). Better Auth's oauthProvider + jwt plugins, configured so that:
// - the issuer is BASE_URL, ID tokens have aud = client ID, access tokens requested with `resource` are JWTs with
//   aud = that resource and live 15 minutes;
// - clients are created only by the operator CLI (src/cli.ts), never over HTTP;
// - sign-out revokes the session and every refresh and opaque access token the user holds.
import { randomUUID } from 'node:crypto';
import { getOAuthProviderApi, oauthProvider } from '@better-auth/oauth-provider';
import { getCurrentAdapter, type BetterAuthOptions, type BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import { jwt } from 'better-auth/plugins';
import { Hono } from 'hono';
import type { AuthDeps } from './auth.ts';
import type { AuthCall } from './app.ts';
import { isLoopback, type Config } from './config.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

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
async function revokeUserTokens(ctx: HookContext, userId: string): Promise<void> {
  const now = new Date();
  // Inside a transaction (an end-session delete may run in one) queries outside it would wait forever.
  const adapter = await getCurrentAdapter(ctx.context.adapter);
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
 */
const SIGN_OUT_PATHS = new Set(['/sign-out', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions', '/change-password', '/reset-password']);

async function userEndingSessions(ctx: HookContext): Promise<string | undefined> {
  if (ctx.path === '/reset-password') {
    const token = ctx.body?.token ?? ctx.query?.token;
    if (typeof token !== 'string' || !token) return undefined; // Better Auth refuses it
    // The same lookup Better Auth makes; it hashes the identifier (verification.storeIdentifier: 'hashed').
    const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
    return verification && verification.expiresAt > new Date() ? verification.value : undefined;
  }
  if (ctx.path === '/change-password' && ctx.body?.revokeOtherSessions !== true) return undefined;
  // The session the cookie names, expired or not, exactly as /sign-out finds it.
  const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
  if (!token) return undefined;
  return (await ctx.context.internalAdapter.findSession(token))?.session.userId;
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
  if (ctx.body.grant_type === 'authorization_code' && typeof ctx.body.code === 'string') {
    const verification = await ctx.context.internalAdapter.findVerificationValue(await hashToken(ctx.body.code, 'authorization_code'));
    if (!verification) return; // unknown code: Better Auth refuses it
    const grant = JSON.parse(verification.value) as { resource?: unknown; query?: { resource?: unknown } };
    if ([grant.resource ?? grant.query?.resource].flat().filter(Boolean).length === 0) throw invalidTarget();
  } else if (ctx.body.grant_type === 'refresh_token' && typeof ctx.body.refresh_token === 'string') {
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

/** Whether a token issued at `iat` (seconds) predates the user's last token revocation. */
async function issuedBeforeRevocation(ctx: HookContext, userId: string, iat: number): Promise<boolean> {
  const user = await ctx.context.adapter.findOne<{ tokensRevokedAt?: Date | null }>({ model: 'user', where: [{ field: 'id', value: userId }] });
  // ponytail: iat has 1s resolution, so a token minted within the same second after a revocation also reads
  // revoked until the app refreshes; record a token id per revocation if that ever bites.
  return Boolean(user?.tokensRevokedAt && iat * 1000 < new Date(user.tokensRevokedAt).getTime());
}

function authwapiOAuthGlue(opts: ProviderOptions): BetterAuthPlugin {
  return {
    id: 'authwapi-oauth',
    schema: {
      // When the user's tokens were last revoked: JWT access tokens issued before it introspect as inactive.
      user: { fields: { tokensRevokedAt: { type: 'date', required: false, input: false, returned: false } } },
    },
    init: () => ({
      options: {
        databaseHooks: {
          session: {
            delete: {
              before: async (session, ctx) => {
                if (ctx?.path && END_SESSION_PATHS.has(ctx.path)) await revokeUserTokens(ctx, session.userId);
              },
            },
          },
        },
      },
    }),
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
            if (userId) await revokeUserTokens(ctx, userId);
          }),
        },
        {
          matcher: (ctx) => ctx.path === '/oauth2/token',
          handler: createAuthMiddleware((ctx) => rejectResourceNotGranted(ctx, opts)),
        },
        {
          matcher: (ctx) => ctx.path === '/oauth2/authorize',
          handler: createAuthMiddleware(async (ctx) => {
            // Better Auth reads a POSTed authorization request from the body, otherwise from the query.
            const params = (ctx.request?.method === 'POST' ? ctx.body : ctx.query) ?? {};
            rejectClaimsOutsideScope(ctx, params.claims, params.scope);
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
          // A JWT access token stays valid until it expires (D9), but introspection is where APIs ask for instant
          // revocation: one issued before the user's tokens were last revoked is inactive. Better Auth only cuts
          // off JWTs whose session (sid) is gone, and an offline refresh after the session ended mints JWTs with none.
          matcher: (ctx) => ctx.path === '/oauth2/introspect',
          handler: createAuthMiddleware(async (ctx) => {
            const result = ctx.context.returned as { active?: unknown; sub?: unknown; iat?: unknown } | undefined;
            if (result?.active !== true || typeof result.sub !== 'string' || typeof result.iat !== 'number') return;
            if (await issuedBeforeRevocation(ctx, result.sub, result.iat)) return ctx.json({ active: false });
          }),
        },
        {
          // Userinfo, our own API, answers the same way. Better Auth has verified the token by now (it returned
          // claims), so reading its iat without verifying again is safe.
          matcher: (ctx) => ctx.path === '/oauth2/userinfo',
          handler: createAuthMiddleware(async (ctx) => {
            const result = ctx.context.returned as { sub?: unknown } | undefined;
            const jwt = ctx.headers?.get('authorization')?.split(' ')[1]?.split('.');
            if (typeof result?.sub !== 'string' || jwt?.length !== 3) return; // an error, or an opaque token (revoked in the database)
            const { iat } = JSON.parse(Buffer.from(jwt[1], 'base64url').toString()) as { iat?: unknown };
            if (typeof iat === 'number' && (await issuedBeforeRevocation(ctx, result.sub, iat))) {
              throw new APIError('UNAUTHORIZED', { error: 'invalid_token', error_description: 'the access token was revoked' });
            }
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
export function oauthPlugins({ config }: AuthDeps): Plugin[] {
  const opts: ProviderOptions = {
    loginPage: '/sign-in',
    consentPage: '/consent',
    scopes: ['openid', 'email', 'offline_access'], // M1 claims: sub, email, email_verified
    grantTypes: ['authorization_code', 'refresh_token'],
    accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
    // Better Auth puts scope claims only in userinfo; apps read email from the ID token at sign-in (D9).
    customIdTokenClaims: ({ user, scopes }) =>
      scopes.includes('email') ? { email: user.email, email_verified: user.emailVerified } : {},
    allowDynamicClientRegistration: false,
    clientPrivileges: isOperator,
    resourcePrivileges: isOperator,
    clientReference: () => 'authwapi-cli', // clients belong to the instance, not to a user
    // Apps on this machine run on http://localhost:<port>. Plain http stays refused for any other host.
    allowInsecureRedirectUri: isLoopback,
  };
  return [jwtForOAuth(config.baseUrl.origin), oauthProvider(opts), authwapiOAuthGlue(opts)];
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
