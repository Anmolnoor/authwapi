// OAuth 2.1 / OIDC provider for apps (plan D9). Better Auth's oauthProvider + jwt plugins, configured so that:
// - the issuer is BASE_URL, ID tokens have aud = client ID, access tokens requested with `resource` are JWTs with
//   aud = that resource and live 15 minutes;
// - clients are created only by the operator CLI (src/cli.ts), never over HTTP;
// - sign-out revokes the session and every refresh and opaque access token the user holds.
import { randomUUID } from 'node:crypto';
import { oauthProvider } from '@better-auth/oauth-provider';
import { getCurrentAdapter, type BetterAuthOptions, type BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware } from 'better-auth/api';
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

/**
 * Endpoints where the user (or a password reset) ends sessions. Better Auth only ends the session; deleting one
 * here also revokes every refresh and opaque access token the user holds, for every client, offline_access ones
 * included. (JWT access tokens carry the session id, and introspection reports them inactive once it's gone.)
 * Other deletions, like clearing an expired session, leave tokens alone: offline_access outlives the browser session.
 */
const SIGN_OUT_PATHS = new Set([
  '/sign-out',
  '/oauth2/end-session',
  '/oauth2/end-session/confirm',
  '/revoke-session',
  '/revoke-sessions',
  '/revoke-other-sessions',
  '/reset-password',
]);

function authwapiOAuthGlue(): BetterAuthPlugin {
  return {
    id: 'authwapi-oauth',
    init: () => ({
      options: {
        databaseHooks: {
          session: {
            delete: {
              // Before the delete: if revoking fails, the session survives and the request fails (500), so a
              // sign-out never reports success while the user's tokens stay valid.
              before: async (session, ctx) => {
                if (!ctx?.path || !SIGN_OUT_PATHS.has(ctx.path)) return;
                const where = [{ field: 'userId', value: session.userId }];
                const update = { revoked: new Date() };
                // The deletion may run inside a transaction (password reset); queries outside it would wait forever.
                const adapter = await getCurrentAdapter(ctx.context.adapter);
                await adapter.updateMany({ model: 'oauthRefreshToken', where, update });
                await adapter.updateMany({ model: 'oauthAccessToken', where, update });
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
  return [
    jwtForOAuth(config.baseUrl.origin),
    oauthProvider({
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
    }),
    authwapiOAuthGlue(),
  ];
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
