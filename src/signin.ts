// M2 sign-in methods (plan flow.md, rev 7): Google/GitHub with an account-linking policy, TOTP 2FA with backup codes
// enforced after EVERY first factor, and passkeys. Better Auth supplies the methods; this file is the policy:
// - linkingPolicy: the one choke point for implicit and explicit linking (user.validateUserInfo).
// - mfaGlue: turns any new session for a 2FA user into the same challenge Better Auth's twoFactor plugin issues, unless
//   the response itself proved both factors; refuses trusted devices; asks for a fresh code before 2FA-sensitive changes.
import { passkey } from '@better-auth/passkey';
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware, isAPIError } from 'better-auth/api';
import { deleteSessionCookie } from 'better-auth/cookies';
import { generateRandomString } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins';
import type { Config } from './config.ts';
import { revokeUserTokens } from './oauth.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];
type HookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type ValidateUserInfo = NonNullable<NonNullable<BetterAuthOptions['user']>['validateUserInfo']>;

/** Hosted pages (src/pages.ts) the challenge sends a browser to. */
export const TWO_FACTOR_PAGE = '/two-factor';
export const OAUTH_RESUME_PAGE = '/oauth/resume';

/**
 * Account linking (account.accountLinking.trustedProviders is empty). Called by Better Auth before it creates a user
 * from a provider profile and before it links a provider account to an existing user, implicitly (same email at
 * sign-in) or explicitly (/link-social). A provider account is accepted only with an email the provider says is
 * verified, and links only to a local account whose email is verified too. Better Auth already refuses implicit links
 * to an unverified local account (requireLocalEmailVerified, default true); this also covers explicit ones. The way in
 * for the owner of such an account is magic link, which verifies the address and removes everything set before.
 */
export const linkingPolicy: ValidateUserInfo = async ({ user, source }, ctx) => {
  if (source.method !== 'oauth' || source.action === 'sign-in') return;
  if (user.emailVerified !== true) {
    return { error: 'email_not_verified', errorDescription: "The provider didn't confirm that this email address is verified." };
  }
  if (source.action === 'link-account' && typeof user.id === 'string') {
    const local = await ctx.context.internalAdapter.findUserById(user.id);
    if (!local?.emailVerified) {
      return { error: 'account_not_linked', errorDescription: 'An account with this email is not verified yet. Sign in with an emailed link first.' };
    }
  }
};

// Responses that prove both factors themselves: a second factor, or a passkey with user verification (required below).
const PROVES_BOTH_FACTORS = new Set(['/two-factor/verify-totp', '/two-factor/verify-backup-code', '/two-factor/verify-otp', '/passkey/verify-authentication']);
const SECOND_FACTOR = new Set(['/two-factor/verify-totp', '/two-factor/verify-backup-code']);
// Changes that weaken or bypass 2FA (or read its secret) need a code entered in the last few minutes on a 2FA account.
const NEEDS_FRESH_CHECK = new Set([
  '/passkey/generate-register-options',
  '/passkey/verify-registration',
  '/two-factor/disable',
  '/two-factor/get-totp-uri',
  '/two-factor/generate-backup-codes',
]);
const FRESH_CHECK_MS = 5 * 60_000;
const CHALLENGE_MAX_AGE = 600; // seconds; twoFactor's twoFactorCookieMaxAge default

/** The session token in a Set-Cookie this response carries (not one that expires the cookie). */
function newSessionToken(ctx: { context: Pick<AuthContext, 'authCookies'> & { responseHeaders?: Headers } }): string | undefined {
  const name = ctx.context.authCookies.sessionToken.name;
  for (const c of ctx.context.responseHeaders?.getSetCookie() ?? []) {
    if (!c.startsWith(`${name}=`)) continue;
    const value = decodeURIComponent(c.slice(name.length + 1).split(';')[0]);
    if (value) return value.split('.')[0]; // signed cookie: "<token>.<signature>"
  }
  return undefined;
}

/** Removes the Set-Cookie lines that carry a session from the response. */
function dropSessionCookies(ctx: HookContext): void {
  const headers = ctx.context.responseHeaders;
  if (!headers) return;
  const names = [ctx.context.authCookies.sessionToken.name, ctx.context.authCookies.sessionData.name];
  const kept = headers.getSetCookie().filter((c) => !names.some((n) => c.startsWith(`${n}=`)));
  headers.delete('set-cookie');
  for (const c of kept) headers.append('set-cookie', c);
}

/**
 * Replaces a first factor's new session with a 2FA challenge, the way twoFactor's own sign-in hook does it, so
 * /two-factor/verify-* accepts it unchanged: the session row is deleted, newSession cleared, its cookie dropped (and any
 * session cookie the browser had, expired), and a "two_factor" cookie names a verification row holding the user id.
 * A redirect goes to the 2FA page instead, carrying the app's signed OAuth request if there is one; anything else
 * answers as twoFactor does, with no token in the body.
 */
async function challenge(ctx: HookContext, token: string, userId: string) {
  await ctx.context.internalAdapter.deleteSession(token);
  ctx.context.setNewSession(null);
  dropSessionCookies(ctx);
  deleteSessionCookie(ctx, true);

  const cookie = ctx.context.createAuthCookie('two_factor', { maxAge: CHALLENGE_MAX_AGE });
  const identifier = `2fa-${generateRandomString(20)}`;
  const expiresAt = new Date(Date.now() + CHALLENGE_MAX_AGE * 1000);
  await ctx.context.internalAdapter.createVerificationValue({ value: userId, identifier, expiresAt });
  await ctx.context.internalAdapter.createVerificationValue({ value: '0', identifier: `2fa-attempts-${identifier}`, expiresAt });
  await ctx.setSignedCookie(cookie.name, identifier, ctx.context.secret, cookie.attributes);

  const returned = ctx.context.returned;
  if (isAPIError(returned) && returned.statusCode >= 300 && returned.statusCode < 400) {
    // The signed request travels in the body (oauth_query) or, for magic link and social sign-in, in the callbackURL
    // the hosted sign-in page chose: OAUTH_RESUME_PAGE?<signed request>.
    const location = new URL(ctx.context.responseHeaders?.get('location') ?? '/', ctx.context.baseURL);
    const signed = typeof ctx.body?.oauth_query === 'string' ? ctx.body.oauth_query : location.pathname === OAUTH_RESUME_PAGE ? location.search.slice(1) : '';
    throw ctx.redirect(signed ? `${TWO_FACTOR_PAGE}?${signed}` : TWO_FACTOR_PAGE);
  }
  return ctx.json({ twoFactorRedirect: true, twoFactorMethods: ['totp'] });
}

function mfaGlue(): BetterAuthPlugin {
  /** The valid session each request arrived with, if any (it may be gone by the time the response is built). */
  const arrivedWith = new WeakMap<Request, { sessionId: string; userId: string; twoFactorEnabled: boolean }>();
  /** Session id → until when its last 2FA check counts as fresh. ponytail: in memory; a restart just asks again. */
  const freshUntil = new Map<string, number>();
  const arrived = (ctx: HookContext) => (ctx.request ? arrivedWith.get(ctx.request) : undefined);

  return {
    id: 'authwapi-mfa',
    hooks: {
      before: [
        {
          // Trusted devices are off: a device never skips the second factor.
          matcher: (ctx) => ctx.path?.startsWith('/two-factor/') === true && ctx.body?.trustDevice !== undefined && ctx.body.trustDevice !== false,
          handler: createAuthMiddleware(async () => {
            throw new APIError('BAD_REQUEST', { code: 'TRUSTED_DEVICES_OFF', message: 'Trusted devices are turned off: every sign-in asks for the second factor.' });
          }),
        },
        {
          // ...and a trust cookie (say, left from another setup) is never even seen by twoFactor's sign-in hook.
          matcher: (ctx) => ctx.headers?.get('cookie')?.includes('trust_device') === true,
          handler: createAuthMiddleware(async (ctx) => {
            const name = ctx.context.createAuthCookie('trust_device').name;
            const cookie = ctx.headers!.get('cookie')!.split(';').filter((c) => c.split('=')[0].trim() !== name).join(';');
            return { context: { headers: new Headers({ cookie }) } };
          }),
        },
        {
          matcher: (ctx) => ctx.request !== undefined && ctx.headers?.get('cookie')?.includes(ctx.context.authCookies.sessionToken.name) === true,
          handler: createAuthMiddleware(async (ctx) => {
            const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
            const found = token ? await ctx.context.internalAdapter.findSession(token) : null;
            if (!found || found.session.expiresAt <= new Date()) return;
            const { session, user } = found as typeof found & { user: { twoFactorEnabled?: boolean | null } };
            arrivedWith.set(ctx.request!, { sessionId: session.id, userId: user.id, twoFactorEnabled: user.twoFactorEnabled === true });
          }),
        },
        {
          matcher: (ctx) => ctx.path !== undefined && NEEDS_FRESH_CHECK.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const s = arrived(ctx);
            if (s?.twoFactorEnabled && !((freshUntil.get(s.sessionId) ?? 0) > Date.now())) {
              throw new APIError('FORBIDDEN', {
                code: 'TWO_FACTOR_CHECK_REQUIRED',
                message: 'Enter a code from your authenticator app first (POST /two-factor/verify-totp while signed in).',
              });
            }
          }),
        },
      ],
      after: [
        {
          // Any response that hands out a session: a first factor (password, magic link, social callback, ... and
          // whatever else creates one) is not enough for a 2FA user. Renewals and rotations for a request that
          // arrived with that user's valid session (get-session, update-user, change-password) are not sign-ins.
          matcher: (ctx) => newSessionToken(ctx) !== undefined,
          handler: createAuthMiddleware(async (ctx) => {
            const token = newSessionToken(ctx)!;
            const found = await ctx.context.internalAdapter.findSession(token);
            // Already deleted (twoFactor's own sign-in challenge): don't send a dead token either.
            if (!found) return dropSessionCookies(ctx);
            const user = found.user as typeof found.user & { twoFactorEnabled?: boolean | null };
            const before = arrived(ctx);
            if (SECOND_FACTOR.has(ctx.path ?? '')) {
              freshUntil.set(found.session.id, Date.now() + FRESH_CHECK_MS);
              if (before && !before.twoFactorEnabled && user.twoFactorEnabled) {
                // 2FA was just turned on (verify-totp rotated the session): every other session and token goes.
                const others = (await ctx.context.internalAdapter.listSessions(user.id)).filter((s) => s.token !== token);
                await ctx.context.internalAdapter.deleteSessions(others.map((s) => s.token));
                await revokeUserTokens(ctx.context, user.id);
              }
              return;
            }
            if (PROVES_BOTH_FACTORS.has(ctx.path ?? '') || !user.twoFactorEnabled || before?.userId === user.id) return;
            return challenge(ctx, token, user.id);
          }),
        },
        {
          // A second factor entered while signed in (no new session): fresh for the changes above.
          matcher: (ctx) => SECOND_FACTOR.has(ctx.path ?? '') && newSessionToken(ctx) === undefined,
          handler: createAuthMiddleware(async (ctx) => {
            const s = arrived(ctx);
            if (s && !isAPIError(ctx.context.returned)) freshUntil.set(s.sessionId, Date.now() + FRESH_CHECK_MS);
            if (freshUntil.size > 10_000) freshUntil.delete(freshUntil.keys().next().value!);
          }),
        },
      ],
    },
  };
}

/**
 * twoFactor (TOTP + backup codes; allowPasswordless so magic-link, social and passkey users can turn it on), the
 * enforcement glue right after it (both before the OAuth provider, whose after-hook resumes an authorization as soon
 * as it sees a session cookie), and passkeys bound to BASE_URL with user verification required, which
 * @simplewebauthn checks on the server (requireUserVerification) at registration and sign-in.
 */
export function signInPlugins(config: Config): Plugin[] {
  return [
    twoFactor({ issuer: 'AuthWAPI', allowPasswordless: true }),
    mfaGlue(),
    passkey({
      rpID: config.baseUrl.hostname,
      rpName: 'AuthWAPI',
      origin: config.baseUrl.origin,
      // Discoverable credentials, so "Sign in with a passkey" needs no email first.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    }),
  ];
}
