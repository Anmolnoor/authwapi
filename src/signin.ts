// M2 sign-in methods (plan flow.md, rev 7): Google/GitHub with an account-linking policy, TOTP 2FA with backup codes
// enforced after EVERY first factor, and passkeys. Better Auth supplies the methods; this file is the policy:
// - linkingPolicy: the one choke point for implicit and explicit linking (user.validateUserInfo).
// - mfaGlue: turns any new session for a 2FA user into the same challenge Better Auth's twoFactor plugin issues, unless
//   the response itself proved both factors; refuses trusted devices; asks for a fresh code before 2FA-sensitive changes.
import { passkey } from '@better-auth/passkey';
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware, isAPIError } from 'better-auth/api';
import { base32 } from '@better-auth/utils/base32';
import { createOTP } from '@better-auth/utils/otp';
import { deleteSessionCookie } from 'better-auth/cookies';
import { generateRandomString, symmetricDecrypt } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins';
import type { Config, SocialConfig } from './config.ts';
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

/**
 * Google / GitHub from config. ID-token sign-in (an app posting a provider ID token to /sign-in/social or
 * /link-social) is off: it would reach accounts without the redirect flow this policy is tested on.
 */
export function socialProviders(social: SocialConfig): NonNullable<BetterAuthOptions['socialProviders']> {
  const providers: NonNullable<BetterAuthOptions['socialProviders']> = {};
  if (social.google) providers.google = { ...social.google, disableIdTokenSignIn: true };
  if (social.github) providers.github = { ...social.github, disableIdTokenSignIn: true };
  return providers;
}

// Responses that prove both factors themselves: a second factor, or a passkey with user verification (required below).
const PROVES_BOTH_FACTORS = new Set(['/two-factor/verify-totp', '/two-factor/verify-backup-code', '/passkey/verify-authentication']);
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
const MAX_SIGNED_IN_FAILURES = 5; // wrong codes from one signed-in session before it is ended
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

/**
 * The check Better Auth's verify-totp makes (twoFactor/totp: the stored secret, decrypted, 6 digits, 30 s, one step
 * either side), for a code that would turn 2FA on.
 */
async function totpMatches(ctx: HookContext, userId: string, code: unknown): Promise<boolean> {
  if (typeof code !== 'string') return false;
  const row = await ctx.context.adapter.findOne<{ secret: string }>({ model: 'twoFactor', where: [{ field: 'userId', value: userId }] });
  if (!row) return false;
  const raw = await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.secret });
  const secret = raw.startsWith('base32:') ? base32.decode(raw.slice(7).toUpperCase()) : raw;
  return createOTP(secret, { digits: 6, period: 30 }).verify(code);
}

function mfaGlue(): BetterAuthPlugin {
  /** The valid session each request arrived with, if any (it may be gone by the time the response is built). */
  const arrivedWith = new WeakMap<Request, { token: string; sessionId: string; userId: string; twoFactorEnabled: boolean }>();
  /** Session id → until when its last 2FA check counts as fresh. ponytail: in memory; a restart just asks again. */
  const freshUntil = new Map<string, number>();
  /** Session id → wrong codes entered while signed in, in a row. */
  const failures = new Map<string, number>();
  const arrived = (ctx: HookContext) => (ctx.request ? arrivedWith.get(ctx.request) : undefined);
  const markFresh = (sessionId: string) => {
    const now = Date.now();
    for (const [id, until] of freshUntil) if (until <= now) freshUntil.delete(id);
    freshUntil.set(sessionId, now + FRESH_CHECK_MS);
  };

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
            arrivedWith.set(ctx.request!, { token: session.token, sessionId: session.id, userId: user.id, twoFactorEnabled: user.twoFactorEnabled === true });
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
        {
          // Turning 2FA on: once the code is known to be right, and BEFORE Better Auth commits the switch, end every
          // other session, revoke the user's OAuth tokens and remove their passkeys (one added by whoever else knew
          // the password would otherwise sign in as both factors). If the switch then fails, 2FA is simply still off
          // and the user can retry; once it is on, nothing from before is left.
          matcher: (ctx) => ctx.path === '/two-factor/verify-totp',
          handler: createAuthMiddleware(async (ctx) => {
            const s = arrived(ctx);
            if (!s || s.twoFactorEnabled || !(await totpMatches(ctx, s.userId, ctx.body?.code))) return;
            const others = (await ctx.context.internalAdapter.listSessions(s.userId)).filter((x) => x.token !== s.token);
            await ctx.context.internalAdapter.deleteSessions(others.map((x) => x.token));
            await revokeUserTokens(ctx.context, s.userId);
            await ctx.context.adapter.deleteMany({ model: 'passkey', where: [{ field: 'userId', value: s.userId }] });
          }),
        },
      ],
      after: [
        {
          // A second factor: a right code makes the resulting session fresh for the changes above (Better Auth's
          // final newSession, or the session it was entered in); wrong codes from a signed-in session are counted.
          matcher: (ctx) => SECOND_FACTOR.has(ctx.path ?? ''),
          handler: createAuthMiddleware(async (ctx) => {
            const s = arrived(ctx);
            if (!isAPIError(ctx.context.returned)) {
              const sessionId = ctx.context.newSession?.session.id ?? s?.sessionId;
              if (sessionId) markFresh(sessionId);
              if (s) failures.delete(s.sessionId);
              return;
            }
            if (!s) return; // a sign-in challenge: twoFactor's own attempt limit and lockout apply
            const count = (failures.get(s.sessionId) ?? 0) + 1;
            failures.delete(s.sessionId); // re-insert at the end: Map order = age, for the cap below
            if (count < MAX_SIGNED_IN_FAILURES) {
              failures.set(s.sessionId, count);
              if (failures.size > 10_000) failures.delete(failures.keys().next().value!);
              return;
            }
            await ctx.context.internalAdapter.deleteSession(s.token);
            deleteSessionCookie(ctx);
          }),
        },
        {
          // Any response that hands out a new session: a first factor (password, magic link, social callback, ... and
          // whatever else creates one) is not enough for a 2FA user, even one already signed in. Only a renewal of
          // the session the request arrived with, or its replacement (change-password rotates it), is not a sign-in.
          matcher: (ctx) => newSessionToken(ctx) !== undefined && !PROVES_BOTH_FACTORS.has(ctx.path ?? ''),
          handler: createAuthMiddleware(async (ctx) => {
            const token = ctx.context.newSession?.session.token;
            const found = token ? await ctx.context.internalAdapter.findSession(token) : null;
            // Already turned into a challenge (twoFactor's own, on /sign-in/email): don't send a dead token either.
            if (!token || !found) return dropSessionCookies(ctx);
            const user = found.user as typeof found.user & { twoFactorEnabled?: boolean | null };
            if (!user.twoFactorEnabled) return;
            const s = arrived(ctx);
            if (s?.userId === user.id && (s.token === token || !(await ctx.context.internalAdapter.findSession(s.token)))) return;
            return challenge(ctx, token, user.id);
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
