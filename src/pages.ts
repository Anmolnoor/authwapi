// Hosted pages (sign-in, sign-up, reset, magic link, OAuth consent, 2FA, passkeys) and the Risk 8 fix (plan flow.md).
// Server-rendered with hono/html, which escapes every interpolated value. Forms post back to these routes, which
// call Better Auth through callAuth (client IP set from the TCP peer, so Better Auth's rate limits apply).
import { verifyOAuthQueryParams } from '@better-auth/oauth-provider';
import { getConnInfo } from '@hono/node-server/conninfo';
import type Database from 'better-sqlite3';
import { Hono, type Context } from 'hono';
import { html } from 'hono/html';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { errors, jwtVerify } from 'jose';
import { createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AuthCall } from './app.ts';
import { memoryRateLimit, SESSION_FRESH_AGE_SECONDS } from './auth.ts';
import type { Config } from './config.ts';
import type { Logger } from './log.ts';
import { OAUTH_RESUME_PAGE, TWO_FACTOR_PAGE } from './signin.ts';

export interface PageDeps {
  callAuth: AuthCall;
  config: Config;
  db: Database.Database;
  log: Logger;
  /** The instance secret Better Auth signs verification tokens with (HS256). */
  secret: string;
}

type Html = ReturnType<typeof html>;

const layout = (title: string, body: Html, passkeyScript: boolean) => html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · AuthWAPI</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}
h1{font-size:1.5rem}label{display:block;margin-top:1rem;font-weight:600}
input{display:block;width:100%;box-sizing:border-box;padding:.5rem;margin-top:.25rem;font:inherit;border:1px solid #767676;border-radius:4px}
button{margin-top:1rem;padding:.5rem 1rem;font:inherit;border:0;border-radius:4px;background:#1f4fd1;color:#fff;cursor:pointer}
button.secondary{background:#e8e8e8;color:#1a1a1a}
:focus-visible{outline:3px solid #1f4fd1;outline-offset:2px}
[role=alert]{padding:.75rem;border-left:4px solid #b00020;background:#fdecee}
.ok{padding:.75rem;border-left:4px solid #137333;background:#e6f4ea}
hr{margin:2rem 0;border:0;border-top:1px solid #ddd}
@media (prefers-color-scheme:dark){body{background:#121212;color:#eee}input{background:#1e1e1e;color:#eee}
button.secondary{background:#333;color:#eee}[role=alert]{background:#3a1d22}.ok{background:#1d3324}}
</style>
${passkeyScript ? html`<script src="/passkey.js" defer></script>` : ''}
</head>
<body><main>
<h1>${title}</h1>
${body}
</main></body>
</html>`;

const alert = (message: string | undefined) => (message ? html`<p role="alert">${message}</p>` : html``);

/** The browser half of passkeys (WebAuthn needs page script): served from our origin, the only one CSP allows. */
const PASSKEY_JS = readFileSync(new URL('./passkey-client.js', import.meta.url), 'utf8');

const PROVIDER_NAMES: Record<string, string> = { google: 'Google', github: 'GitHub' };

/** Why a Google/GitHub sign-in came back with ?error=. */
const socialError = (code: string) =>
  code === 'account_not_linked'
    ? "An account with this email already exists but its address isn't verified, so it can't be joined to that sign-in yet. Use 'Email me a link' below: it verifies the address, then that sign-in works too."
    : code === 'email_not_verified'
      ? "That provider didn't confirm your email address is verified. Verify it there, or sign in another way."
      : `That sign-in didn't work (${code}). Try again or sign in another way.`;

/** Plain-words descriptions for the consent page. Unknown scopes are shown by name. */
const SCOPE_WORDS: Record<string, string> = {
  openid: 'Confirm who you are',
  profile: 'See your name',
  email: 'See your email address and whether it is verified',
  offline_access: "Stay signed in to the app while you're away",
};

// Better Auth stores passwords as "salt:key" from scrypt with these parameters (@better-auth/utils/password.node).
// Its own verifyPassword compares with ===, so this compares in constant time instead. If Better Auth ever
// changes the format, the hash fails to parse or never matches: verification fails closed and the tests fail.
const SCRYPT = { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 };
async function passwordMatches(stored: string, password: string): Promise<boolean> {
  const [salt, key] = stored.split(':');
  const expected = Buffer.from(key ?? '', 'hex');
  if (!salt || expected.length !== 64) throw new Error("the stored password isn't in the expected format");
  const derived = await new Promise<Buffer>((resolve, reject) =>
    scrypt(password.normalize('NFKC'), salt, 64, SCRYPT, (err, k) => (err ? reject(err) : resolve(k)))
  );
  return timingSafeEqual(derived, expected);
}

/**
 * Marks the email verified only if, at that moment, the user still has this address and exactly the password hash
 * that was just checked. One UPDATE, which SQLite runs atomically, so a password reset that lands between the check
 * and here makes it change nothing. Returns whether it changed the row. This replaces Better Auth's verify-email,
 * which here sets only emailVerified and updatedAt (no verification hooks are configured, autoSignIn is off).
 */
export function markEmailVerified(db: Database.Database) {
  const update = db.prepare(
    `UPDATE user SET emailVerified = 1, updatedAt = ? WHERE id = ? AND email = ?
     AND EXISTS (SELECT 1 FROM account WHERE userId = user.id AND providerId = 'credential' AND password = ?)`
  );
  return (userId: string, email: string, hash: string): boolean =>
    update.run(new Date().toISOString(), userId, email, hash).changes === 1;
}

// Better Auth stores a magic link as sha256(token) under "magic-link:", and with verification.storeIdentifier
// 'hashed' hashes that identifier again (both base64url, no padding).
const b64sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');
const magicLinkIdentifier = (token: string) => b64sha256(`magic-link:${b64sha256(token)}`);

/** Every path served here; each gets the anti-framing / no-cache headers below. */
const PAGE_PATHS = [
  '/',
  '/sign-in',
  '/sign-out',
  '/signed-out',
  '/sign-up',
  '/forgot-password',
  '/reset-password',
  '/consent',
  '/api/auth/verify-email',
  '/api/auth/magic-link/verify',
  TWO_FACTOR_PAGE,
  '/two-factor/setup',
  '/two-factor/setup/confirm',
  '/passkeys',
  OAUTH_RESUME_PAGE,
];

/**
 * Mounted BEFORE the /api/auth/* catch-all, so routes here intercept Better Auth paths
 * (GET /api/auth/verify-email, GET /api/auth/magic-link/verify).
 */
export function pageRoutes({ callAuth, config, db, log, secret }: PageDeps): Hono {
  const app = new Hono();
  // No page can be framed (a framing site could trick a click on Allow or Continue; the POST would carry our own
  // Origin) or cached (pages carry tokens and session state). Registered per path, not '*': a '*' middleware here
  // would also run for every route mounted after these, including the whole API.
  for (const path of PAGE_PATHS) {
    app.use(path, async (c, next) => {
      await next();
      // Scripts only from our own origin (/passkey.js): no inline script, nothing injected runs.
      c.res.headers.set('content-security-policy', "frame-ancestors 'none'; script-src 'self'; base-uri 'none'");
      c.res.headers.set('x-frame-options', 'DENY');
      c.res.headers.set('cache-control', 'no-store');
    });
  }
  const limiter = memoryRateLimit();
  const credential = db.prepare(`SELECT password FROM account WHERE userId = ? AND providerId = 'credential'`);
  const markVerified = markEmailVerified(db);
  const verificationKey = new TextEncoder().encode(secret);
  const userWithEmail = db.prepare(`SELECT id FROM user WHERE id = ? AND email = ?`);
  /**
   * The user a verification link was issued for, checked as Better Auth's verify-email checks it (HS256 with the
   * instance secret, not expired, email lowercased at signing) and more strictly: it must name a user id, that user
   * must still have that address, and it must not be an email-change token (change-email is off; refuse rather
   * than guess). Runs before any per-user counter or scrypt work, so a forged token can't lock anyone out.
   */
  const verificationUser = async (token: string): Promise<{ userId: string; email: string } | 'expired' | undefined> => {
    try {
      const { payload } = await jwtVerify(token, verificationKey, { algorithms: ['HS256'], requiredClaims: ['exp'] });
      const { userId, email, updateTo } = payload;
      if (typeof userId !== 'string' || typeof email !== 'string' || updateTo !== undefined) return undefined;
      return userWithEmail.get(userId, email) === undefined ? undefined : { userId, email };
    } catch (err) {
      return err instanceof errors.JWTExpired ? 'expired' : undefined;
    }
  };
  const pendingMagicLink = db.prepare(
    `SELECT u.email AS email, v.expiresAt AS expiresAt FROM verification v JOIN user u ON u.email = lower(json_extract(v.value, '$.email'))
     WHERE v.identifier = ?`
  );

  /** Calls a Better Auth endpoint as the browser behind `c`: its cookie, our origin, JSON answers. */
  const ba = async (c: Context, method: 'GET' | 'POST', path: string, body?: Record<string, unknown>) => {
    const headers = new Headers({ origin: config.baseUrl.origin, accept: 'application/json' });
    const cookie = c.req.header('cookie');
    if (cookie) headers.set('cookie', cookie);
    if (body) headers.set('content-type', 'application/json');
    const res = await callAuth(
      c,
      new Request(`${config.baseUrl.origin}/api/auth${path}`, { method, headers, body: body && JSON.stringify(body) })
    );
    for (const sc of res.headers.getSetCookie()) c.header('set-cookie', sc, { append: true });
    // A redirect comes with an empty body (and still a JSON content type), so parse only what's there.
    const text = await res.text();
    const data = text && res.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : null;
    return { status: res.status, location: res.headers.get('location'), data };
  };
  /** Better Auth's error as a sentence. Unexpected failures are logged with the path, never the body. */
  const errorText = (path: string, r: { status: number; data: unknown }): string => {
    // Core routes answer { code, message }; the OAuth provider answers { error, error_description }.
    const d = r.data as { code?: string; message?: string; error?: string; error_description?: string } | null;
    if (d?.code === 'EMAIL_NOT_VERIFIED') return 'Verify your email first: open the link we emailed you when you signed up.';
    if (d?.error === 'invalid_signature') return 'This sign-in request expired or was changed. Start again from the app.';
    const text = d?.message ?? d?.error_description;
    if (r.status >= 500 || !text) log('error', 'auth call failed', { path, status: r.status, error: d?.error });
    return text ?? `Something went wrong (HTTP ${r.status}). Try again.`;
  };
  const form = async (c: Context) => {
    const body = await c.req.parseBody();
    return (name: string) => (typeof body[name] === 'string' ? (body[name] as string) : '');
  };
  /** `passkeyScript`: the page has passkey buttons, so it loads /passkey.js. */
  const render = (c: Context, title: string, body: Html, status: ContentfulStatusCode = 200, passkeyScript = false) =>
    c.html(layout(title, body, passkeyScript), status);
  /**
   * The OAuth provider's signed query (the loginPage/consentPage is opened with it), or '' if there is none. A social
   * sign-in that failed comes back with ?error= added, which isn't part of the signed request.
   */
  const oauthQuery = (c: Context) => {
    const params = new URLSearchParams(new URL(c.req.url).search);
    params.delete('error');
    params.delete('error_description');
    return params.has('sig') ? params.toString() : '';
  };
  /** Where a sign-in that can't carry the request in its body (magic link, social) lands once it has a session. */
  const resumeUrl = (query: string) => (query ? `${OAUTH_RESUME_PAGE}?${query}` : '/');
  type SessionData = { session: { createdAt: string }; user: { email: string; twoFactorEnabled?: boolean } } | null;
  /** The signed-in session, or null, also when the lookup fails (rate limited, say): pages then act signed out. */
  const currentSession = async (c: Context) => {
    const r = await ba(c, 'GET', '/get-session');
    return r.status === 200 ? (r.data as SessionData) : null;
  };

  app.get('/passkey.js', (c) => c.body(PASSKEY_JS, 200, { 'content-type': 'text/javascript; charset=utf-8' }));

  app.get('/', async (c) => {
    const email = (await currentSession(c))?.user.email;
    const error = c.req.query('error');
    return render(
      c,
      'AuthWAPI',
      html`${alert(error && `That link didn't work (${error}). Ask for a new one from the sign-in page.`)}
        ${email
          ? html`<p>Signed in as <strong>${email}</strong>.</p>
              <p><a href="/two-factor/setup">Two-factor authentication</a> · <a href="/passkeys">Passkeys</a></p>
              <form method="post" action="/sign-out"><button>Sign out</button></form>`
          : html`<p><a href="/sign-in">Sign in</a> or <a href="/sign-up">create an account</a>.</p>`}`
    );
  });

  // ── Sign in (also the OAuth loginPage) ──
  const signInPage = (c: Context, query: string, error?: string, notice?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Sign in',
      html`${alert(error)}${notice ? html`<p class="ok" role="status">${notice}</p>` : ''}
        <form method="post" action="/sign-in">
          <input type="hidden" name="oauth_query" value="${query}">
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button>Sign in</button>
        </form>
        <p><a href="/forgot-password">Forgot password?</a> · <a href="/sign-up">Create an account</a></p>
        <hr>
        <button type="button" class="secondary" data-passkey="sign-in" data-oauth-query="${query}" data-status="passkey-status">Sign in with a passkey</button>
        <p id="passkey-status" role="status"></p>
        ${Object.keys(config.social).map(
          (provider) => html`<form method="post" action="/sign-in">
            <input type="hidden" name="method" value="social">
            <input type="hidden" name="provider" value="${provider}">
            <input type="hidden" name="oauth_query" value="${query}">
            <button class="secondary">Continue with ${PROVIDER_NAMES[provider]}</button>
          </form>`
        )}
        <hr>
        <form method="post" action="/sign-in">
          <input type="hidden" name="method" value="magic-link">
          <input type="hidden" name="oauth_query" value="${query}">
          <label for="ml-email">Or get a sign-in link by email</label>
          <input id="ml-email" name="email" type="email" autocomplete="email" required>
          <button class="secondary">Email me a link</button>
        </form>`,
      status,
      true
    );
  app.get('/sign-in', (c) => {
    const error = c.req.query('error');
    return signInPage(c, oauthQuery(c), error && socialError(error));
  });
  app.post('/sign-in', async (c) => {
    const f = await form(c);
    const query = f('oauth_query');
    if (f('method') === 'magic-link') {
      // During an OAuth request the link brings the browser back to it (resumeUrl), or to the 2FA page first.
      // A link that fails (used, expired) comes back to this page with the error and the request, never to resumeUrl.
      const r = await ba(c, 'POST', '/sign-in/magic-link', {
        email: f('email'),
        callbackURL: resumeUrl(query),
        ...(query ? { errorCallbackURL: `/sign-in?${query}` } : {}),
      });
      if (r.status !== 200) return signInPage(c, query, errorText('/sign-in/magic-link', r), undefined, 400);
      return signInPage(c, query, undefined, 'If that address has an account, a sign-in link is on its way. It works once, for 5 minutes.');
    }
    if (f('method') === 'social') {
      // With oauth_query the provider resumes the app's request right after the callback (or the 2FA page does).
      const r = await ba(c, 'POST', '/sign-in/social', {
        provider: f('provider'),
        callbackURL: resumeUrl(query),
        errorCallbackURL: query ? `/sign-in?${query}` : '/sign-in',
        ...(query ? { oauth_query: query } : {}),
      });
      const url = (r.data as { url?: string } | null)?.url;
      if (r.status !== 200 || !url) return signInPage(c, query, errorText('/sign-in/social', r), undefined, 400);
      return c.redirect(url, 303);
    }
    const r = await ba(c, 'POST', '/sign-in/email', {
      email: f('email'),
      password: f('password'),
      ...(query ? { oauth_query: query } : {}),
    });
    if (r.status !== 200) return signInPage(c, query, errorText('/sign-in/email', r), undefined, r.status === 429 ? 429 : 400);
    if ((r.data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) {
      return c.redirect(query ? `${TWO_FACTOR_PAGE}?${query}` : TWO_FACTOR_PAGE, 303);
    }
    // During an OAuth request the provider's after-hook answers with where to go next (consent or the app).
    const next = (r.data as { redirect?: boolean; url?: string } | null)?.url;
    if (query && !next) throw new Error('sign-in during an OAuth request returned no redirect');
    return c.redirect(next ?? '/', 303);
  });

  app.post('/sign-out', async (c) => {
    const r = await ba(c, 'POST', '/sign-out', {});
    if (r.status !== 200) return render(c, 'Sign out', alert(errorText('/sign-out', r)), 400);
    return c.redirect('/signed-out', 303);
  });
  app.get('/signed-out', (c) => render(c, 'Signed out', html`<p>You're signed out.</p><p><a href="/sign-in">Sign in again</a></p>`));

  // ── Sign up ──
  const signUpPage = (c: Context, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Create an account',
      html`${alert(error)}
        <form method="post" action="/sign-up">
          <label for="name">Name</label><input id="name" name="name" autocomplete="name" required>
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
          <label for="password">Password (8 characters or more)</label>
          <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
          <button>Create account</button>
        </form>
        <p><a href="/sign-in">I have an account</a></p>`,
      status
    );
  app.get('/sign-up', (c) => signUpPage(c));
  app.post('/sign-up', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/sign-up/email', { name: f('name'), email: f('email'), password: f('password') });
    if (r.status !== 200) return signUpPage(c, errorText('/sign-up/email', r), 400);
    return render(
      c,
      'Check your email',
      html`<p class="ok" role="status">We sent a verification link to the address you gave. Open it and enter the password you just chose.</p>`
    );
  });

  // ── Password reset ──
  const forgotPage = (c: Context, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Forgot password',
      html`${alert(error)}
        <form method="post" action="/forgot-password">
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
          <button>Email me a reset link</button>
        </form>`,
      status
    );
  app.get('/forgot-password', (c) => forgotPage(c));
  app.post('/forgot-password', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/request-password-reset', {
      email: f('email'),
      redirectTo: `${config.baseUrl.origin}/reset-password`,
    });
    if (r.status !== 200) return forgotPage(c, errorText('/request-password-reset', r), 400);
    return render(c, 'Check your email', html`<p class="ok" role="status">If that address has an account, a reset link is on its way.</p>`);
  });

  // Better Auth's link (/api/auth/reset-password/<token>) checks the token and redirects here with ?token= or ?error=.
  const resetPage = (c: Context, token: string, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Choose a new password',
      token
        ? html`${alert(error)}
            <form method="post" action="/reset-password">
              <input type="hidden" name="token" value="${token}">
              <label for="password">New password (8 characters or more)</label>
              <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
              <button>Change password</button>
            </form>
            <p>Changing your password signs you out everywhere.</p>`
        : html`${alert(error ?? 'This reset link is invalid or expired.')}<p><a href="/forgot-password">Get a new link</a></p>`,
      status
    );
  app.get('/reset-password', (c) => {
    const error = c.req.query('error');
    return resetPage(c, error ? '' : (c.req.query('token') ?? ''), error && 'This reset link is invalid or expired.', error ? 400 : 200);
  });
  app.post('/reset-password', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/reset-password', { token: f('token'), newPassword: f('password') });
    if (r.status !== 200) return resetPage(c, f('token'), errorText('/reset-password', r), 400);
    return render(
      c,
      'Password changed',
      html`<p class="ok" role="status">Your password is changed and every session is signed out.
        If your email isn't verified yet, open the verification link again and enter the new password.</p>
        <p><a href="/sign-in">Sign in</a></p>`
    );
  });

  // ── Risk 8: verifying an email needs the password chosen at sign-up ──
  // GET shows a form and changes nothing; POST checks the token and the password, then marks the email verified in
  // one conditional UPDATE (markEmailVerified). Better Auth's own route is never called: this path is intercepted
  // for every method Hono routes here (GET, HEAD, POST), and Better Auth matches only this exact path.
  const verifyPage = (c: Context, error?: string, status: ContentfulStatusCode = 200, help = false) =>
    render(
      c,
      'Verify your email',
      html`${alert(error)}
        <form method="post">
          <label for="password">Enter the password you chose when you signed up</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button>Verify email</button>
        </form>
        ${help
          ? html`<p><a href="/forgot-password">Forgot password?</a> Resetting it replaces the password and signs out every
              session; then open this link again with the new password.</p>`
          : ''}`,
      status
    );
  app.get('/api/auth/verify-email', (c) => verifyPage(c));
  app.post('/api/auth/verify-email', async (c) => {
    const tooMany = (retryAfter: number | null) => verifyPage(c, `Too many attempts. Try again in ${retryAfter} seconds.`, 429, true);
    const ip = getConnInfo(c).remote.address ?? 'unknown';
    // Per IP first, before anything else is read. Higher than the per-user limit: several people can share an IP.
    const byIp = await limiter.consume(`verify-email:ip:${ip}`, { window: 300, max: 20 });
    if (!byIp.allowed) return tooMany(byIp.retryAfter);
    const user = await verificationUser(c.req.query('token') ?? '');
    if (user === 'expired') {
      return render(c, 'Verify your email', alert("This verification link has expired. Use 'Email me a link' on the sign-in page: it verifies your email too."), 400);
    }
    if (user === undefined) {
      return render(c, 'Verify your email', alert("This verification link is broken. Use 'Email me a link' on the sign-in page: it verifies your email too."), 400);
    }
    const password = (await form(c))('password');
    if (password === '') return verifyPage(c, 'Enter your password.', 400);
    // Only a genuine link reaches the per-user counter.
    const byUser = await limiter.consume(`verify-email:user:${user.userId}`, { window: 300, max: 5 });
    if (!byUser.allowed) return tooMany(byUser.retryAfter);
    const stored = (credential.get(user.userId) as { password: string | null } | undefined)?.password;
    if (!stored) {
      // None exist in M1 (a magic link can't create an account); fail closed rather than verify without a password.
      return render(c, 'Verify your email', alert("This account has no password, so this link can't verify it. Use 'Email me a link' on the sign-in page instead."), 409);
    }
    let matches: boolean;
    try {
      // Longer than Better Auth's 128-character maximum: can't be the sign-up password; skip the scrypt work.
      matches = password.length <= 128 && (await passwordMatches(stored, password));
    } catch (err) {
      log('error', 'verify-email: could not check the password', { userId: user.userId, error: err instanceof Error ? err.message : 'unknown error' });
      return render(c, 'Verify your email', alert("We couldn't check your password, so nothing was changed. Tell whoever runs this sign-in service."), 500);
    }
    if (!matches) return verifyPage(c, "That isn't the password this account was created with.", 401, true);
    if (!markVerified(user.userId, user.email, stored)) {
      return verifyPage(c, 'The password for this account changed while you were verifying. Enter the current password.', 409, true);
    }
    return render(c, 'Email verified', html`<p class="ok" role="status">Your email is verified.</p><p><a href="/sign-in">Sign in</a></p>`);
  });

  // ── Magic link: GET asks, POST signs in (Risk 7; also stops mail scanners from using up the link) ──
  app.get('/api/auth/magic-link/verify', (c) => {
    const token = c.req.query('token') ?? '';
    const row = pendingMagicLink.get(magicLinkIdentifier(token)) as { email: string; expiresAt: string } | undefined;
    if (row === undefined || new Date(row.expiresAt).getTime() <= Date.now()) {
      return render(c, 'Sign in', html`${alert('This sign-in link is invalid, used or expired.')}<p><a href="/sign-in">Get a new link</a></p>`, 400);
    }
    return render(
      c,
      'Sign in',
      html`<p>Sign in as <strong>${row.email}</strong>?</p>
        <form method="post"><button>Continue</button></form>
        <p>If you didn't ask for this link, close this page.</p>`
    );
  });
  app.post('/api/auth/magic-link/verify', async (c) => {
    const r = await ba(c, 'GET', `/magic-link/verify${new URL(c.req.url).search}`);
    // Better Auth answers with a redirect to callbackURL (or errorCallbackURL with ?error=), validated against
    // BASE_URL; without a callbackURL it answers 200 with JSON.
    if (r.location) return c.redirect(r.location, 303);
    if (r.status === 200) return c.redirect('/', 303);
    return render(c, 'Sign in', alert(errorText('/magic-link/verify', r)), 400);
  });

  // ── OAuth consent (the provider's consentPage) ──
  app.get('/consent', async (c) => {
    const query = oauthQuery(c);
    const params = new URLSearchParams(query);
    const clientId = params.get('client_id');
    if (!query || !clientId) return render(c, 'Allow access?', alert('This page needs a request from an app. Start again from the app.'), 400);
    const r = await ba(c, 'GET', `/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`);
    if (r.status !== 200) return render(c, 'Allow access?', alert(errorText('/oauth2/public-client', r)), r.status === 401 ? 401 : 400);
    const name = (r.data as { client_name?: string }).client_name ?? clientId;
    const scopes = (params.get('scope') ?? '').split(' ').filter(Boolean);
    // RFC 8707 resources: the APIs the app wants tokens for. Allow posts this same query back, and the provider
    // checks its signature, so what's listed here is what's being allowed.
    const resources = params.getAll('resource');
    return render(
      c,
      'Allow access?',
      html`<p><strong>${name}</strong> wants to:</p>
        <ul>
          ${scopes.map((s) => html`<li>${SCOPE_WORDS[s] ?? s}</li>`)}
          ${resources.map((r) => html`<li>Access <strong>${r}</strong> on your behalf</li>`)}
        </ul>
        <form method="post" action="/consent">
          <input type="hidden" name="oauth_query" value="${query}">
          <button name="accept" value="yes">Allow</button>
          <button name="accept" value="no" class="secondary">Deny</button>
        </form>`
    );
  });
  app.post('/consent', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/oauth2/consent', { accept: f('accept') === 'yes', oauth_query: f('oauth_query') });
    const next = (r.data as { url?: string } | null)?.url;
    if (r.status !== 200 || !next) return render(c, 'Allow access?', alert(errorText('/oauth2/consent', r)), 400);
    return c.redirect(next, 303);
  });

  // ── Back to the app after a sign-in that couldn't carry its request in the body (magic link) ──
  // The provider resumes a request itself when a sign-in POST carries oauth_query (password, 2FA, passkey, social).
  // A magic link is a GET, so its callbackURL brings the browser here with the signed request: checked, then sent back
  // to /authorize. Only a session created after the app asked counts as the fresh sign-in prompt=login or max_age want.
  app.get(OAUTH_RESUME_PAGE, async (c) => {
    const query = oauthQuery(c);
    if (c.req.query('error')) return c.redirect(`/sign-in?${new URL(c.req.url).search.slice(1)}`, 303); // a failed sign-in
    if (!query || !(await verifyOAuthQueryParams(query, secret))) {
      return render(c, 'Sign in', alert('This sign-in request expired or was changed. Start again from the app.'), 400);
    }
    const session = await currentSession(c);
    if (!session) return c.redirect(`/sign-in?${query}`, 303);
    const params = new URLSearchParams(query);
    const issuedAt = Number(params.get('ba_iat'));
    for (const p of ['sig', 'exp', 'ba_iat', 'ba_pl', 'ba_param']) params.delete(p); // the provider's signing fields
    if (new Date(session.session.createdAt).getTime() >= issuedAt) {
      const prompts = (params.get('prompt') ?? '').split(' ').filter((p) => p && p !== 'login');
      if (prompts.length > 0) params.set('prompt', prompts.join(' '));
      else params.delete('prompt');
      params.delete('max_age');
    }
    return c.redirect(`/api/auth/oauth2/authorize?${params}`, 303);
  });

  // ── 2FA challenge (after any first factor on a 2FA account; src/signin.ts) ──
  const twoFactorPage = (c: Context, query: string, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Two-factor authentication',
      html`${alert(error)}
        <form method="post" action="${TWO_FACTOR_PAGE}">
          <input type="hidden" name="oauth_query" value="${query}">
          <label for="code">Code from your authenticator app</label>
          <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
          <button>Continue</button>
        </form>
        <hr>
        <form method="post" action="${TWO_FACTOR_PAGE}">
          <input type="hidden" name="oauth_query" value="${query}">
          <input type="hidden" name="method" value="backup">
          <label for="backup">Or use a backup code (each works once)</label>
          <input id="backup" name="code" autocomplete="off" required>
          <button class="secondary">Use backup code</button>
        </form>`,
      status
    );
  app.get(TWO_FACTOR_PAGE, (c) => twoFactorPage(c, oauthQuery(c)));
  app.post(TWO_FACTOR_PAGE, async (c) => {
    const f = await form(c);
    const query = f('oauth_query');
    const path = f('method') === 'backup' ? '/two-factor/verify-backup-code' : '/two-factor/verify-totp';
    const r = await ba(c, 'POST', path, { code: f('code'), ...(query ? { oauth_query: query } : {}) });
    if (r.status !== 200) return twoFactorPage(c, query, errorText(path, r), r.status === 429 ? 429 : 400);
    // With oauth_query the provider continues the app's request and answers with where to go next.
    const next = (r.data as { url?: string } | null)?.url;
    if (query && !next) throw new Error('2FA during an OAuth request returned no redirect');
    return c.redirect(next ?? '/', 303);
  });

  // ── Turning on TOTP: enable (secret + backup codes, shown once), then confirm a code ──
  const signedOut = (c: Context) => c.redirect('/sign-in', 303);
  const confirmForm = html`<p>Turning it on signs out your other sessions, revokes apps' refresh tokens and removes
      your passkeys (add them again afterwards).</p>
    <form method="post" action="/two-factor/setup/confirm">
    <label for="code">Then enter the code it shows</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
    <button>Turn on</button>
  </form>`;
  app.get('/two-factor/setup', async (c) => {
    const session = await currentSession(c);
    if (!session) return signedOut(c);
    if (session.user.twoFactorEnabled) return render(c, 'Two-factor authentication', html`<p class="ok" role="status">Two-factor authentication is on.</p>`);
    return render(
      c,
      'Two-factor authentication',
      html`<p>Each sign-in will also ask for a code from an authenticator app.</p>
        <form method="post" action="/two-factor/setup">
          <label for="password">Your password (leave empty if your account has none)</label>
          <input id="password" name="password" type="password" autocomplete="current-password">
          <button>Set up</button>
        </form>`
    );
  });
  app.post('/two-factor/setup', async (c) => {
    const password = (await form(c))('password');
    const r = await ba(c, 'POST', '/two-factor/enable', password ? { password } : {});
    if (r.status === 401) return signedOut(c);
    if (r.status !== 200) return render(c, 'Two-factor authentication', html`${alert(errorText('/two-factor/enable', r))}<p><a href="/two-factor/setup">Try again</a></p>`, 400);
    const { totpURI, backupCodes } = r.data as { totpURI: string; backupCodes: string[] };
    return render(
      c,
      'Two-factor authentication',
      html`<p>Add this account to your authenticator app with this key:</p>
        <p><code>${new URL(totpURI).searchParams.get('secret')}</code></p>
        <p>or this link: <code>${totpURI}</code></p>
        <p>Backup codes, each works once if you lose the app. Save them now: they won't be shown again.</p>
        <ul>${backupCodes.map((code) => html`<li><code>${code}</code></li>`)}</ul>
        ${confirmForm}`
    );
  });
  app.post('/two-factor/setup/confirm', async (c) => {
    const r = await ba(c, 'POST', '/two-factor/verify-totp', { code: (await form(c))('code') });
    if (r.status !== 200) return render(c, 'Two-factor authentication', html`${alert(errorText('/two-factor/verify-totp', r))}${confirmForm}`, 400);
    return render(c, 'Two-factor authentication', html`<p class="ok" role="status">Two-factor authentication is on. Your other sessions were signed out, apps'
        refresh tokens revoked and passkeys removed. <a href="/passkeys">Add a passkey</a></p>`);
  });

  // ── Adding a passkey (the browser half is /passkey.js). On a 2FA account, a fresh code comes first. ──
  // Better Auth also refuses a session older than its freshAge, so such a session is asked to sign in again first.
  const tooOld = (session: NonNullable<SessionData>) => Date.now() - new Date(session.session.createdAt).getTime() >= SESSION_FRESH_AGE_SECONDS * 1000;
  const signInAgain = (c: Context) =>
    render(
      c,
      'Passkeys',
      html`<p>To add a passkey, sign in again first: your sign-in is more than a day old.</p>
        <form method="post" action="/sign-out"><button>Sign out</button></form>`
    );
  const passkeysPage = (c: Context, needsCode: boolean, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Passkeys',
      needsCode
        ? html`${alert(error)}
            <form method="post" action="/passkeys">
              <label for="code">To add a passkey, enter a code from your authenticator app</label>
              <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
              <button>Continue</button>
            </form>`
        : html`<p>A passkey signs you in with this device's lock (fingerprint, face or PIN) instead of a password.</p>
            <button type="button" data-passkey="add" data-status="passkey-status">Add a passkey</button>
            <p id="passkey-status" role="status"></p>`,
      status,
      !needsCode
    );
  app.get('/passkeys', async (c) => {
    const session = await currentSession(c);
    if (!session) return signedOut(c);
    if (tooOld(session)) return signInAgain(c);
    return passkeysPage(c, session.user.twoFactorEnabled === true);
  });
  app.post('/passkeys', async (c) => {
    const session = await currentSession(c);
    if (!session) return signedOut(c);
    if (tooOld(session)) return signInAgain(c);
    const r = await ba(c, 'POST', '/two-factor/verify-totp', { code: (await form(c))('code') });
    if (r.status !== 200) return passkeysPage(c, true, errorText('/two-factor/verify-totp', r), 400);
    return passkeysPage(c, false);
  });

  return app;
}
