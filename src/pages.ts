// Hosted pages (sign-in, sign-up, reset, magic link, OAuth consent) and the Risk 8 fix (plan flow.md).
// Server-rendered with hono/html, which escapes every interpolated value. Forms post back to these routes, which
// call Better Auth through callAuth (client IP set from the TCP peer, so Better Auth's rate limits apply).
import { getConnInfo } from '@hono/node-server/conninfo';
import type Database from 'better-sqlite3';
import { Hono, type Context } from 'hono';
import { html } from 'hono/html';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { createHash, scrypt, timingSafeEqual } from 'node:crypto';
import type { AuthCall } from './app.ts';
import { memoryRateLimit } from './auth.ts';
import type { Config } from './config.ts';
import type { Logger } from './log.ts';

export interface PageDeps {
  callAuth: AuthCall;
  config: Config;
  db: Database.Database;
  log: Logger;
}

type Html = ReturnType<typeof html>;

const layout = (title: string, body: Html) => html`<!doctype html>
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
</head>
<body><main>
<h1>${title}</h1>
${body}
</main></body>
</html>`;

const alert = (message: string | undefined) => (message ? html`<p role="alert">${message}</p>` : html``);

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
  if (!salt || expected.length !== 64) throw new Error('the stored password is not a Better Auth scrypt hash');
  const derived = await new Promise<Buffer>((resolve, reject) =>
    scrypt(password.normalize('NFKC'), salt, 64, SCRYPT, (err, k) => (err ? reject(err) : resolve(k)))
  );
  return timingSafeEqual(derived, expected);
}

/** The user a verification link belongs to. Better Auth checks the signature and that this user owns the email. */
function verificationUserId(token: string): string | undefined {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'));
    // An email-change token (updateTo) can't be minted (change-email is off); refuse it rather than guess.
    return typeof payload.userId === 'string' && payload.updateTo === undefined ? payload.userId : undefined;
  } catch {
    return undefined;
  }
}

// Better Auth stores a magic link as sha256(token) under "magic-link:", and with verification.storeIdentifier
// 'hashed' hashes that identifier again (both base64url, no padding).
const b64sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');
const magicLinkIdentifier = (token: string) => b64sha256(`magic-link:${b64sha256(token)}`);

/**
 * Mounted BEFORE the /api/auth/* catch-all, so routes here intercept Better Auth paths
 * (GET /api/auth/verify-email, GET /api/auth/magic-link/verify).
 */
export function pageRoutes({ callAuth, config, db, log }: PageDeps): Hono {
  const app = new Hono();
  const limiter = memoryRateLimit();
  const credential = db.prepare(`SELECT password FROM account WHERE userId = ? AND providerId = 'credential'`);
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
  const render = (c: Context, title: string, body: Html, status: ContentfulStatusCode = 200) =>
    c.html(layout(title, body), status);
  /** The OAuth provider's signed query (the loginPage/consentPage is opened with it), or '' if there is none. */
  const oauthQuery = (c: Context) => {
    const q = new URL(c.req.url).search.slice(1);
    return new URLSearchParams(q).has('sig') ? q : '';
  };

  app.get('/', async (c) => {
    const { data } = await ba(c, 'GET', '/get-session');
    const email = (data as { user?: { email?: string } } | null)?.user?.email;
    const error = c.req.query('error');
    return render(
      c,
      'AuthWAPI',
      html`${alert(error && `That link didn't work (${error}). Ask for a new one from the sign-in page.`)}
        ${email
          ? html`<p>Signed in as <strong>${email}</strong>.</p>
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
        ${query
          ? '' // ponytail: no magic link during an OAuth request yet; the emailed link would need to resume it
          : html`<hr>
              <form method="post" action="/sign-in">
                <input type="hidden" name="method" value="magic-link">
                <label for="ml-email">Or get a sign-in link by email</label>
                <input id="ml-email" name="email" type="email" autocomplete="email" required>
                <button class="secondary">Email me a link</button>
              </form>`}`,
      status
    );
  app.get('/sign-in', (c) => signInPage(c, oauthQuery(c)));
  app.post('/sign-in', async (c) => {
    const f = await form(c);
    if (f('method') === 'magic-link') {
      const r = await ba(c, 'POST', '/sign-in/magic-link', { email: f('email'), callbackURL: '/' });
      if (r.status !== 200) return signInPage(c, '', errorText('/sign-in/magic-link', r), undefined, 400);
      return signInPage(c, '', undefined, 'If that address has an account, a sign-in link is on its way. It works once, for 5 minutes.');
    }
    const query = f('oauth_query');
    const r = await ba(c, 'POST', '/sign-in/email', {
      email: f('email'),
      password: f('password'),
      ...(query ? { oauth_query: query } : {}),
    });
    if (r.status !== 200) return signInPage(c, query, errorText('/sign-in/email', r), undefined, r.status === 429 ? 429 : 400);
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
  // GET shows a form and changes nothing; POST checks the password, then asks Better Auth to verify. Better Auth's
  // own GET route is reachable only through the internal call below: this path is intercepted for every method
  // Hono routes here (GET, HEAD, POST), and Better Auth matches only this exact path.
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
    const token = c.req.query('token') ?? '';
    const userId = verificationUserId(token);
    if (userId === undefined) {
      return render(c, 'Verify your email', alert("This verification link is broken. Use 'Email me a link' on the sign-in page: it verifies your email too."), 400);
    }
    const password = (await form(c))('password');
    if (password === '') return verifyPage(c, 'Enter your password.', 400);
    const ip = getConnInfo(c).remote.address ?? 'unknown';
    for (const key of [`verify-email:ip:${ip}`, `verify-email:user:${userId}`]) {
      const { allowed, retryAfter } = await limiter.consume(key, { window: 300, max: 5 });
      if (!allowed) return verifyPage(c, `Too many attempts. Try again in ${retryAfter} seconds.`, 429, true);
    }
    const stored = (credential.get(userId) as { password: string | null } | undefined)?.password;
    if (!stored) {
      // None exist in M1 (a magic link can't create an account); fail closed rather than verify without a password.
      return render(c, 'Verify your email', alert("This account has no password, so this link can't verify it. Use 'Email me a link' on the sign-in page instead."), 409);
    }
    // Longer than Better Auth's 128-character maximum: can't be the sign-up password; skip the scrypt work.
    if (password.length > 128 || !(await passwordMatches(stored, password))) {
      return verifyPage(c, "That isn't the password this account was created with.", 401, true);
    }
    const r = await ba(c, 'GET', `/verify-email?token=${encodeURIComponent(token)}`);
    if (r.status !== 200) {
      return render(c, 'Verify your email', alert(`${errorText('/verify-email', r)} Use 'Email me a link' on the sign-in page to verify instead.`), 400);
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
    return render(
      c,
      'Allow access?',
      html`<p><strong>${name}</strong> wants to:</p>
        <ul>${scopes.map((s) => html`<li>${SCOPE_WORDS[s] ?? s}</li>`)}</ul>
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

  return app;
}
