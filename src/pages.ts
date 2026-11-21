// Hosted pages (sign-in, sign-up, reset, magic link, OAuth consent, 2FA, passkeys, organization pick, invitations) and
// the Risk 8 fix (plan flow.md).
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
import { generate } from 'lean-qr';
import { toSvgPath } from 'lean-qr/extras/svg';
import type { AuthCall } from './app.ts';
import { memoryRateLimit, SESSION_FRESH_AGE_SECONDS } from './auth.ts';
import type { Config } from './config.ts';
import type { Logger } from './log.ts';
import { SELECT_ORG_PAGE, withConsentOrg } from './oauth.ts';
import { ACCEPT_INVITATION_PAGE } from './orgs.ts';
import { alert, icons, layout, type Html, type LayoutOptions } from './pages-ui.ts';
import { OAUTH_RESUME_PAGE, TWO_FACTOR_PAGE } from './signin.ts';
import { purgeUnproven } from './sso.ts';

export interface PageDeps {
  callAuth: AuthCall;
  config: Config;
  db: Database.Database;
  log: Logger;
  /** The instance secret Better Auth signs verification tokens with (HS256). */
  secret: string;
}

/** Who an app is: an MCP client (its client_id is its metadata URL) by host, since its name is self-asserted. */
const appLabel = (clientId: string, name: string | undefined) => {
  const host = URL.canParse(clientId) ? new URL(clientId).host : undefined;
  return host ? html`<strong>${host}</strong> (calls itself "${name ?? clientId}")` : html`<strong>${name ?? clientId}</strong>`;
};

/** The totpURI as a QR code: dark modules on white with a 4-module quiet zone, so it scans in dark mode too. */
const qrCode = (uri: string) => {
  const code = generate(uri);
  const side = code.size + 8;
  return html`<svg class="qr" role="img" aria-label="QR code for your authenticator app" viewBox="-4 -4 ${side} ${side}" shape-rendering="crispEdges"><rect x="-4" y="-4" width="${side}" height="${side}" fill="#fff"/><path d="${toSvgPath(code)}" fill="#000"/></svg>`;
};

/** Plain words for the error codes a browser is most likely to arrive at /error with. Others get the generic text. */
const ERROR_WORDS: Record<string, string> = {
  invalid_redirect: "The app asked to send you back to an address it hasn't registered, so you weren't sent there. Tell the app's developer.",
  invalid_client: "AuthWAPI doesn't know the app that sent you here. Tell the app's developer.",
  invalid_request: "The app's request wasn't valid. Go back to the app and try again; if it keeps happening, tell the app's developer.",
  invalid_scope: "The app asked for access AuthWAPI doesn't offer. Tell the app's developer.",
  state_mismatch: 'This sign-in was started in another browser or took too long. Start again.',
  state_not_found: 'This sign-in was started in another browser or took too long. Start again.',
  please_restart_the_process: 'This sign-in was started in another browser or took too long. Start again.',
};

// RP-initiated logout (@better-auth/oauth-provider) answers browsers with its own fixed pages; restyleLogoutPage
// re-renders them in this layout. No script runs on them, so their CSP stays strict apart from the inline style.
const LOGOUT_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const unescapeHtml = (s: string) =>
  s.replace(/&(lt|gt|quot|#39|amp);/g, (_, e: string) => ({ lt: '<', gt: '>', quot: '"', '#39': "'", amp: '&' })[e]!);

/**
 * Better Auth's logout pages (confirm, logged out, error) in AuthWAPI's layout. The page is chosen by its
 * data-oidc-logout-* marker and its wording is ours; only the confirm form's action and the note or error sentence come
 * from Better Auth (as text, escaped again here). Status and every other header, the confirmation and session cookies
 * included, are kept. HTML of any other shape is served unchanged and logged: a deliberate fallback, since refusing
 * would break logout. test/oauth.test.ts pins the shape, so an upgrade that changes it fails CI.
 */
export async function restyleLogoutPage(res: Response, log: Logger): Promise<Response> {
  if (!res.headers.get('content-type')?.startsWith('text/html')) return res;
  const source = await res.clone().text();
  const text = (state: string) => {
    const m = new RegExp(`<p data-oidc-logout-state="${state}">([^<]*)</p>`).exec(source);
    return m ? unescapeHtml(m[1]) : undefined;
  };
  const action = /<form method="post" data-oidc-logout-confirmation action="([^"<>]+)">/.exec(source)?.[1];
  const loggedOut = text('logged-out');
  const error = text('error');
  let page: Html;
  if (action) {
    page = layout(
      'Sign out?',
      html`<form method="post" action="${unescapeHtml(action)}"><button name="action" value="confirm">Sign out</button></form>`,
      false,
      { icon: icons.shield, subtitle: 'Do you want to sign out of AuthWAPI in this browser?' }
    );
  } else if (loggedOut !== undefined) {
    const note = loggedOut.replace(/^Logged out\.\s*/, '');
    page = layout('Signed out', html`<p class="ok" role="status">You're signed out.</p>${note ? html`<p>${note}</p>` : ''}`, false, {
      icon: icons.check,
    });
  } else if (error !== undefined) {
    page = layout("Couldn't sign out", alert(error), false, { icon: icons.shield });
  } else {
    log('warn', 'logout page: Better Auth sent HTML of an unknown shape; served it unchanged');
    return res;
  }
  const headers = new Headers(res.headers);
  headers.delete('content-length');
  headers.set('content-type', 'text/html; charset=utf-8');
  headers.set('content-security-policy', LOGOUT_CSP);
  return new Response(String(await page), { status: res.status, headers });
}
/** The browser half of passkeys (WebAuthn needs page script): served from our origin, the only one CSP allows. */
const PASSKEY_JS = readFileSync(new URL('./passkey-client.js', import.meta.url), 'utf8');

const PROVIDER_NAMES: Record<string, string> = { google: 'Google', github: 'GitHub' };
const PROVIDER_ICONS: Record<string, Html> = { google: icons.google, github: icons.github };

/** Why a Google/GitHub sign-in came back with ?error=. */
const socialError = (code: string) =>
  code === 'account_not_linked'
    ? "An account with this email already exists but its address isn't verified, so it can't be joined to that sign-in yet. Use 'Email me a link' below: it verifies the address, then that sign-in works too."
    : code === 'email_not_verified'
      ? "That provider didn't confirm your email address is verified. Verify it there, or sign in another way."
      : code === 'account_exists'
        ? 'An account with this email already exists, so this SSO sign-in was refused. Sign in as before, or ask the operator to connect it to SSO.'
        : `That sign-in didn't work (${code}). Try again or sign in another way.`;

/** Plain-words descriptions for the consent page. Unknown scopes are shown by name. */
const SCOPE_WORDS: Record<string, string> = {
  openid: 'Confirm who you are',
  profile: 'See your name',
  email: 'See your email address and whether it is verified',
  offline_access: "Stay signed in to the app while you're away",
  organization: 'See which organization you sign in for and your role in it',
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
 * that was just checked, so a password reset that lands between the check and here makes it change nothing. It is the
 * mailbox owner's first proof, so in the same transaction everything set up before it goes (purgeUnproven, keeping the
 * password just checked). Returns whether it changed the row. This replaces Better Auth's verify-email, which here
 * sets only emailVerified and updatedAt (no verification hooks are configured, autoSignIn is off).
 * Throws TransactionBusy while another request's Better Auth transaction holds the connection: a transaction begun
 * now would nest inside it and be undone by its rollback.
 */
export class TransactionBusy extends Error {}
export function markEmailVerified(db: Database.Database) {
  const update = db.prepare(
    `UPDATE user SET emailVerified = 1, updatedAt = ? WHERE id = ? AND email = ?
     AND EXISTS (SELECT 1 FROM account WHERE userId = user.id AND providerId = 'credential' AND password = ?)`
  );
  const verified = db.prepare('SELECT emailVerified FROM user WHERE id = ?').pluck();
  return (userId: string, email: string, hash: string): boolean => {
    if (db.inTransaction) throw new TransactionBusy();
    return db.transaction(() => {
      const already = verified.get(userId) === 1; // clicking the link again purges nothing
      if (update.run(new Date().toISOString(), userId, email, hash).changes !== 1) return false;
      if (!already) purgeUnproven(db, userId, { keepCredential: true, verify: false });
      return true;
    })();
  };
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
  '/error',
  '/api/auth/verify-email',
  '/api/auth/magic-link/verify',
  TWO_FACTOR_PAGE,
  '/two-factor/setup',
  '/two-factor/setup/confirm',
  '/passkeys',
  OAUTH_RESUME_PAGE,
  SELECT_ORG_PAGE,
  ACCEPT_INVITATION_PAGE,
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
  const render = (c: Context, title: string, body: Html, status: ContentfulStatusCode = 200, passkeyScript = false, options?: LayoutOptions) =>
    c.html(layout(title, body, passkeyScript, options), status);
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
  type SessionData = {
    session: { id: string; createdAt: string; oauthOrgId?: string | null };
    user: { id: string; email: string; twoFactorEnabled?: boolean };
  } | null;
  const memberships = db.prepare(
    `SELECT o.id AS id, o.name AS name, m.role AS role FROM member m JOIN organization o ON o.id = m.organizationId WHERE m.userId = ? ORDER BY o.name, o.id`
  );
  const membership = db.prepare(
    `SELECT o.name AS name, m.role AS role FROM member m JOIN organization o ON o.id = m.organizationId WHERE m.userId = ? AND o.id = ?`
  );
  const setOrgPick = db.prepare('UPDATE session SET oauthOrgId = ? WHERE id = ?');
  /** The signed-in session, or null, also when the lookup fails (rate limited, say): pages then act signed out. */
  const currentSession = async (c: Context) => {
    const r = await ba(c, 'GET', '/get-session');
    return r.status === 200 ? (r.data as SessionData) : null;
  };

  // Better Auth sends browsers here for errors (onAPIError.errorURL in src/auth.ts). Only a code listed in ERROR_WORDS
  // is shown, and error_description never: anything else is text a link put in the URL, shown on this origin.
  app.get('/error', (c) => {
    const code = c.req.query('error') ?? '';
    const known = Object.hasOwn(ERROR_WORDS, code);
    return render(
      c,
      'Something went wrong',
      html`${alert(known ? ERROR_WORDS[code] : "That didn't work. Go back to the app or page you came from and start again.")}
        ${known ? html`<p class="aw-note">Error code: <code>${code}</code></p>` : ''}
        <a class="aw-button secondary" href="/">AuthWAPI home</a>`,
      400,
      false,
      { icon: icons.shield }
    );
  });

  app.get('/passkey.js', (c) => c.body(PASSKEY_JS, 200, { 'content-type': 'text/javascript; charset=utf-8' }));

  app.get('/', async (c) => {
    const email = (await currentSession(c))?.user.email;
    const error = c.req.query('error');
    return render(
      c,
      email ? 'Your account' : 'Welcome',
      html`${alert(error && `That link didn't work (${error}). Ask for a new one from the sign-in page.`)}
        ${email
          ? html`<div class="aw-account">
                <span class="aw-avatar" aria-hidden="true">${email.charAt(0).toUpperCase()}</span>
                <p>Signed in as <strong>${email}</strong></p>
              </div>
              <nav class="aw-nav" aria-label="Account security">
                <a href="/two-factor/setup">${icons.shield}<span>Two-factor authentication<small>Ask for a code from an app at each sign-in</small></span>${icons.chevron}</a>
                <a href="/passkeys">${icons.passkey}<span>Passkeys<small>Sign in with this device's lock</small></span>${icons.chevron}</a>
              </nav>
              <form method="post" action="/sign-out"><button class="secondary">Sign out</button></form>`
          : html`<div class="aw-stack">
                <a class="aw-button" href="/sign-in">Sign in</a>
                <a class="aw-button secondary" href="/sign-up">Create an account</a>
              </div>`}`,
      200,
      false,
      email ? undefined : { subtitle: 'Sign in to your account, or create one.' }
    );
  });

  // ── Sign in (also the OAuth loginPage) ──
  const clientName = db.prepare('SELECT name FROM oauthClient WHERE clientId = ? AND NOT coalesce(disabled, 0)').pluck();
  /**
   * The app a validly signed OAuth request is for, named the way the consent page names it; otherwise undefined.
   * Read here rather than through Better Auth's public-client-prelogin, which would hand any caller holding a
   * signed request the client's contacts, URLs and logo too.
   */
  const appFor = async (query: string) => {
    const clientId = new URLSearchParams(query).get('client_id');
    if (!query || !clientId || !(await verifyOAuthQueryParams(query, secret))) return undefined;
    const name = clientName.get(clientId) as string | null | undefined;
    return name === undefined ? undefined : appLabel(clientId, name ?? undefined);
  };
  const signInPage = async (
    c: Context,
    query: string,
    error?: string,
    notice?: string,
    status: ContentfulStatusCode = 200,
    openDisclosure?: 'sso' | 'magic-link'
  ) => {
    const app = await appFor(query);
    return render(
      c,
      'Sign in',
      html`${app ? html`<p class="aw-note aw-app-banner">Sign in to continue to ${app}.</p>` : ''}${alert(error)}${notice ? html`<p class="ok" role="status">${notice}</p>` : ''}
        <form method="post" action="/sign-in">
          <input type="hidden" name="oauth_query" value="${query}">
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
          <div class="aw-label-row"><label for="password">Password</label><a href="/forgot-password">Forgot password?</a></div>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button>Sign in</button>
        </form>
        <div class="divider">or</div>
        <div class="aw-stack">
          <button type="button" class="secondary" data-passkey="sign-in" data-oauth-query="${query}" data-status="passkey-status">${icons.passkey}<span>Sign in with a passkey</span></button>
          <p id="passkey-status" role="status"></p>
          ${Object.keys(config.social).map(
            (provider) => html`<form method="post" action="/sign-in">
              <input type="hidden" name="method" value="social">
              <input type="hidden" name="provider" value="${provider}">
              <input type="hidden" name="oauth_query" value="${query}">
              <button class="secondary">${PROVIDER_ICONS[provider]}<span>Continue with ${PROVIDER_NAMES[provider]}</span></button>
            </form>`
          )}
        </div>
        <details class="aw-disclosure"${openDisclosure === 'sso' ? html` open` : ''}>
          <summary>${icons.building}<span>Sign in with SSO</span>${icons.chevron}</summary>
          <div class="aw-disclosure-body">
            <form method="post" action="/sign-in">
              <input type="hidden" name="method" value="sso">
              <input type="hidden" name="oauth_query" value="${query}">
              <label for="sso-email">Your work email</label>
              <input id="sso-email" name="email" type="email" autocomplete="email" required>
              <button class="secondary">Sign in with SSO</button>
            </form>
          </div>
        </details>
        <details class="aw-disclosure"${openDisclosure === 'magic-link' ? html` open` : ''}>
          <summary>${icons.mail}<span>Email me a sign-in link</span>${icons.chevron}</summary>
          <div class="aw-disclosure-body">
            <form method="post" action="/sign-in">
              <input type="hidden" name="method" value="magic-link">
              <input type="hidden" name="oauth_query" value="${query}">
              <label for="ml-email">Email</label>
              <input id="ml-email" name="email" type="email" autocomplete="email" required>
              <button class="secondary">Email me a link</button>
            </form>
          </div>
        </details>
        <p class="aw-foot-link">New here? <a href="/sign-up">Create an account</a></p>`,
      status,
      true,
      { subtitle: 'Welcome back. Sign in to continue.' }
    );
  };
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
      if (r.status !== 200) return signInPage(c, query, errorText('/sign-in/magic-link', r), undefined, 400, 'magic-link');
      return signInPage(c, query, undefined, 'If that address has an account, a sign-in link is on its way. It works once, for 5 minutes.', 200, 'magic-link');
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
    if (f('method') === 'sso') {
      // The email's domain picks the organization's provider; like magic link, the callback lands on resumeUrl.
      const r = await ba(c, 'POST', '/sign-in/sso', {
        email: f('email'),
        callbackURL: resumeUrl(query),
        errorCallbackURL: query ? `/sign-in?${query}` : '/sign-in',
      });
      const url = (r.data as { url?: string } | null)?.url;
      if (r.status !== 200 || !url) return signInPage(c, query, r.status === 404 ? 'No organization signs in with SSO at that address.' : errorText('/sign-in/sso', r), undefined, 400, 'sso');
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
    if (r.status !== 200) {
      return render(c, 'Sign out', html`${alert(errorText('/sign-out', r))}<p class="aw-foot-link"><a href="/">Back to your account</a></p>`, 400);
    }
    return c.redirect('/signed-out', 303);
  });
  app.get('/signed-out', (c) =>
    render(
      c,
      'Signed out',
      html`<a class="aw-button" href="/sign-in">Sign in again</a>`,
      200,
      false,
      { icon: icons.check, subtitle: "You're signed out on this device." }
    )
  );

  // ── Sign up ──
  const signUpPage = (c: Context, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Create an account',
      html`${alert(error)}
        <form method="post" action="/sign-up">
          <label for="name">Name</label><input id="name" name="name" autocomplete="name" required>
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
          <label for="password">Password <span class="aw-hint">(8 characters or more)</span></label>
          <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
          <button>Create account</button>
        </form>
        <p class="aw-foot-link"><a href="/sign-in">I have an account</a></p>`,
      status,
      false,
      { subtitle: "Sign up with your email. We'll send a link to verify it." }
    );
  app.get('/sign-up', (c) => signUpPage(c));
  app.post('/sign-up', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/sign-up/email', { name: f('name'), email: f('email'), password: f('password') });
    if (r.status !== 200) return signUpPage(c, errorText('/sign-up/email', r), 400);
    return render(
      c,
      'Check your email',
      html`<p class="ok" role="status">We sent a verification link to the address you gave. Open it and enter the password you just chose.</p>
        <p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`,
      200,
      false,
      { icon: icons.mail }
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
        </form>
        <p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`,
      status,
      false,
      { icon: icons.mail, subtitle: "Enter your email and we'll send you a password reset link." }
    );
  app.get('/forgot-password', (c) => forgotPage(c));
  app.post('/forgot-password', async (c) => {
    const f = await form(c);
    const r = await ba(c, 'POST', '/request-password-reset', {
      email: f('email'),
      redirectTo: `${config.baseUrl.origin}/reset-password`,
    });
    if (r.status !== 200) return forgotPage(c, errorText('/request-password-reset', r), 400);
    return render(
      c,
      'Check your email',
      html`<p class="ok" role="status">If that address has an account, a reset link is on its way.</p>
        <p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`,
      200,
      false,
      { icon: icons.mail }
    );
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
              <label for="password">New password <span class="aw-hint">(8 characters or more)</span></label>
              <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
              <button>Change password</button>
            </form>
            <p class="aw-foot-link">Changing your password signs you out everywhere.</p>`
        : html`${alert(error ?? 'This reset link is invalid or expired.')}
            <a class="aw-button" href="/forgot-password">Get a new link</a>
            <p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`,
      status,
      false,
      token ? { icon: icons.shield, subtitle: 'Enter a new password for your account.' } : { icon: icons.shield }
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
        <a class="aw-button" href="/sign-in">Sign in</a>`,
      200,
      false,
      { icon: icons.check }
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
          ? html`<p class="aw-note"><a href="/forgot-password">Forgot password?</a> Resetting it replaces the password and signs out every
              session; then open this link again with the new password.</p>`
          : ''}`,
      status,
      false,
      {
        icon: icons.shield,
        subtitle: 'To confirm this address is yours, enter the password you chose when you created your account.',
      }
    );
  /** A verification failure the form can't fix: the message and a way back to sign-in. */
  const verifyFailed = (c: Context, message: string, status: ContentfulStatusCode) =>
    render(c, 'Verify your email', html`${alert(message)}<a class="aw-button secondary" href="/sign-in">Go to sign in</a>`, status, false, {
      icon: icons.shield,
    });
  app.get('/api/auth/verify-email', (c) => verifyPage(c));
  app.post('/api/auth/verify-email', async (c) => {
    const tooMany = (retryAfter: number | null) => verifyPage(c, `Too many attempts. Try again in ${retryAfter} seconds.`, 429, true);
    const ip = getConnInfo(c).remote.address ?? 'unknown';
    // Per IP first, before anything else is read. Higher than the per-user limit: several people can share an IP.
    const byIp = await limiter.consume(`verify-email:ip:${ip}`, { window: 300, max: 20 });
    if (!byIp.allowed) return tooMany(byIp.retryAfter);
    const user = await verificationUser(c.req.query('token') ?? '');
    if (user === 'expired') {
      return verifyFailed(c, "This verification link has expired. Use 'Email me a link' on the sign-in page: it verifies your email too.", 400);
    }
    if (user === undefined) {
      return verifyFailed(c, "This verification link is broken. Use 'Email me a link' on the sign-in page: it verifies your email too.", 400);
    }
    const password = (await form(c))('password');
    if (password === '') return verifyPage(c, 'Enter your password.', 400);
    // Only a genuine link reaches the per-user counter.
    const byUser = await limiter.consume(`verify-email:user:${user.userId}`, { window: 300, max: 5 });
    if (!byUser.allowed) return tooMany(byUser.retryAfter);
    const stored = (credential.get(user.userId) as { password: string | null } | undefined)?.password;
    if (!stored) {
      // None exist in M1 (a magic link can't create an account); fail closed rather than verify without a password.
      return verifyFailed(c, "This account has no password, so this link can't verify it. Use 'Email me a link' on the sign-in page instead.", 409);
    }
    let matches: boolean;
    try {
      // Longer than Better Auth's 128-character maximum: can't be the sign-up password; skip the scrypt work.
      matches = password.length <= 128 && (await passwordMatches(stored, password));
    } catch (err) {
      log('error', 'verify-email: could not check the password', { userId: user.userId, error: err instanceof Error ? err.message : 'unknown error' });
      return verifyFailed(c, "We couldn't check your password, so nothing was changed. Tell whoever runs this sign-in service.", 500);
    }
    if (!matches) return verifyPage(c, "That isn't the password this account was created with.", 401, true);
    let changed: boolean;
    try {
      changed = markVerified(user.userId, user.email, stored);
    } catch (err) {
      if (!(err instanceof TransactionBusy)) throw err;
      return verifyPage(c, 'The server was busy and changed nothing. Enter your password again.', 503, true);
    }
    if (!changed) {
      return verifyPage(c, 'The password for this account changed while you were verifying. Enter the current password.', 409, true);
    }
    return render(
      c,
      'Email verified',
      html`<p class="ok" role="status">Your email is verified.</p><a class="aw-button" href="/sign-in">Sign in</a>`,
      200,
      false,
      { icon: icons.check }
    );
  });

  // ── Magic link: GET asks, POST signs in (Risk 7; also stops mail scanners from using up the link) ──
  app.get('/api/auth/magic-link/verify', async (c) => {
    const token = c.req.query('token') ?? '';
    const row = pendingMagicLink.get(magicLinkIdentifier(token)) as { email: string; expiresAt: string } | undefined;
    if (row === undefined || new Date(row.expiresAt).getTime() <= Date.now()) {
      // A link asked for during an app's sign-in carries its signed request in callbackURL: keep it for the retry.
      const back = URL.parse(c.req.query('callbackURL') ?? '/', config.baseUrl);
      const query = back?.pathname === OAUTH_RESUME_PAGE ? back.search.slice(1) : '';
      const retry = query && (await verifyOAuthQueryParams(query, secret)) ? `/sign-in?${query}` : '/sign-in';
      return render(c, 'Sign in', html`${alert('This sign-in link is invalid, used or expired.')}<a class="aw-button" href="${retry}">Get a new link</a>`, 400, false, {
        icon: icons.mail,
      });
    }
    return render(
      c,
      'Sign in',
      html`<div class="aw-account aw-account-ask">
          <span class="aw-avatar" aria-hidden="true">${row.email.charAt(0).toUpperCase()}</span>
          <p>Sign in as <strong>${row.email}</strong>?</p>
        </div>
        <form method="post"><button>Continue</button></form>
        <p class="aw-foot-link">If you didn't ask for this link, close this page.</p>`,
      200,
      false,
      { icon: icons.mail, subtitle: 'Confirm this sign-in request.' }
    );
  });
  app.post('/api/auth/magic-link/verify', async (c) => {
    const r = await ba(c, 'GET', `/magic-link/verify${new URL(c.req.url).search}`);
    // Better Auth answers with a redirect to callbackURL (or errorCallbackURL with ?error=), validated against
    // BASE_URL; without a callbackURL it answers 200 with JSON.
    if (r.location) return c.redirect(r.location, 303);
    if (r.status === 200) return c.redirect('/', 303);
    return render(c, 'Sign in', html`${alert(errorText('/magic-link/verify', r))}<p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`, 400, false, {
      icon: icons.mail,
    });
  });

  // ── OAuth consent (the provider's consentPage) ──
  /** The organization this session picked on SELECT_ORG_PAGE, if it is still a member: what consentReferenceId binds. */
  const orgPick = (session: SessionData) => {
    const id = session?.session.oauthOrgId;
    const found = id ? (membership.get(session.user.id, id) as { name: string; role: string } | undefined) : undefined;
    return found && id ? { id, ...found } : undefined;
  };
  /** A consent request that can't go on: the message and a way back. */
  const consentError = (c: Context, message: string, status: ContentfulStatusCode) =>
    render(c, 'Allow access?', html`${alert(message)}<p class="aw-foot-link"><a href="/">Back to your account</a></p>`, status, false, {
      icon: icons.shield,
    });
  const consentPage = async (c: Context, query: string, error?: string, status: ContentfulStatusCode = 200) => {
    const params = new URLSearchParams(query);
    const clientId = params.get('client_id');
    if (!query || !clientId) return consentError(c, 'This page needs a request from an app. Start again from the app.', 400);
    const r = await ba(c, 'GET', `/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`);
    if (r.status !== 200) return consentError(c, errorText('/oauth2/public-client', r), r.status === 401 ? 401 : 400);
    const scopes = (params.get('scope') ?? '').split(' ').filter(Boolean);
    // RFC 8707 resources: the APIs the app wants tokens for. Allow posts this same query back, and the provider
    // checks its signature, so what's listed here is what's being allowed.
    const resources = params.getAll('resource');
    // The organization this grant is for. Allow posts back the one shown here; POST /consent refuses a mismatch.
    let org = html``;
    let orgField = html``;
    if (scopes.includes('organization')) {
      const picked = orgPick(await currentSession(c));
      org = picked
        ? html`<p class="aw-note">For the organization <strong>${picked.name}</strong>, where you are ${picked.role}.</p>`
        : html`<p class="aw-note">No organization: the app won't see one.</p>`;
      orgField = html`<input type="hidden" name="org_id" value="${picked?.id ?? ''}">`;
    }
    return render(
      c,
      'Allow access?',
      html`${alert(error)}<p class="aw-consent-lead">${appLabel(clientId, (r.data as { client_name?: string }).client_name)} wants to:</p>
        <ul class="aw-perm-list">
          ${scopes.map((s) => html`<li>${SCOPE_WORDS[s] ?? s}</li>`)}
          ${resources.map((r) => html`<li>Access <strong>${r}</strong> on your behalf</li>`)}
        </ul>
        ${org}
        <form method="post" action="/consent">
          <input type="hidden" name="oauth_query" value="${query}">
          ${orgField}
          <div class="aw-actions">
            <button name="accept" value="yes">Allow</button>
            <button name="accept" value="no" class="secondary">Deny</button>
          </div>
        </form>`,
      status,
      false,
      { icon: icons.shield, subtitle: 'Check what the app is asking for before you allow it.' }
    );
  };
  app.get('/consent', (c) => consentPage(c, oauthQuery(c)));
  app.post('/consent', async (c) => {
    const f = await form(c);
    const query = f('oauth_query');
    const accept = f('accept') === 'yes';
    // The grant binds the session's pick as it is now. If another authorization in this session picked since this
    // page was shown, show consent again with the current pick instead of approving one the user didn't see.
    const scopes = (new URLSearchParams(query).get('scope') ?? '').split(' ');
    if (accept && scopes.includes('organization') && (orgPick(await currentSession(c))?.id ?? '') !== f('org_id')) {
      return consentPage(c, query, 'The organization for this request changed in another tab. Check it and allow again.', 409);
    }
    // ...and the grant binds exactly the organization checked here, even if the session's pick changes meanwhile.
    const consent = () => ba(c, 'POST', '/oauth2/consent', { accept, oauth_query: query });
    const r = scopes.includes('organization') ? await withConsentOrg(f('org_id'), consent) : await consent();
    const next = (r.data as { url?: string } | null)?.url;
    if (r.status !== 200 || !next) return consentError(c, errorText('/oauth2/consent', r), 400);
    return c.redirect(next, 303);
  });

  // ── Which organization an app's organization scope is for (the provider's postLogin page; src/oauth.ts) ──
  // The pick is recorded on this session and the provider continues the request; consent shows it, and it becomes the
  // grant's organization. The session's active organization (Better Auth's set-active) plays no part.
  const orgPage = (c: Context, query: string, userId: string, error?: string, status: ContentfulStatusCode = 200) => {
    const orgs = memberships.all(userId) as { id: string; name: string; role: string }[];
    return render(
      c,
      'Choose an organization',
      html`${alert(error)}
        ${orgs.length > 0
          ? html`<form method="post" action="${SELECT_ORG_PAGE}">
                <input type="hidden" name="oauth_query" value="${query}">
                ${orgs.map(
                  (o) =>
                    html`<label class="aw-radio-card"><input type="radio" name="org_id" value="${o.id}" required><span class="aw-radio-name">${o.name}</span><span class="aw-role-badge">${o.role}</span></label>`
                )}
                <button>Continue</button>
              </form>
              <div class="divider">or</div>`
          : html`<p class="aw-note">You aren't a member of any organization.</p>`}
        <form method="post" action="${SELECT_ORG_PAGE}">
          <input type="hidden" name="oauth_query" value="${query}">
          <input type="hidden" name="org_id" value="">
          <button class="secondary">Continue without an organization</button>
        </form>`,
      status,
      false,
      {
        icon: icons.building,
        subtitle: "The app asks which organization you're signing in for. It will see that organization and your role in it.",
      }
    );
  };
  app.get(SELECT_ORG_PAGE, async (c) => {
    const query = oauthQuery(c);
    const session = await currentSession(c);
    if (!query || !session) {
      return render(
        c,
        'Choose an organization',
        html`${alert('This page needs a request from an app. Start again from the app.')}<p class="aw-foot-link"><a href="/">Back to your account</a></p>`,
        400,
        false,
        { icon: icons.building }
      );
    }
    return orgPage(c, query, session.user.id);
  });
  app.post(SELECT_ORG_PAGE, async (c) => {
    const f = await form(c);
    const query = f('oauth_query');
    const orgId = f('org_id');
    const session = await currentSession(c);
    if (!session) return c.redirect(`/sign-in?${query}`, 303);
    if (orgId && !membership.get(session.user.id, orgId)) return orgPage(c, query, session.user.id, "You aren't a member of that organization.", 400);
    setOrgPick.run(orgId || null, session.session.id);
    const r = await ba(c, 'POST', '/oauth2/continue', { postLogin: true, oauth_query: query });
    const next = (r.data as { url?: string } | null)?.url;
    if (r.status !== 200 || !next) return orgPage(c, query, session.user.id, errorText('/oauth2/continue', r), 400);
    return c.redirect(next, 303);
  });

  // ── Accepting an organization invitation (the emailed link; src/orgs.ts) ──
  const invitationError = (c: Context, path: string, r: { status: number; data: unknown }) =>
    render(
      c,
      'Join an organization',
      html`${alert(errorText(path, r))}<p class="aw-foot-link"><a href="/">Back to your account</a></p>`,
      r.status === 403 ? 403 : 400,
      false,
      { icon: icons.building }
    );
  app.get(ACCEPT_INVITATION_PAGE, async (c) => {
    const id = c.req.query('id') ?? '';
    if (!(await currentSession(c))) {
      return render(
        c,
        'Join an organization',
        html`<div class="aw-stack aw-btn-links"><a href="/sign-in">Sign in</a><a href="/sign-up">create an account</a></div>`,
        200,
        false,
        {
          icon: icons.building,
          subtitle: 'Sign in with the email address the invitation was sent to, or create an account with it and verify the address. Then open the link in the email again.',
        }
      );
    }
    const r = await ba(c, 'GET', `/organization/get-invitation?id=${encodeURIComponent(id)}`);
    if (r.status !== 200) return invitationError(c, '/organization/get-invitation', r);
    const invitation = r.data as { organizationName: string; inviterEmail: string; role: string };
    return render(
      c,
      'Join an organization',
      html`<p class="aw-note"><strong>${invitation.inviterEmail}</strong> invited you to join <strong>${invitation.organizationName}</strong> as ${invitation.role}.</p>
        <form method="post" action="${ACCEPT_INVITATION_PAGE}">
          <input type="hidden" name="id" value="${id}">
          <button>Accept</button>
        </form>`,
      200,
      false,
      { icon: icons.building }
    );
  });
  app.post(ACCEPT_INVITATION_PAGE, async (c) => {
    const r = await ba(c, 'POST', '/organization/accept-invitation', { invitationId: (await form(c))('id') });
    if (r.status !== 200) return invitationError(c, '/organization/accept-invitation', r);
    return render(c, 'Join an organization', html`<p class="ok" role="status">You're now a member of the organization.</p><a class="aw-button" href="/">Continue</a>`, 200, false, {
      icon: icons.check,
    });
  });

  // ── Back to the app after a sign-in that couldn't carry its request in the body (magic link) ──
  // The provider resumes a request itself when a sign-in POST carries oauth_query (password, 2FA, passkey, social).
  // A magic link is a GET, so its callbackURL brings the browser here with the signed request: checked, then sent back
  // to /authorize. Only a session created after the app asked counts as the fresh sign-in prompt=login or max_age want.
  app.get(OAUTH_RESUME_PAGE, async (c) => {
    const query = oauthQuery(c);
    if (c.req.query('error')) return c.redirect(`/sign-in?${new URL(c.req.url).search.slice(1)}`, 303); // a failed sign-in
    if (!query || !(await verifyOAuthQueryParams(query, secret))) {
      return render(
        c,
        'Sign in',
        html`${alert('This sign-in request expired or was changed. Start again from the app.')}<p class="aw-foot-link"><a href="/sign-in">Back to sign in</a></p>`,
        400,
        false,
        { icon: icons.shield }
      );
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
  const twoFactorPage = (c: Context, query: string, error?: string, status: ContentfulStatusCode = 200, backup = false) =>
    render(
      c,
      'Two-factor authentication',
      html`${alert(error)}
        <form method="post" action="${TWO_FACTOR_PAGE}">
          <input type="hidden" name="oauth_query" value="${query}">
          <label for="code">Code from your authenticator app</label>
          <input id="code" class="aw-otp" name="code" inputmode="numeric" autocomplete="one-time-code" required>
          <button>Continue</button>
        </form>
        <div class="divider">or</div>
        <details class="aw-disclosure"${backup ? html` open` : ''}>
          <summary><span>Use a backup code</span>${icons.chevron}</summary>
          <div class="aw-disclosure-body">
            <form method="post" action="${TWO_FACTOR_PAGE}">
              <input type="hidden" name="oauth_query" value="${query}">
              <input type="hidden" name="method" value="backup">
              <label for="backup">Backup code <span class="aw-hint">(each works once)</span></label>
              <input id="backup" name="code" autocomplete="off" required>
              <button class="secondary">Use backup code</button>
            </form>
          </div>
        </details>`,
      status,
      false,
      { icon: icons.shield, subtitle: 'Enter the 6-digit code from your authenticator app.' }
    );
  app.get(TWO_FACTOR_PAGE, (c) => twoFactorPage(c, oauthQuery(c)));
  app.post(TWO_FACTOR_PAGE, async (c) => {
    const f = await form(c);
    const query = f('oauth_query');
    const path = f('method') === 'backup' ? '/two-factor/verify-backup-code' : '/two-factor/verify-totp';
    const r = await ba(c, 'POST', path, { code: f('code'), ...(query ? { oauth_query: query } : {}) });
    if (r.status !== 200) return twoFactorPage(c, query, errorText(path, r), r.status === 429 ? 429 : 400, f('method') === 'backup');
    // With oauth_query the provider continues the app's request and answers with where to go next.
    const next = (r.data as { url?: string } | null)?.url;
    if (query && !next) throw new Error('2FA during an OAuth request returned no redirect');
    return c.redirect(next ?? '/', 303);
  });

  // ── Turning on TOTP: enable (secret + backup codes, shown once), then confirm a code ──
  const signedOut = (c: Context) => c.redirect('/sign-in', 303);
  const confirmForm = html`<p class="aw-note">Turning it on signs out your other sessions, revokes apps' refresh tokens and removes
      your passkeys (add them again afterwards).</p>
    <form method="post" action="/two-factor/setup/confirm">
      <label for="code">Then enter the code it shows</label>
      <input id="code" class="aw-otp" name="code" inputmode="numeric" autocomplete="one-time-code" required>
      <button>Turn on</button>
    </form>`;
  const backHome = html`<p class="aw-foot-link"><a href="/">Back to your account</a></p>`;
  app.get('/two-factor/setup', async (c) => {
    const session = await currentSession(c);
    if (!session) return signedOut(c);
    if (session.user.twoFactorEnabled) {
      return render(c, 'Two-factor authentication', html`<p class="ok" role="status">Two-factor authentication is on.</p>${backHome}`, 200, false, {
        icon: icons.check,
      });
    }
    return render(
      c,
      'Two-factor authentication',
      html`<form method="post" action="/two-factor/setup">
          <label for="password">Your password <span class="aw-hint">(leave empty if your account has none)</span></label>
          <input id="password" name="password" type="password" autocomplete="current-password">
          <button>Set up</button>
        </form>
        ${backHome}`,
      200,
      false,
      { icon: icons.shield, subtitle: 'Each sign-in will also ask for a code from an authenticator app.' }
    );
  });
  app.post('/two-factor/setup', async (c) => {
    const password = (await form(c))('password');
    const r = await ba(c, 'POST', '/two-factor/enable', password ? { password } : {});
    if (r.status === 401) return signedOut(c);
    if (r.status !== 200) {
      return render(
        c,
        'Two-factor authentication',
        html`${alert(errorText('/two-factor/enable', r))}<a class="aw-button secondary" href="/two-factor/setup">Try again</a>`,
        400,
        false,
        { icon: icons.shield }
      );
    }
    const { totpURI, backupCodes } = r.data as { totpURI: string; backupCodes: string[] };
    let qr: Html | string = '';
    try {
      qr = qrCode(totpURI);
    } catch (err) {
      // Too long to encode (a very long email address): the key, link and backup codes below still show.
      log('error', 'two-factor setup: no QR code', { error: err instanceof Error ? err.message : 'unknown error' });
    }
    return render(
      c,
      'Two-factor authentication',
      html`${qr ? html`<p>Scan this with your authenticator app:</p><div class="aw-qr-box">${qr}</div><p>Or enter this key:</p>` : html`<p>Add this account to your authenticator app with this key:</p>`}
        <div class="aw-secret-box"><code>${new URL(totpURI).searchParams.get('secret')}</code></div>
        <details class="aw-disclosure">
          <summary><span>Or use the full setup link</span>${icons.chevron}</summary>
          <div class="aw-disclosure-body">
            <p style="margin-top:0">On this device, open <a href="${totpURI}">this link</a>:</p>
            <code>${totpURI}</code>
          </div>
        </details>
        <p class="aw-note">Backup codes, each works once if you lose the app. <strong>Save them now: they won't be shown again.</strong></p>
        <ul class="aw-code-grid">${backupCodes.map((code) => html`<li><code>${code}</code></li>`)}</ul>
        ${confirmForm}`,
      200,
      false,
      { icon: icons.shield, subtitle: 'Scan or type the key, save your backup codes, then confirm a code.' }
    );
  });
  app.post('/two-factor/setup/confirm', async (c) => {
    const r = await ba(c, 'POST', '/two-factor/verify-totp', { code: (await form(c))('code') });
    if (r.status !== 200) {
      return render(c, 'Two-factor authentication', html`${alert(errorText('/two-factor/verify-totp', r))}${confirmForm}`, 400, false, { icon: icons.shield });
    }
    return render(
      c,
      'Two-factor authentication',
      html`<p class="ok" role="status">Two-factor authentication is on. Your other sessions were signed out, apps'
          refresh tokens revoked and passkeys removed. <a href="/passkeys">Add a passkey</a></p>
        <a class="aw-button" href="/">Back to your account</a>`,
      200,
      false,
      { icon: icons.check }
    );
  });

  // ── Adding a passkey (the browser half is /passkey.js). On a 2FA account, a fresh code comes first. ──
  // Better Auth also refuses a session older than its freshAge, so such a session is asked to sign in again first.
  const tooOld = (session: NonNullable<SessionData>) => Date.now() - new Date(session.session.createdAt).getTime() >= SESSION_FRESH_AGE_SECONDS * 1000;
  const signInAgain = (c: Context) =>
    render(
      c,
      'Passkeys',
      html`<form method="post" action="/sign-out"><button>Sign out</button></form>
        ${backHome}`,
      200,
      false,
      { icon: icons.passkey, subtitle: 'To add a passkey, sign in again first: your sign-in is more than a day old.' }
    );
  const passkeysPage = (c: Context, needsCode: boolean, error?: string, status: ContentfulStatusCode = 200) =>
    render(
      c,
      'Passkeys',
      needsCode
        ? html`${alert(error)}
            <form method="post" action="/passkeys">
              <label for="code">Code from your authenticator app</label>
              <input id="code" class="aw-otp" name="code" inputmode="numeric" autocomplete="one-time-code" required>
              <button>Continue</button>
            </form>
            ${backHome}`
        : html`<button type="button" data-passkey="add" data-status="passkey-status">${icons.passkey}<span>Add a passkey</span></button>
            <p id="passkey-status" role="status"></p>
            ${backHome}`,
      status,
      !needsCode,
      needsCode
        ? { icon: icons.shield, subtitle: 'Confirm your identity before adding a passkey.' }
        : { icon: icons.passkey, subtitle: "A passkey signs you in with this device's lock (fingerprint, face or PIN) instead of a password." }
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
