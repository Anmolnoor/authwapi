import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { SignJWT } from 'jose';
import { markEmailVerified } from '../src/pages.ts';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';

let s: TestServer;
const up = async () => (s = await startTestServer());
afterEach(() => s.stop());

const FORM = 'application/x-www-form-urlencoded';
/** A form POST as a browser on our own origin would send it. No redirects followed. */
const submit = (url: string | URL, fields: Record<string, string>, { cookie = '', origin = s.base } = {}) =>
  fetch(new URL(url, s.base), {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': FORM, origin, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(fields),
  });
const get = (url: string | URL, cookie = '') =>
  fetch(new URL(url, s.base), { redirect: 'manual', headers: cookie ? { cookie } : {} });
const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
const session = async (cookie: string) =>
  (await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie } })).json();
const verified = (email: string) => {
  const d = new Database(s.paths.db);
  const v = d.prepare('SELECT emailVerified FROM user WHERE email = ?').pluck().get(email);
  d.close();
  return v === 1;
};

async function signUp(email: string, password = 'correct horse') {
  const res = await submit('/sign-up', { name: 'User', email, password });
  assert.equal(res.status, 200);
  return linkIn((await s.mail(email, 'Verify your email')).text);
}
/** Signed up, verified through the password step, signed in through the page. Returns the session cookie. */
async function signedIn(email: string, password = 'correct horse') {
  const link = await signUp(email, password);
  assert.equal((await submit(link, { password })).status, 200);
  const res = await submit('/sign-in', { email, password });
  assert.equal(res.status, 303);
  return cookieOf(res);
}

test('every page renders with its form', async () => {
  await up();
  const pages: [string, RegExp][] = [
    ['/', /href="\/sign-in"/],
    ['/sign-in', /<form method="post" action="\/sign-in">[\s\S]*name="password"/],
    ['/sign-up', /<form method="post" action="\/sign-up">[\s\S]*name="email"/],
    ['/forgot-password', /<form method="post" action="\/forgot-password">/],
    ['/reset-password?token=abc', /<form method="post" action="\/reset-password">/],
    ['/signed-out', /signed out/],
  ];
  for (const [p, shape] of pages) {
    const res = await get(p);
    assert.equal(res.status, 200, p);
    assert.match(res.headers.get('content-type')!, /text\/html/, p);
    const body = await res.text();
    assert.match(body, shape, p);
    assert.match(body, /<html lang="en">/, p);
    // Every input has a label pointing at it.
    for (const [, id] of body.matchAll(/<input id="([^"]+)"/g)) assert.match(body, new RegExp(`<label for="${id}"`), `${p}: ${id}`);
  }
});

test('Risk 8: GET on the verification link verifies nothing; the sign-up password does', async () => {
  await up();
  const email = 'ada@example.com';
  const link = await signUp(email, 'ada password');
  for (const method of ['GET', 'HEAD']) {
    const res = await fetch(link, { method, redirect: 'manual' });
    assert.equal(res.status, 200, method);
  }
  const page = await (await get(link)).text();
  assert.match(page, /Enter the password you chose when you signed up/);
  assert.ok(!verified(email), 'a GET verified the email');

  const wrong = await submit(link, { password: 'not it' });
  assert.equal(wrong.status, 401);
  const wrongBody = await wrong.text();
  assert.match(wrongBody, /isn&#39;t the password this account was created with/);
  assert.match(wrongBody, /href="\/forgot-password"/);
  assert.ok(!verified(email), 'a wrong password verified the email');

  assert.equal((await submit(link, { password: '' })).status, 400);
  const ok = await submit(link, { password: 'ada password' });
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /Your email is verified/);
  assert.ok(!cookieOf(ok).includes('session_token'), 'verifying signed someone in');
  assert.ok(verified(email));
});

test('Risk 8: no other spelling of the verification path verifies from the token alone', async () => {
  await up();
  const email = 'paths@example.com';
  const link = await signUp(email);
  const token = link.searchParams.get('token')!;
  const variants = [
    `/api/auth/verify-email/?token=${token}`,
    `/api/auth//verify-email?token=${token}`,
    `/api/auth/Verify-Email?token=${token}`,
    `/api/auth/verify%2Demail?token=${token}`,
    `/api/auth/%2e/verify-email?token=${token}`,
    `/api/auth/x/../verify-email?token=${token}`,
    `/api/auth/verify-email?token=${token}&token=${token}`,
  ];
  for (const v of variants) {
    for (const method of ['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE']) await fetch(s.base + v, { method, redirect: 'manual' });
    // A POST without the password (JSON, as an API client would send it) is refused too.
    await fetch(s.base + v, { method: 'POST', headers: { 'content-type': 'application/json', origin: s.base }, body: JSON.stringify({ token }) });
    assert.ok(!verified(email), `${v} verified the email`);
  }
});

test('Risk 8: password attempts on a verification link are rate limited', async () => {
  await up();
  const email = 'brute@example.com';
  const link = await signUp(email, 'right password');
  const statuses: number[] = [];
  for (let i = 0; i < 6; i++) statuses.push((await submit(link, { password: `guess ${i}` })).status);
  assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429]);
  assert.equal((await submit(link, { password: 'right password' })).status, 429, 'the right password got past the limit');
  assert.ok(!verified(email));
});

test('Risk 8: an account without a password fails closed', async () => {
  await up();
  const email = 'nopass@example.com';
  const link = await signUp(email);
  const d = new Database(s.paths.db);
  d.prepare(`DELETE FROM account WHERE providerId = 'credential'`).run();
  d.close();
  const res = await submit(link, { password: 'correct horse' });
  assert.equal(res.status, 409);
  assert.match(await res.text(), /has no password/);
  assert.ok(!verified(email));
});

test('Risk 8: a broken or forged verification token verifies nothing', async () => {
  await up();
  const email = 'forge@example.com';
  const link = await signUp(email);
  const [h, p] = link.searchParams.get('token')!.split('.');
  const forged = new URL(link);
  forged.searchParams.set('token', `${h}.${p}.${Buffer.from('not the signature').toString('base64url')}`);
  const res = await submit(forged, { password: 'correct horse' });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /This verification link is broken/);
  const garbage = new URL(link);
  garbage.searchParams.set('token', 'garbage');
  assert.equal((await submit(garbage, { password: 'correct horse' })).status, 400);
  assert.ok(!verified(email));
});

test('Risk 8: forged tokens for a real user lock nothing; the genuine link still works', async () => {
  await up();
  const email = 'target@example.com';
  const link = await signUp(email, 'target password');
  // The real header and payload (the user id is all an attacker needs to know), a made-up signature.
  const [h, p] = link.searchParams.get('token')!.split('.');
  const forged = new URL(link);
  forged.searchParams.set('token', `${h}.${p}.${Buffer.from('x'.repeat(32)).toString('base64url')}`);
  for (let i = 0; i < 6; i++) assert.equal((await submit(forged, { password: `guess ${i}` })).status, 400, `forged #${i}`);
  const ok = await submit(link, { password: 'target password' });
  assert.equal(ok.status, 200, 'forged tokens locked the owner out');
  assert.ok(verified(email));
});

test('Risk 8: a signed token verifies only the user and address it was issued for', async () => {
  await up();
  const [a, b] = ['a@example.com', 'b@example.com'];
  await signUp(a, 'password a');
  await signUp(b, 'password b');
  const d = new Database(s.paths.db);
  const idOf = (email: string) => d.prepare('SELECT id FROM user WHERE email = ?').pluck().get(email) as string;
  const key = new TextEncoder().encode(readFileSync(s.paths.secret, 'utf8').trim());
  const now = Math.floor(Date.now() / 1000);
  const sign = (payload: Record<string, string>, exp = now + 3600) =>
    new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setIssuedAt(now - 60).setExpirationTime(exp).sign(key);
  const linkWith = (token: string) => `/api/auth/verify-email?token=${token}`;
  const refused: [string, Record<string, string>, number?][] = [
    ["a's id with b's address", { email: b, userId: idOf(a) }],
    ['an email-change token', { email: a, userId: idOf(a), updateTo: 'evil@example.com' }],
    ['no user id', { email: a }],
    ['a user that does not exist', { email: a, userId: 'nobody' }],
    ['expired', { email: a, userId: idOf(a) }, now - 1],
  ];
  for (const [what, payload, exp] of refused) {
    const res = await submit(linkWith(await sign(payload, exp)), { password: 'password a' });
    assert.equal(res.status, 400, what);
    assert.match(await res.text(), exp ? /has expired/ : /This verification link is broken/, what);
  }
  assert.ok(!verified(a) && !verified(b));
  // The same signing, for the right user and address, works: the refusals above are about the payload.
  assert.equal((await submit(linkWith(await sign({ email: a, userId: idOf(a) })), { password: 'password a' })).status, 200);
  assert.ok(verified(a) && !verified(b));
  d.close();
});

test('Risk 8: verification is bound to the password hash that was checked; a reset in between wins', async () => {
  await up();
  const email = 'race@example.com';
  await signUp(email, 'old password');
  const d = new Database(s.paths.db);
  const row = () =>
    d.prepare(`SELECT u.id AS id, a.password AS hash FROM user u JOIN account a ON a.userId = u.id WHERE u.email = ?`).get(email) as {
      id: string;
      hash: string;
    };
  const { id, hash: oldHash } = row();
  // The token holder's old password has just been checked; the owner resets before the update runs.
  assert.equal((await submit('/forgot-password', { email })).status, 200);
  const toPage = await get(linkIn((await s.mail(email, 'Reset your password')).text));
  const token = new URL(toPage.headers.get('location')!).searchParams.get('token')!;
  assert.equal((await submit('/reset-password', { token, password: 'new password' })).status, 200);
  const newHash = row().hash;
  assert.notEqual(newHash, oldHash);
  const markVerified = markEmailVerified(d);
  assert.equal(markVerified(id, email, oldHash), false, 'verified with a replaced password');
  assert.equal(markVerified(id, 'other@example.com', newHash), false, 'verified a different address');
  assert.ok(!verified(email));
  assert.equal(markVerified(id, email, newHash), true);
  assert.ok(verified(email));
  d.close();
});

test('Risk 8: a stored password in another format fails closed, readably, and is logged', async () => {
  await up();
  const email = 'oddhash@example.com';
  const link = await signUp(email);
  const d = new Database(s.paths.db);
  d.prepare(`UPDATE account SET password = ? WHERE providerId = 'credential'`).run('$2b$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP');
  d.close();
  const res = await submit(link, { password: 'correct horse' });
  assert.equal(res.status, 500);
  assert.match(await res.text(), /We couldn&#39;t check your password/);
  assert.ok(!verified(email));
  const log = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8');
  assert.match(log, /"msg":"verify-email: could not check the password".*"error":"the stored password isn't in the expected format"/);
  assert.ok(!log.includes('correct horse') && !log.includes('$2b$'), 'the log has the password or its hash');
});

test('every page forbids framing and caching; API routes are left alone', async () => {
  await up();
  const link = await signUp('frame@example.com');
  const pages: [string, Promise<Response>][] = [
    ...['/', '/sign-in', '/sign-up', '/forgot-password', '/reset-password?token=abc', '/signed-out', '/consent', link, '/api/auth/magic-link/verify?token=x'].map(
      (u): [string, Promise<Response>] => [`GET ${u}`, get(u)]
    ),
    ['POST /sign-in', submit('/sign-in', { email: 'x@example.com', password: 'wrong wrong' })],
    ['POST /sign-up', submit('/sign-up', { name: 'x', email: 'bad', password: 'x' })],
    ['POST /forgot-password', submit('/forgot-password', { email: 'x@example.com' })],
    ['POST /reset-password', submit('/reset-password', { token: 'x', password: 'long enough' })],
    ['POST /sign-out', submit('/sign-out', {})],
    ['POST /consent', submit('/consent', {})],
    ['POST verify-email', submit(link, { password: 'wrong' })],
    ['POST magic-link', submit('/api/auth/magic-link/verify?token=x', {})],
  ];
  for (const [what, pending] of pages) {
    const res = await pending;
    assert.equal(res.headers.get('content-security-policy'), "frame-ancestors 'none'", what);
    assert.equal(res.headers.get('x-frame-options'), 'DENY', what);
    assert.equal(res.headers.get('cache-control'), 'no-store', what);
  }
  for (const u of ['/api/auth/get-session', '/.well-known/openid-configuration']) {
    assert.equal((await get(u)).headers.get('x-frame-options'), null, u);
  }
});

test('sign-up page: happy path, and errors as readable text', async () => {
  await up();
  const ok = await submit('/sign-up', { name: 'Ada', email: 'su@example.com', password: 'long enough' });
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /verification link/);
  await s.mail('su@example.com', 'Verify your email');
  const short = await submit('/sign-up', { name: 'Ada', email: 'short@example.com', password: 'abc' });
  assert.equal(short.status, 400);
  const body = await short.text();
  assert.match(body, /<p role="alert">Password too short<\/p>/);
  assert.ok(!body.includes('"code"'), 'raw JSON on the page');
});

test('sign-in page: signs in, refuses a wrong password, explains an unverified email', async () => {
  await up();
  const cookie = await signedIn('si@example.com');
  assert.equal((await session(cookie)).user.email, 'si@example.com');
  const wrong = await submit('/sign-in', { email: 'si@example.com', password: 'nope nope' });
  assert.equal(wrong.status, 400);
  assert.match(await wrong.text(), /<p role="alert">Invalid email or password<\/p>/);
  await signUp('unv@example.com');
  const unverified = await submit('/sign-in', { email: 'unv@example.com', password: 'correct horse' });
  assert.equal(unverified.status, 400);
  assert.match(await unverified.text(), /Verify your email first/);
});

test('sign-out page ends the session', async () => {
  await up();
  const cookie = await signedIn('so@example.com');
  const res = await submit('/sign-out', {}, { cookie });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/signed-out');
  assert.equal(await session(cookie), null);
  assert.match(await (await get('/', cookie)).text(), /href="\/sign-in"/);
});

test('forgot and reset password pages: a reset replaces the password and ends sessions', async () => {
  await up();
  const email = 'reset@example.com';
  const cookie = await signedIn(email, 'first password');
  assert.match(await (await get('/', cookie)).text(), /Signed in as <strong>reset@example.com<\/strong>/);
  assert.equal((await submit('/forgot-password', { email })).status, 200);
  const toPage = await get(linkIn((await s.mail(email, 'Reset your password')).text));
  assert.equal(toPage.status, 302);
  const pageUrl = new URL(toPage.headers.get('location')!);
  assert.equal(pageUrl.pathname, '/reset-password');
  const token = pageUrl.searchParams.get('token')!;
  assert.match(await (await get(pageUrl)).text(), new RegExp(`name="token" value="${token}"`));
  const bad = await submit('/reset-password', { token: 'wrong', password: 'second password' });
  assert.equal(bad.status, 400);
  assert.match(await bad.text(), /<p role="alert">Invalid token<\/p>/);
  assert.equal((await submit('/reset-password', { token, password: 'second password' })).status, 200);
  assert.equal(await session(cookie), null);
  assert.equal((await submit('/sign-in', { email, password: 'first password' })).status, 400);
  assert.equal((await submit('/sign-in', { email, password: 'second password' })).status, 303);
  assert.equal((await get('/reset-password?error=INVALID_TOKEN')).status, 400);
});

test('magic link: GET asks and consumes nothing; POST signs in once', async () => {
  await up();
  const email = 'ml@example.com';
  await signedIn(email);
  const sent = await submit('/sign-in', { method: 'magic-link', email });
  assert.equal(sent.status, 200);
  assert.match(await sent.text(), /a sign-in link is on its way/);
  const link = linkIn((await s.mail(email, 'Your sign-in link')).text);
  for (let i = 0; i < 3; i++) {
    const res = await get(link);
    assert.equal(res.status, 200);
    assert.ok(!cookieOf(res).includes('session_token'), 'a GET signed in');
    assert.match(await res.text(), /Sign in as <strong>ml@example.com<\/strong>\?/);
  }
  assert.equal((await fetch(link, { method: 'HEAD' })).status, 200);
  const first = await submit(link, {});
  assert.equal(first.status, 303);
  assert.equal((await session(cookieOf(first))).user.email, email);
  const again = await submit(link, {});
  assert.ok(!cookieOf(again).includes('session_token'), 'a used link signed in again');
  assert.match(again.headers.get('location')!, /error=INVALID_TOKEN/);
  const after = await get(link);
  assert.equal(after.status, 400);
  assert.match(await after.text(), /invalid, used or expired/);
});

test('no page reflects input unescaped', async () => {
  await up();
  const x = '<script>alert(1)</script>';
  const e = encodeURIComponent(x);
  const urls = [
    `/?error=${e}`,
    `/sign-in?sig=1&state=${e}`,
    `/reset-password?token=${encodeURIComponent('"><script>alert(1)</script>')}`,
    `/consent?sig=1&client_id=${e}&scope=${e}`,
  ];
  for (const u of urls) {
    const body = await (await get(u)).text();
    assert.ok(!body.includes('<script>'), `${u} reflected a script tag`);
  }
  assert.match(await (await get(`/?error=${e}`)).text(), /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  // A name with markup, through sign-up and back out via the landing page and error paths.
  const res = await submit('/sign-up', { name: x, email: 'not-an-email<script>', password: 'long enough' });
  assert.ok(!(await res.text()).includes('<script>'));
  const cookie = await signedIn('xss@example.com');
  assert.ok(!(await (await get('/', cookie)).text()).includes('<script>'));
});

test('forms refuse a cross-site POST before anything happens', async () => {
  await up();
  const email = 'csrf@example.com';
  const link = await signUp(email);
  const evil = { origin: 'https://evil.example' };
  const before = s.outbox().length;
  const attempts: [string | URL, Record<string, string>][] = [
    ['/sign-up', { name: 'x', email: 'new@example.com', password: 'long enough' }],
    ['/sign-in', { email, password: 'correct horse' }],
    ['/sign-in', { method: 'magic-link', email }],
    ['/forgot-password', { email }],
    ['/reset-password', { token: 'x', password: 'long enough' }],
    ['/sign-out', {}],
    ['/consent', { accept: 'yes', oauth_query: 'sig=x' }],
    [link, { password: 'correct horse' }],
  ];
  for (const [url, fields] of attempts) {
    const res = await submit(url, fields, evil);
    assert.equal(res.status, 403, String(url));
    assert.ok(!cookieOf(res).includes('session_token'));
  }
  await new Promise((r) => setTimeout(r, 200)); // a background send would have landed by now
  assert.equal(s.outbox().length, before, 'an email was sent');
  assert.ok(!verified(email), 'a cross-site POST verified the email');
  const d = new Database(s.paths.db);
  assert.equal(d.prepare('SELECT count(*) FROM user WHERE email = ?').pluck().get('new@example.com'), 0);
  d.close();
});

// ── OAuth pages, against the real provider config (src/oauth.ts) and a client registered with the CLI. ──

interface OAuthServer {
  base: string;
  /** Registers a client with `node src/cli.ts clients create`, as an operator would. */
  createClient: (extraArgs?: string[]) => Promise<string>;
  db: Database.Database;
  stop: () => Promise<void>;
}
async function startOAuthServer(): Promise<OAuthServer> {
  const t = await startTestServer();
  const db = new Database(t.paths.db);
  return {
    base: t.base,
    createClient: async (extraArgs = []) => {
      const { stdout } = await promisify(execFile)(
        process.execPath,
        ['src/cli.ts', 'clients', 'create', '--name', 'Notes <App>', '--redirect-uri', 'http://127.0.0.1:9/callback', ...extraArgs],
        { env: { PATH: process.env.PATH, DATA_DIR: t.paths.root, BASE_URL: t.base } }
      );
      return /client_id:\s+(\S+)/.exec(stdout)![1];
    },
    db,
    stop: async () => {
      db.close();
      await t.stop();
    },
  };
}

// A browser following the app's link. Better Auth answers fetch() with JSON (undici always sends
// sec-fetch-mode: cors), so this uses node:http with the headers a navigation carries.
const navigate = (url: URL, cookie = '') =>
  new Promise<{ status: number; location: string }>((resolve, reject) => {
    const headers = { 'sec-fetch-mode': 'navigate', accept: 'text/html', ...(cookie ? { cookie } : {}) };
    request(url, { headers }, (res) => {
      res.resume();
      resolve({ status: res.statusCode!, location: res.headers.location ?? '' });
    })
      .on('error', reject)
      .end();
  });
const authorizeUrl = (base: string, clientId: string, state: string, extra: Record<string, string> = {}) => {
  const verifier = randomBytes(32).toString('base64url');
  const u = new URL(`${base}/api/auth/oauth2/authorize`);
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: 'http://127.0.0.1:9/callback',
    scope: 'openid email offline_access',
    state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  }).toString();
  return u;
};

test('OAuth: the sign-in page continues the authorization; consent Allow returns a code, Deny an error', async () => {
  const o = await startOAuthServer();
  s = { stop: o.stop } as TestServer; // afterEach stops it
  const email = 'oauth@example.com';
  const signUpRes = await fetch(`${o.base}/api/auth/sign-up/email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: o.base },
    body: JSON.stringify({ email, password: 'correct horse', name: 'O' }),
  });
  assert.equal(signUpRes.status, 200);
  o.db.prepare('UPDATE user SET emailVerified = 1 WHERE email = ?').run(email);
  const clientId = await o.createClient();
  const authorize = (state: string) => authorizeUrl(o.base, clientId, state);

  const form = (url: string, fields: Record<string, string>, cookie = '') =>
    fetch(new URL(url, o.base), {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': FORM, origin: o.base, ...(cookie ? { cookie } : {}) },
      body: new URLSearchParams(fields),
    });

  // Not signed in: the provider sends the browser to our sign-in page with its signed query.
  const toLogin = await navigate(authorize('s1'));
  assert.equal(toLogin.status, 302);
  const loginUrl = new URL(toLogin.location, o.base);
  assert.equal(loginUrl.pathname, '/sign-in');
  const loginPage = await (await fetch(loginUrl)).text();
  const oauthQuery = /name="oauth_query" value="([^"]*)"/.exec(loginPage)![1].replaceAll('&amp;', '&');
  assert.equal(oauthQuery, loginUrl.search.slice(1));
  assert.ok(!loginPage.includes('Email me a link'), 'magic link offered during an OAuth request');

  // Signing in on that page continues the request: next stop is the consent page.
  const signIn = await form('/sign-in', { email, password: 'correct horse', oauth_query: oauthQuery });
  assert.equal(signIn.status, 303);
  const cookie = cookieOf(signIn);
  const consentUrl = new URL(signIn.headers.get('location')!, o.base);
  assert.equal(consentUrl.pathname, '/consent');

  const consentPage = await (await fetch(consentUrl, { headers: { cookie } })).text();
  assert.match(consentPage, /<strong>Notes &lt;App&gt;<\/strong> wants to:/);
  assert.match(consentPage, /Confirm who you are/);
  assert.match(consentPage, /See your email address/);
  assert.match(consentPage, /Stay signed in to the app/);
  const consentQuery = /name="oauth_query" value="([^"]*)"/.exec(consentPage)![1].replaceAll('&amp;', '&');

  const allow = await form('/consent', { accept: 'yes', oauth_query: consentQuery }, cookie);
  assert.equal(allow.status, 303);
  const back = new URL(allow.headers.get('location')!);
  assert.equal(back.origin + back.pathname, 'http://127.0.0.1:9/callback');
  assert.equal(back.searchParams.get('state'), 's1');
  assert.ok(back.searchParams.get('code'), 'no authorization code');

  // A second request from a different state: Deny sends the app an access_denied error.
  o.db.prepare('DELETE FROM oauthConsent').run();
  const toConsent = await navigate(authorize('s2'), cookie);
  const consent2 = new URL(toConsent.location, o.base);
  assert.equal(consent2.pathname, '/consent');
  const deny = await form('/consent', { accept: 'no', oauth_query: consent2.search.slice(1) }, cookie);
  assert.equal(deny.status, 303);
  const denied = new URL(deny.headers.get('location')!);
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert.equal(denied.searchParams.get('state'), 's2');
  assert.equal(denied.searchParams.get('code'), null);

  // A tampered signed query is refused, readably.
  const tampered = await form('/sign-in', { email, password: 'correct horse', oauth_query: oauthQuery.replace('s1', 'sX') });
  assert.equal(tampered.status, 400);
  assert.match(await tampered.text(), /<p role="alert">This sign-in request expired or was changed/);
});

test('OAuth consent names the APIs the app asks for, escaped', async () => {
  const o = await startOAuthServer();
  s = { stop: o.stop } as TestServer; // afterEach stops it
  const email = 'api@example.com';
  const json = (p: string, body: object) =>
    fetch(`${o.base}/api/auth${p}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: o.base }, body: JSON.stringify(body) });
  assert.equal((await json('/sign-up/email', { email, password: 'correct horse', name: 'A' })).status, 200);
  o.db.prepare('UPDATE user SET emailVerified = 1 WHERE email = ?').run(email);
  const cookie = cookieOf(await json('/sign-in/email', { email, password: 'correct horse' }));
  const api = 'https://api.example.test/v1';
  const clientId = await o.createClient(['--resource', api]);

  const toConsent = await navigate(authorizeUrl(o.base, clientId, 's', { resource: api }), cookie);
  const consentUrl = new URL(toConsent.location, o.base);
  assert.equal(consentUrl.pathname, '/consent');
  const page = await (await fetch(consentUrl, { headers: { cookie } })).text();
  assert.match(page, /<li>Access <strong>https:\/\/api\.example\.test\/v1<\/strong> on your behalf<\/li>/);

  // Without a resource, no API line.
  o.db.prepare('DELETE FROM oauthConsent').run();
  const plain = new URL((await navigate(authorizeUrl(o.base, clientId, 's2'), cookie)).location, o.base);
  assert.ok(!(await (await fetch(plain, { headers: { cookie } })).text()).includes('on your behalf'));

  // The page shows what the query says (the provider checks the signature on Allow), so markup in it is escaped.
  const evil = new URL(consentUrl);
  evil.searchParams.append('resource', '<script>alert(1)</script>');
  const evilPage = await (await fetch(evil, { headers: { cookie } })).text();
  assert.ok(!evilPage.includes('<script>'), 'a resource was reflected unescaped');
  assert.match(evilPage, /Access <strong>&lt;script&gt;alert\(1\)&lt;\/script&gt;<\/strong> on your behalf/);
});
