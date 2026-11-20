// TOTP 2FA with backup codes, enforced on the server after every first factor (plan rev 7, M2): no usable session,
// consent or authorization code exists until the second factor, whichever way the user started.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, test } from 'node:test';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';
import { mockOAuth } from './mock-oauth.ts';
import {
  allow,
  authorizeUrl,
  codeFrom,
  createClient,
  currentUser,
  db,
  enableTotp,
  exchange,
  Jar,
  liveSessionCookie,
  passwordSignIn,
  send,
  totp,
  verifiedUser,
} from './signin-helpers.ts';

let s: TestServer;
let oauth: ReturnType<typeof mockOAuth> | undefined;
afterEach(async () => {
  oauth?.restore();
  oauth = undefined;
  await s.stop();
});
const GOOGLE = { GOOGLE_CLIENT_ID: 'google-client', GOOGLE_CLIENT_SECRET: 'google-secret' };

/** A verified user with TOTP on. Returns the TOTP secret and backup codes. */
async function twoFactorUser(email = 'ada@example.com') {
  const userId = await verifiedUser(s, email);
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, email)).status, 200);
  return { userId, jar, ...(await enableTotp(s, jar)) };
}
const sessionCount = (userId: string) => {
  const d = db(s);
  const n = d.prepare('SELECT count(*) FROM session WHERE userId = ?').pluck().get(userId) as number;
  d.close();
  return n;
};

test('password sign-in (direct API) on a 2FA account: no session until a TOTP code, then a normal session', async () => {
  s = await startTestServer();
  const { userId, secret } = await twoFactorUser();
  const before = sessionCount(userId);

  const jar = new Jar();
  const first = await passwordSignIn(s, jar, 'ada@example.com');
  assert.equal(first.status, 200);
  assert.deepEqual(first.json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
  assert.equal(liveSessionCookie(first.setCookies), undefined, 'a session cookie was handed out before the second factor');
  assert.equal(sessionCount(userId), before, 'a session row survived the first factor');
  assert.equal(await currentUser(s, jar), null);

  const wrong = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: '000000' } });
  assert.equal(wrong.status, 401);
  const ok = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(ok.status, 200, ok.body);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('magic-link sign-in on a 2FA account becomes a 2FA challenge; the session it made is deleted, not just un-set', async () => {
  s = await startTestServer();
  const { userId, secret } = await twoFactorUser();
  const before = sessionCount(userId);
  await send(s, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'ada@example.com', callbackURL: '/' } });
  const link = linkIn((await s.mail('ada@example.com', 'Your sign-in link')).text);

  const jar = new Jar();
  const r = await send(s, jar, 'POST', link.pathname + link.search, { form: {} });
  assert.equal(r.status, 303);
  assert.equal(r.location, '/two-factor');
  assert.equal(liveSessionCookie(r.setCookies), undefined);
  assert.ok(jar.get('two_factor'), 'no 2FA challenge cookie');
  assert.equal(sessionCount(userId), before);
  assert.equal(await currentUser(s, jar), null);

  const ok = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(ok.status, 200, ok.body);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('social sign-in (Google, direct API) on a 2FA account becomes a 2FA challenge', async () => {
  s = await startTestServer(GOOGLE);
  oauth = mockOAuth();
  const { userId, secret } = await twoFactorUser();
  // Linked once (a verified local account and a verified Google email), then 2FA applies to every Google sign-in.
  const before = sessionCount(userId);

  const jar = new Jar();
  const start = await send(s, jar, 'POST', '/api/auth/sign-in/social', { json: { provider: 'google', callbackURL: '/' } });
  assert.equal(start.status, 200, start.body);
  const back = await send(s, jar, 'GET', oauth.approve(start.json().url), { navigate: true });
  assert.equal(back.status, 302, back.body);
  assert.equal(back.location, '/two-factor');
  assert.equal(liveSessionCookie(back.setCookies), undefined);
  assert.equal(sessionCount(userId), before);
  assert.equal(await currentUser(s, jar), null);

  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } })).status, 200);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('a backup code completes the challenge once', async () => {
  s = await startTestServer();
  const { backupCodes } = await twoFactorUser();
  const use = async () => {
    const jar = new Jar();
    await passwordSignIn(s, jar, 'ada@example.com');
    const r = await send(s, jar, 'POST', '/api/auth/two-factor/verify-backup-code', { json: { code: backupCodes[0] } });
    return { status: r.status, user: await currentUser(s, jar) };
  };
  assert.deepEqual(await use(), { status: 200, user: 'ada@example.com' });
  const again = await use();
  assert.equal(again.user, null, 'a used backup code worked again');
  assert.notEqual(again.status, 200);
});

test('trusted devices are off: trustDevice is refused, and even a valid trust cookie does not skip the challenge', async () => {
  s = await startTestServer();
  const { userId, secret } = await twoFactorUser();
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  for (const path of ['/api/auth/two-factor/verify-totp', '/api/auth/two-factor/verify-backup-code']) {
    const r = await send(s, jar, 'POST', path, { json: { code: totp(secret), trustDevice: true } });
    assert.equal(r.status, 400, `${path}: ${r.body}`);
    assert.equal(jar.get('trust_device'), undefined);
  }

  // A trust cookie exactly as Better Auth would mint one (a stored record plus an HMAC'd, signed cookie), as if left
  // over from before: the next sign-in is still challenged.
  const instanceSecret = readFileSync(s.paths.secret, 'utf8').trim();
  const trustId = 'trust-device-0123456789abcdefghijklmnopqrstuv';
  const d = db(s);
  d.prepare('INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)').run(
    'trust1',
    createHash('sha256').update(trustId).digest('base64url'), // verification.storeIdentifier: 'hashed'
    userId,
    new Date(Date.now() + 86_400_000).toISOString(),
    new Date().toISOString(),
    new Date().toISOString()
  );
  d.close();
  const value = `${createHmac('sha256', instanceSecret).update(`${userId}!${trustId}`).digest('base64url')}!${trustId}`;
  const signed = encodeURIComponent(`${value}.${createHmac('sha256', instanceSecret).update(value).digest('base64')}`);
  const trusted = new Jar().add([`better-auth.trust_device=${signed}`]);
  const r = await passwordSignIn(s, trusted, 'ada@example.com');
  assert.deepEqual(r.json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
  assert.equal(liveSessionCookie(r.setCookies), undefined);
});

test("a 2FA user's session survives a /get-session renewal past updateAge (no challenge for a signed-in user)", async () => {
  s = await startTestServer();
  const { userId, jar } = await twoFactorUser();
  // Age the session so Better Auth renews it (and re-sets the cookie) on the next /get-session.
  const d = db(s);
  d.prepare('UPDATE session SET expiresAt = ? WHERE userId = ?').run(new Date(Date.now() + 5 * 86_400_000).toISOString(), userId);
  d.close();
  const r = await send(s, jar, 'GET', '/api/auth/get-session');
  assert.equal(r.status, 200);
  assert.ok(liveSessionCookie(r.setCookies), 'the session was not renewed, so this test proves nothing');
  assert.equal(await currentUser(s, jar), 'ada@example.com');
  assert.equal(jar.get('two_factor'), undefined);
});

test('turning on 2FA signs out every other session and revokes OAuth refresh tokens', async () => {
  s = await startTestServer();
  const userId = await verifiedUser(s, 'ada@example.com');
  const client = await createClient(s);
  const other = new Jar();
  await passwordSignIn(s, other, 'ada@example.com');
  // The other session gets an app a refresh token.
  const { url, verifier } = authorizeUrl(s, client, { prompt: 'consent' });
  const consent = await send(s, other, 'GET', url, { navigate: true });
  const tokens = await exchange(s, client, codeFrom(await allow(s, other, consent.location!)), verifier);
  assert.ok(tokens.body.refresh_token);

  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  await enableTotp(s, jar);
  assert.equal(await currentUser(s, jar), 'ada@example.com', 'the session that turned 2FA on was signed out');
  assert.equal(await currentUser(s, other), null, 'another session survived turning 2FA on');
  const refreshed = await fetch(`${s.base}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.body.refresh_token! }),
  });
  assert.notEqual(refreshed.status, 200, 'a refresh token survived turning 2FA on');
  assert.equal(sessionCount(userId), 1);
});

test('OAuth: /authorize → password on a 2FA account → no code and no session → TOTP → consent → code', async () => {
  s = await startTestServer();
  const { secret } = await twoFactorUser();
  const client = await createClient(s);
  const { url, verifier } = authorizeUrl(s, client);
  const jar = new Jar();
  const login = await send(s, jar, 'GET', url, { navigate: true });
  assert.equal(login.status, 302);
  const query = new URL(login.location!, s.base).search.slice(1);

  const signIn = await send(s, jar, 'POST', '/sign-in', { form: { email: 'ada@example.com', password: 'correct horse', oauth_query: query } });
  assert.equal(signIn.status, 303, signIn.body);
  assert.equal(signIn.location, `/two-factor?${query}`, 'the sign-in went somewhere other than the 2FA page');
  assert.equal(liveSessionCookie(signIn.setCookies), undefined);
  assert.equal(await currentUser(s, jar), null);
  // Opening /authorize again before the second factor still asks for a sign-in.
  const again = await send(s, jar, 'GET', url, { navigate: true });
  assert.match(again.location ?? '', /^\/sign-in\?/);

  const page = await send(s, jar, 'GET', signIn.location!);
  assert.equal(page.status, 200);
  assert.match(page.body, /name="code"/);
  const second = await send(s, jar, 'POST', '/two-factor', { form: { code: totp(secret), oauth_query: query } });
  assert.equal(second.status, 303, second.body);
  assert.match(second.location!, /\/consent\?/);
  const tokens = await exchange(s, client, codeFrom(await allow(s, jar, second.location!)), verifier);
  assert.equal(tokens.status, 200);
  assert.ok(tokens.body.id_token);
});

test('OAuth: /authorize → Google on a 2FA account → 2FA page keeps the request → consent → code', async () => {
  s = await startTestServer(GOOGLE);
  oauth = mockOAuth();
  const { secret } = await twoFactorUser();
  const client = await createClient(s);
  const { url, verifier } = authorizeUrl(s, client);
  const jar = new Jar();
  const login = await send(s, jar, 'GET', url, { navigate: true });
  const query = new URL(login.location!, s.base).search.slice(1);

  const page = await send(s, jar, 'GET', login.location!);
  assert.match(page.body, /Continue with Google/);
  const start = await send(s, jar, 'POST', '/sign-in', { form: { method: 'social', provider: 'google', oauth_query: query } });
  assert.equal(start.status, 303, start.body);
  const back = await send(s, jar, 'GET', oauth.approve(start.location!), { navigate: true });
  assert.equal(back.status, 302, back.body);
  assert.equal(back.location, `/two-factor?${query}`);
  assert.equal(liveSessionCookie(back.setCookies), undefined);

  const second = await send(s, jar, 'POST', '/two-factor', { form: { code: totp(secret), oauth_query: query } });
  assert.match(second.location ?? '', /\/consent\?/, second.body);
  assert.equal((await exchange(s, client, codeFrom(await allow(s, jar, second.location!)), verifier)).status, 200);
});

test('OAuth: magic link is offered during an OAuth sign-in and continues to consent and a code (2FA off and on)', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'bob@example.com');
  const { secret } = await twoFactorUser('ada@example.com');
  const client = await createClient(s);

  for (const email of ['bob@example.com', 'ada@example.com']) {
    const { url, verifier } = authorizeUrl(s, client);
    const jar = new Jar();
    const login = await send(s, jar, 'GET', url, { navigate: true });
    const query = new URL(login.location!, s.base).search.slice(1);
    const page = await send(s, jar, 'GET', login.location!);
    assert.match(page.body, /Email me a link/, 'no magic link during an OAuth sign-in');

    const ask = await send(s, jar, 'POST', '/sign-in', { form: { method: 'magic-link', email, oauth_query: query } });
    assert.equal(ask.status, 200, ask.body);
    const link = linkIn((await s.mail(email, 'Your sign-in link')).text);
    let next = (await send(s, jar, 'POST', link.pathname + link.search, { form: {} })).location!;
    if (email === 'ada@example.com') {
      assert.equal(next, `/two-factor?${query}`);
      assert.equal(await currentUser(s, jar), null);
      next = (await send(s, jar, 'POST', '/two-factor', { form: { code: totp(secret), oauth_query: query } })).location!;
    } else {
      // Signed in now; this page re-runs the app's request.
      next = (await send(s, jar, 'GET', next, { navigate: true })).location!;
      next = (await send(s, jar, 'GET', next, { navigate: true })).location!;
    }
    assert.match(next, /\/consent\?/, email);
    assert.equal((await exchange(s, client, codeFrom(await allow(s, jar, next)), verifier)).status, 200, email);
  }
});
