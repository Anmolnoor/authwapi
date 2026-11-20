// TOTP 2FA with backup codes, enforced on the server after every first factor (plan rev 7, M2): no usable session,
// consent or authorization code exists until the second factor, whichever way the user started.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, test } from 'node:test';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';
import { mockOAuth } from './mock-oauth.ts';
import { softAuthenticator } from './webauthn.ts';
import {
  addPasskey,
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
  passkeySignIn,
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

// RFC 6238 §5.2: a TOTP code is accepted once, and never a code from a step at or before the last one accepted.
const challenged = async () => {
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, 'ada@example.com')).status, 200);
  return jar;
};
const verifyTotp = (jar: Jar, code: string) => send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code } });

test('a TOTP code works once: the same code cannot finish a second sign-in', async () => {
  s = await startTestServer();
  const { secret } = await twoFactorUser();
  const code = totp(secret);
  const [a, b] = [await challenged(), await challenged()];
  assert.equal((await verifyTotp(a, code)).status, 200);
  const again = await verifyTotp(b, code);
  assert.equal(again.status, 401);
  assert.equal(again.json().code, 'TOTP_CODE_ALREADY_USED');
  assert.equal(await currentUser(s, b), null, 'a used code signed someone in again');
});

test('a sign-in refused for a used code keeps its challenge: the next code finishes it on the hosted form', async () => {
  s = await startTestServer();
  const { secret, code } = await twoFactorUser();
  const jar = await challenged();
  const used = await send(s, jar, 'POST', '/two-factor', { form: { code } });
  assert.equal(used.status, 400);
  assert.match(used.body, /already used/);
  const next = await send(s, jar, 'POST', '/two-factor', { form: { code: totp(secret) } });
  assert.equal(next.status, 303, next.body);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test("a used code is refused even while the challenge's attempts row is being rewritten by another request", async () => {
  s = await startTestServer();
  const { code } = await twoFactorUser();
  const jar = await challenged();
  // What a concurrent wrong code leaves for a moment: Better Auth consumes the attempts row, then writes it back.
  // (Identifiers are stored hashed; a fresh challenge's attempts row is the one whose value is '0'.)
  assert.equal(one(`SELECT count(*) FROM verification WHERE value = '0'`), 1);
  exec(`DELETE FROM verification WHERE value = '0'`);
  const r = await verifyTotp(jar, code);
  assert.equal(r.status, 401);
  assert.equal(r.json().code, 'TOTP_CODE_ALREADY_USED');
});

test("a code from two steps ahead (a phone clock running fast) doesn't block the codes before it", async () => {
  s = await startTestServer();
  const { secret } = await twoFactorUser();
  const jar = await challenged();
  while (Date.now() % 30_000 >= 28_000) await new Promise((r) => setTimeout(r, 100)); // not near a step's end
  const ahead = await verifyTotp(jar, totp(secret, Date.now() + 60_000));
  assert.equal(ahead.status, 401);
  assert.equal(ahead.json().code, 'INVALID_CODE');
  assert.equal((await verifyTotp(jar, totp(secret))).status, 200);
});

test("a claimed code touches only its own user's row", async () => {
  s = await startTestServer();
  const ada = await twoFactorUser('ada@example.com');
  const bob = await twoFactorUser('bob@example.com');
  const lastStep = (userId: string) => one('SELECT lastUsedStep FROM twoFactor WHERE userId = ?', userId);
  const bobBefore = lastStep(bob.userId);
  assert.equal((await verifyTotp(await challenged(), totp(ada.secret))).status, 200);
  assert.ok((lastStep(ada.userId) as number) > (bobBefore as number), "ada's code was not claimed");
  assert.equal(lastStep(bob.userId), bobBefore, "ada's code moved bob's step");
});

test('two requests confirming a new 2FA secret with the same code: one succeeds', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  const r = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const code = totp(new URL(r.json().totpURI).searchParams.get('secret')!);
  const answers = await Promise.all([verifyTotp(jar, code), verifyTotp(jar, code)]);
  assert.equal(answers.filter((x) => x.status === 200).length, 1, answers.map((x) => x.status).join());
  const winner = answers.find((x) => x.status === 200)!;
  const cookie = liveSessionCookie(winner.setCookies);
  assert.ok(cookie, 'the confirmation that won set no session cookie');
  const winnerJar = new Jar();
  winnerJar.add(winner.setCookies);
  assert.equal(await currentUser(s, winnerJar), 'ada@example.com', "the winner's session was signed out");
});

test("a refused used code doesn't erase the account's failed attempts", async () => {
  s = await startTestServer();
  const { userId, secret } = await twoFactorUser();
  const code = totp(secret);
  assert.equal((await verifyTotp(await challenged(), code)).status, 200);
  const b = await challenged();
  // Wrong backup codes (the per-path rate limit allows 3 per 10 s); they count toward the same lockout.
  for (let i = 0; i < 2; i++) assert.equal((await send(s, b, 'POST', '/api/auth/two-factor/verify-backup-code', { json: { code: '000000' } })).status, 401);
  assert.equal(one('SELECT failedVerificationCount FROM twoFactor WHERE userId = ?', userId), 2);
  assert.equal((await verifyTotp(b, code)).status, 401);
  assert.equal(one('SELECT failedVerificationCount FROM twoFactor WHERE userId = ?', userId), 2);
});

test('two sign-ins racing with the same TOTP code: exactly one gets a session', async () => {
  s = await startTestServer();
  const { secret } = await twoFactorUser();
  const code = totp(secret);
  const jars = [await challenged(), await challenged()];
  const statuses = (await Promise.all(jars.map((j) => verifyTotp(j, code)))).map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 401]);
  const users = await Promise.all(jars.map((j) => currentUser(s, j)));
  assert.equal(users.filter(Boolean).length, 1);
});

test('after a TOTP code is accepted, a code from an earlier step in the window is refused', async (t) => {
  s = await startTestServer();
  const { secret } = await twoFactorUser();
  const step = Math.floor(Date.now() / 30_000);
  const [newer, older] = [totp(secret, (step + 1) * 30_000), totp(secret, step * 30_000)];
  if (newer === older) return t.skip('the two steps happen to share a code (1 in a million)');
  assert.equal((await verifyTotp(await challenged(), newer)).status, 200);
  const refused = await verifyTotp(await challenged(), older);
  assert.equal(refused.status, 401);
  assert.equal(refused.json().code, 'TOTP_CODE_ALREADY_USED');
});

test('a TOTP code that is not six ASCII digits is an ordinary wrong code, not a server error', async () => {
  s = await startTestServer();
  await twoFactorUser();
  const r = await verifyTotp(await challenged(), '12345\u0661');
  assert.equal(r.status, 401);
  assert.equal(r.json().code, 'INVALID_CODE');
});

test("a challenge out of attempts refuses even a right code, and doesn't use it up", async () => {
  s = await startTestServer();
  const { userId, secret } = await twoFactorUser();
  const lastStep = () => one('SELECT lastUsedStep FROM twoFactor WHERE userId = ?', userId);
  const before = lastStep();
  const spent = await challenged();
  // Five wrong codes, alternating paths to stay under the per-path rate limit (3 per 10 s); both count.
  for (const path of ['verify-backup-code', 'verify-totp', 'verify-backup-code', 'verify-totp', 'verify-backup-code']) {
    assert.equal((await send(s, spent, 'POST', `/api/auth/two-factor/${path}`, { json: { code: '000000' } })).status, 401, path);
  }
  assert.notEqual((await verifyTotp(spent, totp(secret))).status, 200);
  assert.equal(await currentUser(s, spent), null);
  assert.equal(lastStep(), before, 'the refused right code was used up');
});

test('the code that turned 2FA on cannot be used again as a signed-in fresh check', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  const r = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const secret = new URL(r.json().totpURI).searchParams.get('secret')!;
  const code = totp(secret);
  assert.equal((await verifyTotp(jar, code)).status, 200);
  const again = await verifyTotp(jar, code);
  assert.equal(again.status, 401);
  assert.equal(again.json().code, 'TOTP_CODE_ALREADY_USED');
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

/** A signed-in 2FA session with no recent code: 2FA on, a passkey added right after, then a passkey sign-in. */
async function staleTwoFactorSession() {
  const { secret, jar: setup } = await twoFactorUser();
  const key = softAuthenticator(s.base);
  assert.equal((await addPasskey(s, setup, key)).status, 200); // fresh: 2FA was just turned on in this session
  const jar = new Jar();
  assert.equal((await passkeySignIn(s, jar, key)).status, 200);
  return { jar, secret, key };
}
const ageSession = (jar: Jar, field: 'expiresAt' | 'createdAt', iso: string) => {
  const d = db(s);
  d.prepare(`UPDATE session SET ${field} = ? WHERE token = ?`).run(iso, decodeURIComponent(jar.get('session_token')!).split('.')[0]);
  d.close();
};
const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

test('a 2FA user who is already signed in and signs in again with a magic link is challenged', async () => {
  s = await startTestServer();
  const { jar } = await twoFactorUser();
  await send(s, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'ada@example.com', callbackURL: '/' } });
  const link = linkIn((await s.mail('ada@example.com', 'Your sign-in link')).text);
  const r = await send(s, jar, 'POST', link.pathname + link.search, { form: {} });
  assert.equal(r.location, '/two-factor');
  assert.equal(liveSessionCookie(r.setCookies), undefined);
});

test('prompt=login: one factor (a magic link) under an existing session yields no code', async () => {
  s = await startTestServer();
  const { jar } = await twoFactorUser();
  const client = await createClient(s);
  const { url } = authorizeUrl(s, client, { prompt: 'login' });
  const login = await send(s, jar, 'GET', url, { navigate: true });
  assert.match(login.location ?? '', /^\/sign-in\?/);
  const query = new URL(login.location!, s.base).search.slice(1);
  await send(s, jar, 'POST', '/sign-in', { form: { method: 'magic-link', email: 'ada@example.com', oauth_query: query } });
  const link = linkIn((await s.mail('ada@example.com', 'Your sign-in link')).text);
  const r = await send(s, jar, 'POST', link.pathname + link.search, { form: {} });
  assert.equal(r.location, `/two-factor?${query}`);
  // Without the second factor, going back to the app's request leads to sign-in, never to consent or a code.
  const resume = await send(s, jar, 'GET', `/oauth/resume?${query}`, { navigate: true });
  assert.equal(resume.location, `/sign-in?${query}`);
});

test("a 2FA user's change-password with revokeOtherSessions keeps them signed in (a rotation, not a sign-in)", async () => {
  s = await startTestServer();
  const { jar } = await twoFactorUser();
  const r = await send(s, jar, 'POST', '/api/auth/change-password', { json: { currentPassword: 'correct horse', newPassword: 'new horse battery', revokeOtherSessions: true } });
  assert.equal(r.status, 200, r.body);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('turning 2FA on while Better Auth renews the session in the same request keeps the user signed in', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  const enable = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const secret = new URL(enable.json().totpURI).searchParams.get('secret')!;
  ageSession(jar, 'expiresAt', inDays(5)); // past updateAge: the session lookup in verify-totp renews it
  const r = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(r.status, 200, r.body);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('turning 2FA on revokes before it commits: a wrong code revokes nothing; a failure after revoking leaves 2FA off, safely', async () => {
  s = await startTestServer();
  const userId = await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  assert.equal((await addPasskey(s, jar, softAuthenticator(s.base))).status, 200);
  const other = new Jar();
  await passwordSignIn(s, other, 'ada@example.com');
  const enable = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const secret = new URL(enable.json().totpURI).searchParams.get('secret')!;
  const count = (sql: string) => {
    const d = db(s);
    const n = d.prepare(sql).pluck().get(userId) as number;
    d.close();
    return n;
  };

  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: '000000' } })).status, 401);
  assert.equal(await currentUser(s, other), 'ada@example.com', 'a wrong code revoked a session');
  assert.equal(count('SELECT count(*) FROM passkey WHERE userId = ?'), 1, 'a wrong code removed a passkey');

  // Enabling fails after the revocation (injected: the UPDATE that turns 2FA on is aborted).
  const d = db(s);
  d.exec(`CREATE TRIGGER fail_2fa BEFORE UPDATE OF twoFactorEnabled ON user BEGIN SELECT RAISE(ABORT, 'injected'); END`);
  d.close();
  assert.notEqual((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } })).status, 200);
  assert.equal(count('SELECT twoFactorEnabled FROM user WHERE id = ?'), 0);
  assert.equal(await currentUser(s, other), null, 'another session survived');
  assert.equal(count('SELECT count(*) FROM passkey WHERE userId = ?'), 0, 'a passkey survived');
  assert.equal(await currentUser(s, jar), 'ada@example.com');

  const d2 = db(s);
  d2.exec('DROP TRIGGER fail_2fa');
  d2.close();
  // The failed attempt used its code (claimed before Better Auth's check); the retry takes the next one.
  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret, Date.now() + 30_000) } })).status, 200);
  assert.equal(count('SELECT twoFactorEnabled FROM user WHERE id = ?'), 1);
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('a failed signed-in verification never counts as a fresh check, even when the session is renewed during it', async () => {
  s = await startTestServer();
  const { jar } = await staleTwoFactorSession();
  ageSession(jar, 'expiresAt', inDays(5));
  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: '000000' } })).status, 401);
  assert.equal((await send(s, jar, 'GET', '/api/auth/passkey/generate-register-options')).status, 403);
});

test('2FA-sensitive endpoints need a fresh code: 403 TWO_FACTOR_CHECK_REQUIRED, then allowed after a signed-in verify-totp', async () => {
  s = await startTestServer();
  const { jar, secret } = await staleTwoFactorSession();
  const calls: [string, unknown][] = [
    ['/api/auth/two-factor/get-totp-uri', { password: 'correct horse' }],
    ['/api/auth/two-factor/generate-backup-codes', { password: 'correct horse' }],
    ['/api/auth/two-factor/disable', { password: 'correct horse' }], // last: it turns 2FA off
  ];
  for (const [path, body] of calls) {
    const r = await send(s, jar, 'POST', path, { json: body });
    assert.equal(r.status, 403, path);
    assert.equal(r.json().code, 'TWO_FACTOR_CHECK_REQUIRED', path);
  }
  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } })).status, 200);
  for (const [path, body] of calls) assert.equal((await send(s, jar, 'POST', path, { json: body })).status, 200, path);
});

test('five wrong codes from a signed-in session end that session', async () => {
  s = await startTestServer();
  const { jar } = await staleTwoFactorSession();
  // Alternating paths keeps under the per-path rate limit (3 per 10 s); the count covers both.
  for (const path of ['verify-totp', 'verify-backup-code', 'verify-totp', 'verify-backup-code']) {
    assert.equal((await send(s, jar, 'POST', `/api/auth/two-factor/${path}`, { json: { code: '000000' } })).status, 401, path);
  }
  assert.equal(await currentUser(s, jar), 'ada@example.com');
  await send(s, jar, 'POST', '/api/auth/two-factor/verify-backup-code', { json: { code: '000000' } });
  assert.equal(await currentUser(s, jar), null);
});

test('OAuth: a magic link that fails goes back to sign-in with the error and the request kept, not on to the app', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'bob@example.com');
  const client = await createClient(s);
  const { url } = authorizeUrl(s, client);
  const jar = new Jar();
  const query = new URL((await send(s, jar, 'GET', url, { navigate: true })).location!, s.base).search.slice(1);
  await send(s, jar, 'POST', '/sign-in', { form: { method: 'magic-link', email: 'bob@example.com', oauth_query: query } });
  const link = linkIn((await s.mail('bob@example.com', 'Your sign-in link')).text);
  await send(s, jar, 'POST', link.pathname + link.search, { form: {} }); // signed in now
  const reused = await send(s, jar, 'POST', link.pathname + link.search, { form: {} });
  const back = new URL(reused.location ?? '/', s.base);
  assert.ok(`${back.pathname}${back.search}`.startsWith(`/sign-in?${query}&error=`), String(reused.location));
  const page = await send(s, jar, 'GET', reused.location!);
  assert.match(page.body, /role="alert"/);
  assert.ok(page.body.includes(`value="${query.replaceAll('&', '&amp;')}"`), 'the signed request was not kept for a retry');
  // And /oauth/resume refuses a request carrying an error rather than continuing under the session.
  const resume = await send(s, jar, 'GET', `/oauth/resume?${query}&error=INVALID_TOKEN`, { navigate: true });
  assert.ok(!resume.location?.includes("/oauth2/authorize"), String(resume.location));
});

test('/oauth/resume refuses a signed request with a parameter changed or added', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'bob@example.com');
  const client = await createClient(s);
  const jar = new Jar();
  await passwordSignIn(s, jar, 'bob@example.com');
  const { url } = authorizeUrl(s, client, { prompt: 'login' });
  const query = new URL((await send(s, jar, 'GET', url, { navigate: true })).location!, s.base).search.slice(1);
  const changed = new URLSearchParams(query);
  changed.set('redirect_uri', 'http://localhost:5999/elsewhere');
  for (const bad of [changed.toString(), `${query}&scope=openid`]) {
    const r = await send(s, jar, 'GET', `/oauth/resume?${bad}`, { navigate: true });
    assert.equal(r.status, 400, bad);
    assert.equal(r.location, undefined);
  }
});

test('a rate-limited session lookup does not break the hosted pages', async () => {
  s = await startTestServer();
  const { jar } = await twoFactorUser();
  // Use up /get-session's budget (100 per 10 s per IP).
  await Promise.all(Array.from({ length: 101 }, () => send(s, jar, 'GET', '/api/auth/get-session')));
  assert.equal((await send(s, jar, 'GET', '/api/auth/get-session')).status, 429);
  for (const page of ['/', '/two-factor/setup', '/passkeys', '/oauth/resume?sig=x']) {
    const r = await send(s, jar, 'GET', page, { navigate: true });
    assert.ok(r.status < 500, `${page}: ${r.status}`);
  }
});

const tokenOf = (jar: Jar) => decodeURIComponent(jar.get('session_token')!).split('.')[0];
const one = (sql: string, ...args: unknown[]) => {
  const d = db(s);
  const v = d.prepare(sql).pluck().get(...args);
  d.close();
  return v;
};
const exec = (sql: string) => {
  const d = db(s);
  d.exec(sql);
  d.close();
};

test('turning 2FA on sweeps again after it commits: when the pre-check saw no match but Better Auth accepted the code', async () => {
  s = await startTestServer();
  const userId = await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  assert.equal((await addPasskey(s, jar, softAuthenticator(s.base))).status, 200);
  const other = new Jar();
  await passwordSignIn(s, other, 'ada@example.com');
  const enable = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const secret = new URL(enable.json().totpURI).searchParams.get('secret')!;
  // Someone else's encrypted secret: the pre-check (a before-hook) decrypts it fine and finds no match. Better Auth's
  // own session lookup then renews the aged session, and that UPDATE puts the real secret back before it checks.
  await verifiedUser(s, 'bob@example.com');
  const bob = new Jar();
  await passwordSignIn(s, bob, 'bob@example.com');
  await send(s, bob, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  ageSession(jar, 'expiresAt', inDays(5));
  exec(`CREATE TABLE stash AS SELECT secret FROM twoFactor WHERE userId = '${userId}';
    UPDATE twoFactor SET secret = (SELECT secret FROM twoFactor WHERE userId != '${userId}') WHERE userId = '${userId}';
    CREATE TRIGGER put_back AFTER UPDATE ON session BEGIN
      UPDATE twoFactor SET secret = (SELECT secret FROM stash) WHERE userId = '${userId}'; END;`);

  const r = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(r.status, 200, r.body);
  assert.equal(one('SELECT twoFactorEnabled FROM user WHERE id = ?', userId), 1);
  assert.equal(await currentUser(s, other), null, 'another session survived turning 2FA on');
  assert.equal(one('SELECT count(*) FROM passkey WHERE userId = ?', userId), 0, 'a passkey survived turning 2FA on');
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('turning 2FA on sweeps again after it commits: a session created between the pre-check sweep and the switch is gone', async () => {
  s = await startTestServer();
  const userId = await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  const other = new Jar();
  await passwordSignIn(s, other, 'ada@example.com');
  const enable = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  const secret = new URL(enable.json().totpURI).searchParams.get('secret')!;
  // When the pre-check sweep deletes the other session, a sign-in lands (a session row appears) before Better Auth
  // turns 2FA on.
  const now = new Date().toISOString();
  exec(`CREATE TRIGGER sneak AFTER DELETE ON session WHEN old.token = '${tokenOf(other)}' BEGIN
    INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES ('sneak', '${inDays(5)}', 'sneaked-token', '${now}', '${now}', '${userId}'); END;`);

  assert.equal((await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } })).status, 200);
  assert.equal(one("SELECT count(*) FROM session WHERE token = 'sneaked-token'"), 0, 'a session from the gap survived');
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('a 2FA user whose session is revoked (another tab) while signing in with a magic link is still challenged', async () => {
  s = await startTestServer();
  const { jar } = await twoFactorUser();
  await send(s, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'ada@example.com', callbackURL: '/' } });
  const link = linkIn((await s.mail('ada@example.com', 'Your sign-in link')).text);
  const arriving = tokenOf(jar);
  exec(`CREATE TRIGGER other_tab AFTER INSERT ON session WHEN new.token != '${arriving}' BEGIN
    DELETE FROM session WHERE token = '${arriving}'; END;`);
  const r = await send(s, jar, 'POST', link.pathname + link.search, { form: {} });
  assert.equal(r.location, '/two-factor');
  assert.equal(liveSessionCookie(r.setCookies), undefined);
});

test('only wrong codes count toward ending a signed-in session, not other refusals', async () => {
  s = await startTestServer();
  const { jar } = await staleTwoFactorSession();
  // Setup used one verify-totp; this stays under the per-path limit (3 per 10 s).
  for (const path of ['verify-backup-code', 'verify-totp', 'verify-backup-code', 'verify-totp', 'verify-backup-code']) {
    assert.equal((await send(s, jar, 'POST', `/api/auth/two-factor/${path}`, { json: {} })).status, 400, path); // no code
  }
  assert.equal(await currentUser(s, jar), 'ada@example.com');
});

test('a 2FA-sensitive endpoint without any session is refused by the fresh-check too', async () => {
  s = await startTestServer();
  const r = await send(s, new Jar(), 'POST', '/api/auth/two-factor/get-totp-uri', { json: {} });
  assert.equal(r.status, 403);
  assert.equal(r.json().code, 'TWO_FACTOR_CHECK_REQUIRED');
});

test('OAuth: opening a used magic link offers a new one for the same app request', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'bob@example.com');
  const client = await createClient(s);
  const { url } = authorizeUrl(s, client);
  const jar = new Jar();
  const query = new URL((await send(s, jar, 'GET', url, { navigate: true })).location!, s.base).search.slice(1);
  await send(s, jar, 'POST', '/sign-in', { form: { method: 'magic-link', email: 'bob@example.com', oauth_query: query } });
  const link = linkIn((await s.mail('bob@example.com', 'Your sign-in link')).text);
  await send(s, new Jar(), 'POST', link.pathname + link.search, { form: {} }); // used
  const page = await send(s, new Jar(), 'GET', link.pathname + link.search);
  assert.equal(page.status, 400);
  assert.ok(page.body.includes(`href="/sign-in?${query.replaceAll('&', '&amp;')}"`), 'the retry link lost the app request');
  // A changed request is not carried.
  const tampered = new URL(link);
  tampered.searchParams.set('callbackURL', `/oauth/resume?${query.replace('state=app-state', 'state=other')}`);
  assert.match((await send(s, new Jar(), 'GET', tampered.pathname + tampered.search)).body, /href="\/sign-in"/);
});

test('a password change that rotates the session while 2FA is turned on meanwhile issues no session without a code', async () => {
  s = await startTestServer();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: { password: 'correct horse' } });
  // 2FA turns on (another tab confirming enrolment) while change-password deletes the old sessions.
  exec('CREATE TRIGGER enable_mid AFTER DELETE ON session BEGIN UPDATE user SET twoFactorEnabled = 1 WHERE id = old.userId; END');
  const r = await send(s, jar, 'POST', '/api/auth/change-password', { json: { currentPassword: 'correct horse', newPassword: 'new horse battery', revokeOtherSessions: true } });
  assert.equal(liveSessionCookie(r.setCookies), undefined, 'a session was issued without a code');
  assert.doesNotMatch(r.body, /"token":"/);
  assert.equal(await currentUser(s, jar), null);
});

test('a used magic link with a malformed callbackURL shows the error page, not a 500', async () => {
  s = await startTestServer();
  const r = await send(s, new Jar(), 'GET', `/api/auth/magic-link/verify?token=nope&callbackURL=${encodeURIComponent('http://[')}`);
  assert.equal(r.status, 400);
  assert.match(r.body, /href="\/sign-in"/);
});
