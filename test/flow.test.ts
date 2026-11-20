import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { request } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';

// A fresh server per test: rate-limit buckets and outboxes don't leak between tests.
let s: TestServer;
beforeEach(async () => (s = await startTestServer()));
afterEach(() => s.stop());

const post = (p: string, body: unknown, { cookie = '', origin = s.base, headers = {} as Record<string, string> } = {}) =>
  fetch(s.base + p, {
    method: 'POST',
    // Send Cookie only when there is one: Better Auth checks Origin itself whenever a Cookie header exists,
    // which would hide whether our own Origin check works.
    headers: { 'content-type': 'application/json', origin, ...(cookie ? { cookie } : {}), ...headers },
    body: JSON.stringify(body),
  });
const session = async (cookie: string) =>
  (await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie } })).json();
const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
/** Verifies an email the way the page does: POST the sign-up password to the link (a GET verifies nothing). */
const verifyEmail = (link: URL, password: string, cookie = '') =>
  fetch(link, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.base, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams({ password }),
  });

/** Sign up, open the verification link, sign in. Returns the session cookie. */
async function verifiedUser(email: string, password = 'correct horse') {
  assert.equal((await post('/api/auth/sign-up/email', { email, password, name: 'User' })).status, 200);
  assert.equal((await verifyEmail(linkIn((await s.mail(email, 'Verify your email')).text), password)).status, 200);
  const res = await post('/api/auth/sign-in/email', { email, password });
  assert.equal(res.status, 200);
  return cookieOf(res);
}

const rawStatus = (p: string, host: string) =>
  new Promise<number>((resolve, reject) => {
    const req = request(s.base + p, { headers: { host } }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    });
    req.on('error', reject);
    req.end();
  });

test('sign up → sign-in refused until verified → verify → sign in → sign out', async () => {
  const email = 'ada@example.com';
  assert.equal((await post('/api/auth/sign-up/email', { email, password: 'correct horse', name: 'Ada' })).status, 200);
  assert.equal((await post('/api/auth/sign-in/email', { email, password: 'correct horse' })).status, 403);

  const verify = await verifyEmail(linkIn((await s.mail(email, 'Verify your email')).text), 'correct horse');
  assert.equal(verify.status, 200);

  const signIn = await post('/api/auth/sign-in/email', { email, password: 'correct horse' });
  assert.equal(signIn.status, 200);
  const cookie = cookieOf(signIn);
  assert.equal((await session(cookie)).user.emailVerified, true);
  assert.equal((await post('/api/auth/sign-out', {}, { cookie })).status, 200);
  assert.equal(await session(cookie), null);
});

test("opening someone else's verification link does not switch your session", async () => {
  const mine = await verifiedUser('me@example.com');
  await post('/api/auth/sign-up/email', { email: 'them@example.com', password: 'their password', name: 'Them' });
  const res = await verifyEmail(linkIn((await s.mail('them@example.com', 'Verify your email')).text), 'their password', mine);
  assert.equal(res.status, 200);
  assert.ok(!cookieOf(res).includes('session_token'), 'verification set a session cookie');
  assert.equal((await session(mine)).user.email, 'me@example.com');
});

test('password reset revokes existing sessions', async () => {
  const email = 'grace@example.com';
  const cookie = await verifiedUser(email, 'first password');
  assert.equal((await post('/api/auth/request-password-reset', { email, redirectTo: '/' })).status, 200);
  const token = linkIn((await s.mail(email, 'Reset your password')).text).pathname.split('/').pop();
  assert.equal((await post('/api/auth/reset-password', { token, newPassword: 'second password' })).status, 200);
  assert.equal(await session(cookie), null);
  assert.equal((await post('/api/auth/sign-in/email', { email, password: 'second password' })).status, 200);
});

test('a request from an untrusted Origin is refused before anything happens', async () => {
  const email = 'eve-target@example.com';
  await verifiedUser(email);
  const before = s.outbox().length;
  const res = await post('/api/auth/request-password-reset', { email, redirectTo: '/' }, { origin: 'https://evil.example' });
  assert.equal(res.status, 403);
  await new Promise((r) => setTimeout(r, 200)); // give a background send time to land, if one were queued
  assert.equal(s.outbox().length, before, 'an email was sent');
});

test('sign-in is rate limited per connection; a spoofed X-Forwarded-For does not get a fresh bucket', async () => {
  const statuses: number[] = [];
  for (let i = 0; i < 6; i++) {
    const res = await post(
      '/api/auth/sign-in/email',
      { email: 'nobody@example.com', password: 'guess' },
      { headers: { 'x-forwarded-for': `203.0.113.${i}`, 'x-authwapi-client-ip': `198.51.100.${i}` } }
    );
    statuses.push(res.status);
  }
  assert.ok(statuses.includes(429), `no 429 in ${statuses}`);
});

test('Host check: unknown host gets 421 on auth routes; /health still answers for the container healthcheck', async () => {
  assert.equal(await rawStatus('/api/auth/get-session', 'evil.example:4000'), 421);
  assert.equal(await rawStatus('/health', '127.0.0.1:4000'), 200);
});

test('nothing in the data folder is readable by other users, and no link or token reaches the log', async () => {
  await verifiedUser('priv@example.com');
  for (const dir of [s.paths.root, s.paths.logs, s.paths.outbox, s.paths.migrations, s.paths.backups]) {
    assert.equal(statSync(dir).mode & 0o777, 0o700, dir);
    for (const f of readdirSync(dir)) {
      const st = statSync(path.join(dir, f));
      if (st.isFile()) assert.equal(st.mode & 0o777, 0o600, path.join(dir, f));
    }
  }
  const log = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8');
  for (const mail of s.outbox()) {
    const url = linkIn(mail.text);
    assert.ok(!log.includes(url.href), 'link in log');
    for (const value of [...url.searchParams.values(), url.pathname.split('/').pop()!]) {
      if (value.length >= 16) assert.ok(!log.includes(value), 'token in log');
    }
  }
});

test('someone who signed up with your email loses access once you verify it', async () => {
  const email = 'victim@example.com';
  const verifyWith = (link: URL, password: string) =>
    fetch(link, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.base },
      body: new URLSearchParams({ password }),
    });
  const { default: Database } = await import('better-sqlite3'); // read the flag directly: sign-in is rate limited
  const verified = () => {
    const d = new Database(s.paths.db);
    const v = d.prepare('SELECT emailVerified FROM user WHERE email = ?').pluck().get(email);
    d.close();
    return v === 1;
  };
  await post('/api/auth/sign-up/email', { email, password: 'attacker pass', name: 'A' });
  const link = linkIn((await s.mail(email, 'Verify your email')).text);
  // The victim opens the link: that alone verifies nothing (the attacker's sign-in still gets "not verified").
  await fetch(link, { redirect: 'manual' });
  assert.equal(verified(), false, 'opening the link verified the email');
  // The victim doesn't know the attacker's password, so verification refuses...
  assert.equal((await verifyWith(link, 'my usual password')).status, 401);
  assert.equal(verified(), false, 'a wrong password verified the email');
  // ...and offers "forgot password": the reset replaces the attacker's password and ends every session.
  assert.equal((await post('/api/auth/request-password-reset', { email, redirectTo: '/' })).status, 200);
  const token = linkIn((await s.mail(email, 'Reset your password')).text).pathname.split('/').pop();
  assert.equal((await post('/api/auth/reset-password', { token, newPassword: 'victim new pass' })).status, 200);
  assert.equal((await verifyWith(link, 'victim new pass')).status, 200);
  assert.equal(verified(), true);
  assert.equal((await post('/api/auth/sign-in/email', { email, password: 'attacker pass' })).status, 401);
  assert.equal((await post('/api/auth/sign-in/email', { email, password: 'victim new pass' })).status, 200);
});
