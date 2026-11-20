import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, test } from 'node:test';
import type { SendMail } from '../src/mailer.ts';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';

let s: TestServer;
const up = async (sendMail?: SendMail) => (s = await startTestServer({}, sendMail));
afterEach(() => s.stop());

const post = (p: string, body: unknown) =>
  fetch(s.base + p, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: s.base },
    body: JSON.stringify(body),
  });
const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
const session = async (cookie: string) =>
  (await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie } })).json();
const SUBJECT = 'Your sign-in link';
const settle = () => new Promise((r) => setTimeout(r, 200)); // let a background send land, if one were queued
const db = () => new Database(s.paths.db);

async function verifiedUser(email: string) {
  await post('/api/auth/sign-up/email', { email, password: 'correct horse', name: 'User' });
  const verify = await fetch(linkIn((await s.mail(email, 'Verify your email')).text), {
    method: 'POST', // a GET shows the password form and verifies nothing
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.base },
    body: new URLSearchParams({ password: 'correct horse' }),
  });
  assert.equal(verify.status, 200);
}
/** Signs in the way the confirm page does: POST to the link (a GET only asks "Sign in as ...?"). */
const signedIn = async (link: URL) => {
  const cookie = cookieOf(await fetch(link, { method: 'POST', redirect: 'manual', headers: { origin: s.base } }));
  return cookie !== '' && (await session(cookie)) !== null;
};

test('a magic link signs an existing user in, once', async () => {
  await up();
  const email = 'ml@example.com';
  await verifiedUser(email);
  assert.equal((await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' })).status, 200);
  const link = linkIn((await s.mail(email, SUBJECT)).text);
  assert.equal(await signedIn(link), true);
  assert.equal(await signedIn(link), false, 'a reused link signed in');
});

test('the link goes to the stored address, whatever case the request used', async () => {
  await up();
  await verifiedUser('mixed@example.com');
  await post('/api/auth/sign-in/magic-link', { email: 'MiXeD@Example.com', callbackURL: '/' });
  await s.mail('mixed@example.com', SUBJECT);
  assert.ok(!s.outbox().some((m) => m.to === 'MiXeD@Example.com'));
});

test('an unknown email gets the same answer, no email, and no account', async () => {
  await up();
  await verifiedUser('known@example.com');
  const known = await post('/api/auth/sign-in/magic-link', { email: 'known@example.com', callbackURL: '/' });
  const unknown = await post('/api/auth/sign-in/magic-link', { email: 'stranger@example.com', callbackURL: '/' });
  assert.equal(unknown.status, known.status);
  assert.deepEqual(await unknown.json(), await known.json());
  await settle();
  assert.ok(!s.outbox().some((m) => m.to === 'stranger@example.com'));
  const d = db();
  assert.equal(d.prepare('SELECT count(*) FROM user WHERE email = ?').pluck().get('stranger@example.com'), 0);
  d.close();
});

test('a slow or failing mail provider changes neither the answer nor its timing; the failure is logged', async () => {
  const sendMail: SendMail = () => new Promise((_, reject) => setTimeout(() => reject(new Error('provider down')), 400));
  await up(sendMail);
  // A verified account, made directly: the mailer can't deliver the verification email.
  await post('/api/auth/sign-up/email', { email: 'slow@example.com', password: 'correct horse', name: 'S' });
  const d = db();
  d.prepare('UPDATE user SET emailVerified = 1 WHERE email = ?').run('slow@example.com');
  d.close();
  const timedPost = async (p: string, body: unknown) => {
    const t0 = performance.now();
    const res = await post(p, body);
    return { status: res.status, ms: performance.now() - t0, body: await res.json() };
  };
  const known = await timedPost('/api/auth/sign-in/magic-link', { email: 'slow@example.com', callbackURL: '/' });
  const unknown = await timedPost('/api/auth/sign-in/magic-link', { email: 'nobody@example.com', callbackURL: '/' });
  assert.equal(known.status, 200);
  assert.deepEqual(known.body, unknown.body);
  assert.ok(known.ms < 300, `known address waited ${known.ms.toFixed(0)}ms for the mail provider`);
  // Better Auth's own emails: password reset, and the public "resend verification" route, which awaits its
  // callback directly. An unverified account and an unknown address must look the same there too.
  const t0 = performance.now();
  const reset = await post('/api/auth/request-password-reset', { email: 'slow@example.com', redirectTo: '/' });
  const resetMs = performance.now() - t0;
  assert.equal(reset.status, 200);
  assert.ok(resetMs < 300, `password reset waited ${resetMs.toFixed(0)}ms for the mail provider`);
  await post('/api/auth/sign-up/email', { email: 'unverified@example.com', password: 'correct horse', name: 'U' });
  const resendKnown = await timedPost('/api/auth/send-verification-email', { email: 'unverified@example.com' });
  const resendUnknown = await timedPost('/api/auth/send-verification-email', { email: 'ghost@example.com' });
  assert.deepEqual({ status: resendKnown.status, body: resendKnown.body }, { status: resendUnknown.status, body: resendUnknown.body });
  // Better Auth pads this route to a 500ms minimum for everyone; what matters is that both take the same time.
  assert.ok(Math.abs(resendKnown.ms - resendUnknown.ms) < 150, `known ${resendKnown.ms.toFixed(0)}ms vs unknown ${resendUnknown.ms.toFixed(0)}ms`);
  await new Promise((r) => setTimeout(r, 600));
  const log = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8');
  assert.match(log, /magic link email failed.*provider down/);
  assert.match(log, /password reset email failed.*provider down/);
  assert.match(log, /verification email failed.*provider down/);
});

test('one link per address per minute; the answer stays the same', async () => {
  await up();
  const email = 'cool@example.com';
  await verifiedUser(email);
  const first = await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  await s.mail(email, SUBJECT);
  const second = await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  assert.deepEqual(await second.json(), await first.json());
  await settle();
  assert.equal(s.outbox().filter((m) => m.to === email && m.subject === SUBJECT).length, 1);
});

test('links expire within 5 minutes; an expired link signs no one in', async () => {
  await up();
  const email = 'exp@example.com';
  await verifiedUser(email);
  await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  const link = linkIn((await s.mail(email, SUBJECT)).text);
  const d = db();
  const expiries = (d.prepare('SELECT expiresAt FROM verification').pluck().all() as string[]).map((e) => new Date(e).getTime());
  assert.ok(expiries.every((e) => e - Date.now() <= 5 * 60 * 1000 + 1000), 'a link lives longer than 5 minutes');
  d.prepare('UPDATE verification SET expiresAt = ?').run(new Date(Date.now() - 1000).toISOString());
  d.close();
  assert.equal(await signedIn(link), false);
});

test('a link for an account deleted since it was sent creates nothing', async () => {
  await up();
  const email = 'gone@example.com';
  await verifiedUser(email);
  await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  const link = linkIn((await s.mail(email, SUBJECT)).text);
  const d = db();
  d.prepare('DELETE FROM user WHERE email = ?').run(email);
  assert.equal(await signedIn(link), false);
  assert.equal(d.prepare('SELECT count(*) FROM user WHERE email = ?').pluck().get(email), 0);
  d.close();
});

test("someone who signed up with your email is locked out when you sign in by magic link", async () => {
  await up();
  await post('/api/auth/sign-up/email', { email: 'victim@example.com', password: 'attacker pass', name: 'A' });
  await post('/api/auth/sign-in/magic-link', { email: 'victim@example.com', callbackURL: '/' });
  assert.equal(await signedIn(linkIn((await s.mail('victim@example.com', SUBJECT)).text)), true);
  assert.equal((await post('/api/auth/sign-in/email', { email: 'victim@example.com', password: 'attacker pass' })).status, 401);
});

test('the token is stored hashed, never as sent', async () => {
  await up();
  const email = 'hash@example.com';
  await verifiedUser(email);
  await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  const token = linkIn((await s.mail(email, SUBJECT)).text).searchParams.get('token')!;
  const d = db();
  const rows = d.prepare('SELECT identifier, value FROM verification').all() as { identifier: string; value: string }[];
  d.close();
  assert.ok(rows.length > 0);
  for (const r of rows) assert.ok(!r.identifier.includes(token) && !r.value.includes(token), 'plain token in database');
});

test('a callback URL on another site is refused and no email is sent', async () => {
  await up();
  const email = 'cb@example.com';
  await verifiedUser(email);
  const res = await post('/api/auth/sign-in/magic-link', { email, callbackURL: 'https://evil.example/steal' });
  assert.equal(res.status, 403);
  await settle();
  assert.ok(!s.outbox().some((m) => m.to === email && m.subject === SUBJECT));
});

test('no magic link or token reaches the log', async () => {
  await up();
  const email = 'log@example.com';
  await verifiedUser(email);
  await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/' });
  const token = linkIn((await s.mail(email, SUBJECT)).text).searchParams.get('token')!;
  assert.ok(!readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8').includes(token));
});

test('a rejected callback URL never reaches the log, whatever its shape', async () => {
  await up();
  const email = 'redact@example.com';
  await verifiedUser(email);
  // Five shapes: the magic-link route allows five requests a minute per client.
  const shapes = ['https://evil.example/cb?token=', 'HTTPS://evil.example/d?token=', '//evil.example/a?token=', 'javascript:', '/\\evil.example/e?token='];
  const secrets = shapes.map((_, i) => `Sup3rSecretValue${i}abcdef`);
  for (const [i, shape] of shapes.entries()) {
    assert.equal((await post('/api/auth/sign-in/magic-link', { email, callbackURL: shape + secrets[i] })).status, 403, shape);
  }
  const log = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8');
  assert.match(log, /callbackURL: \[redacted\]/i, 'the rejections were not logged at all');
  for (const secret of secrets) assert.ok(!log.includes(secret), `a rejected URL was logged in full (${secret})`);
});
