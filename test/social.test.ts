// Google and GitHub sign-in (on only when their credentials are set) and account linking (plan rev 7, M2): a provider
// account links to a local one only when the provider asserts a verified email AND the local email is verified, for
// implicit (sign-in by email) and explicit (link-social) linking alike. An unverified local account points to magic link.
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { loadConfig } from '../src/config.ts';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';
import { mockOAuth } from './mock-oauth.ts';
import { currentUser, db, Jar, passwordSignIn, send, verifiedUser } from './signin-helpers.ts';

let s: TestServer;
let oauth: ReturnType<typeof mockOAuth> | undefined;
afterEach(async () => {
  oauth?.restore();
  oauth = undefined;
  await s.stop();
});
const PROVIDERS = { GOOGLE_CLIENT_ID: 'google-client', GOOGLE_CLIENT_SECRET: 'google-secret', GITHUB_CLIENT_ID: 'gh-client', GITHUB_CLIENT_SECRET: 'gh-secret' };
const up = async () => {
  s = await startTestServer(PROVIDERS);
  oauth = mockOAuth();
};

/** Starts a social sign-in (or, with `link`, an explicit link) and comes back from the provider. */
async function viaProvider(jar: Jar, provider: 'google' | 'github', link = false) {
  const start = link
    ? await send(s, jar, 'POST', '/api/auth/link-social', { json: { provider, callbackURL: '/' } })
    : await send(s, jar, 'POST', '/api/auth/sign-in/social', { json: { provider, callbackURL: '/', errorCallbackURL: '/sign-in' } });
  assert.equal(start.status, 200, start.body);
  return send(s, jar, 'GET', oauth!.approve(start.json().url), { navigate: true });
}
const accounts = (email: string) => {
  const d = db(s);
  const rows = d.prepare('SELECT a.providerId FROM account a JOIN user u ON u.id = a.userId WHERE u.email = ? ORDER BY 1').pluck().all(email);
  d.close();
  return rows;
};

test('providers are on only when both their variables are set; half a pair stops the server', async () => {
  assert.throws(() => loadConfig({ GOOGLE_CLIENT_ID: 'x' }), /GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET/);
  assert.throws(() => loadConfig({ GITHUB_CLIENT_SECRET: 'x' }), /GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET/);
  assert.deepEqual(Object.keys(loadConfig({}).social), []);

  s = await startTestServer();
  const page = await send(s, new Jar(), 'GET', '/sign-in');
  assert.doesNotMatch(page.body, /Continue with/);
  const r = await send(s, new Jar(), 'POST', '/api/auth/sign-in/social', { json: { provider: 'google', callbackURL: '/' } });
  assert.notEqual(r.status, 200);
  await s.stop();

  s = await startTestServer(PROVIDERS);
  const both = await send(s, new Jar(), 'GET', '/sign-in');
  assert.match(both.body, /Continue with Google/);
  assert.match(both.body, /Continue with GitHub/);
});

test('a new Google or GitHub user with a provider-verified email is signed up and signed in', async () => {
  await up();
  oauth!.profiles.github.email = 'gh@example.com';
  for (const [provider, email] of [['google', 'ada@example.com'], ['github', 'gh@example.com']] as const) {
    const jar = new Jar();
    const back = await viaProvider(jar, provider);
    assert.equal(back.status, 302, back.body);
    assert.equal(back.location, '/');
    assert.equal(await currentUser(s, jar), email);
    assert.deepEqual(accounts(email), [provider]);
  }
});

test('an email the provider does not say is verified signs up no one and links to no one', async () => {
  await up();
  oauth!.profiles.github.emailVerified = false;
  const back = await viaProvider(new Jar(), 'github');
  assert.match(back.location ?? '', /^\/sign-in\?error=/);
  assert.deepEqual(accounts('ada@example.com'), []);

  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  assert.match((await viaProvider(jar, 'github')).location ?? '', /^\/sign-in\?error=/);
  assert.equal(await currentUser(s, jar), null);
  // Explicitly, while signed in, too.
  await passwordSignIn(s, jar, 'ada@example.com');
  assert.match((await viaProvider(jar, 'github', true)).location ?? '', /error=/);
  assert.deepEqual(accounts('ada@example.com'), ['credential']);
});

test('a verified local account links a verified Google identity by email (implicit) and by link-social (explicit)', async () => {
  await up();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  const back = await viaProvider(jar, 'google');
  assert.equal(back.location, '/');
  assert.equal(await currentUser(s, jar), 'ada@example.com');
  assert.deepEqual(accounts('ada@example.com'), ['credential', 'google']);

  const linked = await viaProvider(jar, 'github', true);
  assert.equal(linked.location, '/', linked.body);
  assert.deepEqual(accounts('ada@example.com'), ['credential', 'github', 'google']);
});

test('an unverified local account is never linked (implicitly or explicitly); the user is sent to magic link, which then works', async () => {
  await up();
  // Someone pre-registered ada@example.com with their own password and never verified it (Risk 8).
  assert.equal((await send(s, new Jar(), 'POST', '/api/auth/sign-up/email', { json: { email: 'ada@example.com', password: 'attacker pass', name: 'X' } })).status, 200);

  const jar = new Jar();
  const back = await viaProvider(jar, 'google');
  assert.equal(back.location, '/sign-in?error=account_not_linked');
  assert.equal(await currentUser(s, jar), null);
  const page = await send(s, jar, 'GET', back.location);
  assert.match(page.body, /email me a link/i, 'the refusal does not point to magic link');
  assert.deepEqual(accounts('ada@example.com'), ['credential']);

  // Explicit linking from a session on an unverified account (made directly: such a session can't come from sign-in).
  const d = db(s);
  d.prepare('UPDATE user SET emailVerified = 1 WHERE email = ?').run('ada@example.com');
  d.close();
  const attacker = new Jar();
  await passwordSignIn(s, attacker, 'ada@example.com', 'attacker pass');
  const d2 = db(s);
  d2.prepare('UPDATE user SET emailVerified = 0 WHERE email = ?').run('ada@example.com');
  d2.close();
  assert.match((await viaProvider(attacker, 'google', true)).location ?? '', /error=/);
  assert.deepEqual(accounts('ada@example.com'), ['credential']);

  // Magic link proves the address: it verifies it, drops the unproven password and every session. Then Google links.
  await send(s, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'ada@example.com', callbackURL: '/' } });
  const link = linkIn((await s.mail('ada@example.com', 'Your sign-in link')).text);
  const owner = new Jar();
  assert.equal((await send(s, owner, 'POST', link.pathname + link.search, { form: {} })).status, 303);
  assert.equal(await currentUser(s, owner), 'ada@example.com');
  assert.equal(await currentUser(s, attacker), null);
  assert.equal((await passwordSignIn(s, new Jar(), 'ada@example.com', 'attacker pass')).status, 401);
  const google = new Jar();
  assert.equal((await viaProvider(google, 'google')).location, '/');
  assert.equal(await currentUser(s, google), 'ada@example.com');
  assert.deepEqual(accounts('ada@example.com'), ['google']);
});

test('ID-token sign-in and linking are off (they would skip the account-linking policy)', async () => {
  await up();
  await verifiedUser(s, 'ada@example.com');
  const jar = new Jar();
  await passwordSignIn(s, jar, 'ada@example.com');
  const idToken = { token: 'x.y.z' };
  for (const path of ['/api/auth/link-social', '/api/auth/sign-in/social']) {
    const r = await send(s, jar, 'POST', path, { json: { provider: 'google', idToken } });
    assert.equal(r.status, 404, `${path}: ${r.body}`);
    assert.equal(r.json().code, 'ID_TOKEN_NOT_SUPPORTED', path);
  }
});
