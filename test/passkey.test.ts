// Passkeys (plan rev 7, M2): RP ID = BASE_URL's hostname, origin = BASE_URL's origin, user verification required and
// checked on the server. A passkey sign-in counts as both factors; adding one to a 2FA account needs a fresh 2FA check.
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { startTestServer, type TestServer } from './helpers.ts';
import {
  allow,
  authorizeUrl,
  codeFrom,
  createClient,
  currentUser,
  enableTotp,
  exchange,
  Jar,
  passwordSignIn,
  send,
  totp,
  verifiedUser,
} from './signin-helpers.ts';
import { softAuthenticator } from './webauthn.ts';

let s: TestServer;
afterEach(() => s.stop());

type Authenticator = ReturnType<typeof softAuthenticator>;

async function signedIn(email = 'ada@example.com') {
  await verifiedUser(s, email);
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, email)).status, 200);
  return jar;
}
async function addPasskey(jar: Jar, key: Authenticator, opts: { uv?: boolean } = {}) {
  const options = await send(s, jar, 'GET', '/api/auth/passkey/generate-register-options');
  if (options.status !== 200) return options;
  const o = options.json();
  assert.equal(o.rp.id, new URL(s.base).hostname);
  assert.equal(o.authenticatorSelection.userVerification, 'required');
  return send(s, jar, 'POST', '/api/auth/passkey/verify-registration', { json: { response: key.register(o, opts) } });
}
async function passkeySignIn(jar: Jar, key: Authenticator, opts: { uv?: boolean; oauth_query?: string } = {}) {
  const options = await send(s, jar, 'GET', '/api/auth/passkey/generate-authenticate-options');
  assert.equal(options.status, 200, options.body);
  assert.equal(options.json().userVerification, 'required');
  const body = { response: key.authenticate(options.json(), opts), ...(opts.oauth_query ? { oauth_query: opts.oauth_query } : {}) };
  return send(s, jar, 'POST', '/api/auth/passkey/verify-authentication', { json: body });
}

test('a passkey registered with user verification signs in; one without user verification is refused both ways', async () => {
  s = await startTestServer();
  const jar = await signedIn();
  const key = softAuthenticator(s.base);
  const noUv = await addPasskey(jar, softAuthenticator(s.base), { uv: false });
  assert.equal(noUv.status, 400, 'a passkey registered without user verification');
  assert.equal((await addPasskey(jar, key)).status, 200);

  const refused = new Jar();
  assert.notEqual((await passkeySignIn(refused, key, { uv: false })).status, 200);
  assert.equal(await currentUser(s, refused), null, 'a passkey sign-in without user verification made a session');

  const browser = new Jar();
  assert.equal((await passkeySignIn(browser, key)).status, 200);
  assert.equal(await currentUser(s, browser), 'ada@example.com');
});

test('a passkey sign-in counts as both factors on a 2FA account', async () => {
  s = await startTestServer();
  const jar = await signedIn();
  const key = softAuthenticator(s.base);
  assert.equal((await addPasskey(jar, key)).status, 200);
  await enableTotp(s, jar);

  const browser = new Jar();
  const r = await passkeySignIn(browser, key);
  assert.equal(r.status, 200, r.body);
  assert.equal(await currentUser(s, browser), 'ada@example.com');
  assert.equal(browser.get('two_factor'), undefined);
});

test('adding a passkey to a 2FA account needs a fresh 2FA check', async () => {
  s = await startTestServer();
  const setup = await signedIn();
  const first = softAuthenticator(s.base);
  assert.equal((await addPasskey(setup, first)).status, 200);
  const { secret } = await enableTotp(s, setup); // entering that code counts as a fresh check, for that session only
  // A session with no recent 2FA code: signed in with the first passkey (both factors, but no code entered).
  const jar = new Jar();
  assert.equal((await passkeySignIn(jar, first)).status, 200);
  const key = softAuthenticator(s.base);
  const refused = await addPasskey(jar, key);
  assert.equal(refused.status, 403, refused.body);
  // Skipping the options call doesn't help either.
  const direct = await send(s, jar, 'POST', '/api/auth/passkey/verify-registration', { json: { response: key.register({ challenge: 'x' }) } });
  assert.equal(direct.status, 403, direct.body);

  // A step-up check: the signed-in user confirms a current code.
  const check = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(check.status, 200, check.body);
  assert.equal((await addPasskey(jar, key)).status, 200);
});

test('OAuth: a passkey sign-in during an authorization request continues to consent and a code', async () => {
  s = await startTestServer();
  const jar = await signedIn();
  const key = softAuthenticator(s.base);
  assert.equal((await addPasskey(jar, key)).status, 200);
  const client = await createClient(s);
  const { url, verifier } = authorizeUrl(s, client);
  const browser = new Jar();
  const login = await send(s, browser, 'GET', url, { navigate: true });
  const query = new URL(login.location!, s.base).search.slice(1);
  const page = await send(s, browser, 'GET', login.location!);
  assert.match(page.body, /data-passkey="sign-in"/);

  const r = await passkeySignIn(browser, key, { oauth_query: query });
  assert.equal(r.status, 200, r.body);
  const next = r.json().url as string;
  assert.match(next, /\/consent\?/);
  assert.equal((await exchange(s, client, codeFrom(await allow(s, browser, next)), verifier)).status, 200);
});

test('hosted pages load the passkey script from our own origin only (CSP)', async () => {
  s = await startTestServer();
  const res = await fetch(`${s.base}/sign-in`);
  const csp = res.headers.get('content-security-policy') ?? '';
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(await res.text(), /<script src="\/passkey\.js" defer><\/script>/);
  const js = await fetch(`${s.base}/passkey.js`);
  assert.equal(js.status, 200);
  assert.match(js.headers.get('content-type') ?? '', /javascript/);
});
