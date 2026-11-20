// M4a: OIDC SSO per organization (plan flow.md, M4a in "Rev 9 execution"). The identity provider is a second AuthWAPI,
// in-process; a small proxy in front of its token endpoint forges the negative cases (wrong audience, bad signature).
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { execFile } from 'node:child_process';
import { chmodSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { promisify } from 'node:util';
import { freePort, linkIn, startTestServer, type TestServer } from './helpers.ts';
import { allow, authorizeUrl, codeFrom, createClient, currentUser, db, enableTotp, exchange, Jar, passwordSignIn, send, totp, verifiedUser } from './signin-helpers.ts';

let idp: TestServer; // the organizations' identity provider
let sp: TestServer; // the AuthWAPI under test
let proxy: Server;
let proxyMode: 'pass' | 'other-client' | 'tamper' = 'pass';
let otherClient: { id: string; secret: string };

const run = promisify(execFile);
let spEnv: Record<string, string>;
const cli = (s: TestServer, args: string[], input?: string) => {
  const env = { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base, ...(s === sp ? spEnv : {}) };
  const child = run(process.execPath, ['src/cli.ts', ...args], { env });
  if (input !== undefined) child.child.stdin!.end(input);
  return child;
};

beforeEach(async () => {
  idp = await startTestServer();
  const proxyPort = await freePort();
  // The token endpoint, as the identity provider would answer it, or forged: a token issued to another client (wrong
  // audience), or an ID token with a broken signature.
  proxy = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const authorization =
      proxyMode === 'other-client' ? `Basic ${Buffer.from(`${otherClient.id}:${otherClient.secret}`).toString('base64')}` : req.headers.authorization!;
    const upstream = await fetch(`${idp.base}/api/auth/oauth2/token`, { method: 'POST', headers: { 'content-type': req.headers['content-type']!, authorization }, body });
    const json = (await upstream.json()) as { id_token?: string };
    if (proxyMode === 'tamper' && json.id_token) {
      const [h, p, sig] = json.id_token.split('.');
      json.id_token = `${h}.${p}.${sig.startsWith('A') ? 'B' : 'A'}${sig.slice(1)}`;
    }
    res.writeHead(upstream.status, { 'content-type': 'application/json' }).end(JSON.stringify(json));
  }).listen(proxyPort, '127.0.0.1');
  proxyMode = 'pass';
  // The IdP and proxy run on loopback, which Better Auth refuses unless trusted: trusted here, in the fixture only.
  spEnv = { ALLOWED_HOSTS: `${new URL(idp.base).host},127.0.0.1:${proxyPort}` };
  sp = await startTestServer(spEnv);
});
afterEach(async () => {
  await new Promise((r) => proxy.close(r));
  await sp.stop();
  await idp.stop();
});

// ── MCP on the AuthWAPI under test ──
async function connect(key: string) {
  const client = new Client({ name: 'test-agent', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${sp.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${key}` } } }));
  return client;
}
async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, data: JSON.parse((r.content as { text: string }[])[0].text) };
}
const ok = async (p: ReturnType<typeof call>) => {
  const r = await p;
  assert.equal(r.isError, false, JSON.stringify(r.data));
  return r.data;
};
async function agents() {
  const boot = await connect(readFileSync(sp.paths.bootstrapKey, 'utf8').trim());
  const write = await connect((await call(boot, 'mint_agent_key', { scope: 'write' })).data.key);
  await boot.close();
  const read = await connect((await call(write, 'mint_agent_key', { scope: 'read' })).data.key);
  return { write, read };
}
const audit = () =>
  readFileSync(path.join(sp.paths.logs, 'audit.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));

/** An organization on the AuthWAPI under test, with an owner. */
async function org(write: Client, slug: string) {
  const owner = await ok(call(write, 'create_user', { email: `owner@${slug}.test`, name: 'Owner', password: 'correct horse', emailVerified: true }));
  return (await ok(call(write, 'create_org', { name: slug, slug, ownerUserId: owner.user.id }))).organization.id as string;
}

/** One IdP client for every provider in a test: a redirect URI per provider ID. */
let idpClient: { id: string; secret: string } | undefined;
async function idpClientFor(slugs: string[]) {
  const uris = slugs.flatMap((slug) => ['--redirect-uri', `${sp.base}/api/auth/sso/callback/sso-${slug}`]);
  const { stdout } = await cli(idp, ['clients', 'create', '--name', 'SP', ...uris]);
  return { id: /client_id:\s+(\S+)/.exec(stdout)![1], secret: /client_secret:\s+(\S+)/.exec(stdout)![1] };
}
const providerArgs = (organizationId: string, slug: string, domain: string, client: { id: string; secret: string }, tokenEndpoint = `${idp.base}/api/auth/oauth2/token`) => ({
  organizationId,
  slug,
  domain,
  issuer: idp.base,
  clientId: client.id,
  clientSecret: client.secret,
  authorizationEndpoint: `${idp.base}/api/auth/oauth2/authorize`,
  tokenEndpoint,
  jwksEndpoint: `${idp.base}/api/auth/jwks`,
});
const proxyUrl = () => `http://127.0.0.1:${(proxy.address() as { port: number }).port}/token`;

/** An organization `slug` whose provider routes `domain` to the IdP. */
async function ssoOrg(write: Client, slug: string, domain: string, tokenEndpoint?: string) {
  idpClient ??= await idpClientFor(['a', 'b', 'gmail']);
  const organizationId = await org(write, slug);
  const { provider } = await ok(call(write, 'register_sso_provider', providerArgs(organizationId, slug, domain, idpClient, tokenEndpoint)));
  return { organizationId, providerId: provider.providerId as string };
}

/** Someone signed in at the IdP (verified there, unless set otherwise). */
async function idpUser(email: string) {
  await verifiedUser(idp, email);
  const jar = new Jar();
  assert.equal((await passwordSignIn(idp, jar, email)).status, 200);
  return jar;
}

/**
 * The browser round trip: SSO sign-in on the AuthWAPI under test (by email domain, or `providerId`), the IdP's
 * authorize and consent, then the callback. Returns the callback's answer and the callback URL (for replays).
 */
async function ssoSignIn(spJar: Jar, idpJar: Jar, email: string, providerId?: string, asClient?: string) {
  const start = await send(sp, spJar, 'POST', '/api/auth/sign-in/sso', { json: { ...(providerId ? { providerId } : { email }), callbackURL: '/', errorCallbackURL: '/sign-in' } });
  assert.equal(start.status, 200, start.body);
  const authorize = new URL(start.json().url);
  if (asClient) authorize.searchParams.set('client_id', asClient); // the IdP issues the code to that client instead
  let at = await send(idp, idpJar, 'GET', authorize.toString(), { navigate: true });
  if (at.location?.startsWith('/consent')) at = { ...at, location: await allow(idp, idpJar, at.location) };
  assert.ok(at.location?.startsWith(`${sp.base}/api/auth/sso/callback/`), `expected the callback, got ${at.location}`);
  const callback = at.location!;
  return { back: await send(sp, spJar, 'GET', callback, { navigate: true }), callback };
}
const errorOf = (location: string | undefined) => new URL(location ?? '/', sp.base).searchParams.get('error');

const row = (sql: string, ...args: unknown[]) => {
  const d = db(sp);
  try {
    return d.prepare(sql).get(...args) as Record<string, any> | undefined;
  } finally {
    d.close();
  }
};
const count = (sql: string, ...args: unknown[]) => Object.values(row(sql, ...args)!)[0] as number;

beforeEach(() => {
  idpClient = undefined;
});

test("org A's provider signs in a new user: a member of A, email unverified, bound to (A's provider, sub)", async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const spJar = new Jar();
  const { back } = await ssoSignIn(spJar, await idpUser('alice@a.example'), 'alice@a.example');
  assert.equal(back.status, 302, back.body);
  assert.equal(back.location, '/');
  assert.equal(await currentUser(sp, spJar), 'alice@a.example');
  const user = row('SELECT id, emailVerified FROM user WHERE email = ?', 'alice@a.example')!;
  assert.equal(user.emailVerified, 0);
  assert.equal(row('SELECT role FROM member WHERE userId = ? AND organizationId = ?', user.id, a.organizationId)?.role, 'member');
  const idpSub = row('SELECT accountId FROM account WHERE userId = ?', user.id)!.accountId;
  const d = db(idp);
  assert.ok(d.prepare('SELECT 1 FROM user WHERE id = ?').get(idpSub), 'the binding is the IdP subject');
  d.close();
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId = 'sso-a'", user.id), 1);

  // A second sign-in resolves through the binding to the same user.
  const again = new Jar();
  assert.equal((await ssoSignIn(again, await idpJarFor('alice@a.example'), 'alice@a.example')).back.location, '/');
  assert.equal(await currentUser(sp, again), 'alice@a.example');
});

/** A fresh IdP session for an IdP user created earlier. */
async function idpJarFor(email: string) {
  const jar = new Jar();
  assert.equal((await passwordSignIn(idp, jar, email)).status, 200);
  return jar;
}

test('the hosted sign-in page starts SSO by email domain; an unknown domain is told so', async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const page = await send(sp, new Jar(), 'GET', '/sign-in');
  assert.match(page.body, /Sign in with SSO/);
  const jar = new Jar();
  const go = await send(sp, jar, 'POST', '/sign-in', { form: { method: 'sso', email: 'alice@a.example', oauth_query: '' } });
  assert.equal(go.status, 303, go.body);
  assert.ok(go.location?.startsWith(`${idp.base}/api/auth/oauth2/authorize?`), String(go.location));
  const unknown = await send(sp, new Jar(), 'POST', '/sign-in', { form: { method: 'sso', email: 'bob@nowhere.example', oauth_query: '' } });
  assert.equal(unknown.status, 400);
  assert.match(unknown.body, /No organization signs in with SSO/);
});

test("SSO during an app's sign-in: the app's request carries on to consent and a code", async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  const app = await createClient(sp);
  const { url, verifier } = authorizeUrl(sp, app);
  const jar = new Jar();
  const signIn = await send(sp, jar, 'GET', url, { navigate: true });
  const query = new URL(signIn.location!, sp.base).search.slice(1);
  assert.match(signIn.location!, /^\/sign-in\?/);
  const go = await send(sp, jar, 'POST', '/sign-in', { form: { method: 'sso', email: 'alice@a.example', oauth_query: query } });
  assert.equal(go.status, 303, go.body);
  let at = await send(idp, idpJar, 'GET', go.location!, { navigate: true });
  if (at.location?.startsWith('/consent')) at = { ...at, location: await allow(idp, idpJar, at.location) };
  const back = await send(sp, jar, 'GET', at.location!, { navigate: true });
  assert.match(back.location ?? '', /^\/oauth\/resume\?/);
  let resumed = await send(sp, jar, 'GET', back.location!, { navigate: true }); // checked, then back to the authorize step
  if (resumed.location?.startsWith('/api/auth/oauth2/authorize')) resumed = await send(sp, jar, 'GET', resumed.location, { navigate: true });
  assert.match(resumed.location ?? '', /^\/consent\?/);
  const tokens = (await exchange(sp, app, codeFrom(await allow(sp, jar, resumed.location!)), verifier)).body;
  assert.ok(tokens.id_token);
});

test('an org claiming gmail.com gets no existing account, and a later mailbox owner takes theirs back by magic link', async () => {
  const { write } = await agents();
  await ssoOrg(write, 'gmail', 'gmail.com');
  // Existing: a verified user with that address is not linked, and nothing changes on their account.
  await verifiedUser(sp, 'victim@gmail.com');
  const refused = await ssoSignIn(new Jar(), await idpUser('victim@gmail.com'), 'victim@gmail.com');
  assert.equal(errorOf(refused.back.location), 'account_exists');
  assert.equal(count("SELECT count(*) FROM account a JOIN user u ON u.id = a.userId WHERE u.email = 'victim@gmail.com' AND a.providerId != 'credential'"), 0);

  // Future: the org's IdP signs up an address nobody has here yet. It stays unverified, and the verification link
  // can't verify it (the account has no password); the mailbox owner uses magic link.
  const attacker = new Jar();
  const created = await ssoSignIn(attacker, await idpUser('future@gmail.com'), 'future@gmail.com');
  assert.equal(created.back.location, '/');
  const user = row("SELECT id, emailVerified FROM user WHERE email = 'future@gmail.com'")!;
  assert.equal(user.emailVerified, 0);
  const verify = await fetch(linkIn((await sp.mail('future@gmail.com', 'Verify your email')).text), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: sp.base },
    body: new URLSearchParams({ password: 'anything at all' }),
  });
  assert.equal(verify.status, 409);
  assert.equal(row('SELECT emailVerified FROM user WHERE id = ?', user.id)!.emailVerified, 0);
  // Meanwhile the SSO session enrolls 2FA (no password needed) and is granted an OAuth token.
  await enableTotp(sp, attacker, undefined);
  const app = await createClient(sp);
  const { url, verifier } = authorizeUrl(sp, app);
  const consent = await send(sp, attacker, 'GET', url, { navigate: true });
  const code = codeFrom(await allow(sp, attacker, consent.location!));
  const tokens = (await exchange(sp, app, code, verifier)).body;
  assert.ok(tokens.refresh_token);
  // ...and an authorization code it hasn't exchanged yet.
  const second = authorizeUrl(sp, app);
  const pendingCode = codeFrom((await send(sp, attacker, 'GET', second.url, { navigate: true })).location);
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ?', user.id), 1);
  assert.equal(count("SELECT count(*) FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.userId') = ?", user.id), 1);

  // The mailbox owner signs in by magic link: verified, and everything set up before is gone in one step.
  await send(sp, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'future@gmail.com', callbackURL: '/' } });
  const link = linkIn((await sp.mail('future@gmail.com', 'Your sign-in link')).text);
  const owner = new Jar();
  const signedIn = await send(sp, owner, 'POST', link.pathname + link.search, { form: {} });
  assert.ok(signedIn.status < 400, signedIn.body);
  assert.equal(await currentUser(sp, owner), 'future@gmail.com', 'signed in, and not asked for the 2FA enrolled before');
  assert.equal(row('SELECT emailVerified, twoFactorEnabled FROM user WHERE id = ?', user.id)!.emailVerified, 1);
  assert.equal(row('SELECT twoFactorEnabled FROM user WHERE id = ?', user.id)!.twoFactorEnabled, 0);
  for (const table of ['account', 'twoFactor', 'passkey', 'oauthConsent']) assert.equal(count(`SELECT count(*) FROM ${table} WHERE userId = ?`, user.id), 0, table);
  assert.equal(count("SELECT count(*) FROM oauthRefreshToken WHERE userId = ? AND revoked IS NULL", user.id), 0);
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ?', user.id), 0, 'the org membership made before the proof');
  const codes = "SELECT count(*) FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.userId') = ?";
  assert.equal(count(codes, user.id), 0, 'the pending authorization code');
  assert.equal((await exchange(sp, app, pendingCode, second.verifier)).status, 400);
  assert.equal(await currentUser(sp, attacker), null);
  // And the org's IdP can't get back in: no binding, and the address is taken.
  const back = await ssoSignIn(new Jar(), await idpJarFor('future@gmail.com'), 'future@gmail.com');
  assert.equal(errorOf(back.back.location), 'account_exists');
});

test("a password reset by the mailbox owner clears what a magic link clears: the org's IdP can't get back in", async () => {
  const { write } = await agents();
  await ssoOrg(write, 'gmail', 'gmail.com');
  const attacker = new Jar();
  const idpJar = await idpUser('future@gmail.com');
  assert.equal((await ssoSignIn(attacker, idpJar, 'future@gmail.com')).back.location, '/');
  const user = row("SELECT id FROM user WHERE email = 'future@gmail.com'")!;
  await enableTotp(sp, attacker, undefined);

  // The owner uses "Forgot password?", then the verification link (it asks for the account's password).
  const ownerJar = new Jar();
  assert.equal((await send(sp, ownerJar, 'POST', '/api/auth/request-password-reset', { json: { email: 'future@gmail.com', redirectTo: '/' } })).status, 200);
  const token = linkIn((await sp.mail('future@gmail.com', 'Reset your password')).text).pathname.split('/').pop();
  const reset = await send(sp, ownerJar, 'POST', '/api/auth/reset-password', { json: { token, newPassword: 'owner new pass' } });
  assert.equal(reset.status, 200, reset.body);
  assert.equal(row('SELECT emailVerified FROM user WHERE id = ?', user.id)!.emailVerified, 0, 'a reset alone verifies nothing (M1)');
  const verify = await fetch(linkIn((await sp.mail('future@gmail.com', 'Verify your email')).text), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: sp.base },
    body: new URLSearchParams({ password: 'owner new pass' }),
  });
  assert.equal(verify.status, 200);

  const after = row('SELECT emailVerified, twoFactorEnabled FROM user WHERE id = ?', user.id)!;
  assert.deepEqual([after.emailVerified, after.twoFactorEnabled], [1, 0]);
  assert.deepEqual(row("SELECT group_concat(providerId) AS p FROM account WHERE userId = ?", user.id)!.p, 'credential');
  for (const table of ['twoFactor', 'passkey', 'member']) assert.equal(count(`SELECT count(*) FROM ${table} WHERE userId = ?`, user.id), 0, table);
  assert.equal(await currentUser(sp, attacker), null);
  assert.equal(errorOf((await ssoSignIn(new Jar(), idpJar, 'future@gmail.com')).back.location), 'account_exists');
  const signIn = await passwordSignIn(sp, new Jar(), 'future@gmail.com', 'owner new pass');
  assert.equal(signIn.status, 200);
  assert.notEqual(signIn.json().twoFactorRedirect, true, 'no 2FA left from before the proof');
});

/** A signed-in admin (role from set_role). */
async function signedInAdmin(write: Client) {
  const adminId = await verifiedUser(sp, 'admin@example.com');
  await ok(call(write, 'set_role', { userId: adminId, role: 'admin' }));
  const jar = new Jar();
  assert.equal((await passwordSignIn(sp, jar, 'admin@example.com')).status, 200);
  return jar;
}

/** future@gmail.com, created by the gmail.com org's IdP, with 2FA enrolled by that SSO session. */
async function squatted(write: Client) {
  await ssoOrg(write, 'gmail', 'gmail.com');
  const attacker = new Jar();
  const idpJar = await idpUser('future@gmail.com');
  assert.equal((await ssoSignIn(attacker, idpJar, 'future@gmail.com')).back.location, '/');
  await enableTotp(sp, attacker, undefined);
  return { attacker, idpJar, userId: row("SELECT id FROM user WHERE email = 'future@gmail.com'")!.id as string };
}
/** Everything set up before the first mailbox proof is gone, and the org's IdP can't get back in. */
async function purged(userId: string, attacker: Jar, idpJar: Jar) {
  const after = row('SELECT emailVerified, twoFactorEnabled FROM user WHERE id = ?', userId)!;
  assert.deepEqual([after.emailVerified, after.twoFactorEnabled], [1, 0]);
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId != 'credential'", userId), 0, 'SSO binding');
  for (const table of ['twoFactor', 'passkey', 'member']) assert.equal(count(`SELECT count(*) FROM ${table} WHERE userId = ?`, userId), 0, table);
  assert.equal(await currentUser(sp, attacker), null);
  assert.equal(errorOf((await ssoSignIn(new Jar(), idpJar, 'future@gmail.com')).back.location), 'account_exists');
}

test('verifying with a password an admin set is a first mailbox proof too: it purges in the same step', async () => {
  const { write } = await agents();
  const { attacker, idpJar, userId } = await squatted(write);
  const admin = await signedInAdmin(write);
  const set = await send(sp, admin, 'POST', '/api/auth/admin/set-user-password', { json: { userId, newPassword: 'admin set pass' } });
  assert.equal(set.status, 200, set.body);
  const verify = await fetch(linkIn((await sp.mail('future@gmail.com', 'Verify your email')).text), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: sp.base },
    body: new URLSearchParams({ password: 'admin set pass' }),
  });
  assert.equal(verify.status, 200);
  await purged(userId, attacker, idpJar);
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId = 'credential'", userId), 1, 'the password just checked stays');
  assert.equal((await passwordSignIn(sp, new Jar(), 'future@gmail.com', 'admin set pass')).status, 200);
});

test("an admin marking an unverified SSO user's email verified purges the same way", async () => {
  const { write } = await agents();
  const { attacker, idpJar, userId } = await squatted(write);
  const admin = await signedInAdmin(write);
  const r = await send(sp, admin, 'POST', '/api/auth/admin/update-user', { json: { userId, data: { emailVerified: true } } });
  assert.equal(r.status, 200, r.body);
  await purged(userId, attacker, idpJar);
});

test("an organization's owner must have a verified email: create_org and register_sso_provider refuse otherwise", async () => {
  const { write } = await agents();
  const unverified = await ok(call(write, 'create_user', { email: 'owner@u.test', name: 'Owner', password: 'correct horse' }));
  const refused = await call(write, 'create_org', { name: 'u', slug: 'u', ownerUserId: unverified.user.id });
  assert.deepEqual([refused.isError, refused.data.error], [true, 'owner_email_not_verified']);
  // An organization made before this rule, whose owner is unverified, gets no provider either.
  const organizationId = await org(write, 'a');
  const d = db(sp);
  d.prepare("UPDATE user SET emailVerified = 0 WHERE email = 'owner@a.test'").run();
  d.close();
  idpClient = await idpClientFor(['a']);
  const r = await call(write, 'register_sso_provider', providerArgs(organizationId, 'a', 'a.example', idpClient));
  assert.deepEqual([r.isError, r.data.error], [true, 'owner_email_not_verified']);
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 0);
});

test('the database refuses to delete the user who registered a provider, or its organization (RESTRICT)', async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const d = db(sp);
  d.pragma('foreign_keys = ON');
  try {
    assert.throws(() => d.prepare('DELETE FROM organization WHERE id = ?').run(a.organizationId), /FOREIGN KEY/);
    assert.throws(() => d.prepare("DELETE FROM user WHERE email = 'owner@a.test'").run(), /FOREIGN KEY/);
  } finally {
    d.close();
  }
  assert.match(readFileSync(new URL('../migrations/0007_sso.sql', import.meta.url), 'utf8'), /"userId" text not null references "user" \("id"\) on delete restrict.*"organizationId" text references "organization" \("id"\) on delete restrict/);
});

test("a new SSO user's membership commits with the user: if it can't be written, no user is created, and a retry works", async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  const d = db(sp);
  d.exec("CREATE TRIGGER fail_member BEFORE INSERT ON member BEGIN SELECT RAISE(ABORT, 'injected'); END");
  const failed = await ssoSignIn(new Jar(), idpJar, 'alice@a.example');
  assert.notEqual(failed.back.location, '/');
  assert.equal(count("SELECT count(*) FROM user WHERE email = 'alice@a.example'"), 0);
  assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-a'"), 0);
  d.exec('DROP TRIGGER fail_member');
  d.close();
  const jar = new Jar();
  assert.equal((await ssoSignIn(jar, idpJar, 'alice@a.example')).back.location, '/');
  const userId = row("SELECT id FROM user WHERE email = 'alice@a.example'")!.id;
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ? AND organizationId = ?', userId, a.organizationId), 1);
});

/** The squatted account's state from before the proof is all still there (nothing was purged). */
async function intact(userId: string, attacker: Jar) {
  const u = row('SELECT emailVerified, twoFactorEnabled FROM user WHERE id = ?', userId)!;
  assert.deepEqual([u.emailVerified, u.twoFactorEnabled], [0, 1]);
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId = 'sso-gmail'", userId), 1, 'SSO binding');
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ?', userId), 1, 'membership');
  assert.equal(await currentUser(sp, attacker), 'future@gmail.com', 'the session from before');
}

test('a password reset that fails part-way changes nothing: purge, token and password roll back together', async () => {
  const { write } = await agents();
  const { attacker, idpJar, userId } = await squatted(write);
  assert.equal((await send(sp, new Jar(), 'POST', '/api/auth/request-password-reset', { json: { email: 'future@gmail.com', redirectTo: '/' } })).status, 200);
  const token = linkIn((await sp.mail('future@gmail.com', 'Reset your password')).text).pathname.split('/').pop();
  const d = db(sp);
  d.exec("CREATE TRIGGER fail_credential BEFORE INSERT ON account WHEN NEW.providerId = 'credential' BEGIN SELECT RAISE(ABORT, 'injected'); END");
  const failed = await send(sp, new Jar(), 'POST', '/api/auth/reset-password', { json: { token, newPassword: 'owner new pass' } });
  assert.equal(failed.status, 500);
  await intact(userId, attacker);
  d.exec('DROP TRIGGER fail_credential');
  d.close();
  const retried = await send(sp, new Jar(), 'POST', '/api/auth/reset-password', { json: { token, newPassword: 'owner new pass' } });
  assert.equal(retried.status, 200, retried.body);
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId = 'sso-gmail'", userId), 0);
  assert.equal(await currentUser(sp, attacker), null);
  assert.equal(errorOf((await ssoSignIn(new Jar(), idpJar, 'future@gmail.com')).back.location), 'account_exists');
});

test('a magic link that fails part-way changes nothing, and the same link works afterwards', async () => {
  const { write } = await agents();
  const { attacker, idpJar, userId } = await squatted(write);
  await send(sp, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'future@gmail.com', callbackURL: '/' } });
  const link = linkIn((await sp.mail('future@gmail.com', 'Your sign-in link')).text);
  const d = db(sp);
  d.exec(`CREATE TRIGGER fail_session BEFORE INSERT ON session WHEN NEW.userId = '${userId}' BEGIN SELECT RAISE(ABORT, 'injected'); END`);
  const owner = new Jar();
  await send(sp, owner, 'POST', link.pathname + link.search, { form: {} });
  assert.equal(await currentUser(sp, owner), null);
  await intact(userId, attacker);
  d.exec('DROP TRIGGER fail_session');
  d.close();
  const signedIn = await send(sp, owner, 'POST', link.pathname + link.search, { form: {} });
  assert.ok(signedIn.status < 400, signedIn.body);
  assert.equal(await currentUser(sp, owner), 'future@gmail.com');
  await purged(userId, attacker, idpJar);
});

test("no unverified user becomes an organization's owner; and a proof never removes the last owner of an org with SSO", async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  assert.equal((await ssoSignIn(new Jar(), idpJar, 'alice@a.example')).back.location, '/');
  const alice = row("SELECT id FROM user WHERE email = 'alice@a.example'")!.id as string;
  const memberId = row('SELECT id FROM member WHERE userId = ?', alice)!.id;
  const owner = new Jar();
  assert.equal((await passwordSignIn(sp, owner, 'owner@a.test')).status, 200);
  const promoted = await send(sp, owner, 'POST', '/api/auth/organization/update-member-role', { json: { memberId, role: 'owner', organizationId: a.organizationId } });
  assert.equal(promoted.status, 400, promoted.body);
  assert.match(promoted.body, /verified email/);
  assert.equal(row('SELECT role FROM member WHERE id = ?', memberId)!.role, 'member');

  // Data from before this rule: Alice (unverified) is the only owner. Her magic link verifies her but keeps that
  // membership, so the provider still has an owner who can delete it.
  const d = db(sp);
  d.prepare("UPDATE member SET role = 'owner' WHERE id = ?").run(memberId);
  d.prepare("DELETE FROM member WHERE organizationId = ? AND userId != ?").run(a.organizationId, alice);
  d.close();
  await send(sp, new Jar(), 'POST', '/api/auth/sign-in/magic-link', { json: { email: 'alice@a.example', callbackURL: '/' } });
  const link = linkIn((await sp.mail('alice@a.example', 'Your sign-in link')).text);
  assert.ok((await send(sp, new Jar(), 'POST', link.pathname + link.search, { form: {} })).status < 400);
  assert.equal(row('SELECT emailVerified FROM user WHERE id = ?', alice)!.emailVerified, 1);
  assert.equal(row('SELECT role FROM member WHERE id = ?', memberId)?.role, 'owner');
  await ok(call(write, 'delete_sso_provider', { providerId: a.providerId }));
});

test('/admin/update-user refuses an emailVerified that is not a boolean, and purges on true', async () => {
  const { write } = await agents();
  const { attacker, userId } = await squatted(write);
  const admin = await signedInAdmin(write);
  for (const value of [1, '1', 'true']) {
    const r = await send(sp, admin, 'POST', '/api/auth/admin/update-user', { json: { userId, data: { emailVerified: value } } });
    assert.equal(r.status, 400, `${JSON.stringify(value)}: ${r.body}`);
  }
  await intact(userId, attacker);
});

test("cross-org: org B's provider can't sign in an identity bound to org A's", async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const b = await ssoOrg(write, 'b', 'b.example');
  const idpJar = await idpUser('alice@a.example');
  assert.equal((await ssoSignIn(new Jar(), idpJar, 'alice@a.example')).back.location, '/');
  // Same IdP, same subject, through B's provider: refused, and Alice doesn't join B.
  const jar = new Jar();
  const viaB = await ssoSignIn(jar, idpJar, 'alice@a.example', b.providerId);
  assert.equal(errorOf(viaB.back.location), 'account_exists');
  assert.equal(await currentUser(sp, jar), null);
  assert.equal(count("SELECT count(*) FROM member m JOIN user u ON u.id = m.userId WHERE u.email = 'alice@a.example' AND m.organizationId = ?", b.organizationId), 0);
  assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-b'"), 0);
});

test('refused: an email the IdP does not call verified, a wrong-audience or badly signed ID token', async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example', proxyUrl());
  otherClient = await idpClientFor(['a']); // another client at the same IdP, with the same redirect URI
  const users = () => count('SELECT count(*) FROM user WHERE email LIKE ?', '%@a.example');

  // Unverified at the IdP (signed in there, then the flag cleared).
  const idpJar = await idpUser('alice@a.example');
  const d = db(idp);
  d.prepare("UPDATE user SET emailVerified = 0 WHERE email = 'alice@a.example'").run();
  d.close();
  assert.equal(errorOf((await ssoSignIn(new Jar(), idpJar, 'alice@a.example')).back.location), 'email_not_verified');
  assert.equal(users(), 0);
  const d2 = db(idp);
  d2.prepare("UPDATE user SET emailVerified = 1 WHERE email = 'alice@a.example'").run();
  d2.close();

  // An ID token issued to another client: wrong audience.
  proxyMode = 'other-client';
  const wrongAud = await ssoSignIn(new Jar(), idpJar, 'alice@a.example', undefined, otherClient.id);
  assert.equal(errorOf(wrongAud.back.location), 'invalid_provider');
  assert.equal(new URL(wrongAud.back.location!, sp.base).searchParams.get('error_description'), 'token_not_verified');
  // A signature that doesn't verify.
  proxyMode = 'tamper';
  const badSig = await ssoSignIn(new Jar(), idpJar, 'alice@a.example');
  assert.equal(errorOf(badSig.back.location), 'invalid_provider');
  assert.equal(new URL(badSig.back.location!, sp.base).searchParams.get('error_description'), 'token_not_verified');
  assert.equal(users(), 0);
});

test('refused: a replayed callback, in the same browser and in another', async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  const jar = new Jar();
  const first = await ssoSignIn(jar, idpJar, 'alice@a.example');
  assert.equal(first.back.location, '/');
  const sessions = count('SELECT count(*) FROM session');
  for (const replayJar of [jar, new Jar()]) {
    const replay = await send(sp, replayJar, 'GET', first.callback, { navigate: true });
    assert.equal(replay.status, 302);
    assert.notEqual(replay.location, '/');
    assert.match(replay.location ?? '', /error=/);
  }
  assert.equal(count('SELECT count(*) FROM session'), sessions);
});

test('the HTTP routes that change providers are closed (404), even for an org owner', async () => {
  const { write } = await agents();
  const { providerId } = await ssoOrg(write, 'a', 'a.example');
  const owner = new Jar();
  assert.equal((await passwordSignIn(sp, owner, 'owner@a.test')).status, 200);
  for (const [p, body] of [
    ['/sso/register', providerArgs('x', 'evil', 'evil.example', { id: 'x', secret: 'y' })],
    ['/sso/update-provider', { providerId, domain: 'other.example' }],
    ['/sso/delete-provider', { providerId }],
    ['/sso/request-domain-verification', { providerId }],
    ['/sso/verify-domain', { providerId }],
  ] as const) {
    assert.equal((await send(sp, owner, 'POST', `/api/auth${p}`, { json: body })).status, 404, p);
  }
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 1);
});

test('MCP: register needs write and a domain no other provider has; list never shows the secret; every call is audited', async () => {
  const { write, read } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const orgB = await org(write, 'b');
  const taken = await call(write, 'register_sso_provider', providerArgs(orgB, 'b', 'a.example', idpClient!));
  assert.deepEqual([taken.isError, taken.data.error], [true, 'domain_taken']);
  const denied = await call(read, 'register_sso_provider', providerArgs(orgB, 'b', 'b.example', idpClient!));
  assert.deepEqual([denied.isError, denied.data.error], [true, 'forbidden']);
  const noOrg = await call(write, 'register_sso_provider', providerArgs('missing', 'c', 'c.example', idpClient!));
  assert.deepEqual([noOrg.isError, noOrg.data.error], [true, 'organization_not_found']);

  const listed = await ok(call(read, 'list_sso_providers'));
  assert.deepEqual(listed.providers, [
    { providerId: 'sso-a', organizationId: a.organizationId, domain: 'a.example', issuer: idp.base, redirectUri: `${sp.base}/api/auth/sso/callback/sso-a` },
  ]);
  assert.doesNotMatch(JSON.stringify(listed), new RegExp(idpClient!.secret));
  assert.doesNotMatch(readFileSync(path.join(sp.paths.logs, 'audit.jsonl'), 'utf8') + readFileSync(path.join(sp.paths.logs, 'app.jsonl'), 'utf8'), new RegExp(idpClient!.secret));
  const lines = audit().filter((l) => l.tool.includes('sso'));
  assert.deepEqual(
    lines.map((l) => [l.tool, l.outcome, l.target ?? l.reason ?? null]),
    [
      ['register_sso_provider', 'ok', 'sso-a'],
      ['register_sso_provider', 'error', null],
      ['register_sso_provider', 'denied', 'scope'],
      ['register_sso_provider', 'error', null],
      ['list_sso_providers', 'ok', null],
    ]
  );
});

test("deleting a provider revokes its users' sessions and OAuth tokens, and removes their bindings", async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const jar = new Jar();
  assert.equal((await ssoSignIn(jar, await idpUser('alice@a.example'), 'alice@a.example')).back.location, '/');
  const app = await createClient(sp);
  const { url, verifier } = authorizeUrl(sp, app);
  const consent = await send(sp, jar, 'GET', url, { navigate: true });
  const tokens = (await exchange(sp, app, codeFrom(await allow(sp, jar, consent.location!)), verifier)).body;
  assert.ok(tokens.refresh_token);
  // Someone who never used SSO keeps their session.
  const other = new Jar();
  await verifiedUser(sp, 'carol@example.com');
  assert.equal((await passwordSignIn(sp, other, 'carol@example.com')).status, 200);

  await ok(call(write, 'delete_sso_provider', { providerId: a.providerId }));
  assert.equal(await currentUser(sp, jar), null);
  const refresh = await fetch(`${sp.base}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${app.id}:${app.secret}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }),
  });
  assert.equal(refresh.status, 400);
  assert.equal(await currentUser(sp, other), 'carol@example.com');
  assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-a'"), 0);
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 0);
  assert.deepEqual(audit().filter((l) => l.tool === 'delete_sso_provider').map((l) => [l.outcome, l.target]), [['ok', 'sso-a']]);
  const again = await call(write, 'delete_sso_provider', { providerId: a.providerId });
  assert.deepEqual([again.isError, again.data.error], [true, 'provider_not_found']);
});

test('a user with 2FA signing in through SSO is asked for the second factor', async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  const jar = new Jar();
  assert.equal((await ssoSignIn(jar, idpJar, 'alice@a.example')).back.location, '/');
  const { secret } = await enableTotp(sp, jar, undefined);
  await send(sp, jar, 'POST', '/api/auth/sign-out', { json: {} });

  const next = new Jar();
  const { back } = await ssoSignIn(next, idpJar, 'alice@a.example');
  assert.equal(back.location, '/two-factor');
  assert.equal(await currentUser(sp, next), null, 'no session before the second factor');
  const verified = await send(sp, next, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(verified.status, 200, verified.body);
  assert.equal(await currentUser(sp, next), 'alice@a.example');
});

test('registration refuses http endpoints and issuers (only the trusted loopback test IdP may use http)', async () => {
  const { write } = await agents();
  const organizationId = await org(write, 'a');
  idpClient = await idpClientFor(['a']);
  for (const field of ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksEndpoint']) {
    const args = { ...providerArgs(organizationId, 'a', 'a.example', idpClient), [field]: `http://idp.example.com/${field}` };
    const r = await call(write, 'register_sso_provider', args);
    assert.deepEqual([r.isError, r.data.error], [true, 'insecure_endpoint'], field);
  }
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 0);
});

test('a provider whose audit line cannot be written is not registered', async () => {
  const { write } = await agents();
  const organizationId = await org(write, 'a');
  idpClient = await idpClientFor(['a']);
  chmodSync(path.join(sp.paths.logs, 'audit.jsonl'), 0o400);
  try {
    const r = await call(write, 'register_sso_provider', providerArgs(organizationId, 'a', 'a.example', idpClient)).catch((err: unknown) => ({ isError: true, data: { error: String(err) } }));
    assert.equal(r.isError, true);
  } finally {
    chmodSync(path.join(sp.paths.logs, 'audit.jsonl'), 0o600);
  }
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 0);
});

test("the owner who registered a provider can't be deleted, nor its organization, until the provider is", async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const ownerId = row("SELECT id FROM user WHERE email = 'owner@a.test'")!.id;
  const adminId = await verifiedUser(sp, 'admin@example.com');
  await ok(call(write, 'set_role', { userId: adminId, role: 'admin' }));
  const admin = new Jar();
  assert.equal((await passwordSignIn(sp, admin, 'admin@example.com')).status, 200);
  const removed = await send(sp, admin, 'POST', '/api/auth/admin/remove-user', { json: { userId: ownerId } });
  assert.equal(removed.status, 400, removed.body);
  assert.match(removed.body, /SSO provider/);
  const owner = new Jar();
  assert.equal((await passwordSignIn(sp, owner, 'owner@a.test')).status, 200);
  const deleted = await send(sp, owner, 'POST', '/api/auth/organization/delete', { json: { organizationId: a.organizationId } });
  assert.equal(deleted.status, 400, deleted.body);
  assert.match(deleted.body, /delete its SSO providers first/);
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 1);
  assert.equal(count('SELECT count(*) FROM organization'), 1);
  assert.equal(count('SELECT count(*) FROM user WHERE id = ?', ownerId), 1);

  await ok(call(write, 'delete_sso_provider', { providerId: a.providerId }));
  assert.equal((await send(sp, owner, 'POST', '/api/auth/organization/delete', { json: { organizationId: a.organizationId } })).status, 200);
  assert.equal((await send(sp, admin, 'POST', '/api/auth/admin/remove-user', { json: { userId: ownerId } })).status, 200);
});

test('membership is given only to users SSO creates: a removed member signing in again is not re-added', async () => {
  const { write } = await agents();
  const a = await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  assert.equal((await ssoSignIn(new Jar(), idpJar, 'alice@a.example')).back.location, '/');
  const userId = row("SELECT id FROM user WHERE email = 'alice@a.example'")!.id;
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ? AND organizationId = ?', userId, a.organizationId), 1);
  const d = db(sp);
  d.prepare('DELETE FROM member WHERE userId = ?').run(userId); // the org removed her
  d.close();
  const jar = new Jar();
  assert.equal((await ssoSignIn(jar, idpJar, 'alice@a.example')).back.location, '/');
  assert.equal(await currentUser(sp, jar), 'alice@a.example');
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ?', userId), 0);
});

test("2FA after SSO during an app's sign-in: the 2FA page, then consent", async () => {
  const { write } = await agents();
  await ssoOrg(write, 'a', 'a.example');
  const idpJar = await idpUser('alice@a.example');
  const first = new Jar();
  assert.equal((await ssoSignIn(first, idpJar, 'alice@a.example')).back.location, '/');
  const { secret } = await enableTotp(sp, first, undefined);

  const app = await createClient(sp);
  const { url, verifier } = authorizeUrl(sp, app);
  const jar = new Jar();
  const query = new URL((await send(sp, jar, 'GET', url, { navigate: true })).location!, sp.base).search.slice(1);
  const go = await send(sp, jar, 'POST', '/sign-in', { form: { method: 'sso', email: 'alice@a.example', oauth_query: query } });
  let at = await send(idp, idpJar, 'GET', go.location!, { navigate: true });
  if (at.location?.startsWith('/consent')) at = { ...at, location: await allow(idp, idpJar, at.location) };
  const back = await send(sp, jar, 'GET', at.location!, { navigate: true });
  assert.equal(back.location, `/two-factor?${query}`);
  assert.equal(await currentUser(sp, jar), null);
  const verified = await send(sp, jar, 'POST', '/two-factor', { form: { code: totp(secret), oauth_query: query } });
  assert.equal(verified.status, 303, verified.body);
  assert.match(verified.location ?? '', /\/consent\?/);
  const tokens = (await exchange(sp, app, codeFrom(await allow(sp, jar, verified.location!)), verifier)).body;
  assert.ok(tokens.id_token);
});

test('CLI: the operator registers, binds an existing verified account, lists and deletes', async () => {
  const { write } = await agents();
  const organizationId = await org(write, 'a');
  idpClient = await idpClientFor(['a']);
  const p = providerArgs(organizationId, 'a', 'a.example', idpClient);
  const flags = ['--org', organizationId, '--slug', 'a', '--domain', 'a.example', '--issuer', p.issuer, '--client-id', p.clientId];
  const endpoints = ['--authorization-endpoint', p.authorizationEndpoint, '--token-endpoint', p.tokenEndpoint, '--jwks-endpoint', p.jwksEndpoint];
  const registered = await cli(sp, ['sso', 'register', ...flags, ...endpoints], p.clientSecret);
  assert.match(registered.stdout, /sso-a/);
  assert.match(registered.stdout, new RegExp(`${sp.base}/api/auth/sso/callback/sso-a`));
  assert.doesNotMatch(registered.stdout, new RegExp(p.clientSecret));

  // An existing verified account here, bound to its IdP subject: SSO signs in as it (no new user).
  const userId = await verifiedUser(sp, 'alice@a.example');
  const idpJar = await idpUser('alice@a.example');
  const d = db(idp);
  const sub = d.prepare("SELECT id FROM user WHERE email = 'alice@a.example'").pluck().get() as string;
  d.close();
  await assert.rejects(cli(sp, ['sso', 'bind', '--provider', 'sso-a', '--subject', sub, '--user', 'nobody']), /user_not_found/);
  await cli(sp, ['sso', 'bind', '--provider', 'sso-a', '--subject', sub, '--user', userId]);
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ? AND organizationId = ?', userId, organizationId), 1, 'bind adds the membership');
  const jar = new Jar();
  assert.equal((await ssoSignIn(jar, idpJar, 'alice@a.example')).back.location, '/');
  assert.equal(await currentUser(sp, jar), 'alice@a.example');
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId = 'sso-a'", userId), 1);

  assert.match((await cli(sp, ['sso', 'list'])).stdout, /sso-a\s+a\.example/);
  await cli(sp, ['sso', 'delete', 'sso-a']);
  assert.equal(await currentUser(sp, jar), null);
  assert.deepEqual(
    audit().filter((l) => l.who === 'operator-cli').map((l) => [l.tool, l.outcome, l.target, l.provider ?? null, l.subject ?? null]),
    [
      ['sso register', 'ok', 'sso-a', null, null],
      ['sso bind', 'ok', userId, 'sso-a', sub],
      ['sso delete', 'ok', 'sso-a', null, null],
    ]
  );
});
