// M3: organizations and invitations, the admin ban, impersonation and org claims (plan flow.md, M3 in "Rev 8
// execution"), driven over HTTP and MCP against a real server.
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { promisify } from 'node:util';
import { decodeJwt } from 'jose';
import { linkIn, startTestServer, type TestServer } from './helpers.ts';
import { codeFrom, db, enableTotp, Jar, passwordSignIn, REDIRECT, send, verifiedUser } from './signin-helpers.ts';

let s: TestServer;
beforeEach(async () => (s = await startTestServer()));
afterEach(() => s.stop());

const API = 'http://localhost:5999/api';

// ── MCP ──
async function connect(key: string) {
  const client = new Client({ name: 'test-agent', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${key}` } } }));
  return client;
}
async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, data: JSON.parse((r.content as { text: string }[])[0].text) };
}
/** A write-scoped agent (minted with the bootstrap key) and a read-scoped one. */
async function agents() {
  const boot = await connect(readFileSync(s.paths.bootstrapKey, 'utf8').trim());
  const write = await connect((await call(boot, 'mint_agent_key', { scope: 'write' })).data.key);
  await boot.close();
  const read = await connect((await call(write, 'mint_agent_key', { scope: 'read' })).data.key);
  return { write, read };
}
const audit = () =>
  readFileSync(path.join(s.paths.logs, 'audit.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
const ok = async (p: ReturnType<typeof call>) => {
  const r = await p;
  assert.equal(r.isError, false, JSON.stringify(r.data));
  return r.data;
};

/** A verified user, signed in. */
async function user(email: string) {
  const id = await verifiedUser(s, email);
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, email)).status, 200);
  return { id, email, jar };
}
/** A verified user who never signs in, made over MCP (sign-up is rate limited to 3 per 10 seconds). */
async function mcpUser(write: Client, email: string): Promise<string> {
  return (await ok(call(write, 'create_user', { email, name: 'User', password: 'correct horse', emailVerified: true }))).user.id;
}
/** A signed-in admin; the role comes from set_role, the only way to make the first admin. */
async function adminUser(write: Client, email = 'admin@example.com') {
  const id = await verifiedUser(s, email);
  await ok(call(write, 'set_role', { userId: id, role: 'admin' }));
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, email)).status, 200);
  return { id, email, jar };
}

// ── OAuth (the app side) ──
async function oauthClient(resource?: string) {
  const args = ['src/cli.ts', 'clients', 'create', '--name', 'Test App', '--redirect-uri', REDIRECT, ...(resource ? ['--resource', resource] : [])];
  const { stdout } = await promisify(execFile)(process.execPath, args, { env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base } });
  return { id: /client_id:\s+(\S+)/.exec(stdout)![1], secret: /client_secret:\s+(\S+)/.exec(stdout)![1] };
}
type OAuthClient = Awaited<ReturnType<typeof oauthClient>>;
type Tokens = { access_token: string; refresh_token?: string; id_token?: string };

function authorizeUrl(client: OAuthClient, scope: string, extra: Record<string, string> = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.id,
    redirect_uri: REDIRECT,
    scope,
    state: 'app-state',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  });
  return { url: `/api/auth/oauth2/authorize?${params}`, verifier };
}
const tokenRequest = (client: OAuthClient, body: Record<string, string>) =>
  fetch(`${s.base}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}` },
    body: new URLSearchParams(body),
  });
const exchange = (client: OAuthClient, code: string, verifier: string, resource?: string) =>
  tokenRequest(client, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, ...(resource ? { resource } : {}) });
const refresh = (client: OAuthClient, refreshToken: string, resource?: string) =>
  tokenRequest(client, { grant_type: 'refresh_token', refresh_token: refreshToken, ...(resource ? { resource } : {}) });
async function introspect(client: OAuthClient, token: string): Promise<boolean> {
  const res = await fetch(`${s.base}/api/auth/oauth2/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}` },
    body: new URLSearchParams({ token }),
  });
  return ((await res.json()) as { active: boolean }).active;
}
const userinfo = async (accessToken: string) =>
  (await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })).json() as Promise<Record<string, unknown>>;

/** The consent page's form fields: the signed request and the organization it showed (if it shows one). */
const consentForm = (page: string) => ({
  oauth_query: /name="oauth_query" value="([^"]*)"/.exec(page)![1].replaceAll('&amp;', '&'),
  ...(/name="org_id" value="([^"]*)"/.test(page) ? { org_id: /name="org_id" value="([^"]*)"/.exec(page)![1] } : {}),
});

/** Authorization up to the consent page: the organization page (picking `org`, or none), then `beforeConsent`. */
async function toConsent(
  jar: Jar,
  client: OAuthClient,
  { scope = 'openid email offline_access', resource, org, beforeConsent }: { scope?: string; resource?: string; org?: string; beforeConsent?: () => Promise<void> } = {}
) {
  const { url, verifier } = authorizeUrl(client, scope, { prompt: 'consent', ...(resource ? { resource } : {}) });
  let r = await send(s, jar, 'GET', url, { navigate: true });
  assert.equal(r.status, 302, r.body);
  let location = r.location!;
  let orgPage: string | undefined;
  if (location.startsWith('/select-org')) {
    orgPage = (await send(s, jar, 'GET', location, { navigate: true })).body;
    const query = new URL(location, s.base).search.slice(1);
    r = await send(s, jar, 'POST', '/select-org', { form: { oauth_query: query, org_id: org ?? '' } });
    assert.equal(r.status, 303, r.body);
    location = r.location!;
  }
  await beforeConsent?.();
  assert.equal(new URL(location, s.base).pathname, '/consent', location);
  const consentPage = (await send(s, jar, 'GET', location, { navigate: true })).body;
  return { verifier, orgPage, consentPage };
}

/** A browser signed in as `jar` goes through the app's authorization (toConsent), then Allow. Returns the code and pages seen. */
async function authorizeAs(jar: Jar, client: OAuthClient, opts: Parameters<typeof toConsent>[2] = {}) {
  const { verifier, orgPage, consentPage } = await toConsent(jar, client, opts);
  const r = await send(s, jar, 'POST', '/consent', { form: { ...consentForm(consentPage), accept: 'yes' } });
  assert.equal(r.status, 303, r.body);
  return { code: codeFrom(r.location), verifier, orgPage, consentPage };
}
async function tokensFor(jar: Jar, client: OAuthClient, opts: Parameters<typeof authorizeAs>[2] = {}) {
  const { code, verifier, ...pages } = await authorizeAs(jar, client, opts);
  const res = await exchange(client, code, verifier, opts.resource);
  assert.equal(res.status, 200, await res.clone().text());
  return { tokens: (await res.json()) as Tokens, ...pages };
}
const unrevokedRefreshTokens = (userId: string) => {
  const d = db(s);
  const n = d.prepare('SELECT count(*) FROM oauthRefreshToken WHERE userId = ? AND revoked IS NULL').pluck().get(userId) as number;
  d.close();
  return n;
};
const codeCount = () => {
  const d = db(s);
  const n = d.prepare(`SELECT count(*) FROM verification WHERE value LIKE '%"type":"authorization_code"%'`).pluck().get() as number;
  d.close();
  return n;
};

// ── MCP tools ──

test('a read key lists and calls only list_orgs among the M3 tools; each write tool call is audited once', async () => {
  const { write, read } = await agents();
  const readTools = (await read.listTools()).tools.map((t) => t.name);
  assert.ok(readTools.includes('list_orgs'));
  for (const name of ['create_org', 'invite_member', 'ban_user', 'unban_user', 'set_role']) {
    assert.ok(!readTools.includes(name), `read key sees ${name}`);
    const r = await call(read, name, {});
    assert.equal(r.isError, true);
    assert.equal(r.data.error, 'forbidden');
    const lines = audit().filter((e) => e.tool === name);
    assert.equal(lines.length, 1, name);
    assert.equal(lines[0].outcome, 'denied');
    assert.equal(lines[0].reason, 'scope');
  }
  const writeTools = (await write.listTools()).tools.map((t) => t.name);
  for (const name of ['list_orgs', 'create_org', 'invite_member', 'ban_user', 'unban_user', 'set_role']) assert.ok(writeTools.includes(name), name);

  const alice = await verifiedUser(s, 'alice@example.com');
  const org = await ok(call(write, 'create_org', { name: 'Acme', slug: 'acme', ownerUserId: alice }));
  await ok(call(write, 'invite_member', { organizationId: org.organization.id, email: 'bob@example.com', role: 'member' }));
  await ok(call(write, 'set_role', { userId: alice, role: 'admin' }));
  await ok(call(write, 'ban_user', { userId: alice, reason: 'test' }));
  await ok(call(write, 'unban_user', { userId: alice }));
  const listed = await ok(call(read, 'list_orgs'));
  assert.deepEqual(
    listed.organizations.map((o: { slug: string; members: number }) => [o.slug, o.members]),
    [['acme', 1]]
  );
  for (const [tool, target] of [
    ['create_org', org.organization.id],
    ['set_role', alice],
    ['ban_user', alice],
    ['unban_user', alice],
  ]) {
    const lines = audit().filter((e) => e.tool === tool && e.scope === 'write');
    assert.equal(lines.length, 1, tool);
    assert.equal(lines[0].outcome, 'ok', tool);
    assert.equal(lines[0].target, target, tool);
  }
  assert.equal(audit().filter((e) => e.tool === 'invite_member' && e.outcome === 'ok').length, 1);
  assert.equal(audit().filter((e) => e.tool === 'list_orgs' && e.scope === 'read' && e.outcome === 'ok').length, 1);
  await write.close();
  await read.close();
});

test('the first admin is made with set_role: before it the user is refused the admin API, after it allowed', async () => {
  const { write } = await agents();
  const u = await user('first@example.com');
  assert.notEqual((await send(s, u.jar, 'GET', '/api/auth/admin/list-users')).status, 200);
  assert.equal((await call(write, 'set_role', { userId: u.id, role: 'superuser' })).isError, true); // only user | admin
  await ok(call(write, 'set_role', { userId: u.id, role: 'admin' }));
  assert.equal((await send(s, u.jar, 'GET', '/api/auth/admin/list-users')).status, 200);
  assert.equal((await call(write, 'set_role', { userId: 'no-such-user', role: 'admin' })).data.error, 'user_not_found');
  await write.close();
});

test('invitation end to end: invite_member emails a link; the invited user signs in and accepts on the hosted page', async () => {
  const { write } = await agents();
  const alice = await verifiedUser(s, 'alice@example.com');
  const { organization } = await ok(call(write, 'create_org', { name: 'Acme <b>', slug: 'acme', ownerUserId: alice }));
  const invited = await ok(call(write, 'invite_member', { organizationId: organization.id, email: 'Bob@Example.com', role: 'admin' }));
  assert.equal(invited.invitation.email, 'bob@example.com');
  const mail = await s.mail('bob@example.com', 'You are invited to join an organization on AuthWAPI');
  const link = linkIn(mail.text);
  assert.equal(`${link.origin}${link.pathname}`, `${s.base}/accept-invitation`);

  // Signed out: the page asks for a sign-in first.
  const signedOut = await send(s, new Jar(), 'GET', link.pathname + link.search, { navigate: true });
  assert.equal(signedOut.status, 200);
  assert.match(signedOut.body, /Sign in/);

  // Someone else signed in can't see or accept it.
  const carol = await user('carol@example.com');
  const wrong = await send(s, carol.jar, 'GET', link.pathname + link.search, { navigate: true });
  assert.equal(wrong.status, 403);
  assert.equal((await send(s, carol.jar, 'POST', '/accept-invitation', { form: { id: link.searchParams.get('id')! } })).status, 403);

  const bob = await user('bob@example.com');
  const page = await send(s, bob.jar, 'GET', link.pathname + link.search, { navigate: true });
  assert.equal(page.status, 200);
  assert.match(page.body, /Acme &lt;b&gt;/); // escaped
  assert.match(page.body, /admin/);
  const accepted = await send(s, bob.jar, 'POST', '/accept-invitation', { form: { id: link.searchParams.get('id')! } });
  assert.equal(accepted.status, 200, accepted.body);
  const d = db(s);
  assert.equal(d.prepare('SELECT role FROM member WHERE userId = ? AND organizationId = ?').pluck().get(bob.id, organization.id), 'admin');
  d.close();
  assert.deepEqual((await ok(call(write, 'list_orgs'))).organizations.map((o: { members: number }) => o.members), [2]);
  await write.close();
});

// ── Ban ──

test('ban_user ends sessions, refuses refresh and code exchange, and introspection reports the tokens inactive; unban lets the user back', async () => {
  const { write } = await agents();
  const u = await user('ban@example.com');
  const client = await oauthClient(API);
  const opaque = (await tokensFor(u.jar, client)).tokens;
  const jwt = (await tokensFor(u.jar, client, { resource: API })).tokens;
  const pending = await authorizeAs(u.jar, client); // a code issued before the ban, not yet exchanged
  assert.equal(await introspect(client, jwt.access_token), true);

  await ok(call(write, 'ban_user', { userId: u.id, reason: 'abuse' }));

  assert.equal((await refresh(client, opaque.refresh_token!)).status, 400);
  assert.equal((await refresh(client, jwt.refresh_token!, API)).status, 400);
  assert.equal((await exchange(client, pending.code, pending.verifier)).status, 400);
  assert.equal(await introspect(client, opaque.access_token), false);
  assert.equal(await introspect(client, jwt.access_token), false);
  assert.equal(await introspect(client, opaque.refresh_token!), false);
  assert.equal(unrevokedRefreshTokens(u.id), 0);
  const d = db(s);
  assert.equal(d.prepare('SELECT count(*) FROM session WHERE userId = ?').pluck().get(u.id), 0);
  const codes = `SELECT count(*) FROM verification WHERE value LIKE '%"type":"authorization_code"%' AND value LIKE ?`;
  assert.equal(d.prepare(codes).pluck().get(`%"userId":"${u.id}"%`), 0, 'the pending code was not deleted');
  d.close();
  assert.equal((await passwordSignIn(s, new Jar(), u.email)).status, 403);

  await ok(call(write, 'unban_user', { userId: u.id }));
  const jar = new Jar();
  assert.equal((await passwordSignIn(s, jar, u.email)).status, 200);
  await tokensFor(jar, client);
  await write.close();
});

test('the HTTP ban (/admin/ban-user and /admin/update-user ban fields) revokes refresh tokens too', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const client = await oauthClient();
  for (const how of ['ban-user', 'update-user'] as const) {
    const u = await user(`${how}@example.com`);
    const { tokens } = await tokensFor(u.jar, client);
    const body = how === 'ban-user' ? { userId: u.id } : { userId: u.id, data: { banned: true, banReason: 'abuse' } };
    const r = await send(s, admin.jar, 'POST', `/api/auth/admin/${how}`, { json: body });
    assert.equal(r.status, 200, r.body);
    assert.equal(unrevokedRefreshTokens(u.id), 0, how);
    assert.equal((await refresh(client, tokens.refresh_token!)).status, 400, how);
    assert.equal(await introspect(client, tokens.access_token), false, how);
  }
  await write.close();
});

test('a ban that lands between the user read and the token write: issuance re-checks and revokes what it wrote', async () => {
  const u = await user('race@example.com');
  const client = await oauthClient();
  const { tokens } = await tokensFor(u.jar, client);
  const pending = await authorizeAs(u.jar, client);
  // Every user read and check has passed when the provider writes the refresh token; the trigger bans the user
  // right then (in SQL, so none of AuthWAPI's own ban steps run).
  const d = db(s);
  d.exec(`CREATE TRIGGER ban_mid_issue BEFORE INSERT ON oauthRefreshToken BEGIN UPDATE "user" SET banned = 1 WHERE id = NEW.userId; END`);
  d.close();
  for (const attempt of [() => refresh(client, tokens.refresh_token!), () => exchange(client, pending.code, pending.verifier)]) {
    const res = await attempt();
    assert.equal(res.status, 400, await res.clone().text());
    assert.equal(((await res.json()) as { error: string }).error, 'invalid_grant');
    assert.equal(unrevokedRefreshTokens(u.id), 0);
    const reset = db(s);
    reset.prepare('UPDATE "user" SET banned = 0 WHERE id = ?').run(u.id); // so the next attempt passes the pre-check
    reset.close();
  }
  assert.equal(await introspect(client, tokens.access_token), false);
});

test('introspection and userinfo report a banned or deleted user\'s token inactive, even with no revocation recorded', async () => {
  const u = await user('quiet@example.com');
  const client = await oauthClient(API);
  const { tokens } = await tokensFor(u.jar, client, { resource: API });
  // A JWT minted by refresh after the session is gone carries no sid, so Better Auth's own session check can't cut it off.
  const d = db(s);
  d.prepare('DELETE FROM session WHERE userId = ?').run(u.id);
  const res = await refresh(client, tokens.refresh_token!, API);
  assert.equal(res.status, 200);
  const jwt = ((await res.json()) as Tokens).access_token;
  assert.equal(decodeJwt(jwt).sid, undefined);
  const info = async () => (await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${jwt}` } })).status;
  assert.equal(await introspect(client, jwt), true);
  d.prepare('UPDATE "user" SET banned = 1 WHERE id = ?').run(u.id); // in SQL: none of the ban's revocation runs
  assert.equal(await introspect(client, jwt), false);
  assert.equal(await info(), 401);
  d.prepare('UPDATE "user" SET banned = 0 WHERE id = ?').run(u.id);
  assert.equal(await introspect(client, jwt), true);
  d.prepare('DELETE FROM "user" WHERE id = ?').run(u.id);
  d.close();
  assert.equal(await introspect(client, jwt), false);
  assert.notEqual(await info(), 200); // Better Auth's userinfo refuses an unknown user itself (400)
});

test('a ban racing a refresh leaves no usable token, whichever wins', async () => {
  const { write } = await agents();
  const u = await user('concurrent@example.com');
  const client = await oauthClient(API);
  const { tokens } = await tokensFor(u.jar, client, { resource: API });
  const [res] = await Promise.all([refresh(client, tokens.refresh_token!, API), ok(call(write, 'ban_user', { userId: u.id }))]);
  if (res.status === 200) {
    const fresh = (await res.json()) as Tokens;
    assert.equal(await introspect(client, fresh.access_token), false);
    assert.equal((await refresh(client, fresh.refresh_token!, API)).status, 400);
  }
  assert.equal(unrevokedRefreshTokens(u.id), 0);
  await write.close();
});

const sessionToken = (userId: string) => {
  const d = db(s);
  const t = d.prepare('SELECT token FROM session WHERE userId = ?').pluck().get(userId) as string;
  d.close();
  return t;
};
for (const [route, body] of [
  ['revoke-user-sessions', (id) => ({ userId: id })],
  ['revoke-user-session', (id) => ({ sessionToken: sessionToken(id) })],
  ['set-user-password', (id) => ({ userId: id, newPassword: 'another horse' })],
  ['remove-user', (id) => ({ userId: id })],
] as [string, (id: string) => object][]) {
  test(`/admin/${route} also revokes the user's refresh tokens`, async () => {
    const { write } = await agents();
    const admin = await adminUser(write);
    const client = await oauthClient(API);
    const u = await user('target@example.com');
    const { tokens } = await tokensFor(u.jar, client, { resource: API });
    const r = await send(s, admin.jar, 'POST', `/api/auth/admin/${route}`, { json: body(u.id) });
    assert.equal(r.status, 200, r.body);
    assert.equal((await refresh(client, tokens.refresh_token!, API)).status, 400);
    assert.equal(await introspect(client, tokens.access_token), false);
    await write.close();
  });
}

// ── Impersonation ──

test('impersonation is short and audited, and never targets admins or organization owners and admins', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const otherAdmin = await mcpUser(write, 'admin2@example.com');
  await ok(call(write, 'set_role', { userId: otherAdmin, role: 'admin' }));
  const owner = await mcpUser(write, 'owner@example.com');
  const orgAdmin = await mcpUser(write, 'orgadmin@example.com');
  const member = await mcpUser(write, 'member@example.com');
  const { organization } = await ok(call(write, 'create_org', { name: 'Acme', slug: 'acme', ownerUserId: owner }));
  const d = db(s);
  const addMember = d.prepare('INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)');
  addMember.run('m-admin', organization.id, orgAdmin, 'admin', new Date().toISOString());
  addMember.run('m-member', organization.id, member, 'member', new Date().toISOString());
  d.close();

  for (const target of [otherAdmin, owner, orgAdmin]) {
    const r = await send(s, admin.jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: target } });
    assert.equal(r.status, 403, r.body);
  }
  const r = await send(s, admin.jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: member } });
  assert.equal(r.status, 200, r.body);
  const row = db(s).prepare('SELECT expiresAt, createdAt FROM session WHERE impersonatedBy = ?').get(admin.id) as { expiresAt: string; createdAt: string };
  assert.ok(Date.parse(row.expiresAt) - Date.parse(row.createdAt) <= 10 * 60_000);
  assert.equal((await send(s, admin.jar, 'GET', '/api/auth/get-session')).json().user.email, 'member@example.com');
  assert.equal((await send(s, admin.jar, 'POST', '/api/auth/admin/stop-impersonating', { json: {} })).status, 200);
  assert.equal((await send(s, admin.jar, 'GET', '/api/auth/get-session')).json().user.email, admin.email);

  const lines = audit().filter((e) => e.tool === 'impersonate_user' || e.tool === 'stop_impersonating');
  assert.deepEqual(
    lines.map((e) => [e.tool, e.who, e.target, e.outcome]),
    [
      ['impersonate_user', admin.id, member, 'ok'],
      ['stop_impersonating', admin.id, member, 'ok'],
    ]
  );
  await write.close();
});

test('an impersonated session gets no authorization code or consent write (authorize, consent, continue) and cannot change credentials', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const target = await user('target@example.com');
  const client = await oauthClient();
  await tokensFor(target.jar, client); // the target has consented to this app already
  const consentsBefore = JSON.stringify(db(s).prepare('SELECT * FROM oauthConsent ORDER BY id').all());
  const codesBefore = codeCount();

  assert.equal((await send(s, admin.jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: target.id } })).status, 200);
  const jar = admin.jar; // now the impersonated session (plus the admin_session cookie)

  // /oauth2/authorize: consent exists, so without the guard this would redirect to the app with a code.
  const direct = await send(s, jar, 'GET', authorizeUrl(client, 'openid email offline_access').url, { navigate: true });
  assert.ok(!direct.location?.startsWith(REDIRECT), `authorize issued a code: ${direct.location}`);
  // /oauth2/consent: with a signed request from a consent prompt.
  const prompt = await send(s, jar, 'GET', authorizeUrl(client, 'openid email', { prompt: 'consent' }).url, { navigate: true });
  assert.equal(prompt.status, 302);
  const signed = new URL(prompt.location!, s.base).search.slice(1);
  const consent = await send(s, jar, 'POST', '/api/auth/oauth2/consent', { json: { accept: true, oauth_query: signed } });
  assert.equal(consent.status, 403, consent.body);
  // /oauth2/continue resumes the same shared authorization step: here after the organization page (no consent prompt).
  const orgStep = await send(s, jar, 'GET', authorizeUrl(client, 'openid organization').url, { navigate: true });
  assert.match(orgStep.location ?? '', /^\/select-org\?/);
  const orgQuery = new URL(orgStep.location!, s.base).search.slice(1);
  const resumed = await send(s, jar, 'POST', '/api/auth/oauth2/continue', { json: { postLogin: true, oauth_query: orgQuery } });
  assert.equal(resumed.status, 403, resumed.body);
  assert.equal(codeCount(), codesBefore);
  assert.equal(JSON.stringify(db(s).prepare('SELECT * FROM oauthConsent ORDER BY id').all()), consentsBefore);

  const consentId = db(s).prepare('SELECT id FROM oauthConsent WHERE userId = ?').pluck().get(target.id) as string;
  for (const [method, route, body] of [
    // Consent edits outside the authorization step (they never call consentReferenceId).
    ['POST', '/api/auth/oauth2/update-consent', { id: consentId, update: { scopes: ['openid'] } }],
    ['POST', '/api/auth/oauth2/delete-consent', { id: consentId }],
    // Linked providers' credentials.
    ['POST', '/api/auth/get-access-token', { providerId: 'google' }],
    ['POST', '/api/auth/refresh-token', { providerId: 'google' }],
    ['GET', '/api/auth/account-info', undefined],
    ['POST', '/api/auth/change-password', { currentPassword: 'correct horse', newPassword: 'another horse' }],
    ['POST', '/api/auth/two-factor/enable', { password: 'correct horse' }],
    ['GET', '/api/auth/passkey/generate-register-options', undefined],
    ['POST', '/api/auth/change-email', { newEmail: 'evil@example.com' }],
    ['POST', '/api/auth/unlink-account', { providerId: 'credential' }],
    ['POST', '/api/auth/delete-user', {}],
  ] as const) {
    const r = await send(s, jar, method, route, body ? { json: body } : {});
    assert.equal(r.status, 403, `${route}: ${r.body}`);
  }
  assert.equal((await passwordSignIn(s, new Jar(), target.email)).status, 200); // password unchanged
  await write.close();
});

test('impersonating a 2FA user is not turned into a 2FA challenge, and stopping restores a 2FA admin', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  await enableTotp(s, admin.jar);
  const target = await user('2fa@example.com');
  await enableTotp(s, target.jar);
  const r = await send(s, admin.jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: target.id } });
  assert.equal(r.status, 200, r.body);
  assert.equal((await send(s, admin.jar, 'GET', '/api/auth/get-session')).json().user.email, target.email);
  assert.equal((await send(s, admin.jar, 'POST', '/api/auth/admin/stop-impersonating', { json: {} })).status, 200);
  assert.equal((await send(s, admin.jar, 'GET', '/api/auth/get-session')).json()?.user.email, admin.email);
  await write.close();
});

// ── Org claims ──

/** alice owns Acme and Globex (made with create_org); bob is a member of Acme. */
async function orgs() {
  const { write } = await agents();
  const alice = await user('alice@example.com');
  const bob = await user('bob@example.com');
  const acme = (await ok(call(write, 'create_org', { name: 'Acme', slug: 'acme', ownerUserId: alice.id }))).organization.id as string;
  const globex = (await ok(call(write, 'create_org', { name: 'Globex', slug: 'globex', ownerUserId: alice.id }))).organization.id as string;
  await write.close();
  const d = db(s);
  d.prepare('INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)').run('m-bob', acme, bob.id, 'member', new Date().toISOString());
  d.close();
  return { alice, bob, acme, globex };
}

test('org claims come only with the organization scope, in the access token and userinfo, never the ID token', async () => {
  const { alice, acme } = await orgs();
  const client = await oauthClient(API);
  const scope = 'openid email offline_access organization';

  const withOrg = await tokensFor(alice.jar, client, { scope, resource: API, org: acme });
  assert.match(withOrg.orgPage!, /Acme/);
  assert.match(withOrg.orgPage!, /Globex/);
  assert.match(withOrg.consentPage, /Acme/);
  const access = decodeJwt(withOrg.tokens.access_token);
  assert.equal(access.org_id, acme);
  assert.deepEqual(access.roles, ['owner']);
  const id = decodeJwt(withOrg.tokens.id_token!);
  assert.equal(id.org_id, undefined);
  assert.equal(id.roles, undefined);

  const opaque = await tokensFor(alice.jar, client, { scope, org: acme });
  const info = await userinfo(opaque.tokens.access_token);
  assert.equal(info.org_id, acme);
  assert.deepEqual(info.roles, ['owner']);

  // No organization scope: no organization page, no claims.
  const plain = await tokensFor(alice.jar, client, { resource: API });
  assert.equal(plain.orgPage, undefined);
  assert.equal(decodeJwt(plain.tokens.access_token).org_id, undefined);
  const plainInfo = await userinfo((await tokensFor(alice.jar, client)).tokens.access_token);
  assert.equal(plainInfo.org_id, undefined);

  // Organization scope but no organization picked: no claims.
  const none = await tokensFor(alice.jar, client, { scope, resource: API, org: '' });
  assert.equal(decodeJwt(none.tokens.access_token).org_id, undefined);
});

test('the org is bound to the grant: switching the active organization before consent or before refresh changes nothing', async () => {
  const { alice, acme, globex } = await orgs();
  const client = await oauthClient(API);
  const switchTo = async (organizationId: string) => {
    const r = await send(s, alice.jar, 'POST', '/api/auth/organization/set-active', { json: { organizationId } });
    assert.equal(r.status, 200, r.body);
  };
  const { tokens } = await tokensFor(alice.jar, client, {
    scope: 'openid offline_access organization',
    resource: API,
    org: acme,
    beforeConsent: () => switchTo(globex),
  });
  assert.equal(decodeJwt(tokens.access_token).org_id, acme);
  await switchTo(globex);
  const res = await refresh(client, tokens.refresh_token!, API);
  assert.equal(res.status, 200);
  assert.equal(decodeJwt(((await res.json()) as Tokens).access_token).org_id, acme);
});

test('refresh re-checks membership and role: a role change shows, a removed member gets no org claims', async () => {
  const { bob, acme, globex } = await orgs();
  const client = await oauthClient(API);
  // Bob can't pick an organization he isn't in.
  const { url } = authorizeUrl(client, 'openid offline_access organization', { resource: API });
  const start = await send(s, bob.jar, 'GET', url, { navigate: true });
  const query = new URL(start.location!, s.base).search.slice(1);
  assert.equal((await send(s, bob.jar, 'POST', '/select-org', { form: { oauth_query: query, org_id: globex } })).status, 400);

  const { tokens } = await tokensFor(bob.jar, client, { scope: 'openid offline_access organization', resource: API, org: acme });
  assert.deepEqual(decodeJwt(tokens.access_token).roles, ['member']);
  const d = db(s);
  d.prepare('UPDATE member SET role = ? WHERE id = ?').run('admin', 'm-bob');
  let res = await refresh(client, tokens.refresh_token!, API);
  let next = (await res.json()) as Tokens;
  assert.deepEqual(decodeJwt(next.access_token).roles, ['admin']);
  d.prepare('DELETE FROM member WHERE id = ?').run('m-bob');
  d.close();
  res = await refresh(client, next.refresh_token!, API);
  assert.equal(res.status, 200);
  next = (await res.json()) as Tokens;
  const claims = decodeJwt(next.access_token);
  assert.equal(claims.org_id, undefined);
  assert.equal(claims.roles, undefined);
});

// ── Review round 1 ──

test('consent binds exactly the organization it showed: a pick made in another tab meanwhile re-renders consent', async () => {
  const { alice, acme, globex } = await orgs();
  const client = await oauthClient(API);
  const scope = 'openid offline_access organization';
  const tabA = await toConsent(alice.jar, client, { scope, resource: API, org: acme });
  const tabB = await toConsent(alice.jar, client, { scope, resource: API, org: globex }); // same session, later pick
  const formA = consentForm(tabA.consentPage);
  assert.equal(formA.org_id, acme);
  const allowA = await send(s, alice.jar, 'POST', '/consent', { form: { ...formA, accept: 'yes' } });
  assert.equal(allowA.status, 409, allowA.body); // shown Acme, the session now holds Globex: shown again, not approved
  assert.match(allowA.body, /Globex/);
  assert.equal(allowA.location, undefined);
  const allowB = await send(s, alice.jar, 'POST', '/consent', { form: { ...consentForm(tabB.consentPage), accept: 'yes' } });
  assert.equal(allowB.status, 303, allowB.body);
  const res = await exchange(client, codeFrom(allowB.location), tabB.verifier, API);
  assert.equal(decodeJwt(((await res.json()) as Tokens).access_token).org_id, globex);
});

test('an impersonated session is never refreshed past its own expiry', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const target = await mcpUser(write, 'target@example.com');
  assert.equal((await send(s, admin.jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: target } })).status, 200);
  const expiry = () => db(s).prepare('SELECT expiresAt FROM session WHERE impersonatedBy = ?').pluck().get(admin.id) as string;
  const before = expiry();
  // Without the dont_remember cookie Better Auth would refresh it: 10 minutes left is well past updateAge (1 day).
  admin.jar.add(['better-auth.dont_remember=']);
  assert.equal((await send(s, admin.jar, 'GET', '/api/auth/get-session')).json().user.email, 'target@example.com');
  assert.equal(expiry(), before);
  await write.close();
});

test("an impersonator's sign-out or session revocation doesn't revoke the target's refresh tokens", async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const target = await user('target@example.com');
  const client = await oauthClient();
  let refreshToken = (await tokensFor(target.jar, client)).tokens.refresh_token!;
  for (const route of ['/api/auth/sign-out', '/api/auth/revoke-sessions']) {
    const jar = route === '/api/auth/sign-out' ? admin.jar : new Jar(); // sign-in is limited to 3 per 10 seconds
    if (jar !== admin.jar) assert.equal((await passwordSignIn(s, jar, admin.email)).status, 200);
    assert.equal((await send(s, jar, 'POST', '/api/auth/admin/impersonate-user', { json: { userId: target.id } })).status, 200);
    assert.equal((await send(s, jar, 'POST', route, { json: {} })).status, 200);
    const res = await refresh(client, refreshToken);
    assert.equal(res.status, 200, `${route}: ${await res.clone().text()}`);
    refreshToken = ((await res.json()) as Tokens).refresh_token!;
  }
  await write.close();
});

test('ban_user is indefinite: it re-bans after an expired timed ban and replaces an active one; an HTTP timed ban keeps its expiry', async () => {
  const { write } = await agents();
  const admin = await adminUser(write);
  const u = await mcpUser(write, 'timed@example.com');
  const banExpires = () => db(s).prepare('SELECT banExpires FROM "user" WHERE id = ?').pluck().get(u);
  const r = await send(s, admin.jar, 'POST', '/api/auth/admin/ban-user', { json: { userId: u, banExpiresIn: 3600 } });
  assert.equal(r.status, 200, r.body);
  assert.notEqual(banExpires(), null);
  await ok(call(write, 'ban_user', { userId: u }));
  assert.equal(banExpires(), null);

  const d = db(s);
  d.prepare('UPDATE "user" SET banned = 1, banExpires = ? WHERE id = ?').run(new Date(Date.now() - 60_000).toISOString(), u);
  d.close();
  await ok(call(write, 'ban_user', { userId: u }));
  assert.equal(banExpires(), null);
  assert.equal((await passwordSignIn(s, new Jar(), 'timed@example.com')).status, 403);
  await write.close();
});

test('a revocation that lands (and a ban lifted) while tokens are being issued: issuance revokes what it wrote', async () => {
  const u = await user('lifted@example.com');
  const client = await oauthClient();
  const { tokens } = await tokensFor(u.jar, client);
  // A ban revoked the user's tokens and was lifted between the checks and the write: only tokensRevokedAt moved.
  const d = db(s);
  d.exec(`CREATE TRIGGER revoke_mid_issue BEFORE INSERT ON oauthRefreshToken BEGIN
    UPDATE "user" SET tokensRevokedAt = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.userId; END`);
  d.close();
  const res = await refresh(client, tokens.refresh_token!);
  assert.equal(res.status, 400, await res.clone().text());
  assert.equal(((await res.json()) as { error: string }).error, 'invalid_grant');
  assert.equal(unrevokedRefreshTokens(u.id), 0);
});

test('an authorization request without scope gets the M1 scopes, never the organization step or org claims', async () => {
  const { alice } = await orgs();
  const client = await oauthClient(API);
  const { url, verifier } = authorizeUrl(client, 'unused', { prompt: 'consent', resource: API });
  const noScope = new URL(url, s.base);
  noScope.searchParams.delete('scope');
  const r = await send(s, alice.jar, 'GET', noScope.pathname + noScope.search, { navigate: true });
  assert.equal(r.status, 302, r.body);
  const consent = new URL(r.location!, s.base);
  assert.equal(consent.pathname, '/consent', String(r.location));
  assert.equal(consent.searchParams.get('scope'), 'openid email offline_access');
  const page = (await send(s, alice.jar, 'GET', r.location!, { navigate: true })).body;
  const allow = await send(s, alice.jar, 'POST', '/consent', { form: { ...consentForm(page), accept: 'yes' } });
  const res = await exchange(client, codeFrom(allow.location), verifier, API);
  const t = (await res.json()) as Tokens & { scope: string };
  assert.equal(t.scope, 'openid email offline_access');
  assert.equal(decodeJwt(t.access_token).org_id, undefined);
});

test('signed-in users cannot create organizations over HTTP; create_org (a system action) still can', async () => {
  const { write } = await agents();
  const u = await user('creator@example.com');
  const r = await send(s, u.jar, 'POST', '/api/auth/organization/create', { json: { name: 'Mine', slug: 'mine' } });
  assert.equal(r.status, 403, r.body);
  await ok(call(write, 'create_org', { name: 'Mine', slug: 'mine', ownerUserId: u.id }));
  await write.close();
});

test('invite_member emails only once its audited transaction has committed', async () => {
  const { write } = await agents();
  const alice = await verifiedUser(s, 'alice@example.com');
  const { organization } = await ok(call(write, 'create_org', { name: 'Acme', slug: 'acme', ownerUserId: alice }));
  // A deferred foreign key violated by a trigger on invitation: every statement succeeds, COMMIT fails.
  const d = db(s);
  d.exec(`CREATE TABLE trap_parent (id INTEGER PRIMARY KEY);
    CREATE TABLE trap_child (pid INTEGER REFERENCES trap_parent (id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER trap AFTER INSERT ON invitation BEGIN INSERT INTO trap_child VALUES (1); END;`);
  d.close();
  const r = await call(write, 'invite_member', { organizationId: organization.id, email: 'bob@example.com', role: 'member' });
  assert.equal(r.isError, true, JSON.stringify(r.data));
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(s.outbox().filter((m) => m.to === 'bob@example.com').length, 0, 'an invitation that was rolled back was emailed');
  assert.equal(db(s).prepare('SELECT count(*) FROM invitation').pluck().get(), 0);
  await write.close();
});
