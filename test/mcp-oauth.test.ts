// Users' own MCP servers protected by AuthWAPI (M5). Two MCP resource servers and an MCP client's Client ID Metadata
// Document (CIMD) are small in-process Hono apps on made-up public hostnames: AuthWAPI's metadata fetch is pointed at
// the client's app, and the resource servers are called with app.request. AuthWAPI itself is a real server.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { request } from 'node:http';
import { afterEach, beforeEach, test } from 'node:test';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { Hono } from 'hono';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { fetchClientMetadataResource } from '@better-auth/cimd/node';
import { loadConfig } from '../src/config.ts';
import { oauthPlugins } from '../src/oauth.ts';
import { startTestServer, type TestServer } from './helpers.ts';

const CLIENT = 'https://mcp-client.example/oauth/client.json'; // the MCP client's client_id: its metadata URL
const REDIRECT = 'http://localhost:5999/callback'; // a local MCP client's loopback redirect; never contacted
const A = 'https://mcp-a.example/mcp';
const B = 'https://mcp-b.example/mcp';

const OFF_ORIGIN = 'https://mcp-client.example/oauth/off-origin.json'; // lists a redirect URI on another origin
const NATIVE = 'https://mcp-client.example/oauth/native.json'; // a native app's private-use redirect URI
const NATIVE_REDIRECT = 'example.mcp-client:/callback';

/** The MCP client's website: serves its metadata documents. */
const doc = (clientId: string, redirect: string) => ({ client_id: clientId, client_name: 'Example MCP Client', redirect_uris: [redirect], token_endpoint_auth_method: 'none' });
const clientSite = new Hono()
  .get('/oauth/client.json', (c) => c.json(doc(CLIENT, REDIRECT)))
  .get('/oauth/off-origin.json', (c) => c.json(doc(OFF_ORIGIN, 'https://elsewhere.example/callback')))
  .get('/oauth/native.json', (c) => c.json(doc(NATIVE, NATIVE_REDIRECT)));
let fetched: string[] = [];

let s: TestServer;
beforeEach(async () => {
  fetched = [];
  s = await startTestServer({}, undefined, {
    fetchClientMetadata: async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      fetched.push(url);
      return clientSite.request(url, init);
    },
  });
});
afterEach(() => s.stop());

/** An MCP server (RFC 9728 metadata + a bearer-protected /mcp) that accepts only AuthWAPI JWTs with aud = itself. */
function mcpServer(resource: string) {
  const origin = new URL(resource).origin;
  const metadataUrl = `${origin}/.well-known/oauth-protected-resource`;
  const app = new Hono();
  app.get('/.well-known/oauth-protected-resource', (c) => c.json({ resource, authorization_servers: [s.base], bearer_methods_supported: ['header'] }));
  app.post('/mcp', async (c) => {
    const challenge = { 'www-authenticate': `Bearer resource_metadata="${metadataUrl}"` };
    const bearer = /^Bearer (\S+)$/.exec(c.req.header('authorization') ?? '')?.[1];
    if (!bearer) return c.json({ error: 'unauthorized' }, 401, challenge);
    try {
      // jwtVerify with `audience` also refuses a token with no aud.
      const { payload } = await jwtVerify(bearer, createRemoteJWKSet(new URL(`${s.base}/api/auth/jwks`)), { issuer: s.base, audience: resource, typ: 'at+jwt' });
      if (payload.cnf !== undefined) throw new Error('a sender-constrained (DPoP) token needs a DPoP proof; this server takes bearer tokens only');
      return c.json({ sub: payload.sub });
    } catch {
      return c.json({ error: 'invalid_token' }, 401, challenge);
    }
  });
  return { call: (bearer?: string) => app.request(resource, { method: 'POST', headers: bearer ? { authorization: `Bearer ${bearer}` } : {} }), get: (url: string) => app.request(url) };
}

const cli = async (...args: string[]) => {
  try {
    const { stdout, stderr } = await promisify(execFile)(process.execPath, ['src/cli.ts', ...args], {
      env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code: number; stdout: string; stderr: string };
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
};
const ok = async (...args: string[]) => {
  const r = await cli(...args);
  assert.equal(r.code, 0, r.stderr);
  return r.stdout;
};

const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
const postJson = (p: string, body: unknown, cookie = '') =>
  fetch(s.base + p, { method: 'POST', headers: { 'content-type': 'application/json', origin: s.base, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });

async function signedInUser(email = 'ada@example.com', password = 'correct horse') {
  assert.equal((await postJson('/api/auth/sign-up/email', { email, password, name: 'Ada' })).status, 200);
  const db = new Database(s.paths.db);
  db.prepare('UPDATE "user" SET emailVerified = 1 WHERE email = ?').run(email);
  db.close();
  const res = await postJson('/api/auth/sign-in/email', { email, password });
  assert.equal(res.status, 200);
  return cookieOf(res);
}

/** A browser navigation (node:http: undici's fetch sends sec-fetch-mode: cors and gets JSON instead of redirects). */
const browserGet = (url: string, cookie: string) =>
  new Promise<{ status: number; location: string | undefined; body: string }>((resolve, reject) => {
    const req = request(url, { headers: { accept: 'text/html', 'sec-fetch-mode': 'navigate', cookie } }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode!, location: res.headers.location, body }));
    });
    req.on('error', reject);
    req.end();
  });

/** The authorization request, as the MCP client sends it. Returns AuthWAPI's answer to the browser. */
function startAuthorization(authorizationEndpoint: string, cookie: string, clientId: string, resource: string, redirect = REDIRECT) {
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirect,
    scope: 'offline_access',
    state: 'st',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    resource,
    prompt: 'consent',
  });
  return { verifier, response: browserGet(`${authorizationEndpoint}?${params}`, cookie) };
}

const tokenRequest = (tokenEndpoint: string, body: Record<string, string>) =>
  fetch(tokenEndpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: CLIENT, ...body }) });

type Tokens = { access_token: string; refresh_token?: string };

/** RFC 9728 → RFC 8414 discovery from the MCP server's 401, as an MCP client does it. */
async function discover(server: ReturnType<typeof mcpServer>) {
  const unauthorized = await server.call();
  assert.equal(unauthorized.status, 401);
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(unauthorized.headers.get('www-authenticate') ?? '')?.[1];
  assert.ok(metadataUrl);
  const prm = (await (await server.get(metadataUrl)).json()) as { authorization_servers: string[] };
  const [issuer] = prm.authorization_servers;
  const res = await fetch(`${issuer}/.well-known/oauth-authorization-server`);
  assert.equal(res.status, 200);
  const as = (await res.json()) as Record<string, unknown>;
  assert.equal(as.issuer, issuer);
  assert.equal(as.client_id_metadata_document_supported, true);
  assert.ok((as.code_challenge_methods_supported as string[]).includes('S256'));
  return as as { authorization_endpoint: string; token_endpoint: string };
}

test('a CIMD client linked to MCP server A: discovery, code + PKCE, token, refresh; A accepts its tokens, B refuses them', async () => {
  await ok('resource', 'add', A);
  await ok('resource', 'add', B);
  assert.match(await ok('resource', 'link', CLIENT, A), /Linked/);
  assert.deepEqual(fetched, [], 'linking fetches nothing');
  const a = mcpServer(A);
  const b = mcpServer(B);
  const cookie = await signedInUser();

  const as = await discover(a);
  const { verifier, response } = startAuthorization(as.authorization_endpoint, cookie, CLIENT, A);
  const res = await response;
  assert.equal(res.status, 302, res.body);
  const consent = new URL(res.location!, s.base);
  assert.equal(consent.pathname, '/consent');
  assert.deepEqual(fetched, [CLIENT]);

  // The consent page shows where the client really comes from; its name is whatever its document says.
  const page = await browserGet(consent.href, cookie);
  assert.equal(page.status, 200);
  assert.match(page.body, /Example MCP Client/);
  assert.match(page.body, /<strong>mcp-client\.example<\/strong> \(calls itself "Example MCP Client"\) wants to/);

  const accept = await postJson('/api/auth/oauth2/consent', { accept: true, oauth_query: consent.search.slice(1) }, cookie);
  assert.equal(accept.status, 200, await accept.clone().text());
  const code = new URL(((await accept.json()) as { url: string }).url).searchParams.get('code')!;

  const exchanged = await tokenRequest(as.token_endpoint, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, resource: A });
  assert.equal(exchanged.status, 200, await exchanged.clone().text());
  const first = (await exchanged.json()) as Tokens;
  assert.ok(first.refresh_token);
  assert.equal((await a.call(first.access_token)).status, 200);
  assert.equal((await b.call(first.access_token)).status, 401);
  // Never accepted by AuthWAPI's own admin MCP either.
  const admin = await fetch(`${s.base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${first.access_token}`, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(admin.status, 401);

  const refreshed = await tokenRequest(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: first.refresh_token, resource: A });
  assert.equal(refreshed.status, 200, await refreshed.clone().text());
  const second = (await refreshed.json()) as Tokens;
  assert.ok(second.refresh_token && second.refresh_token !== first.refresh_token);
  assert.equal((await a.call(second.access_token)).status, 200);
  assert.equal((await b.call(second.access_token)).status, 401);

  // Rotation is strict: the used refresh token fails at once, with no grace window.
  const reuse = await tokenRequest(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: first.refresh_token });
  assert.equal(reuse.status, 400);
  assert.equal(((await reuse.json()) as { error: string }).error, 'invalid_grant');
  // ...and the reuse revokes the rotated one too.
  const afterReuse = await tokenRequest(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: second.refresh_token });
  assert.equal(afterReuse.status, 400);
});

test('a CIMD client gets no token for an MCP server it is not linked to, even one that exists', async () => {
  await ok('resource', 'add', A);
  await ok('resource', 'add', B);
  await ok('resource', 'link', CLIENT, A);
  const cookie = await signedInUser();
  const as = await discover(mcpServer(B));
  const res = await startAuthorization(as.authorization_endpoint, cookie, CLIENT, B).response;
  assert.notEqual(new URL(res.location ?? '/', s.base).pathname, '/consent');
  assert.match(decodeURIComponent(res.location ?? '') + res.body, /invalid_target/);
});

test('a metadata URL the operator has not linked, or that is not public https, is refused without being fetched', async () => {
  await ok('resource', 'add', A);
  const cookie = await signedInUser();
  const as = await discover(mcpServer(A));
  for (const clientId of [CLIENT, 'http://mcp-client.example/oauth/client.json', 'https://localhost/oauth/client.json', 'https://10.0.0.1/client.json']) {
    const res = await startAuthorization(as.authorization_endpoint, cookie, clientId, A).response;
    assert.notEqual(new URL(res.location ?? '/', s.base).pathname, '/consent', clientId);
    assert.match(decodeURIComponent(res.location ?? '') + res.body, /invalid_client/, clientId);
  }
  assert.deepEqual(fetched, []);
});

test('CLI: resource add and link check their input; clients list shows a CIMD client and its resources', async () => {
  const addA = await cli('resource', 'add', A);
  assert.equal(addA.code, 0, addA.stderr);
  assert.match(addA.stdout, /mcp-a\.example/);
  assert.notEqual((await cli('resource', 'add', A)).code, 0); // already exists
  assert.notEqual((await cli('resource', 'add')).code, 0);
  assert.notEqual((await cli('resource', 'add', 'not a url')).code, 0);
  assert.notEqual((await cli('resource', 'link', CLIENT, B)).code, 0); // no such resource
  for (const bad of ['http://mcp-client.example/client.json', 'https://localhost/client.json', 'not-a-client']) {
    const r = await cli('resource', 'link', bad, A);
    assert.notEqual(r.code, 0, bad);
  }
  await ok('resource', 'link', CLIENT, A);
  await ok('resource', 'link', CLIENT, A); // twice is fine
  const list = await ok('clients', 'list');
  assert.match(list, new RegExp(`${CLIENT.replaceAll('.', '\\.')}[\\s\\S]*resources: ${A.replaceAll('.', '\\.')}`));
  assert.deepEqual(fetched, []);
});

/** Signs the user in through `clientId` for `resource` and exchanges the code. */
async function tokensFor(as: { authorization_endpoint: string; token_endpoint: string }, cookie: string, clientId: string, resource: string) {
  const { verifier, response } = startAuthorization(as.authorization_endpoint, cookie, clientId, resource);
  const res = await response;
  assert.equal(res.status, 302, res.body);
  const consent = new URL(res.location!, s.base);
  assert.equal(consent.pathname, '/consent', res.body);
  const accept = await postJson('/api/auth/oauth2/consent', { accept: true, oauth_query: consent.search.slice(1) }, cookie);
  const code = new URL(((await accept.json()) as { url: string }).url).searchParams.get('code')!;
  const res2 = await tokenRequest(as.token_endpoint, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, resource });
  assert.equal(res2.status, 200, await res2.clone().text());
  return (await res2.json()) as Tokens;
}

/** The answer to an authorization request AuthWAPI refused before consent, as text to match an error code in. */
async function refusal(as: { authorization_endpoint: string }, cookie: string, clientId: string, resource: string, redirect = REDIRECT) {
  const res = await startAuthorization(as.authorization_endpoint, cookie, clientId, resource, redirect).response;
  assert.notEqual(new URL(res.location ?? '/', s.base).pathname, '/consent', clientId);
  return decodeURIComponent(res.location ?? '') + res.body;
}

test('a client row with no resource link is refused without its document being fetched', async () => {
  await ok('resource', 'add', A);
  // What an interrupted link could have left behind (the CLI now writes the row and the link together).
  const db = new Database(s.paths.db);
  db.prepare("INSERT INTO oauthClient (id, clientId, clientDiscoveryId, redirectUris, createdAt, updatedAt) VALUES ('stub', ?, 'cimd', '[]', ?, ?)").run(CLIENT, new Date().toISOString(), new Date().toISOString());
  db.close();
  const cookie = await signedInUser();
  assert.match(await refusal(await discover(mcpServer(A)), cookie, CLIENT, A), /invalid_client/);
  assert.deepEqual(fetched, []);
});

test('unlinking a client stops its new sign-ins and refreshes at once, even while its document is cached', async () => {
  await ok('resource', 'add', A);
  await ok('resource', 'link', CLIENT, A);
  const cookie = await signedInUser();
  const as = await discover(mcpServer(A));
  const tokens = await tokensFor(as, cookie, CLIENT, A);
  assert.deepEqual(fetched, [CLIENT]);

  assert.match(await ok('resource', 'unlink', CLIENT, A), /Unlinked/);
  assert.match(await refusal(as, cookie, CLIENT, A), /invalid_client/);
  const refreshed = await tokenRequest(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, resource: A });
  assert.equal(refreshed.status, 400);
  assert.equal(((await refreshed.json()) as { error: string }).error, 'invalid_client');
  assert.deepEqual(fetched, [CLIENT], 'the cached document was used, and still refused');
});

test('a linked document cannot move its redirect URIs to another origin; loopback and private-use ones are fine', async () => {
  await ok('resource', 'add', A);
  await ok('resource', 'link', OFF_ORIGIN, A);
  await ok('resource', 'link', NATIVE, A);
  const cookie = await signedInUser();
  const as = await discover(mcpServer(A));
  assert.match(await refusal(as, cookie, OFF_ORIGIN, A, 'https://elsewhere.example/callback'), /invalid_client/);
  const native = await startAuthorization(as.authorization_endpoint, cookie, NATIVE, A, NATIVE_REDIRECT).response;
  assert.equal(new URL(native.location ?? '/', s.base).pathname, '/consent', native.body);
});

test("AuthWAPI's own userinfo URL can't be registered or linked as a resource", async () => {
  const userinfo = `${s.base}/api/auth/oauth2/userinfo`;
  for (const args of [['resource', 'add', userinfo], ['resource', 'link', CLIENT, userinfo], ['clients', 'create', '--name', 'X', '--redirect-uri', REDIRECT, '--resource', userinfo]]) {
    const r = await cli(...args);
    assert.notEqual(r.code, 0, args.join(' '));
    assert.match(r.stderr, /reserved/, args.join(' '));
  }
  // An older release could have stored one (clients create --resource): unlink still removes it.
  const db = new Database(s.paths.db);
  const now = new Date().toISOString();
  db.prepare("INSERT INTO oauthClient (id, clientId, clientDiscoveryId, redirectUris, createdAt, updatedAt) VALUES ('old', ?, 'cimd', '[]', ?, ?)").run(CLIENT, now, now);
  db.prepare("INSERT INTO oauthResource (id, identifier, name, createdAt) VALUES ('old', ?, 'userinfo', ?)").run(userinfo, now);
  db.prepare("INSERT INTO oauthClientResource (id, clientId, resourceId, createdAt) VALUES ('old', ?, ?, ?)").run(CLIENT, userinfo, now);
  assert.match(await ok('resource', 'unlink', CLIENT, userinfo), /Unlinked/);
  assert.equal(db.prepare('SELECT count(*) FROM oauthClientResource').pluck().get(), 0);
  db.close();
});

test('without a test override, client metadata is fetched with the SSRF-safe Node transport from @better-auth/cimd', () => {
  const deps = { config: loadConfig({ DATA_DIR: '/nonexistent' }), db: new Database(':memory:'), secret: 'x'.repeat(32), sendMail: async () => {}, log: () => {} };
  const provider = oauthPlugins(deps).find((p) => p.id === 'oauth-provider') as unknown as { options: { extensions?: { clientDiscovery?: { fetchClientMetadataResource?: unknown } }[] } };
  const transports = (provider.options.extensions ?? []).map((e) => e.clientDiscovery?.fetchClientMetadataResource);
  assert.deepEqual(transports, [fetchClientMetadataResource]);
  deps.db.close();
});
