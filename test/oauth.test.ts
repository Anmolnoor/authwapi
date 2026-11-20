// OAuth 2.1 / OIDC provider (plan D9), driven over HTTP against a real server. The relying party's redirect URI is
// on `localhost` while the server is on 127.0.0.1, so nothing here depends on sharing a hostname or cookies.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import { startTestServer, type TestServer } from './helpers.ts';

let s: TestServer;
beforeEach(async () => (s = await startTestServer()));
afterEach(() => s.stop());

const RP = 'http://localhost:5999'; // the app; never contacted, we only read redirects to it
const REDIRECT = `${RP}/callback`;
const API = `${RP}/api`;
const OTHER_API = 'http://localhost:6001/api';

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

async function createClient(...extra: string[]) {
  const r = await cli('clients', 'create', '--name', 'Test App', '--redirect-uri', REDIRECT, ...extra);
  assert.equal(r.code, 0, r.stderr);
  const id = /client_id:\s+(\S+)/.exec(r.stdout)?.[1];
  const secret = /client_secret:\s+(\S+)/.exec(r.stdout)?.[1];
  assert.ok(id && secret, r.stdout);
  return { id, secret, stdout: r.stdout };
}

const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
const postJson = (p: string, body: unknown, cookie = '') =>
  fetch(s.base + p, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: s.base, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  });

/**
 * A signed-in user. Email verification is set in the database directly: verification has its own tests and its
 * own hosted pages; here it is only setup.
 */
async function signedInUser(email = 'ada@example.com', password = 'correct horse') {
  assert.equal((await postJson('/api/auth/sign-up/email', { email, password, name: 'Ada' })).status, 200);
  const db = new Database(s.paths.db);
  db.prepare('UPDATE "user" SET emailVerified = 1 WHERE email = ?').run(email);
  const userId = db.prepare('SELECT id FROM "user" WHERE email = ?').pluck().get(email) as string;
  db.close();
  const res = await postJson('/api/auth/sign-in/email', { email, password });
  assert.equal(res.status, 200);
  return { cookie: cookieOf(res), userId, email };
}

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

/**
 * A browser navigation (GET). node:http, not fetch: undici always sends sec-fetch-mode: cors, which Better Auth
 * answers with JSON instead of the redirect or page a browser gets.
 */
const browserGet = (url: string, cookie: string) =>
  new Promise<{ status: number; location: string | undefined; body: string; cookies: string }>((resolve, reject) => {
    const headers = { accept: 'text/html', 'sec-fetch-mode': 'navigate', ...(cookie ? { cookie } : {}) };
    const req = request(url, { headers }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () =>
        resolve({
          status: res.statusCode!,
          location: res.headers.location,
          body,
          cookies: (res.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).join('; '),
        })
      );
    });
    req.on('error', reject);
    req.end();
  });
const navigate = (params: Record<string, string>, cookie: string) =>
  browserGet(`${s.base}/api/auth/oauth2/authorize?${new URLSearchParams(params)}`, cookie);

/** Authorize → consent page → accept. Returns the code from the redirect to the app. */
async function authorize(client: { id: string }, cookie: string, opts: { scope?: string; resource?: string; claims?: object } = {}) {
  const { verifier, challenge } = pkce();
  const state = randomBytes(8).toString('hex');
  const params: Record<string, string> = {
    response_type: 'code',
    client_id: client.id,
    redirect_uri: REDIRECT,
    scope: opts.scope ?? 'openid email offline_access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'consent',
  };
  if (opts.resource) params.resource = opts.resource;
  if (opts.claims) params.claims = JSON.stringify(opts.claims);
  const res = await navigate(params, cookie);
  assert.equal(res.status, 302, res.body);
  const consent = new URL(res.location!, s.base);
  assert.equal(`${consent.origin}${consent.pathname}`, `${s.base}/consent`);

  const accept = await postJson('/api/auth/oauth2/consent', { accept: true, oauth_query: consent.search.slice(1) }, cookie);
  assert.equal(accept.status, 200, await accept.clone().text());
  const back = new URL(((await accept.json()) as { url: string }).url);
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT);
  assert.equal(back.searchParams.get('state'), state);
  assert.equal(back.searchParams.get('iss'), s.base);
  return { code: back.searchParams.get('code')!, verifier };
}

const token = (client: { id: string; secret: string }, body: Record<string, string>) =>
  fetch(`${s.base}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
    },
    body: new URLSearchParams(body),
  });

type Tokens = { access_token: string; id_token?: string; refresh_token?: string; expires_in: number; scope: string };

async function codeForTokens(client: { id: string; secret: string }, cookie: string, opts: { scope?: string; resource?: string; claims?: object } = {}) {
  const { code, verifier } = await authorize(client, cookie, opts);
  const body: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier };
  if (opts.resource) body.resource = opts.resource;
  const res = await token(client, body);
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()) as Tokens;
}

const refresh = (client: { id: string; secret: string }, refreshToken: string) =>
  token(client, { grant_type: 'refresh_token', refresh_token: refreshToken });

const introspect = async (client: { id: string; secret: string }, t: string) => {
  const res = await fetch(`${s.base}/api/auth/oauth2/introspect`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
    },
    body: new URLSearchParams({ token: t }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()) as { active: boolean };
};

const discovery = async () => {
  const res = await fetch(`${s.base}/.well-known/openid-configuration`);
  assert.equal(res.status, 200);
  return (await res.json()) as Record<string, string>;
};

test('authorization code + PKCE for a CLI-registered client on another hostname; ID token verifies via discovery JWKS', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie, { resource: API });

  const meta = await discovery();
  assert.equal(meta.issuer, s.base);
  const asMeta = (await (await fetch(`${s.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  assert.equal(asMeta.issuer, s.base);
  assert.equal(asMeta.jwks_uri, meta.jwks_uri);
  const jwks = createRemoteJWKSet(new URL(meta.jwks_uri));
  const { payload: id } = await jwtVerify(tokens.id_token!, jwks, { issuer: s.base, audience: client.id });
  assert.equal(id.sub, user.userId);
  assert.equal(id.email, user.email);
  assert.equal(id.email_verified, true);
  assert.equal(id.name, undefined); // M1 claims only: no profile scope

  // The access token is a JWT for the API, valid 15 minutes, verifiable through the same JWKS.
  const { payload: at } = await jwtVerify(tokens.access_token, jwks, { issuer: s.base, audience: API });
  assert.equal(at.sub, user.userId);
  assert.equal(at.exp! - at.iat!, 15 * 60);
  assert.equal(tokens.expires_in, 15 * 60);
});

test('signed out: authorize sends the browser to /sign-in, and signing in with oauth_query continues to consent', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const { challenge } = pkce();
  const params = { response_type: 'code', client_id: client.id, redirect_uri: REDIRECT, scope: 'openid email', state: 'st', code_challenge: challenge, code_challenge_method: 'S256' };
  const res = await navigate(params, '');
  assert.equal(res.status, 302, res.body);
  const login = new URL(res.location!, s.base);
  assert.equal(`${login.origin}${login.pathname}`, `${s.base}/sign-in`);
  assert.equal(login.searchParams.get('client_id'), client.id);
  assert.ok(login.searchParams.get('sig'), 'the OAuth query is signed');

  // What /sign-in does with it (lane B): pass the query back as oauth_query on sign-in.
  const signIn = await postJson('/api/auth/sign-in/email', { email: user.email, password: 'correct horse', oauth_query: login.search.slice(1) });
  assert.equal(signIn.status, 200);
  const next = new URL(((await signIn.json()) as { url: string }).url, s.base);
  assert.equal(`${next.origin}${next.pathname}`, `${s.base}/consent`);
  assert.equal(next.searchParams.get('client_id'), client.id);

  const tampered = login.search.slice(1).replace('scope=openid+email', 'scope=openid+email+offline_access');
  const bad = await postJson('/api/auth/sign-in/email', { email: user.email, password: 'correct horse', oauth_query: tampered });
  assert.equal(bad.status, 400);
});

test('a verifier checking aud rejects a validly signed token minted for another audience', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie, { resource: API });
  const jwks = createRemoteJWKSet(new URL((await discovery()).jwks_uri));

  // Another API (its own resource) must not accept a token minted for API, nor the app's ID token.
  await assert.rejects(jwtVerify(tokens.access_token, jwks, { issuer: s.base, audience: OTHER_API }), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
  await assert.rejects(jwtVerify(tokens.id_token!, jwks, { issuer: s.base, audience: API }), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
  // Both are validly signed: without the aud check they would pass.
  await jwtVerify(tokens.access_token, jwks, { issuer: s.base });
  await jwtVerify(tokens.id_token!, jwks, { issuer: s.base });
});

test('a client can only get tokens for resources it was registered with', async () => {
  const client = await createClient('--resource', API);
  await cli('clients', 'create', '--name', 'Other', '--redirect-uri', 'http://localhost:6001/cb', '--resource', OTHER_API);
  const user = await signedInUser();
  const { challenge } = pkce();
  const res = await navigate(
    { response_type: 'code', client_id: client.id, redirect_uri: REDIRECT, scope: 'openid', state: 'x', code_challenge: challenge, code_challenge_method: 'S256', resource: OTHER_API },
    user.cookie
  );
  const location = new URL(res.location ?? 'http://none/', s.base);
  assert.equal(location.searchParams.get('error'), 'invalid_target', `${res.status} ${res.location} ${res.body}`);
});

test('userinfo accepts a bearer access token and refuses a browser session cookie', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);

  const withCookie = await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { cookie: user.cookie } });
  assert.equal(withCookie.status, 401, await withCookie.text());

  const withToken = await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(withToken.status, 200);
  const info = (await withToken.json()) as Record<string, unknown>;
  assert.equal(info.sub, user.userId);
  assert.equal(info.email, user.email);
  assert.equal(info.email_verified, true);
});

test('sign-out ends the session and revokes every token the user holds: JWT and opaque access, refresh, offline_access', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  const jwtTokens = await codeForTokens(client, user.cookie, { resource: API });
  const opaqueTokens = await codeForTokens(client, user.cookie); // no resource → opaque access token
  assert.ok(jwtTokens.refresh_token && opaqueTokens.refresh_token);
  assert.match(jwtTokens.scope, /offline_access/);
  assert.equal(decodeJwt(jwtTokens.access_token).aud?.includes(API), true);

  assert.equal((await introspect(client, jwtTokens.access_token)).active, true);
  assert.equal((await introspect(client, opaqueTokens.access_token)).active, true);

  assert.equal((await postJson('/api/auth/sign-out', {}, user.cookie)).status, 200);

  assert.equal((await introspect(client, jwtTokens.access_token)).active, false);
  assert.equal((await introspect(client, opaqueTokens.access_token)).active, false);
  for (const rt of [jwtTokens.refresh_token, opaqueTokens.refresh_token]) {
    const res = await refresh(client, rt);
    assert.equal(res.status, 400, await res.clone().text());
    assert.equal(((await res.json()) as { error: string }).error, 'invalid_grant');
  }
});

test("sign-out leaves other users' tokens alone", async () => {
  const client = await createClient();
  const ada = await signedInUser('ada@example.com');
  const bob = await signedInUser('bob@example.com');
  const adaTokens = await codeForTokens(client, ada.cookie);
  const bobTokens = await codeForTokens(client, bob.cookie);
  assert.equal((await postJson('/api/auth/sign-out', {}, ada.cookie)).status, 200);
  assert.equal((await refresh(client, adaTokens.refresh_token!)).status, 400);
  assert.equal((await refresh(client, bobTokens.refresh_token!)).status, 200);
});

/** Ways a user ends sessions other than /sign-out. Each must revoke the user's tokens like sign-out does. */
const otherSignOuts: Record<string, (user: { cookie: string; email: string }) => Promise<void>> = {
  async 'revoke-session'(user) {
    const { session } = (await (await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } })).json()) as { session: { token: string } };
    assert.equal((await postJson('/api/auth/revoke-session', { token: session.token }, user.cookie)).status, 200);
  },
  async 'revoke-sessions'(user) {
    assert.equal((await postJson('/api/auth/revoke-sessions', {}, user.cookie)).status, 200);
  },
  async 'revoke-other-sessions (from a second device)'(user) {
    const other = await postJson('/api/auth/sign-in/email', { email: user.email, password: 'correct horse' });
    assert.equal((await postJson('/api/auth/revoke-other-sessions', {}, cookieOf(other))).status, 200);
  },
  async 'password reset'(user) {
    assert.equal((await postJson('/api/auth/request-password-reset', { email: user.email, redirectTo: '/' })).status, 200);
    const link = /(https?:\/\/\S+)/.exec((await s.mail(user.email, 'Reset your password')).text)![1];
    const resetToken = new URL(link).pathname.split('/').pop();
    assert.equal((await postJson('/api/auth/reset-password', { token: resetToken, newPassword: 'a new password' })).status, 200);
  },
  async 'OIDC end-session, confirmed'(user) {
    const page = await browserGet(`${s.base}/api/auth/oauth2/end-session`, user.cookie);
    assert.equal(page.status, 200, page.body);
    const confirm = await fetch(`${s.base}/api/auth/oauth2/end-session/confirm`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.base, cookie: `${user.cookie}; ${page.cookies}` },
      body: new URLSearchParams({ action: 'confirm' }),
    });
    assert.ok(confirm.status < 300, `${confirm.status} ${await confirm.text()}`);
  },
};

for (const [name, signOut] of Object.entries(otherSignOuts)) {
  test(`${name} also revokes the user's refresh and access tokens`, async () => {
    const client = await createClient();
    const user = await signedInUser();
    const tokens = await codeForTokens(client, user.cookie);
    await signOut(user);
    assert.equal((await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } }).then((r) => r.json())), null);
    assert.equal((await introspect(client, tokens.access_token)).active, false);
    assert.equal((await refresh(client, tokens.refresh_token!)).status, 400);
  });
}

/** Expires the user's sessions in the database and lets a request with the old cookie clear them. */
async function expireAndClearSessions(user: { cookie: string; userId: string }) {
  const db = new Database(s.paths.db);
  db.prepare('UPDATE session SET expiresAt = ? WHERE userId = ?').run(Date.now() - 1000, user.userId);
  db.close();
  assert.equal(await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } }).then((r) => r.json()), null);
  const db2 = new Database(s.paths.db, { readonly: true });
  assert.equal(db2.prepare('SELECT count(*) FROM session WHERE userId = ?').pluck().get(user.userId), 0, 'the expired session was not cleared');
  db2.close();
}

test('a password reset revokes tokens even when the user has no session rows left', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  await expireAndClearSessions(user);
  await otherSignOuts['password reset'](user);
  assert.equal((await introspect(client, tokens.access_token)).active, false);
  const res = await refresh(client, tokens.refresh_token!);
  assert.equal(res.status, 400, await res.clone().text());
});

test('revoke-other-sessions revokes tokens even when there is no other session to delete', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  assert.equal((await postJson('/api/auth/revoke-other-sessions', {}, user.cookie)).status, 200);
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 400);
});

test('change-password revokes tokens only when it signs out other sessions', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const kept = await codeForTokens(client, user.cookie);
  const change = (from: string, to: string, revokeOtherSessions: boolean) =>
    postJson('/api/auth/change-password', { currentPassword: from, newPassword: to, revokeOtherSessions }, user.cookie);
  assert.equal((await change('correct horse', 'second password', false)).status, 200);
  const keptRes = await refresh(client, kept.refresh_token!);
  assert.equal(keptRes.status, 200, await keptRes.clone().text());

  const tokens = await codeForTokens(client, user.cookie);
  const res = await change('second password', 'third password', true);
  assert.equal(res.status, 200, await res.clone().text());
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 400);
});

test('if revoking fails, sign-out fails and the session stays', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  const db = new Database(s.paths.db);
  db.exec("CREATE TRIGGER fail_revoke BEFORE UPDATE ON oauthRefreshToken BEGIN SELECT RAISE(ABORT, 'injected failure'); END");
  try {
    const res = await postJson('/api/auth/sign-out', {}, user.cookie);
    assert.ok(res.status >= 500, `${res.status} ${await res.text()}`);
  } finally {
    db.exec('DROP TRIGGER fail_revoke');
    db.close();
  }
  const session = (await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } }).then((r) => r.json())) as { user?: { id: string } } | null;
  assert.equal(session?.user?.id, user.userId, 'the session was deleted although its tokens were not revoked');
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 200);
});

test('a resource that was not in the authorization request is refused at the token endpoint', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  // Code exchange: authorized without resource, exchanged with one.
  const { code, verifier } = await authorize(client, user.cookie);
  const exchange = await token(client, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, resource: API });
  assert.equal(exchange.status, 400, await exchange.clone().text());
  assert.equal(((await exchange.json()) as { error: string }).error, 'invalid_target');
  // Refresh: granted without resource, refreshed with one.
  const tokens = await codeForTokens(client, user.cookie);
  const res = await token(client, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, resource: API });
  assert.equal(res.status, 400, await res.clone().text());
  assert.equal(((await res.json()) as { error: string }).error, 'invalid_target');
  // A resource that was authorized still works on refresh.
  const withApi = await codeForTokens(client, user.cookie, { resource: API });
  const ok = await token(client, { grant_type: 'refresh_token', refresh_token: withApi.refresh_token!, resource: API });
  assert.equal(ok.status, 200, await ok.clone().text());
});

test('introspection and userinfo refuse a refresh-minted JWT (no sid) once the user signs out', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  const first = await codeForTokens(client, user.cookie, { resource: API });
  // Once the browser session is gone, the offline refresh token outlives it and mints JWTs with no sid, which
  // Better Auth's session-liveness check can't cut off.
  await expireAndClearSessions(user);
  const res = await token(client, { grant_type: 'refresh_token', refresh_token: first.refresh_token!, resource: API });
  assert.equal(res.status, 200, await res.clone().text());
  const jwt = ((await res.json()) as Tokens).access_token;
  assert.equal(decodeJwt(jwt).sid, undefined, 'the refresh-minted JWT is bound to a session');
  assert.equal((await introspect(client, jwt)).active, true);
  assert.equal((await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${jwt}` } })).status, 200);

  const again = await postJson('/api/auth/sign-in/email', { email: user.email, password: 'correct horse' });
  assert.equal((await postJson('/api/auth/sign-out', {}, cookieOf(again))).status, 200);
  assert.equal((await introspect(client, jwt)).active, false);
  const info = await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${jwt}` } });
  assert.equal(info.status, 401, await info.text());
});

test('a claims request for email needs the email scope', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const { challenge } = pkce();
  const base = { response_type: 'code', client_id: client.id, redirect_uri: REDIRECT, state: 's', code_challenge: challenge, code_challenge_method: 'S256', prompt: 'consent' };
  for (const claims of [{ userinfo: { email: null } }, { id_token: { email_verified: { essential: true } } }]) {
    const res = await navigate({ ...base, scope: 'openid', claims: JSON.stringify(claims) }, user.cookie);
    const at = new URL(res.location ?? 'http://none/', s.base);
    assert.equal(at.searchParams.get('error'), 'invalid_request', `${res.status} ${res.location} ${res.body}`);
    assert.match(at.searchParams.get('error_description') ?? '', /email/);
  }
  // With the email scope the same request goes to consent.
  const ok = await navigate({ ...base, scope: 'openid email', claims: JSON.stringify({ userinfo: { email: null } }) }, user.cookie);
  assert.equal(new URL(ok.location!, s.base).pathname, '/consent', `${ok.status} ${ok.location}`);
  // Accepting only openid at consent while the claims ask for email is refused too.
  const consent = new URL(ok.location!, s.base);
  const narrowed = await postJson('/api/auth/oauth2/consent', { accept: true, scope: 'openid', oauth_query: consent.search.slice(1) }, user.cookie);
  assert.equal(narrowed.status, 400, await narrowed.clone().text());
  assert.equal(((await narrowed.json()) as { error: string }).error, 'invalid_request');
});

/** Requests a password reset email and returns the token from its link. */
async function resetTokenFor(email: string) {
  assert.equal((await postJson('/api/auth/request-password-reset', { email, redirectTo: '/' })).status, 200);
  const link = /(https?:\/\/\S+)/.exec((await s.mail(email, 'Reset your password')).text)![1];
  return new URL(link).pathname.split('/').pop()!;
}

const signInStatus = async (email: string, password: string) => (await postJson('/api/auth/sign-in/email', { email, password })).status;

test('a password reset with an empty token in the body and the real one in the query revokes tokens', async () => {
  // Better Auth takes `body.token || query.token`, so an empty body token falls through to the query.
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  const resetToken = await resetTokenFor(user.email);
  const res = await postJson(`/api/auth/reset-password?token=${resetToken}`, { token: '', newPassword: 'a new password' });
  assert.equal(res.status, 200, await res.clone().text());
  assert.equal((await introspect(client, tokens.access_token)).active, false);
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 400);
});

test('if revoking fails, a password reset fails before the password changes (token in the query, empty in the body)', async () => {
  const client = await createClient();
  const user = await signedInUser();
  await codeForTokens(client, user.cookie);
  const resetToken = await resetTokenFor(user.email);
  const db = new Database(s.paths.db);
  // Only revocation fails: deleting the sessions also updates these rows (sessionId is set to null).
  db.exec("CREATE TRIGGER fail_revoke BEFORE UPDATE OF revoked ON oauthRefreshToken BEGIN SELECT RAISE(ABORT, 'injected failure'); END");
  try {
    const res = await postJson(`/api/auth/reset-password?token=${resetToken}`, { token: '', newPassword: 'a new password' });
    assert.ok(res.status >= 500, `${res.status} ${await res.text()}`);
  } finally {
    db.exec('DROP TRIGGER fail_revoke');
    db.close();
  }
  assert.equal(await signInStatus(user.email, 'correct horse'), 200, 'the password changed although the tokens were not revoked');
});

test('a refresh token minted while a password reset is running (after the first revocation) is revoked once it is saved', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const bob = await signedInUser('bob@example.com');
  const early = await codeForTokens(client, user.cookie);
  const late = await codeForTokens(client, user.cookie);
  // Simulate `late` being minted after the reset's first revocation: park its row under another user, and move it
  // back to this user the moment the first revocation records itself (tokensRevokedAt).
  const db = new Database(s.paths.db);
  const lateId = db.prepare('SELECT id FROM oauthRefreshToken WHERE userId = ? ORDER BY rowid DESC LIMIT 1').pluck().get(user.userId) as string;
  db.prepare('UPDATE oauthRefreshToken SET userId = ? WHERE id = ?').run(bob.userId, lateId);
  db.exec(`CREATE TRIGGER mint_during_reset AFTER UPDATE OF tokensRevokedAt ON "user" WHEN NEW.id = '${user.userId}'
           BEGIN UPDATE oauthRefreshToken SET userId = NEW.id WHERE id = '${lateId}'; END`);
  try {
    await otherSignOuts['password reset'](user);
  } finally {
    db.exec('DROP TRIGGER mint_during_reset');
    db.close();
  }
  // `late` first: presenting a revoked refresh token (early) makes Better Auth delete the user's whole token family.
  const res = await refresh(client, late.refresh_token!);
  assert.equal(res.status, 400, `the token minted during the reset still works: ${await res.text()}`);
  assert.equal((await refresh(client, early.refresh_token!)).status, 400);
});

test('userinfo refuses a revoked JWT however the token is sent: POST body, extra whitespace, no scheme', async () => {
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  const first = await codeForTokens(client, user.cookie, { resource: API });
  await expireAndClearSessions(user); // a refresh now mints a JWT with no sid, which only our revocation check cuts off
  const res = await token(client, { grant_type: 'refresh_token', refresh_token: first.refresh_token!, resource: API });
  assert.equal(res.status, 200, await res.clone().text());
  const jwt = ((await res.json()) as Tokens).access_token;
  const userinfo = {
    'POST body': () =>
      fetch(`${s.base}/api/auth/oauth2/userinfo`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ access_token: jwt }),
      }),
    'two spaces': () => fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer  ${jwt}` } }),
    'no scheme': () => fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: jwt } }),
  };
  for (const [how, send] of Object.entries(userinfo)) {
    const ok = await send();
    assert.equal(ok.status, 200, `${how}, before sign-out: ${await ok.text()}`);
  }
  const again = await postJson('/api/auth/sign-in/email', { email: user.email, password: 'correct horse' });
  assert.equal((await postJson('/api/auth/sign-out', {}, cookieOf(again))).status, 200);
  for (const [how, send] of Object.entries(userinfo)) {
    const info = await send();
    assert.equal(info.status, 401, `${how}: ${info.status} ${await info.text()}`);
  }
});

test('a padded grant_type does not skip the resource check at the token endpoint', async () => {
  // Better Auth trims grant_type before dispatching it.
  const client = await createClient('--resource', API);
  const user = await signedInUser();
  for (const grantType of [' refresh_token', 'refresh_token\t', '\nrefresh_token']) {
    const tokens = await codeForTokens(client, user.cookie);
    const res = await token(client, { grant_type: grantType, refresh_token: tokens.refresh_token!, resource: API });
    assert.equal(res.status, 400, `${JSON.stringify(grantType)}: ${await res.clone().text()}`);
    assert.equal(((await res.json()) as { error: string }).error, 'invalid_target');
  }
  const { code, verifier } = await authorize(client, user.cookie);
  const exchange = await token(client, { grant_type: ' authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, resource: API });
  assert.equal(exchange.status, 400, await exchange.clone().text());
  assert.equal(((await exchange.json()) as { error: string }).error, 'invalid_target');
});

test('a refresh that drops the email scope drops email from userinfo and the ID token, even if claims asked for it', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const first = await codeForTokens(client, user.cookie, { claims: { userinfo: { email: null, email_verified: null } } });
  const userinfo = async (t: string) => {
    const res = await fetch(`${s.base}/api/auth/oauth2/userinfo`, { headers: { authorization: `Bearer ${t}` } });
    assert.equal(res.status, 200, await res.clone().text());
    return (await res.json()) as Record<string, unknown>;
  };
  assert.equal((await userinfo(first.access_token)).email, user.email);

  const res = await token(client, { grant_type: 'refresh_token', refresh_token: first.refresh_token!, scope: 'openid offline_access' });
  assert.equal(res.status, 200, await res.clone().text());
  const narrowed = (await res.json()) as Tokens;
  assert.equal(narrowed.scope, 'openid offline_access');
  const info = await userinfo(narrowed.access_token);
  assert.equal(info.sub, user.userId);
  assert.equal(info.email, undefined, JSON.stringify(info));
  assert.equal(info.email_verified, undefined, JSON.stringify(info));
  const id = decodeJwt(narrowed.id_token!);
  assert.equal(id.email, undefined);
  assert.equal(id.email_verified, undefined);
});

test('RP-initiated logout with a real id_token_hint ends the session and revokes refresh tokens', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  assert.ok(decodeJwt(tokens.id_token!).sid, 'the ID token carries sid');
  const res = await fetch(`${s.base}/api/auth/oauth2/end-session?${new URLSearchParams({ id_token_hint: tokens.id_token! })}`);
  assert.equal(res.status, 200, await res.clone().text());
  assert.equal(await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } }).then((r) => r.json()), null);
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 400);
});

test('an expired session being cleared does not revoke offline_access tokens', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie);
  await expireAndClearSessions(user);
  assert.equal((await refresh(client, tokens.refresh_token!)).status, 200);
});

test('the ID token carries email only when the email scope was granted', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const tokens = await codeForTokens(client, user.cookie, { scope: 'openid' });
  const id = decodeJwt(tokens.id_token!);
  assert.equal(id.sub, user.userId);
  assert.equal(id.email, undefined);
  assert.equal(id.email_verified, undefined);
});

test('refresh tokens rotate: the old one stops working once used', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const first = await codeForTokens(client, user.cookie);

  const res = await refresh(client, first.refresh_token!);
  assert.equal(res.status, 200, await res.clone().text());
  const second = (await res.json()) as Tokens;
  assert.ok(second.refresh_token && second.refresh_token !== first.refresh_token);

  const reuse = await refresh(client, first.refresh_token!);
  assert.equal(reuse.status, 400);
  assert.equal(((await reuse.json()) as { error: string }).error, 'invalid_grant');
});

test('PKCE is required, and an unregistered redirect URI is refused without redirecting to it', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const base = { response_type: 'code', client_id: client.id, redirect_uri: REDIRECT, scope: 'openid email', state: 's' };

  const noPkce = await navigate(base, user.cookie);
  const errorAt = new URL(noPkce.location ?? 'http://none/', s.base);
  assert.equal(`${errorAt.origin}${errorAt.pathname}`, REDIRECT, `${noPkce.status} ${noPkce.location} ${noPkce.body}`);
  assert.equal(errorAt.searchParams.get('error'), 'invalid_request');
  assert.match(errorAt.searchParams.get('error_description') ?? '', /pkce is required/);

  const { challenge } = pkce();
  // Same host and port as the registered URI, different path; and a different host. Both go to AuthWAPI's own error
  // page, never to the requested URI.
  for (const redirect_uri of ['http://localhost:5999/elsewhere', 'https://evil.example/callback']) {
    const res = await navigate({ ...base, redirect_uri, code_challenge: challenge, code_challenge_method: 'S256' }, user.cookie);
    assert.equal(res.status, 302);
    const at = new URL(res.location!);
    assert.equal(`${at.origin}${at.pathname}`, `${s.base}/api/auth/error`, res.location!);
    assert.equal(at.searchParams.get('error'), 'invalid_redirect');
  }
});

test('only the M1 scopes exist: profile is refused', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const { challenge } = pkce();
  const res = await navigate(
    { response_type: 'code', client_id: client.id, redirect_uri: REDIRECT, scope: 'openid profile', state: 's', code_challenge: challenge, code_challenge_method: 'S256' },
    user.cookie
  );
  const at = new URL(res.location ?? 'http://none/', s.base);
  assert.equal(`${at.origin}${at.pathname}`, REDIRECT, `${res.status} ${res.location}`);
  assert.equal(at.searchParams.get('error'), 'invalid_scope');
  assert.deepEqual((await discovery()).scopes_supported, ['openid', 'email', 'offline_access']);
});

test('CLI: create prints the secret once and stores only a hash; list shows the client without it; bad input fails', async () => {
  const client = await createClient('--resource', API);
  assert.match(client.stdout, /shown only this once/);

  const dbBytes = readFileSync(s.paths.db);
  assert.equal(dbBytes.includes(client.secret), false, 'client secret stored in plain text');
  const db = new Database(s.paths.db, { readonly: true });
  const stored = db.prepare('SELECT clientSecret FROM oauthClient WHERE clientId = ?').pluck().get(client.id) as string;
  db.close();
  assert.ok(stored && stored !== client.secret);
  const log = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8');
  assert.match(log, new RegExp(`"oauth client created","clientId":"${client.id}"`));
  assert.equal(log.includes(client.secret), false, 'client secret in app.jsonl');

  const list = await cli('clients', 'list');
  assert.equal(list.code, 0, list.stderr);
  assert.match(list.stdout, new RegExp(`${client.id}\\s+Test App`));
  assert.match(list.stdout, new RegExp(`redirect URIs: ${REDIRECT}`));
  assert.match(list.stdout, new RegExp(`resources: ${API}`));
  assert.equal(list.stdout.includes(client.secret), false);

  // The secret works at the token endpoint (a wrong one doesn't), so what's stored is a usable hash.
  const wrong = await token({ id: client.id, secret: 'wrong' }, { grant_type: 'refresh_token', refresh_token: 'x' });
  assert.equal(wrong.status, 401);

  const usage = [
    ['clients', 'create', '--redirect-uri', REDIRECT], // no name
    ['clients', 'create', '--name', 'x'], // no redirect URI
    ['clients', 'create', '--name', 'x', '--redirect-uri', REDIRECT, '--colour', 'red'], // unknown option
    ['clients', 'delete'],
    [],
  ];
  for (const args of usage) {
    const r = await cli(...args);
    assert.equal(r.code, 2, `${args.join(' ')} → ${r.code} ${r.stderr}`);
    assert.match(r.stderr, /Usage:/);
  }
  for (const uri of ['http://app.example.com/cb', 'not a url', 'https://app.example.com/cb#frag']) {
    const r = await cli('clients', 'create', '--name', 'x', '--redirect-uri', uri);
    assert.equal(r.code, 1, `${uri} → ${r.code} ${r.stdout}`);
    assert.match(r.stderr, /redirect/i);
    assert.equal(r.stdout, '');
  }
  assert.equal((await cli('clients', 'list')).stdout.match(/^\S+ {2}/gm)?.length, 1, 'a refused create left a client behind');
});

test('CLI refuses a data folder the server has not set up', async () => {
  const r = await promisify(execFile)(process.execPath, ['src/cli.ts', 'clients', 'list'], {
    env: { PATH: process.env.PATH, DATA_DIR: path.join(s.paths.root, 'missing'), BASE_URL: s.base },
  }).catch((e: { code: number; stderr: string }) => e);
  assert.equal((r as { code: number }).code, 1);
  assert.match((r as { stderr: string }).stderr, /Start the server once/);
});

test('clients and resources can only be created by the CLI: dynamic registration and session-based CRUD are refused', async () => {
  const user = await signedInUser();
  const body = { redirect_uris: ['http://localhost:7000/cb'], client_name: 'sneaky' };
  for (const p of ['/api/auth/oauth2/register', '/api/auth/oauth2/create-client', '/api/auth/admin/oauth2/create-client']) {
    for (const cookie of [user.cookie, '']) {
      const res = await postJson(p, body, cookie);
      assert.ok([401, 403, 404].includes(res.status), `${p} ${cookie ? 'with' : 'without'} session → ${res.status} ${await res.text()}`);
    }
  }
  for (const cookie of [user.cookie, '']) {
    const res = await postJson('/api/auth/admin/oauth2/resources', { identifier: 'http://localhost:7000/api', name: 'sneaky' }, cookie);
    assert.ok([401, 403, 404].includes(res.status), `resources ${cookie ? 'with' : 'without'} session → ${res.status} ${await res.text()}`);
  }
  const db = new Database(s.paths.db, { readonly: true });
  assert.equal(db.prepare('SELECT count(*) FROM oauthClient').pluck().get(), 0);
  assert.equal(db.prepare('SELECT count(*) FROM oauthResource').pluck().get(), 0);
  db.close();
  assert.equal((await discovery()).registration_endpoint, undefined);
});

test('session-based client endpoints refuse a signed-in user: get, list, update, delete, rotate-secret', async () => {
  const client = await createClient();
  const user = await signedInUser();
  const q = `client_id=${encodeURIComponent(client.id)}`;
  const calls: [string, () => Promise<Response>][] = [];
  for (const cookie of [user.cookie, '']) {
    const headers: Record<string, string> = cookie ? { cookie } : {};
    const label = cookie ? 'with session' : 'without session';
    calls.push(
      [`get-client ${label}`, () => fetch(`${s.base}/api/auth/oauth2/get-client?${q}`, { headers })],
      [`get-clients ${label}`, () => fetch(`${s.base}/api/auth/oauth2/get-clients`, { headers })],
      [`update-client ${label}`, () => postJson('/api/auth/oauth2/update-client', { client_id: client.id, update: { client_name: 'pwned' } }, cookie)],
      [`delete-client ${label}`, () => postJson('/api/auth/oauth2/delete-client', { client_id: client.id }, cookie)],
      [`rotate-secret ${label}`, () => postJson('/api/auth/oauth2/client/rotate-secret', { client_id: client.id }, cookie)]
    );
  }
  for (const [label, call] of calls) {
    const res = await call();
    const body = await res.text();
    assert.ok([401, 403].includes(res.status), `${label} → ${res.status} ${body}`);
    assert.equal(body.includes(client.id), false, `${label} leaked the client`);
  }
  const list = await cli('clients', 'list');
  assert.match(list.stdout, new RegExp(`${client.id}\\s+Test App`), 'the client was changed or deleted');
  const wrong = await token(client, { grant_type: 'refresh_token', refresh_token: 'x' });
  assert.equal(wrong.status, 400, 'the client secret was rotated'); // right secret, bad refresh token
});

test('no session JWTs: GET /api/auth/token is gone and get-session sets no JWT header', async () => {
  const user = await signedInUser();
  const res = await fetch(`${s.base}/api/auth/token`, { headers: { cookie: user.cookie } });
  assert.equal(res.status, 404, await res.text());
  const session = await fetch(`${s.base}/api/auth/get-session`, { headers: { cookie: user.cookie } });
  assert.equal(session.status, 200);
  assert.equal(session.headers.get('set-auth-jwt'), null);
});
