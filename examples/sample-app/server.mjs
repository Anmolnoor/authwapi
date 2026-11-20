import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRemoteJWKSet, errors, jwtVerify } from 'jose';

const { ISSUER, APP_ORIGIN, API_ORIGIN, CLIENT_ID, CLIENT_SECRET_FILE, UNSAFE_CHECK_TOKENS_DIR } = process.env;
const redirectUri = new URL('/callback', APP_ORIGIN).href;
const resources = { '/api': new URL('/api', API_ORIGIN).href, '/other-api': new URL('/other-api', API_ORIGIN).href };
const secret = (await readFile(CLIENT_SECRET_FILE, 'utf8')).trim();
const credentials = `Basic ${Buffer.from(`${CLIENT_ID}:${secret}`).toString('base64')}`;
const discovery = await fetch(`${ISSUER}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(5000) });
if (!discovery.ok) throw new Error('OIDC discovery failed');
const metadata = await discovery.json();
if (metadata.issuer !== ISSUER) throw new Error('OIDC issuer mismatch');
const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
const pending = new Map();

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function handle(req, res) {
  const url = new URL(req.url, APP_ORIGIN);
  if (req.method !== 'GET') return json(res, 405, { error: 'method_not_allowed' });
  if (url.pathname === '/health') return json(res, 200, { status: 'ok' });

  if (Object.hasOwn(resources, url.pathname)) {
    const token = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? '')?.[1];
    if (!token) return json(res, 401, { error: 'bearer_required' });
    // A JWT stays valid until it expires, even after sign-out: APIs that need instant revocation use introspection.
    try {
      const { payload } = await jwtVerify(token, jwks, { issuer: ISSUER, audience: resources[url.pathname] });
      return json(res, 200, { sub: payload.sub });
    } catch (err) {
      const error = err instanceof errors.JWTClaimValidationFailed && err.claim === 'aud' ? 'wrong_audience' : 'invalid_token';
      return json(res, 401, { error });
    }
  }

  if (url.pathname === '/login') {
    const other = url.searchParams.has('other');
    const resource = resources[other ? '/other-api' : '/api'];
    const state = randomBytes(32).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    pending.set(state, { verifier, nonce, resource, other });
    setTimeout(() => pending.delete(state), 300_000).unref();
    const authorize = new URL(metadata.authorization_endpoint);
    authorize.search = new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: redirectUri, state, nonce, resource,
      scope: other ? 'openid email' : 'openid email offline_access', prompt: 'consent',
      code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    });
    const secure = new URL(APP_ORIGIN).protocol === 'https:' ? '; Secure' : '';
    res.writeHead(302, {
      Location: authorize.href,
      'Set-Cookie': `sso_state=${state}; Path=/callback; Max-Age=300; HttpOnly; SameSite=Lax${secure}`,
      'Cache-Control': 'no-store',
    });
    return res.end();
  }

  if (url.pathname === '/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const cookieState = /(?:^|;\s*)sso_state=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    const flow = pending.get(state);
    if (!code || state !== cookieState || !flow || url.searchParams.get('iss') !== ISSUER) {
      return json(res, 400, { error: 'invalid_callback' });
    }
    pending.delete(state);
    const tokenResponse = await fetch(metadata.token_endpoint, {
      method: 'POST', headers: { Authorization: credentials }, signal: AbortSignal.timeout(5000),
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri,
        code_verifier: flow.verifier, resource: flow.resource }),
    });
    if (!tokenResponse.ok) return json(res, 502, { error: 'token_exchange_failed' });
    const tokens = await tokenResponse.json();
    const { payload: id } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: CLIENT_ID });
    if (id.nonce !== flow.nonce || !id.sub) return json(res, 502, { error: 'invalid_id_token' });
    const api = await fetch(flow.resource, {
      headers: { Authorization: `Bearer ${tokens.access_token}` }, signal: AbortSignal.timeout(5000),
    });
    if (!api.ok || (await api.json()).sub !== id.sub) return json(res, 502, { error: 'api_request_failed' });

    // Private test fixture for the curl driver's negative and revocation checks.
    if (UNSAFE_CHECK_TOKENS_DIR) {
      const { access_token, refresh_token, scope } = tokens;
      await writeFile(`${UNSAFE_CHECK_TOKENS_DIR}/${flow.other ? 'other' : 'primary'}.json`,
        JSON.stringify({ access_token, refresh_token, scope }), { mode: 0o600, flag: 'wx' });
    }
    return json(res, 200, { sub: id.sub, email: id.email, emailVerified: id.email_verified, resource: flow.resource });
  }

  return json(res, 404, { error: 'not_found' });
}

createServer((req, res) => {
  handle(req, res).catch(() => json(res, 502, { error: 'oidc_or_api_request_failed' }));
}).listen(Number(process.env.PORT ?? 3000), '0.0.0.0');
