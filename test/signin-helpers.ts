// Shared by the M2 sign-in tests (2FA, social, passkeys): a cookie jar, browser-like requests, TOTP, OAuth clients.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import type { TestServer } from './helpers.ts';

/** The cookies a browser holds: Set-Cookie applied in order, an empty value or Max-Age=0 removes one. */
export class Jar {
  #cookies = new Map<string, string>();
  add(setCookies: string[]): this {
    for (const sc of setCookies) {
      const [pair, ...attrs] = sc.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      if (value === '' || attrs.some((a) => /^\s*max-age=0\s*$/i.test(a))) this.#cookies.delete(name);
      else this.#cookies.set(name, value);
    }
    return this;
  }
  /** A cookie by the end of its name (the prefix depends on BASE_URL's scheme). */
  get(suffix: string): string | undefined {
    return [...this.#cookies].find(([k]) => k.endsWith(suffix))?.[1];
  }
  toString(): string {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

/** A session token a response hands out (a Set-Cookie with a value), if any. */
export const liveSessionCookie = (setCookies: string[]) =>
  setCookies.map((c) => /^[^=]*session_token=([^;]*)/.exec(c)?.[1]).find((v) => v !== undefined && v !== '');

export interface Answer {
  status: number;
  location: string | undefined;
  body: string;
  setCookies: string[];
  json: () => any;
}

/**
 * A request as a browser on our own origin sends it. `navigate` makes it a top-level navigation (node:http, since
 * fetch always sends sec-fetch-mode: cors, which Better Auth answers with JSON instead of a redirect).
 */
export function send(
  s: TestServer,
  jar: Jar,
  method: string,
  url: string,
  { json, form, navigate = false }: { json?: unknown; form?: Record<string, string>; navigate?: boolean } = {}
): Promise<Answer> {
  const target = new URL(url, s.base);
  const body = json !== undefined ? JSON.stringify(json) : form ? new URLSearchParams(form).toString() : undefined;
  const headers: Record<string, string> = { cookie: jar.toString() };
  if (body !== undefined) {
    headers['content-type'] = json !== undefined ? 'application/json' : 'application/x-www-form-urlencoded';
    headers.origin = s.base;
  }
  if (navigate) Object.assign(headers, { accept: 'text/html', 'sec-fetch-mode': 'navigate' });
  else headers.accept = 'application/json';
  return new Promise((resolve, reject) => {
    const req = request(target, { method, headers }, (res) => {
      let text = '';
      res.on('data', (d) => (text += d));
      res.on('end', () => {
        const setCookies = res.headers['set-cookie'] ?? [];
        jar.add(setCookies);
        resolve({ status: res.statusCode!, location: res.headers.location, body: text, setCookies, json: () => JSON.parse(text) });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

export const db = (s: TestServer) => new Database(s.paths.db);

export async function currentUser(s: TestServer, jar: Jar): Promise<string | null> {
  const r = await send(s, jar, 'GET', '/api/auth/get-session');
  return (r.json() as { user?: { email: string } } | null)?.user?.email ?? null;
}

/** A user with a verified email and a password. Verification is set directly: it has its own tests. */
export async function verifiedUser(s: TestServer, email: string, password = 'correct horse'): Promise<string> {
  const r = await send(s, new Jar(), 'POST', '/api/auth/sign-up/email', { json: { email, password, name: 'User' } });
  assert.equal(r.status, 200, r.body);
  const d = db(s);
  d.prepare('UPDATE user SET emailVerified = 1 WHERE email = ?').run(email);
  const id = d.prepare('SELECT id FROM user WHERE email = ?').pluck().get(email) as string;
  d.close();
  return id;
}

export async function passwordSignIn(s: TestServer, jar: Jar, email: string, password = 'correct horse') {
  return send(s, jar, 'POST', '/api/auth/sign-in/email', { json: { email, password } });
}

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) from the otpauth URI's base32 secret.
const base32 = (s: string) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out: number[] = [];
  let bits = 0;
  let v = 0;
  for (const ch of s.toUpperCase().replace(/=+$/, '')) {
    v = (v << 5) | A.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((v >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
};
export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const h = createHmac('sha1', base32(secret)).update(counter).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** Turns on TOTP for the signed-in user in `jar` (enable, then confirm a code). Returns the secret and backup codes. */
export async function enableTotp(s: TestServer, jar: Jar, password: string | undefined = 'correct horse') {
  const r = await send(s, jar, 'POST', '/api/auth/two-factor/enable', { json: password ? { password } : {} });
  assert.equal(r.status, 200, r.body);
  const { totpURI, backupCodes } = r.json() as { totpURI: string; backupCodes: string[] };
  const secret = new URL(totpURI).searchParams.get('secret')!;
  const ok = await send(s, jar, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } });
  assert.equal(ok.status, 200, ok.body);
  return { secret, backupCodes };
}

// ── OAuth clients (the app side) ──
export const REDIRECT = 'http://localhost:5999/callback';

export async function createClient(s: TestServer) {
  const { stdout } = await promisify(execFile)(process.execPath, ['src/cli.ts', 'clients', 'create', '--name', 'Test App', '--redirect-uri', REDIRECT], {
    env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base },
  });
  return { id: /client_id:\s+(\S+)/.exec(stdout)![1], secret: /client_secret:\s+(\S+)/.exec(stdout)![1] };
}

/** An app's authorization request (code + PKCE). */
export function authorizeUrl(s: TestServer, client: { id: string }, extra: Record<string, string> = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.id,
    redirect_uri: REDIRECT,
    scope: 'openid email offline_access',
    state: 'app-state',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  });
  return { url: `${s.base}/api/auth/oauth2/authorize?${params}`, verifier };
}

/** The code in a redirect back to the app, after checking it is one. */
export function codeFrom(location: string | undefined): string {
  if (!location?.startsWith(REDIRECT)) assert.fail(`expected a redirect to the app, got ${location}`);
  const code = new URL(location).searchParams.get('code');
  assert.ok(code, location);
  return code;
}

export async function exchange(s: TestServer, client: { id: string; secret: string }, code: string, verifier: string) {
  const res = await fetch(`${s.base}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }),
  });
  return { status: res.status, body: (await res.json()) as { access_token?: string; refresh_token?: string; id_token?: string } };
}

/** On the consent page: Allow. Returns where the browser goes next. */
export async function allow(s: TestServer, jar: Jar, consentLocation: string) {
  const query = new URL(consentLocation, s.base).search.slice(1);
  const r = await send(s, jar, 'POST', '/consent', { form: { oauth_query: query, accept: 'yes' } });
  assert.equal(r.status, 303, r.body);
  return r.location;
}

// ── Passkeys (with test/webauthn.ts) ──
type Authenticator = { register: (o: any, opts?: { uv?: boolean }) => object; authenticate: (o: any, opts?: { uv?: boolean }) => object };

export async function addPasskey(s: TestServer, jar: Jar, key: Authenticator, opts: { uv?: boolean } = {}) {
  const options = await send(s, jar, 'GET', '/api/auth/passkey/generate-register-options');
  if (options.status !== 200) return options;
  const o = options.json();
  assert.equal(o.rp.id, new URL(s.base).hostname);
  assert.equal(o.authenticatorSelection.userVerification, 'required');
  return send(s, jar, 'POST', '/api/auth/passkey/verify-registration', { json: { response: key.register(o, opts) } });
}

export async function passkeySignIn(s: TestServer, jar: Jar, key: Authenticator, opts: { uv?: boolean; oauth_query?: string } = {}) {
  const options = await send(s, jar, 'GET', '/api/auth/passkey/generate-authenticate-options');
  assert.equal(options.status, 200, options.body);
  assert.equal(options.json().userVerification, 'required');
  const body = { response: key.authenticate(options.json(), opts), ...(opts.oauth_query ? { oauth_query: opts.oauth_query } : {}) };
  return send(s, jar, 'POST', '/api/auth/passkey/verify-authentication', { json: body });
}
