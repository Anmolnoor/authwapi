// Writes site/public/openapi.json: the HTTP API AuthWAPI supports, as OpenAPI 3.1.
// Request and response schemas come from Better Auth itself (its open-api plugin, run against src/auth.ts), so they
// match the pinned version. The list of paths, their notes and the routes outside /api/auth are AuthWAPI's.
//   node site/scripts/openapi.ts           regenerate (run from the repo root, after npm ci)
//   node site/scripts/openapi.ts --check   exit 1 if the committed file is out of date
import Database from 'better-sqlite3';
import { betterAuth } from 'better-auth';
import { openAPI } from 'better-auth/plugins';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { authOptions } from '../../src/auth.ts';
import { loadConfig } from '../../src/config.ts';

const OUT = new URL('../public/openapi.json', import.meta.url);
const MIGRATIONS = new URL('../../migrations/', import.meta.url);

const SESSION = [{ sessionCookie: [] }];
const CLIENT = [{ clientSecretBasic: [] }];

/**
 * Better Auth paths (under /api/auth) that AuthWAPI M1 supports, with what AuthWAPI adds. Better Auth mounts more
 * (update-user, change-email, social sign-in, client admin...), but M1 doesn't configure, test or support them.
 * A path missing from Better Auth's output fails the script: rename it here rather than ship a stale reference.
 */
const SUPPORTED: Record<string, { methods: string[]; security?: object[]; note?: string; tag: string }> = {
  '/sign-up/email': {
    methods: ['post'],
    tag: 'Email and password',
    note: 'Creates the account and emails a verification link. The account cannot sign in until the email is verified. The answer is the same whether or not the address already has an account.',
  },
  '/sign-in/email': {
    methods: ['post'],
    tag: 'Email and password',
    note: 'Sets the session cookie. Refused with 403 `EMAIL_NOT_VERIFIED` until the email is verified.',
  },
  '/send-verification-email': {
    methods: ['post'],
    tag: 'Email and password',
    note: 'Sends the verification email again. Rate-limited per IP. Opening the link shows a page that asks for the sign-up password; see the hosted pages docs.',
  },
  '/request-password-reset': {
    methods: ['post'],
    tag: 'Email and password',
    note: 'Emails a reset link if the address has an account. Same answer either way.',
  },
  '/reset-password': {
    methods: ['post'],
    tag: 'Email and password',
    note: "Sets a new password from the emailed token. Ends every session and revokes every OAuth refresh token the user has, for every app.",
  },
  '/change-password': {
    methods: ['post'],
    security: SESSION,
    tag: 'Sessions',
    note: 'With `revokeOtherSessions: true`, also revokes every OAuth refresh token the user has.',
  },
  '/sign-in/magic-link': {
    methods: ['post'],
    tag: 'Magic link',
    note: 'Signs in an existing account only, never creates one. The link works once, for 5 minutes. No email is sent for an address with no account, and one address gets at most one link a minute, but the answer is the same. `callbackURL`, `newUserCallbackURL` and `errorCallbackURL` must be on BASE_URL or an ALLOWED_HOSTS name.',
  },
  '/get-session': { methods: ['get'], security: SESSION, tag: 'Sessions', note: 'The signed-in user and session, or `null`.' },
  '/sign-out': {
    methods: ['post'],
    security: SESSION,
    tag: 'Sessions',
    note: 'Ends the session and revokes every OAuth refresh token the user has, for every app.',
  },
  '/list-sessions': { methods: ['get'], security: SESSION, tag: 'Sessions' },
  '/revoke-session': { methods: ['post'], security: SESSION, tag: 'Sessions', note: 'Also revokes every OAuth refresh token the user has.' },
  '/revoke-sessions': { methods: ['post'], security: SESSION, tag: 'Sessions', note: 'Also revokes every OAuth refresh token the user has.' },
  '/revoke-other-sessions': { methods: ['post'], security: SESSION, tag: 'Sessions', note: 'Also revokes every OAuth refresh token the user has.' },
  '/oauth2/authorize': {
    methods: ['get'],
    tag: 'OAuth 2.1 / OpenID Connect',
    note: 'Open this in the browser. Authorization code flow only; PKCE with `S256` is required. Scopes: `openid`, `email`, `offline_access`. Pass `resource=<api>` to get a JWT access token for that API (the client must be registered for it).',
  },
  '/oauth2/token': {
    methods: ['post'],
    security: CLIENT,
    tag: 'OAuth 2.1 / OpenID Connect',
    note: 'Grant types `authorization_code` and `refresh_token`. Refresh tokens rotate. Send `resource` only if it was on the authorization request (`invalid_target` otherwise). Access tokens last 15 minutes.',
  },
  '/oauth2/introspect': {
    methods: ['post'],
    security: CLIENT,
    tag: 'OAuth 2.1 / OpenID Connect',
    note: 'Reports a token inactive if it was issued before the user signed out, reset the password or had sessions revoked. Use it when an API needs revocation to take effect at once.',
  },
  '/oauth2/revoke': { methods: ['post'], security: CLIENT, tag: 'OAuth 2.1 / OpenID Connect' },
  '/oauth2/userinfo': {
    methods: ['get', 'post'],
    tag: 'OAuth 2.1 / OpenID Connect',
    note: 'Send the access token as `Authorization: Bearer <token>`. Returns `sub`, plus `email` and `email_verified` when the token has the `email` scope. Refuses tokens issued before a revocation.',
  },
  '/oauth2/end-session': {
    methods: ['get'],
    tag: 'OAuth 2.1 / OpenID Connect',
    note: 'RP-initiated logout. `id_token_hint` works for clients created with the CLI. Revokes every refresh token the user has.',
  },
  '/jwks': { methods: ['get'], tag: 'OAuth 2.1 / OpenID Connect', note: 'Public keys for verifying ID tokens and JWT access tokens.' },
};

/** AuthWAPI routes outside Better Auth's handler. Paths are relative to the /api/auth server, hence the ../ form. */
const json = (description: string, example: unknown) => ({ description, content: { 'application/json': { example } } });
const page = (summary: string, get: string, post: string) => ({
  get: { tags: ['Pages'], summary, description: get, parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'An HTML page', content: { 'text/html': {} } } } },
  post: { tags: ['Pages'], summary, description: post, parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'An HTML page', content: { 'text/html': {} } }, 303: { description: 'Redirect after signing in' } } },
});
const AUTHWAPI_PATHS = {
  '/verify-email': page(
    'Verify an email address (the link in the verification email)',
    'Shows a form that asks for the password chosen at sign-up. Verifies nothing.',
    'Form field `password`. Marks the email verified only if the password matches the one the account was created with, so someone who signed up with your address cannot get in when you verify it.'
  ),
  '/magic-link/verify': page(
    'Sign in with a magic link (the link in the email)',
    'Shows "Sign in as you@example.com?" with a Continue button. Consumes nothing, so mail scanners cannot use the link up.',
    'Signs in, sets the session cookie and redirects to the callbackURL.'
  ),
};
const SERVER_PATHS = {
  '/health': { get: { tags: ['Server'], summary: 'Health check', description: 'Answers on any Host header.', responses: { 200: json('Up', { status: 'ok' }) } } },
  '/.well-known/openid-configuration': {
    get: { tags: ['OAuth 2.1 / OpenID Connect'], summary: 'OpenID Connect discovery', description: 'Issuer = BASE_URL.', responses: { 200: { description: 'Discovery document' } } },
  },
  '/.well-known/oauth-authorization-server': {
    get: { tags: ['OAuth 2.1 / OpenID Connect'], summary: 'OAuth authorization server metadata (RFC 8414)', responses: { 200: { description: 'Metadata document' } } },
  },
};

async function generate(): Promise<string> {
  const db = new Database(':memory:');
  for (const f of readdirSync(MIGRATIONS).filter((n) => n.endsWith('.sql')).sort()) db.exec(readFileSync(new URL(f, MIGRATIONS), 'utf8'));
  const options = authOptions({ config: loadConfig({}), db, secret: 'openapi-generation-only-'.padEnd(32, 'x'), sendMail: async () => {}, log: () => {} });
  const auth = betterAuth({ ...options, plugins: [...options.plugins!, openAPI()] });
  const generated = (await (auth.api as unknown as { generateOpenAPISchema: () => Promise<any> }).generateOpenAPISchema()) as {
    paths: Record<string, Record<string, any>>;
    components: { schemas: Record<string, unknown> };
  };

  const paths: Record<string, unknown> = {};
  for (const [path, { methods, security, note, tag }] of Object.entries(SUPPORTED)) {
    const ops = generated.paths[path];
    if (!ops) throw new Error(`Better Auth no longer has ${path}; update SUPPORTED in site/scripts/openapi.ts`);
    paths[path] = Object.fromEntries(
      methods.map((m) => {
        const op = ops[m];
        if (!op) throw new Error(`Better Auth has no ${m.toUpperCase()} ${path}; update SUPPORTED in site/scripts/openapi.ts`);
        const description = [op.description, note].filter(Boolean).join('\n\n');
        // OAuth clients POST form-encoded bodies (RFC 6749); Better Auth accepts that as well as the JSON it lists.
        const json = op.requestBody?.content?.['application/json'];
        const requestBody =
          security === CLIENT && json ? { ...op.requestBody, content: { 'application/x-www-form-urlencoded': json, 'application/json': json } } : op.requestBody;
        return [m, { ...op, ...(requestBody ? { requestBody } : {}), tags: [tag], description, security: security ?? [] }];
      })
    );
  }
  Object.assign(paths, AUTHWAPI_PATHS);
  // Server routes live at the origin, not under /api/auth: give them their own server.
  const origin = [{ url: '{baseUrl}', variables: { baseUrl: { default: 'http://localhost:4000', description: 'Your BASE_URL' } } }];
  for (const [p, item] of Object.entries(SERVER_PATHS)) paths[p] = { ...item, servers: origin };

  // Keep the generated component schemas the kept operations point at (User, Session).
  const refs = [...JSON.stringify(paths).matchAll(/"#\/components\/schemas\/(\w+)"/g)].map((m) => m[1]);
  const schemas = Object.fromEntries([...new Set(refs)].sort().map((n) => [n, generated.components.schemas[n]]));

  const spec = {
    openapi: '3.1.1',
    info: {
      title: 'AuthWAPI',
      version: '0.2.0',
      description:
        'Self-hosted auth server (M1). Every path below is under BASE_URL/api/auth except the ones that declare their own server. ' +
        'Browser-style requests must send an Origin equal to BASE_URL (or an ALLOWED_HOSTS name), and every request must use a Host that is BASE_URL\'s host or in ALLOWED_HOSTS (421 `unknown_host` otherwise). ' +
        'Errors from core routes are `{ "code", "message" }`; OAuth endpoints answer `{ "error", "error_description" }`. All routes are rate-limited per client IP (429). ' +
        'Request and response schemas are generated from Better Auth.',
    },
    servers: [{ url: '{baseUrl}/api/auth', variables: { baseUrl: { default: 'http://localhost:4000', description: 'Your BASE_URL' } } }],
    tags: [
      { name: 'Email and password' },
      { name: 'Magic link' },
      { name: 'Sessions' },
      { name: 'OAuth 2.1 / OpenID Connect' },
      { name: 'Pages', description: 'Links in emails. GET shows a page and changes nothing; POST acts.' },
      { name: 'Server' },
    ],
    components: {
      schemas,
      securitySchemes: {
        sessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'better-auth.session_token',
          description: 'Set by sign-in. Named `__Secure-better-auth.session_token` when BASE_URL is https.',
        },
        clientSecretBasic: { type: 'http', scheme: 'basic', description: 'OAuth client ID and secret from `node src/cli.ts clients create`.' },
      },
    },
    paths,
  };
  return `${JSON.stringify(spec, null, 2)}\n`;
}

const text = await generate();
if (process.argv.includes('--check')) {
  if (readFileSync(OUT, 'utf8') !== text) {
    console.error('site/public/openapi.json is out of date: run node site/scripts/openapi.ts');
    process.exit(1);
  }
  console.log('openapi.json is up to date');
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT.pathname}`);
}
process.exit(0); // Better Auth's rate-limit sweeper keeps the event loop alive
