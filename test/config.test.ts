import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.ts';

test('defaults: localhost:4000, outbox email, /data', () => {
  const c = loadConfig({});
  assert.equal(c.baseUrl.origin, 'http://localhost:4000');
  assert.deepEqual(c.email, { mode: 'outbox' });
  assert.equal(c.dataDir, '/data');
  assert.deepEqual([...c.allowedHosts], ['localhost:4000']);
});

test('ALLOWED_HOSTS names without a port get the listening port', () => {
  const c = loadConfig({ ALLOWED_HOSTS: 'authwapi, host.docker.internal,proxy:8443' });
  assert.deepEqual([...c.allowedHosts], ['localhost:4000', 'authwapi:4000', 'host.docker.internal:4000', 'proxy:8443']);
  assert.deepEqual(c.trustedOrigins, [
    'http://localhost:4000',
    'http://authwapi:4000',
    'http://host.docker.internal:4000',
    'http://proxy:8443',
  ]);
});

test('RESEND_API_KEY switches to Resend, even on localhost', () => {
  const c = loadConfig({ RESEND_API_KEY: 're_x', EMAIL_FROM: 'auth@example.com' });
  assert.deepEqual(c.email, { mode: 'resend', apiKey: 're_x', from: 'auth@example.com' });
});

test('bad settings stop the server with a clear message', () => {
  assert.throws(() => loadConfig({ BASE_URL: 'https://auth.example.com' }), /RESEND_API_KEY and EMAIL_FROM are required/);
  assert.throws(() => loadConfig({ RESEND_API_KEY: 're_x' }), /EMAIL_FROM is required/);
  assert.throws(() => loadConfig({ BASE_URL: 'http://localhost:4000/auth' }), /origin with no path/);
  assert.throws(() => loadConfig({ BASE_URL: 'localhost:4000' }), /must be http\(s\)|not a URL/);
  assert.throws(() => loadConfig({ PORT: 'abc' }), /PORT is not a port/);
});
