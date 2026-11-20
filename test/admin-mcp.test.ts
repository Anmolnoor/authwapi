import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import Database from 'better-sqlite3';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { start } from '../src/server.ts';
import { freePort, startTestServer, type TestServer } from './helpers.ts';

let s: TestServer;
beforeEach(async () => (s = await startTestServer()));
afterEach(() => s.stop());

/** Every MCP tool result the tests saw, except mint_agent_key's: the leak test greps these. */
const outputs: string[] = [];

const bootstrapKey = () => readFileSync(s.paths.bootstrapKey, 'utf8').trim();

/** An MCP client on the 2026-07-28 protocol (the `auto` probe), authenticated with `key`. */
async function connect(key: string) {
  const client = new Client({ name: 'test-agent', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  const transport = new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${key}` } },
  });
  await client.connect(transport);
  return client;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args });
  const text = (r.content as { type: string; text: string }[])[0].text;
  if (name !== 'mint_agent_key' || r.isError) outputs.push(text);
  return { isError: r.isError === true, data: JSON.parse(text) };
}

/** Status of a raw MCP POST with this key; refused keys never reach the MCP handler. */
const mcpStatus = async (key: string) =>
  (
    await fetch(`${s.base}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    })
  ).status;

const audit = () =>
  readFileSync(path.join(s.paths.logs, 'audit.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));

async function mintWriteKey() {
  const boot = await connect(bootstrapKey());
  const { data } = await call(boot, 'mint_agent_key', { scope: 'write' });
  await boot.close();
  return data as { keyId: string; scope: string; key: string };
}

test('first boot writes a 0600 bootstrap key that only mint_agent_key accepts, once', async () => {
  assert.equal(statSync(s.paths.bootstrapKey).mode & 0o777, 0o600);
  const key = bootstrapKey();
  assert.equal(await mcpStatus('not-a-key'), 401);
  assert.equal(await mcpStatus(''), 401);

  const boot = await connect(key);
  const status = await call(boot, 'get_status');
  assert.equal(status.isError, true);
  assert.equal(status.data.error, 'forbidden');

  const minted = await call(boot, 'mint_agent_key', { scope: 'write' });
  assert.equal(minted.isError, false);
  assert.equal(minted.data.scope, 'write');
  assert.match(minted.data.key, /^awk_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(minted.data.keyId, minted.data.key);
  await boot.close();

  assert.equal(await mcpStatus(key), 401, 'the bootstrap key worked twice');
  assert.equal(existsSync(s.paths.bootstrapKey), false, 'the spent bootstrap key file was left behind');
  assert.equal(await mcpStatus(minted.data.key), 200);
});

test('the bootstrap key is refused 24 hours after it was created', async () => {
  const key = bootstrapKey();
  assert.equal(await mcpStatus(key), 200);
  const db = new Database(s.paths.db);
  const { createdAt, expiresAt } = db.prepare(`SELECT createdAt, expiresAt FROM adminKey WHERE scope = 'bootstrap'`).get() as {
    createdAt: string;
    expiresAt: string;
  };
  assert.equal(Date.parse(expiresAt) - Date.parse(createdAt), 24 * 3600 * 1000);
  db.prepare(`UPDATE adminKey SET expiresAt = ? WHERE scope = 'bootstrap'`).run(new Date(Date.now() - 1000).toISOString());
  db.close();
  assert.equal(await mcpStatus(key), 401);
});

test('a restart neither replaces an unused bootstrap key nor makes a new one after it is spent', async () => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'authwapi-test-'));
  const boot = async () => {
    const port = await freePort();
    return start({ BASE_URL: `http://127.0.0.1:${port}`, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: dataDir });
  };
  try {
    let r = await boot();
    const first = readFileSync(r.paths.bootstrapKey, 'utf8');
    await r.close();
    r = await boot();
    assert.equal(readFileSync(r.paths.bootstrapKey, 'utf8'), first);
    const db = new Database(r.paths.db);
    db.prepare(`UPDATE adminKey SET revokedAt = ? WHERE scope = 'bootstrap'`).run(new Date().toISOString());
    db.close();
    rmSync(r.paths.bootstrapKey);
    await r.close();
    r = await boot();
    assert.equal(existsSync(r.paths.bootstrapKey), false);
    await r.close();
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a revoked agent key is refused', async () => {
  const write = await connect((await mintWriteKey()).key);
  const read = (await call(write, 'mint_agent_key', { scope: 'read' })).data;
  assert.equal(await mcpStatus(read.key), 200);
  assert.deepEqual((await call(write, 'revoke_agent_key', { keyId: read.keyId })).data, { keyId: read.keyId, revoked: true });
  assert.equal(await mcpStatus(read.key), 401);
  await write.close();
});

test('a read key can read but cannot create users, mint or revoke keys; each refusal is audited', async () => {
  const writeKey = await mintWriteKey();
  const write = await connect(writeKey.key);
  const readKey = (await call(write, 'mint_agent_key', { scope: 'read' })).data;
  await write.close();

  const read = await connect(readKey.key);
  for (const [tool, args] of [
    ['create_user', { email: 'x@example.com', name: 'X', password: 'correct horse' }],
    ['mint_agent_key', { scope: 'write' }],
    ['revoke_agent_key', { keyId: writeKey.keyId }],
  ] as const) {
    const r = await call(read, tool, args);
    assert.equal(r.isError, true, tool);
    assert.equal(r.data.error, 'forbidden', tool);
  }
  assert.equal((await call(read, 'list_users')).data.users.length, 0);
  assert.equal((await call(read, 'get_status')).isError, false);
  await read.close();

  const denied = audit().filter((e) => e.who === readKey.keyId && e.outcome === 'denied').map((e) => e.tool);
  assert.deepEqual(denied, ['create_user', 'mint_agent_key', 'revoke_agent_key']);
  assert.equal(await mcpStatus(writeKey.key), 200, 'the read key revoked the write key');
});

test('/mcp refuses an unknown Host (DNS rebinding) and a foreign Origin', async () => {
  const key = bootstrapKey();
  const hostStatus = await new Promise<number>((resolve, reject) => {
    const req = request(`${s.base}/mcp`, { method: 'POST', headers: { host: 'evil.example:4000', authorization: `Bearer ${key}` } }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    });
    req.on('error', reject);
    req.end('{}');
  });
  assert.equal(hostStatus, 421);
  const res = await fetch(`${s.base}/mcp`, {
    method: 'POST',
    headers: { origin: 'https://evil.example', authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(res.status, 403);
});

test('end to end: an agent mints a write key, creates a user who can sign in, and reads the audit entry', async () => {
  const writeKey = await mintWriteKey();
  const agent = await connect(writeKey.key);
  assert.equal(agent.getNegotiatedProtocolVersion(), '2026-07-28');

  const created = await call(agent, 'create_user', { email: 'New.User@Example.com', name: 'New User', password: 'correct horse' });
  assert.equal(created.isError, false);
  assert.equal(created.data.user.email, 'new.user@example.com');
  assert.equal(created.data.user.emailVerified, true);
  const dup = await call(agent, 'create_user', { email: 'new.user@example.com', name: 'Again', password: 'correct horse' });
  assert.deepEqual([dup.isError, dup.data.error], [true, 'email_taken']);

  const users = (await call(agent, 'list_users')).data.users;
  assert.deepEqual(users.map((u: { email: string }) => u.email), ['new.user@example.com']);
  const status = (await call(agent, 'get_status')).data;
  assert.equal(status.users, 1);
  assert.equal(status.emailMode, 'outbox');

  const entries = (await call(agent, 'read_audit')).data.entries as Record<string, unknown>[];
  const entry = entries.find((e) => e.tool === 'create_user' && e.outcome === 'ok');
  assert.ok(entry, JSON.stringify(entries));
  assert.equal(entry.who, writeKey.keyId);
  assert.equal(entry.target, created.data.user.id);
  assert.ok(entries.some((e) => e.tool === 'mint_agent_key' && e.who !== writeKey.keyId && e.target === writeKey.keyId));
  await agent.close();

  const signIn = await fetch(`${s.base}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: s.base },
    body: JSON.stringify({ email: 'new.user@example.com', password: 'correct horse' }),
  });
  assert.equal(signIn.status, 200);
});

test('no key or password reaches logs/, the database, or MCP output, except the one-time mint result', async () => {
  outputs.length = 0;
  const boot = bootstrapKey();
  const writeKey = await mintWriteKey();
  const agent = await connect(writeKey.key);
  const readKey = (await call(agent, 'mint_agent_key', { scope: 'read' })).data;
  await call(agent, 'create_user', { email: 'leak@example.com', name: 'Leak', password: 'secret password 123' });
  await call(agent, 'revoke_agent_key', { keyId: readKey.keyId });
  await call(agent, 'list_users');
  await call(agent, 'get_status');
  await call(agent, 'read_audit');
  await agent.close();

  const haystacks = [
    ...readdirSync(s.paths.logs).map((f) => readFileSync(path.join(s.paths.logs, f), 'utf8')),
    readFileSync(s.paths.db).toString('latin1'),
    ...outputs,
  ];
  assert.ok(outputs.length >= 5);
  for (const secret of [boot, writeKey.key, readKey.key, 'secret password 123']) {
    for (const h of haystacks) assert.ok(!h.includes(secret), 'a key or password leaked');
  }
});

test('a 2025-era client (initialize handshake) is served too', async () => {
  const client = new Client({ name: 'old-agent', version: '1.0.0' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${bootstrapKey()}` } } })
  );
  assert.notEqual(client.getNegotiatedProtocolVersion(), '2026-07-28');
  assert.equal((await call(client, 'mint_agent_key', { scope: 'read' })).data.scope, 'read');
  await client.close();
});
