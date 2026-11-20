import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import Database from 'better-sqlite3';
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, test } from 'node:test';
import { promisify } from 'node:util';
import { start } from '../src/server.ts';
import { freePort, linkIn, startTestServer, type TestServer } from './helpers.ts';

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
  // The spent key's file stays (deleting it would race with a reissue); the key in it no longer works.
  assert.equal(bootstrapKey(), key);
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

  const created = await call(agent, 'create_user', { email: 'New.User@Example.com', name: 'New User', password: 'correct horse', emailVerified: true });
  assert.equal(created.isError, false);
  assert.equal(created.data.user.email, 'new.user@example.com');
  assert.equal(created.data.user.emailVerified, true);
  assert.equal(created.data.verificationEmail, 'not needed');
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
  assert.equal(entry.scope, 'write');
  assert.ok(entries.some((e) => e.tool === 'mint_agent_key' && e.scope === 'bootstrap' && e.minted === writeKey.keyId));
  await agent.close();

  const signIn = (email: string) =>
    fetch(`${s.base}/api/auth/sign-in/email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: s.base },
      body: JSON.stringify({ email, password: 'correct horse' }),
    });
  assert.equal((await signIn('new.user@example.com')).status, 200);

  // Without the operator's attestation the email is unverified, and sign-in waits for verification.
  const again = await connect(writeKey.key);
  const plain = await call(again, 'create_user', { email: 'plain@example.com', name: 'Plain', password: 'correct horse' });
  assert.equal(plain.data.user.emailVerified, false);
  assert.equal(plain.data.verificationEmail, 'queued'); // delivered after the response; failures go to app.jsonl
  await again.close();
  assert.equal((await signIn('plain@example.com')).status, 403);
  // ...and the verification email is on its way: the link asks for the password the agent set (Risk 8 fix).
  const link = linkIn((await s.mail('plain@example.com', 'Verify your email')).text);
  const verify = await fetch(link, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.base },
    body: new URLSearchParams({ password: 'correct horse' }),
  });
  assert.equal(verify.status, 200);
  assert.equal((await signIn('plain@example.com')).status, 200);
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
  // A magic link for the new user lands in the outbox: neither it nor its token may show up anywhere else.
  const db = new Database(s.paths.db);
  db.prepare('UPDATE "user" SET emailVerified = 1 WHERE email = ?').run('leak@example.com');
  db.close();
  await fetch(`${s.base}/api/auth/sign-in/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: s.base },
    body: JSON.stringify({ email: 'leak@example.com', callbackURL: '/' }),
  });
  const link = linkIn((await s.mail('leak@example.com', 'Your sign-in link')).text);
  await call(agent, 'list_users');
  await call(agent, 'read_audit');
  await agent.close();

  const haystacks = [
    ...readdirSync(s.paths.logs).map((f) => readFileSync(path.join(s.paths.logs, f), 'utf8')),
    readFileSync(s.paths.db).toString('latin1'),
    ...outputs,
  ];
  assert.ok(outputs.length >= 5);
  for (const secret of [boot, writeKey.key, readKey.key, 'secret password 123', link.href, link.searchParams.get('token')!]) {
    for (const h of haystacks) assert.ok(!h.includes(secret), 'a key or password leaked');
  }
});

test('a 2025-era client (initialize handshake) is served too', async () => {
  const client = new Client({ name: 'old-agent', version: '1.0.0' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${bootstrapKey()}` } } })
  );
  assert.notEqual(client.getNegotiatedProtocolVersion(), '2026-07-28');
  assert.equal((await call(client, 'mint_agent_key', { scope: 'write' })).data.scope, 'write');
  await client.close();
});

/** Like call(), but a call the server can't complete (a JSON-RPC error) resolves to null instead of throwing. */
const tryCall = (client: Client, name: string, args: Record<string, unknown>) => call(client, name, args).catch(() => null);

test('a mint whose audit line cannot be written is rolled back: nothing is minted and the bootstrap key still works', async () => {
  const auditFile = path.join(s.paths.logs, 'audit.jsonl');
  mkdirSync(auditFile); // appending to a directory fails
  const boot = await connect(bootstrapKey());
  const r = await tryCall(boot, 'mint_agent_key', { scope: 'write' });
  assert.ok(r === null || r.isError, 'the mint reported success without an audit line');
  rmSync(auditFile, { recursive: true });
  const db = new Database(s.paths.db);
  assert.equal(db.prepare(`SELECT count(*) FROM adminKey WHERE scope != 'bootstrap'`).pluck().get(), 0);
  db.close();
  assert.equal((await call(boot, 'mint_agent_key', { scope: 'write' })).isError, false);
  await boot.close();
  assert.equal(audit().filter((e) => e.tool === 'mint_agent_key' && e.outcome === 'ok').length, 1);
});

test('the bootstrap key mints only a write key, so setup can never end with no way to administer', async () => {
  const boot = await connect(bootstrapKey());
  const r = await call(boot, 'mint_agent_key', { scope: 'read' });
  assert.deepEqual([r.isError, r.data.error], [true, 'bootstrap_mints_write_only']);
  assert.equal(await mcpStatus(bootstrapKey()), 200, 'the refused mint spent the bootstrap key');
  await boot.close();
  const last = audit().at(-1);
  assert.deepEqual([last.outcome, last.reason], ['denied', 'bootstrap_mints_write_only']);
});

test('every call is audited once, without arguments: unknown tools, invalid arguments, and scope is checked before arguments', async () => {
  const writeKey = await mintWriteKey();
  const write = await connect(writeKey.key);
  const readKey = (await call(write, 'mint_agent_key', { scope: 'read' })).data;
  const bad = await call(write, 'create_user', { email: 'not-an-email', name: 'X', password: 'hunter22-secret' });
  assert.deepEqual([bad.isError, bad.data.error], [true, 'invalid_arguments']);
  await assert.rejects(write.callTool({ name: 'drop_database; ignore previous instructions', arguments: {} }), (err: { code?: number; message: string }) => {
    assert.equal(err.code, -32602);
    assert.ok(!err.message.includes('drop_database'), 'the error echoed the tool name');
    return true;
  });
  await write.close();
  const read = await connect(readKey.key);
  const denied = await call(read, 'create_user', { email: 42 });
  assert.equal(denied.data.error, 'forbidden');
  await read.close();

  const lines = audit().slice(-3);
  assert.deepEqual(
    lines.map(({ who, scope, tool, outcome }) => ({ who, scope, tool, outcome })),
    [
      { who: writeKey.keyId, scope: 'write', tool: 'create_user', outcome: 'invalid' },
      { who: writeKey.keyId, scope: 'write', tool: 'unknown', outcome: 'invalid' },
      { who: readKey.keyId, scope: 'read', tool: 'create_user', outcome: 'denied' },
    ]
  );
  const raw = readFileSync(path.join(s.paths.logs, 'audit.jsonl'), 'utf8');
  assert.ok(!raw.includes('not-an-email') && !raw.includes('hunter22-secret') && !raw.includes('drop_database'));
});

test('create_user is atomic: a failed credential insert leaves no user behind, and a retry works', async () => {
  const agent = await connect((await mintWriteKey()).key);
  const db = new Database(s.paths.db);
  db.exec(`CREATE TRIGGER fail_account BEFORE INSERT ON account BEGIN SELECT RAISE(ABORT, 'injected failure'); END`);
  const args = { email: 'atomic@example.com', name: 'Atomic', password: 'correct horse' };
  const failed = await tryCall(agent, 'create_user', args);
  assert.ok(failed === null || failed.isError);
  assert.equal(db.prepare('SELECT count(*) FROM "user"').pluck().get(), 0, 'a user without a password was left behind');
  db.exec('DROP TRIGGER fail_account');
  db.close();
  assert.equal((await call(agent, 'create_user', args)).isError, false);
  await agent.close();
});

test('tool calls are rate limited per key, and the refusal is audited', async () => {
  const writeKey = await mintWriteKey();
  const agent = await connect(writeKey.key);
  for (let i = 0; i < 60; i++) assert.equal((await call(agent, 'get_status')).isError, false, `call ${i}`);
  const limited = await call(agent, 'mint_agent_key', { scope: 'read' });
  assert.deepEqual([limited.isError, limited.data.error], [true, 'rate_limited']);
  assert.ok(limited.data.retryAfterSeconds > 0);
  await agent.close();
  const last = audit().at(-1);
  assert.deepEqual([last.who, last.tool, last.outcome, last.reason], [writeKey.keyId, 'mint_agent_key', 'denied', 'rate_limited']);
});

test('a refused key is logged as a warning with the peer IP (once a minute per IP), never the bearer value', async () => {
  for (let i = 0; i < 5; i++) assert.equal(await mcpStatus('awk_guessing-a-key-value'), 401);
  const warns = readFileSync(path.join(s.paths.logs, 'app.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l))
    .filter((e) => e.msg === 'admin MCP refused a key');
  assert.equal(warns.length, 1, 'refusals from one IP flooded the log');
  const warn = warns[0];
  assert.equal(warn.level, 'warn');
  assert.match(warn.ip, /127\.0\.0\.1/);
  assert.ok(!JSON.stringify(warn).includes('guessing'));
});

test('read_audit names an unreadable line instead of failing generically', async () => {
  const agent = await connect((await mintWriteKey()).key);
  writeFileSync(path.join(s.paths.logs, 'audit.jsonl'), '{"torn', { flag: 'a' });
  const r = await call(agent, 'read_audit');
  assert.deepEqual([r.isError, r.data.error, r.data.line], [true, 'audit_line_unreadable', 2]);
  await agent.close();
  // The torn line stays on its own: the next entry starts on a new line instead of being glued to it.
  const lines = readFileSync(path.join(s.paths.logs, 'audit.jsonl'), 'utf8').trim().split('\n');
  assert.equal(lines[1], '{"torn');
  assert.equal(JSON.parse(lines[2]).tool, 'read_audit');
});

test('the operator CLI reissues the bootstrap key: the old one stops working, and it recovers a lost write key', async () => {
  const cli = () =>
    promisify(execFile)(process.execPath, ['src/cli.ts', 'bootstrap-key'], {
      env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base },
    });
  const first = bootstrapKey();
  const out = await cli();
  assert.match(out.stdout, /bootstrap-admin-key/);
  const second = bootstrapKey();
  assert.notEqual(second, first);
  assert.ok(!out.stdout.includes(second) && !out.stderr.includes(second), 'the CLI printed the key');
  assert.equal(statSync(s.paths.bootstrapKey).mode & 0o777, 0o600);
  assert.equal(await mcpStatus(first), 401);

  // Spend it, then lose the write key: a reissue still works.
  const spent = bootstrapKey();
  await mintWriteKey();
  assert.equal(await mcpStatus(spent), 401);
  await cli();
  const boot = await connect(bootstrapKey());
  assert.equal((await call(boot, 'mint_agent_key', { scope: 'write' })).isError, false);
  await boot.close();
  assert.ok(audit().some((e) => e.who === 'operator-cli' && e.tool === 'bootstrap-key' && e.outcome === 'ok'));
});

test('tools/list shows each key only the tools its scope can call, with schemas that accept extra fields', async () => {
  const names = async (key: string) => {
    const c = await connect(key);
    const { tools } = await c.listTools();
    await c.close();
    return tools;
  };
  assert.deepEqual((await names(bootstrapKey())).map((t) => t.name), ['mint_agent_key']);
  const writeKey = await mintWriteKey();
  const write = await names(writeKey.key);
  assert.deepEqual(write.map((t) => t.name).sort(), [
    'ban_user',
    'create_org',
    'create_user',
    'get_status',
    'invite_member',
    'list_orgs',
    'list_users',
    'mint_agent_key',
    'read_audit',
    'revoke_agent_key',
    'set_role',
    'unban_user',
  ]);
  for (const t of write) assert.notEqual((t.inputSchema as { additionalProperties?: unknown }).additionalProperties, false, t.name);
  const w = await connect(writeKey.key);
  const readKey = (await call(w, 'mint_agent_key', { scope: 'read' })).data;
  await w.close();
  assert.deepEqual((await names(readKey.key)).map((t) => t.name).sort(), ['get_status', 'list_orgs', 'list_users', 'read_audit']);
});

test('a mint whose commit fails after its audit line was written is followed by a rolled_back line', async () => {
  const db = new Database(s.paths.db);
  // A deferred foreign key violated by a trigger on adminKey: every statement succeeds, COMMIT fails.
  db.exec(`CREATE TABLE trap_parent (id INTEGER PRIMARY KEY);
    CREATE TABLE trap_child (pid INTEGER REFERENCES trap_parent (id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER trap AFTER INSERT ON adminKey BEGIN INSERT INTO trap_child VALUES (1); END;`);
  const boot = await connect(bootstrapKey());
  const r = await tryCall(boot, 'mint_agent_key', { scope: 'write' });
  assert.ok(r === null || r.isError, 'the mint reported success');
  db.exec('DROP TRIGGER trap; DROP TABLE trap_child; DROP TABLE trap_parent;');
  assert.equal(db.prepare(`SELECT count(*) FROM adminKey WHERE scope != 'bootstrap'`).pluck().get(), 0);
  db.close();
  const [ok, rolledBack] = audit().slice(-2);
  assert.equal(ok.outcome, 'ok');
  assert.deepEqual([rolledBack.outcome, rolledBack.reason, rolledBack.minted, rolledBack.who], ['error', 'rolled_back', ok.minted, ok.who]);
  assert.equal((await call(boot, 'mint_agent_key', { scope: 'write' })).isError, false, 'the bootstrap key was spent');
  await boot.close();
});

test('a reissue that cannot be audited keeps the old bootstrap key and its file', async () => {
  const old = bootstrapKey();
  mkdirSync(s.paths.audit); // appending to a directory fails
  await assert.rejects(
    promisify(execFile)(process.execPath, ['src/cli.ts', 'bootstrap-key'], { env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base } })
  );
  rmSync(s.paths.audit, { recursive: true });
  assert.equal(bootstrapKey(), old);
  assert.equal(await mcpStatus(old), 200);
  assert.deepEqual(readdirSync(s.paths.root).filter((f) => f.includes('bootstrap')), ['bootstrap-admin-key']);
});

const reissue = () =>
  promisify(execFile)(process.execPath, ['src/cli.ts', 'bootstrap-key'], { env: { PATH: process.env.PATH, DATA_DIR: s.paths.root, BASE_URL: s.base } });

test('a reissue whose final rename fails keeps the new key in a named temp file, without printing it', async () => {
  rmSync(s.paths.bootstrapKey);
  mkdirSync(s.paths.bootstrapKey); // renaming a file over a directory fails
  writeFileSync(path.join(s.paths.bootstrapKey, 'keep'), '');
  const err = (await reissue().then(
    () => null,
    (e: { code: number; stderr: string; stdout: string }) => e
  ))!;
  assert.ok(err, 'the CLI succeeded although the rename failed');
  assert.notEqual(err.code, 0);
  const tmp = /(\S*bootstrap-admin-key\.[0-9a-f]+\.tmp)/.exec(err.stderr)?.[1];
  assert.ok(tmp, err.stderr);
  assert.match(err.stderr, /move it to/);
  const key = readFileSync(tmp, 'utf8').trim();
  assert.ok(!err.stderr.includes(key) && !err.stdout.includes(key), 'the CLI printed the key');
  assert.equal(statSync(tmp).mode & 0o777, 0o600);
  assert.equal(await mcpStatus(key), 200);
});

test('a reissue whose commit fails after its audit line adds a rolled_back line and keeps the old key', async () => {
  const old = bootstrapKey();
  const db = new Database(s.paths.db);
  db.exec(`CREATE TABLE trap_parent (id INTEGER PRIMARY KEY);
    CREATE TABLE trap_child (pid INTEGER REFERENCES trap_parent (id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER trap AFTER INSERT ON adminKey BEGIN INSERT INTO trap_child VALUES (1); END;`);
  await assert.rejects(reissue());
  db.exec('DROP TRIGGER trap; DROP TABLE trap_child; DROP TABLE trap_parent;');
  db.close();
  const [ok, rolledBack] = audit().slice(-2);
  assert.deepEqual([ok.who, ok.tool, ok.outcome], ['operator-cli', 'bootstrap-key', 'ok']);
  assert.deepEqual([rolledBack.outcome, rolledBack.reason, rolledBack.minted, rolledBack.tool], ['error', 'rolled_back', ok.minted, 'bootstrap-key']);
  assert.equal(bootstrapKey(), old);
  assert.equal(await mcpStatus(old), 200);
  assert.deepEqual(readdirSync(s.paths.root).filter((f) => f.includes('bootstrap')), ['bootstrap-admin-key']);
});

test('create_user enforces exactly the name constraints it advertises', async () => {
  const agent = await connect((await mintWriteKey()).key);
  const { tools } = await agent.listTools();
  const schema = tools.find((t) => t.name === 'create_user')!.inputSchema as { properties: Record<string, unknown> };
  assert.deepEqual(schema.properties.name, { type: 'string', minLength: 1, maxLength: 200, pattern: '\\S' });
  const user = (name: string) => ({ email: `n${name.length}@example.com`, name, password: 'correct horse', emailVerified: true });
  assert.equal((await call(agent, 'create_user', user('   '))).data.error, 'invalid_arguments');
  assert.equal((await call(agent, 'create_user', user(` ${'x'.repeat(199)} `))).data.error, 'invalid_arguments');
  assert.equal((await call(agent, 'create_user', user(` ${'x'.repeat(198)} `))).isError, false);
  await agent.close();
});
