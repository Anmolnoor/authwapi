import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { freePort } from './helpers.ts';
import { start } from '../src/server.ts';
import { createMailer } from '../src/mailer.ts';
import { createLogger } from '../src/log.ts';
import { memoryRateLimit } from '../src/auth.ts';

test('a restored, world-readable data folder is made private on boot, and stale outbox mail is swept', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'authwapi-restored-'));
  try {
    chmodSync(root, 0o755);
    writeFileSync(path.join(root, 'secret'), 'r'.repeat(43), { mode: 0o644 });
    mkdirSync(path.join(root, 'outbox'), { mode: 0o755 });
    const stale = path.join(root, 'outbox', 'old.json');
    const fresh = path.join(root, 'outbox', 'new.json');
    writeFileSync(stale, '{}', { mode: 0o644 });
    writeFileSync(fresh, '{}', { mode: 0o644 });
    const dayAgo = (Date.now() - 25 * 60 * 60 * 1000) / 1000;
    utimesSync(stale, dayAgo, dayAgo);

    const port = await freePort();
    const running = await start({ BASE_URL: `http://127.0.0.1:${port}`, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: root });
    await running.close();

    assert.equal(statSync(root).mode & 0o777, 0o700);
    assert.equal(statSync(path.join(root, 'secret')).mode & 0o777, 0o600);
    assert.equal(statSync(path.join(root, 'authwapi.db')).mode & 0o777, 0o600);
    assert.equal(statSync(fresh).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(path.join(root, 'outbox')), ['new.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a symlink where AuthWAPI keeps its files stops the server before it opens anything', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'authwapi-link-'));
  const outside = mkdtempSync(path.join(tmpdir(), 'authwapi-outside-'));
  try {
    writeFileSync(path.join(outside, 'secret'), 'o'.repeat(43));
    chmodSync(path.join(outside, 'secret'), 0o644); // explicit: an earlier start() set the process umask to 077
    symlinkSync(path.join(outside, 'secret'), path.join(root, 'secret'));
    const port = await freePort();
    await assert.rejects(
      start({ BASE_URL: `http://127.0.0.1:${port}`, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: root }),
      /is a symlink/
    );
    assert.equal(statSync(path.join(outside, 'secret')).mode & 0o777, 0o644, 'the link target was changed');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('Resend mode still sweeps stale outbox mail left from outbox mode, at boot', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'authwapi-sweep-'));
  try {
    mkdirSync(path.join(root, 'outbox'));
    const stale = path.join(root, 'outbox', 'old.json');
    writeFileSync(stale, '{}');
    const dayAgo = (Date.now() - 25 * 60 * 60 * 1000) / 1000;
    utimesSync(stale, dayAgo, dayAgo);
    const port = await freePort();
    const running = await start({
      BASE_URL: `http://127.0.0.1:${port}`, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: root,
      RESEND_API_KEY: 're_test', EMAIL_FROM: 'auth@example.com',
    });
    await running.close();
    assert.deepEqual(readdirSync(path.join(root, 'outbox')), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('logging never throws, even when the log folder is gone', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'authwapi-logs-'));
  const log = createLogger(dir);
  rmSync(dir, { recursive: true, force: true });
  assert.doesNotThrow(() => log('error', 'still alive'));
});

test('the rate-limit store stays bounded: the oldest bucket is evicted past the cap', async () => {
  const store = memoryRateLimit(3);
  const rule = { window: 60, max: 1 };
  assert.equal((await store.consume('a', rule)).allowed, true);
  assert.equal((await store.consume('a', rule)).allowed, false); // 'a' is at its limit
  for (const k of ['b', 'c', 'd']) await store.consume(k, rule); // 4 keys > cap 3: 'a' is evicted
  assert.equal((await store.consume('a', rule)).allowed, true);
  assert.equal((await store.consume('d', rule)).allowed, false); // newest buckets kept
});

test('a symlinked data folder is refused even with a trailing slash, and nothing is created in its target', async () => {
  const target = mkdtempSync(path.join(tmpdir(), 'authwapi-target-'));
  const link = path.join(tmpdir(), `authwapi-rootlink-${process.pid}`);
  try {
    symlinkSync(target, link);
    const port = await freePort();
    await assert.rejects(
      start({ BASE_URL: `http://127.0.0.1:${port}`, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: `${link}/` }),
      /is a symlink/
    );
    assert.deepEqual(readdirSync(target), []);
  } finally {
    rmSync(link, { force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test('an hourly outbox sweep that fails is logged and does not crash the server', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  const dir = mkdtempSync(path.join(tmpdir(), 'authwapi-gone-'));
  const logged: string[] = [];
  createMailer({ mode: 'outbox' }, dir, (_level, msg) => logged.push(msg));
  rmSync(dir, { recursive: true, force: true });
  assert.doesNotThrow(() => t.mock.timers.tick(60 * 60 * 1000));
  for (let i = 0; i < 50 && logged.length === 0; i++) await new Promise((r) => setTimeout(r, 10)); // the sweep is async
  assert.deepEqual(logged, ['outbox sweep failed']);
});

test('outbox emails appear whole: a reader never sees a half-written file', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'authwapi-atomic-'));
  try {
    const send = createMailer({ mode: 'outbox' }, dir, () => {});
    const big = 'x'.repeat(2_000_000); // large enough that a non-atomic write is visible mid-way
    const sends = Array.from({ length: 20 }, (_, i) => send({ to: `r${i}@example.com`, subject: 's', text: big }));
    let reads = 0;
    const reader = (async () => {
      for (let n = 0; n < 400; n++) {
        for (const f of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
          JSON.parse(readFileSync(path.join(dir, f), 'utf8')); // throws on a partial file
          reads++;
        }
        await new Promise((r) => setImmediate(r));
      }
    })();
    await Promise.all([...sends, reader]);
    assert.equal(readdirSync(dir).filter((f) => f.endsWith('.json')).length, 20);
    assert.ok(reads > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
