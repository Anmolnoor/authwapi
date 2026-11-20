// `authwapi export` / `import` (plan D6): moving the data folder, including while the server runs.
// The CLI runs as its own process, as an operator would run it, against real servers on temp folders.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, writeSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { freePort, startTestServer, type TestServer } from './helpers.ts';
import { start } from '../src/server.ts';

const tmps: string[] = [];
const tmp = () => {
  const d = mkdtempSync(path.join(tmpdir(), 'authwapi-move-'));
  tmps.push(d);
  return d;
};
const servers: { stop: () => Promise<void> }[] = [];
afterEach(async () => {
  for (const s of servers.splice(0)) await s.stop();
  tmps.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true }));
});

async function server(): Promise<TestServer> {
  const s = await startTestServer();
  servers.push(s);
  return s;
}

const cli = async (dataDir: string, ...args: string[]) => {
  try {
    const { stdout, stderr } = await promisify(execFile)(process.execPath, ['src/cli.ts', ...args], {
      env: { PATH: process.env.PATH, DATA_DIR: dataDir },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code: number; stdout: string; stderr: string };
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
};

const signUp = (base: string, email: string, password = 'correct horse') =>
  fetch(`${base}/api/auth/sign-up/email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: base },
    body: JSON.stringify({ email, password, name: 'Ada' }),
  });
const signIn = (base: string, email: string, password = 'correct horse') =>
  fetch(`${base}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: base },
    body: JSON.stringify({ email, password }),
  });

const integrity = (file: string) => {
  const db = new Database(file, { readonly: true });
  try {
    return db.pragma('integrity_check', { simple: true });
  } finally {
    db.close();
  }
};
const mode = (file: string) => statSync(file).mode & 0o777;

test('export while the database is being written produces a consistent copy that passes integrity_check', async () => {
  const s = await server();
  // Sign-up is rate limited, so the writes come from a second connection to the live database: to SQLite that is
  // the same as the server writing from another process. Each transaction adds a row to two tables, so a copy
  // taken mid-transaction (or stitched from different moments) would show different counts.
  const live = new Database(s.paths.db);
  live.pragma('busy_timeout = 5000');
  live.exec('CREATE TABLE test_a (v BLOB); CREATE TABLE test_b (v BLOB);');
  const pair = live.transaction(() => {
    live.prepare('INSERT INTO test_a VALUES (randomblob(1000))').run();
    live.prepare('INSERT INTO test_b VALUES (randomblob(1000))').run();
  });
  for (let i = 0; i < 1000; i++) pair(); // a few hundred pages: more than one default backup step
  const before = live.prepare('SELECT count(*) FROM test_a').pluck().get() as number;
  let writing = true;
  const writer = (async () => {
    while (writing) {
      pair();
      await new Promise((r) => setImmediate(r));
    }
  })();

  const out = path.join(tmp(), 'export'); // doesn't exist yet: export creates it
  const r = await cli(s.paths.root, 'export', out);
  writing = false;
  await writer;
  const after = live.prepare('SELECT count(*) FROM test_a').pluck().get() as number;
  live.close();

  assert.equal(r.code, 0, r.stderr);
  assert.ok(after > before, 'nothing was written during the export');
  assert.deepEqual(readdirSync(out).sort(), ['authwapi.db', 'secret']);
  assert.equal(integrity(path.join(out, 'authwapi.db')), 'ok');
  assert.equal(mode(path.join(out, 'secret')), 0o600);
  assert.equal(mode(path.join(out, 'authwapi.db')), 0o600);
  assert.equal(mode(out), 0o700);
  const db = new Database(path.join(out, 'authwapi.db'), { readonly: true });
  const a = db.prepare('SELECT count(*) FROM test_a').pluck().get() as number;
  const b = db.prepare('SELECT count(*) FROM test_b').pluck().get() as number;
  db.close();
  assert.equal(a, b);
  assert.ok(a >= before && a <= after, `${a} rows exported; ${before} before, ${after} after`);
});

test('export → import into a fresh folder at another path restores users, sessions and the secret', async () => {
  const s = await server();
  assert.equal((await signUp(s.base, 'ada@example.com')).status, 200);
  const setup = new Database(s.paths.db);
  setup.prepare('UPDATE "user" SET emailVerified = 1 WHERE email = ?').run('ada@example.com');
  setup.close();
  const signedIn = await signIn(s.base, 'ada@example.com');
  assert.equal(signedIn.status, 200);
  const cookie = signedIn.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');

  const out = path.join(tmp(), 'export');
  assert.equal((await cli(s.paths.root, 'export', out)).code, 0);
  const secret = readFileSync(s.paths.secret);

  const moved = path.join(tmp(), 'somewhere', 'else'); // doesn't exist yet: import creates it
  const r = await cli(moved, 'import', out);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(readFileSync(path.join(moved, 'secret')).equals(secret), 'the secret was not restored'); // never print it
  assert.equal(mode(path.join(moved, 'secret')), 0o600);
  assert.equal(mode(path.join(moved, 'authwapi.db')), 0o600);
  assert.equal(mode(moved), 0o700);

  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const restored = await start({ BASE_URL: base, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: moved });
  servers.push({ stop: restored.close });
  // The session survives the move: its cookie is signed with the restored secret.
  const session = await (await fetch(`${base}/api/auth/get-session`, { headers: { cookie, origin: base } })).json();
  assert.equal(session?.user?.email, 'ada@example.com');
  assert.equal((await signIn(base, 'ada@example.com')).status, 200);
  assert.equal((await signIn(base, 'ada@example.com', 'wrong password')).status, 401);
});

test('export refuses a target folder that is not empty, and leaves it alone', async () => {
  const s = await server();
  const out = tmp();
  writeFileSync(path.join(out, 'keep.txt'), 'mine');
  const r = await cli(s.paths.root, 'export', out);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /not empty/);
  assert.deepEqual(readdirSync(out), ['keep.txt']);
});

test('export refuses a data folder with no database', async () => {
  const r = await cli(tmp(), 'export', path.join(tmp(), 'export'));
  assert.equal(r.code, 1);
  assert.match(r.stderr, /No database/);
});

test('import refuses a data folder that already has a database, and changes nothing', async () => {
  const s = await server();
  const out = path.join(tmp(), 'export');
  assert.equal((await cli(s.paths.root, 'export', out)).code, 0);
  const before = readFileSync(s.paths.db);
  const r = await cli(s.paths.root, 'import', out);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /already has a database/);
  assert.ok(readFileSync(s.paths.db).equals(before));
});

test('import refuses an export whose database fails integrity_check, and copies nothing', async () => {
  const s = await server();
  const out = path.join(tmp(), 'export');
  assert.equal((await cli(s.paths.root, 'export', out)).code, 0);
  // Overwrite the middle of the file (past the header page) with junk.
  const file = path.join(out, 'authwapi.db');
  const fd = openSync(file, 'r+');
  writeSync(fd, Buffer.alloc(8192, 0xab), 0, 8192, Math.floor(statSync(file).size / 2));
  closeSync(fd);

  const target = path.join(tmp(), 'new');
  const r = await cli(target, 'import', out);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /integrity/);
  assert.ok(!existsSync(path.join(target, 'authwapi.db')) && !existsSync(path.join(target, 'secret')));
});

test('import refuses a folder that is not an export', async () => {
  const src = tmp();
  mkdirSync(path.join(src, 'logs'));
  const r = await cli(path.join(tmp(), 'new'), 'import', src);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /not an AuthWAPI export/);
});
