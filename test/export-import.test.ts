// `authwapi export` / `import` (plan D6): moving the data folder, including while the server runs.
// The CLI runs as its own process, as an operator would run it, against real servers on temp folders.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, writeSync } from 'node:fs';
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

const run = async (file: string, args: string[], env: NodeJS.ProcessEnv) => {
  try {
    const { stdout, stderr } = await promisify(execFile)(file, args, { env: { PATH: process.env.PATH, ...env } });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code: number; stdout: string; stderr: string };
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
};
const cli = (dataDir: string, ...args: string[]) => run(process.execPath, ['src/cli.ts', ...args], { DATA_DIR: dataDir });

/** An export of a fresh server's data folder (the server is stopped afterwards). */
async function freshExport(): Promise<string> {
  const s = await server();
  const out = path.join(tmp(), 'export');
  assert.equal((await cli(s.paths.root, 'export', out)).code, 0);
  return out;
}

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
  // Import needs only DATA_DIR: settings the server checks at boot (here, a broken BASE_URL) don't block a restore.
  const r = await run(process.execPath, ['src/cli.ts', 'import', out], { DATA_DIR: moved, BASE_URL: 'not a url' });
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

test('export fails cleanly when the database stays locked: no folder is left behind, so a retry works', async () => {
  const s = await server();
  const lock = new Database(s.paths.db);
  lock.exec('BEGIN EXCLUSIVE'); // held past export's 5s busy timeout
  const out = path.join(tmp(), 'export');
  try {
    const r = await cli(s.paths.root, 'export', out);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /copied nothing.*busy.*retry/);
  } finally {
    lock.exec('ROLLBACK');
    lock.close();
  }
  assert.ok(!existsSync(out), 'the failed export left its folder behind');
  assert.equal((await cli(s.paths.root, 'export', out)).code, 0);
});

test('export refuses a database that is not an AuthWAPI database, and leaves nothing behind', async () => {
  const data = tmp();
  writeFileSync(path.join(data, 'secret'), 's'.repeat(43));
  const other = new Database(path.join(data, 'authwapi.db'));
  other.exec('CREATE TABLE notes (body TEXT)');
  other.close();
  const out = path.join(tmp(), 'export');
  const r = await run(process.execPath, ['src/cli.ts', 'export', out], { DATA_DIR: data, BASE_URL: 'not a url' });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /_authwapi_migrations/);
  assert.ok(!existsSync(out));
});

test('import refuses an empty or foreign database, or a short secret, before creating anything', async () => {
  const cases: [string, (out: string) => void, RegExp][] = [
    ['an empty database file', (out) => writeFileSync(path.join(out, 'authwapi.db'), ''), /_authwapi_migrations/],
    [
      'a database from some other app',
      (out) => {
        rmSync(path.join(out, 'authwapi.db'));
        const db = new Database(path.join(out, 'authwapi.db'));
        db.exec('CREATE TABLE notes (body TEXT)');
        db.close();
      },
      /_authwapi_migrations/,
    ],
    ['a short secret', (out) => writeFileSync(path.join(out, 'secret'), 'short\n'), /shorter than 32/],
  ];
  for (const [what, spoil, reason] of cases) {
    const out = await freshExport();
    spoil(out);
    const target = path.join(tmp(), 'new');
    const r = await cli(target, 'import', out);
    assert.equal(r.code, 1, what);
    assert.match(r.stderr, reason, what);
    assert.ok(!existsSync(target), `${what}: import created ${target}`);
  }
});

test('an import that fails mid-copy removes what it wrote, so a retry works', async () => {
  const out = await freshExport();
  const target = path.join(tmp(), 'new');
  // A file-size limit makes the database copy fail with EFBIG (Node ignores SIGXFSZ) after the folder exists.
  const r = await run('/bin/sh', ['-c', 'ulimit -f 8; exec "$0" "$@"', process.execPath, 'src/cli.ts', 'import', out], { DATA_DIR: target });
  assert.equal(r.code, 1, r.stderr);
  assert.match(r.stderr, /EFBIG|too large/);
  assert.deepEqual(readdirSync(target).filter((f) => statSync(path.join(target, f)).isFile()), []);
  const retry = await cli(target, 'import', out);
  assert.equal(retry.code, 0, retry.stderr);
});

test('a refused import changes nothing in the data folder, modes included; a dangling link counts as a file', async () => {
  const out = await freshExport();
  const data = tmp();
  writeFileSync(path.join(data, 'authwapi.db'), 'mine');
  chmodSync(path.join(data, 'authwapi.db'), 0o644);
  chmodSync(data, 0o755);
  const r = await cli(data, 'import', out);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /already has a database/);
  assert.deepEqual(readdirSync(data), ['authwapi.db']);
  assert.equal(mode(data), 0o755);
  assert.equal(mode(path.join(data, 'authwapi.db')), 0o644);
  assert.equal(readFileSync(path.join(data, 'authwapi.db'), 'utf8'), 'mine');

  const linked = tmp();
  symlinkSync(path.join(linked, 'nowhere'), path.join(linked, 'secret'));
  const r2 = await cli(linked, 'import', out);
  assert.equal(r2.code, 1);
  assert.match(r2.stderr, /already has a database or secret/);
  assert.deepEqual(readdirSync(linked), ['secret']);
});

test('import refuses to run as root, which would leave files the server cannot read', async () => {
  const out = await freshExport();
  const target = path.join(tmp(), 'new');
  const asRoot = 'data:text/javascript,process.getuid=()=>0';
  const r = await run(process.execPath, ['--import', asRoot, 'src/cli.ts', 'import', out], { DATA_DIR: target });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /as root.*--user/);
  assert.ok(!existsSync(target));
});

test('a failed export removes only what it wrote: a file someone else adds meanwhile stays', async () => {
  const s = await server();
  const lock = new Database(s.paths.db);
  lock.exec('BEGIN EXCLUSIVE'); // the export waits 5s on it, then fails
  const out = path.join(tmp(), 'export');
  try {
    let exited = false;
    const running = cli(s.paths.root, 'export', out).finally(() => (exited = true));
    const deadline = Date.now() + 4000; // well inside export's 5s busy wait
    while (!exited && Date.now() < deadline && !existsSync(path.join(out, 'authwapi.db'))) await new Promise((r) => setTimeout(r, 20));
    if (!existsSync(path.join(out, 'authwapi.db'))) assert.fail(`export never created its copy: ${(await running).stderr}`);
    writeFileSync(path.join(out, 'theirs.txt'), 'not the export');
    const r = await running;
    assert.equal(r.code, 1);
    assert.match(r.stderr, /busy/);
  } finally {
    lock.exec('ROLLBACK');
    lock.close();
  }
  assert.deepEqual(readdirSync(out), ['theirs.txt']);
});

test('export refuses a target among the data folder\'s own files, but a new folder at its top level is fine', async () => {
  const s = await server();
  for (const target of [s.paths.root, path.join(s.paths.backups, 'export'), path.join(s.paths.logs, 'a', 'b')]) {
    const r = await cli(s.paths.root, 'export', target);
    assert.equal(r.code, 1, target);
    assert.match(r.stderr, /data folder/, target);
  }
  assert.deepEqual(readdirSync(s.paths.backups), []);
  assert.deepEqual(readdirSync(s.paths.logs).filter((f) => f === 'a'), []);
  const r = await cli(s.paths.root, 'export', path.join(s.paths.root, 'export-1')); // the README's docker exec example
  assert.equal(r.code, 0, r.stderr);
});

test('two imports into the same folder at once: exactly one succeeds and the folder ends complete', async () => {
  const out = await freshExport();
  const secret = readFileSync(path.join(out, 'secret'));
  for (let round = 0; round < 5; round++) {
    const target = path.join(tmp(), 'new');
    const results = await Promise.all([cli(target, 'import', out), cli(target, 'import', out)]);
    assert.deepEqual(results.map((r) => r.code).sort(), [0, 1], results.map((r) => r.stderr).join('\n'));
    const loser = results.find((r) => r.code === 1)!.stderr;
    assert.match(loser, /another import|already has a database/);
    assert.doesNotMatch(loser, /delete the folder/); // that would destroy the winner's result
    if (/another import/.test(loser)) assert.match(loser, /fresh, empty folder/);
    assert.ok(readFileSync(path.join(target, 'secret')).equals(secret), 'the secret is missing or wrong');
    assert.equal(integrity(path.join(target, 'authwapi.db')), 'ok');
    assert.deepEqual(readdirSync(target).filter((f) => f.startsWith('.import')), []);
  }
});

test('import never reads the whole database into memory (a large database would not fit in one buffer)', async () => {
  const out = await freshExport();
  const target = path.join(tmp(), 'new');
  // Make any whole-file read of a .db fail inside the CLI process.
  const guard = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
    const readFileSync = fs.readFileSync;
    fs.readFileSync = (file, ...rest) => {
      if (String(file).endsWith('.db')) throw new Error('read a whole database into memory');
      return readFileSync(file, ...rest);
    };
    syncBuiltinESMExports();`;
  const r = await run(process.execPath, ['--import', `data:text/javascript,${encodeURIComponent(guard)}`, 'src/cli.ts', 'import', out], { DATA_DIR: target });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(integrity(path.join(target, 'authwapi.db')), 'ok');
});

test('export refuses the data folder\'s own files however the path is spelled: ..names and symlinks', async () => {
  const s = await server();
  const link = path.join(tmp(), 'link');
  symlinkSync(s.paths.logs, link);
  for (const target of [path.join(s.paths.logs, '..snapshot'), path.join(link, 'export')]) {
    const r = await cli(s.paths.root, 'export', target);
    assert.equal(r.code, 1, target);
    assert.match(r.stderr, /data folder/, target);
  }
  assert.deepEqual(readdirSync(s.paths.logs).filter((f) => f !== 'app.jsonl'), []);
});
