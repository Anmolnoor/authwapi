import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { getMigrations } from 'better-auth/db/migration';
import { authOptions } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { loadOrCreateSecret, prepareDataDir } from '../src/data.ts';
import { openDb } from '../src/db.ts';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';

const silent = () => {};
const tmps: string[] = [];
const tmp = () => {
  const d = mkdtempSync(path.join(tmpdir(), 'authwapi-mig-'));
  tmps.push(d);
  return d;
};
afterEach(() => tmps.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

test('fresh install applies every migration once and writes schema.sql', async () => {
  const paths = prepareDataDir(tmp());
  const db = openDb(paths.db);
  assert.deepEqual(await migrate(db, MIGRATIONS_DIR, paths, silent), readdirSync(MIGRATIONS_DIR).sort());
  assert.deepEqual(await migrate(db, MIGRATIONS_DIR, paths, silent), []);
  assert.match(readFileSync(paths.schema, 'utf8'), /CREATE TABLE "user"/);
  assert.equal(db.pragma('journal_mode', { simple: true }), 'delete');
  assert.deepEqual(readdirSync(paths.backups), []); // nothing to back up on a fresh install
  db.close();
});

test('committed migrations match the schema Better Auth expects (run scripts/new-migration.ts if this fails)', async () => {
  const paths = prepareDataDir(tmp());
  const db = openDb(paths.db);
  await migrate(db, MIGRATIONS_DIR, paths, silent);
  const plan = await getMigrations(
    authOptions({ config: loadConfig({ DATA_DIR: paths.root }), db, secret: 'x'.repeat(32), sendMail: async () => {} })
  );
  assert.deepEqual(
    { create: plan.toBeCreated.length, add: plan.toBeAdded.length, indexes: plan.toBeAddedIndexes.length },
    { create: 0, add: 0, indexes: 0 }
  );
  db.close();
});

test('an upgrade whose second migration fails rolls back entirely and names the backup', async () => {
  const dir = tmp();
  for (const f of readdirSync(MIGRATIONS_DIR)) copyFileSync(path.join(MIGRATIONS_DIR, f), path.join(dir, f));
  const paths = prepareDataDir(tmp());
  loadOrCreateSecret(paths.secret);
  const db = openDb(paths.db);
  await migrate(db, dir, paths, silent);

  writeFileSync(path.join(dir, '9998_good.sql'), 'create table good_step (id text);');
  writeFileSync(path.join(dir, '9999_bad.sql'), 'create table half_done (id text);\nthis is not sql;');
  await assert.rejects(migrate(db, dir, paths, silent), /9999_bad\.sql failed, so the whole upgrade was rolled back.*backups/);
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").pluck().all();
  assert.ok(!tables.includes('good_step') && !tables.includes('half_done'), tables.join());
  assert.equal(db.prepare("SELECT count(*) FROM _authwapi_migrations WHERE name LIKE '999%'").pluck().get(), 0);
  const backups = readdirSync(paths.backups);
  assert.ok(backups.some((f) => f.endsWith('.db')) && backups.some((f) => f.endsWith('.secret')), backups.join());
  db.close();
});

test('a lost copy in <data>/migrations is restored on the next boot', async () => {
  const paths = prepareDataDir(tmp());
  const db = openDb(paths.db);
  await migrate(db, MIGRATIONS_DIR, paths, silent);
  const [first] = readdirSync(paths.migrations);
  rmSync(path.join(paths.migrations, first));
  await migrate(db, MIGRATIONS_DIR, paths, silent);
  assert.ok(readdirSync(paths.migrations).includes(first));
  db.close();
});

test('a database from a newer AuthWAPI is refused', async () => {
  const paths = prepareDataDir(tmp());
  const db = openDb(paths.db);
  await migrate(db, MIGRATIONS_DIR, paths, silent);
  db.prepare('INSERT INTO _authwapi_migrations VALUES (?, ?)').run('9000_future.sql', new Date().toISOString());
  await assert.rejects(migrate(db, MIGRATIONS_DIR, paths, silent), /made by a newer AuthWAPI/);
  db.close();
});
