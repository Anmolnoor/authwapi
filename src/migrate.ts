// Applies migrations/NNNN_name.sql in order, all pending ones in ONE transaction (SQLite DDL is
// transactional): an upgrade either fully applies or leaves the database exactly as it was, and the
// server stops. Before upgrading an existing database, a backup of it and the secret goes to <data>/backups.
import { chmodSync, copyFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import type { DataPaths } from './data.ts';
import type { Logger } from './log.ts';

export const MIGRATIONS_DIR = new URL('../migrations/', import.meta.url).pathname;
const FILE = /^\d{4}_[a-z0-9_]+\.sql$/;

export async function migrate(db: Database.Database, dir: string, paths: DataPaths, log: Logger): Promise<string[]> {
  db.exec('CREATE TABLE IF NOT EXISTS _authwapi_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)');
  const applied = new Set(db.prepare('SELECT name FROM _authwapi_migrations').pluck().all() as string[]);
  const files = readdirSync(dir).filter((f) => FILE.test(f)).sort();
  for (const name of applied) {
    if (!files.includes(name)) {
      throw new Error(`Database has migration ${name}, which this image doesn't know: it was made by a newer AuthWAPI.`);
    }
  }
  const pending = files.filter((f) => !applied.has(f));

  let backup: string | undefined;
  if (pending.length > 0 && applied.size > 0) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    backup = path.join(paths.backups, `before-${pending[0].replace('.sql', '')}-${stamp}`);
    await db.backup(`${backup}.db`);
    copyFileSync(paths.secret, `${backup}.secret`);
    log('info', 'backed up database before migrating', { backup: `${backup}.db` });
  }

  const record = db.prepare('INSERT INTO _authwapi_migrations (name, applied_at) VALUES (?, ?)');
  let current = '';
  try {
    db.transaction(() => {
      for (const name of pending) {
        current = name;
        db.exec(readFileSync(path.join(dir, name), 'utf8'));
        record.run(name, new Date().toISOString());
      }
    })();
  } catch (err) {
    const where = backup ? ` A backup from before the upgrade is at ${backup}.db.` : '';
    throw new Error(`Migration ${current} failed, so the whole upgrade was rolled back; the database is unchanged.${where}`, {
      cause: err,
    });
  }
  for (const name of pending) log('info', 'applied migration', { name });

  // Keep <data>/migrations a complete copy of what this database has applied (also repairs a copy lost
  // to a crash between commit and copy).
  for (const name of files.filter((f) => applied.has(f) || pending.includes(f))) {
    const copy = path.join(paths.migrations, name);
    if (!existsSync(copy)) {
      copyFileSync(path.join(dir, name), copy);
      chmodSync(copy, 0o600); // copyFileSync keeps the source's mode, not the umask
    }
  }
  writeFileSync(paths.schema, schemaSql(db));
  return pending;
}

/** The current schema as SQL, written to <data>/schema.sql after every boot. */
export function schemaSql(db: Database.Database): string {
  const rows = db
    .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type DESC, name")
    .pluck()
    .all() as string[];
  return rows.map((s) => `${s};`).join('\n\n') + '\n';
}
