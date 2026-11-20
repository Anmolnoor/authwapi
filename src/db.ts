import Database from 'better-sqlite3';
import { chmodSync } from 'node:fs';

// DELETE journal, not WAL: WAL needs shared memory on one host and has corrupted databases on
// Docker Desktop bind mounts (virtiofs). AuthWAPI is the only writer, so WAL's concurrency isn't needed.
export function openDb(file: string): Database.Database {
  const db = new Database(file);
  chmodSync(file, 0o600); // the process umask (077) covers new files; this covers a restored one
  db.pragma('journal_mode = DELETE');
  db.pragma('synchronous = FULL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return db;
}
