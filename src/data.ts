// The data folder layout. Everything AuthWAPI keeps lives under one directory.
import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { accessSync, chmodSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export interface DataPaths {
  root: string;
  db: string;
  secret: string;
  schema: string;
  logs: string;
  outbox: string;
  migrations: string; // copies of applied migrations
  backups: string;
}

export function dataPaths(root: string): DataPaths {
  return {
    root,
    db: path.join(root, 'authwapi.db'),
    secret: path.join(root, 'secret'),
    schema: path.join(root, 'schema.sql'),
    logs: path.join(root, 'logs'),
    outbox: path.join(root, 'outbox'),
    migrations: path.join(root, 'migrations'),
    backups: path.join(root, 'backups'),
  };
}

export function prepareDataDir(dataDir: string): DataPaths {
  // resolve() drops a trailing slash, which would otherwise make lstat look through a symlinked root.
  const root = path.resolve(dataDir);
  const p = dataPaths(root);
  // Refuse symlinks before creating anything, so nothing is made inside a link's target.
  for (const dir of [p.root, p.logs, p.outbox, p.migrations, p.backups]) {
    if (existsSync(dir) && lstatSync(dir).isSymbolicLink()) throw new Error(`${dir} is a symlink; AuthWAPI won't follow it`);
  }
  try {
    mkdirSync(root, { recursive: true });
    accessSync(root, constants.W_OK);
  } catch (err) {
    throw new Error(
      `Data folder ${root} is not writable by uid ${process.getuid?.()}. ` +
        'Rootless podman: add --userns=keep-id. On SELinux (Fedora, RHEL), add :Z to the volume (-v "$PWD/authwapi-data:/data:Z"). ' +
        'Otherwise make the folder owned by PUID:PGID.',
      { cause: err }
    );
  }
  for (const dir of [p.logs, p.outbox, p.migrations, p.backups]) mkdirSync(dir, { recursive: true, mode: 0o700 });
  makePrivate(p);
  return p;
}

/**
 * The database holds password hashes and session tokens, so nothing in the folder may be readable by
 * other users, even when the host folder is traversable or was restored with loose permissions.
 * Folders become 0700 and files 0600. A symlink at the top level of any of these folders stops the server:
 * that's where every file AuthWAPI opens lives (by fixed path), and a planted link would redirect those reads
 * and writes outside the folder. AuthWAPI never creates or opens anything deeper, so deeper entries are left alone.
 */
function makePrivate(p: DataPaths): void {
  for (const dir of [p.root, p.logs, p.outbox, p.migrations, p.backups]) {
    if (lstatSync(dir).isSymbolicLink()) throw new Error(`${dir} is a symlink; AuthWAPI won't follow it`);
    chmodSync(dir, 0o700);
    for (const name of readdirSync(dir)) {
      const file = path.join(dir, name);
      const st = lstatSync(file);
      if (st.isSymbolicLink()) throw new Error(`${file} is a symlink; AuthWAPI won't follow links in its data folder`);
      if (st.isFile()) chmodSync(file, 0o600);
    }
  }
}

/** The instance secret: created once on first boot (mode 0600), then reused. */
export function loadOrCreateSecret(file: string): string {
  if (!existsSync(file)) {
    writeFileSync(file, randomBytes(32).toString('base64url'), { mode: 0o600, flag: 'wx' });
  }
  chmodSync(file, 0o600);
  const secret = readFileSync(file, 'utf8').trim();
  if (secret.length < 32) throw new Error(`Secret file ${file} is shorter than 32 characters`);
  return secret;
}

/**
 * `authwapi export <dir>`: the database and the secret, which is everything a new data folder needs. Safe while
 * the server runs: the database is read through SQLite's online backup API, never copied as a file.
 * Left behind on purpose: schema.sql and migrations/ (rebuilt on every boot), backups/ (pre-upgrade copies of
 * this instance), logs/ (this instance's history; a copy taken mid-append can cut a line), and outbox/ (live
 * sign-in links that expire within a day; an export folder shouldn't carry working credentials around).
 */
export async function exportData(p: DataPaths, dir: string): Promise<string> {
  const out = path.resolve(dir);
  if (existsSync(out) && readdirSync(out).length > 0) throw new Error(`${out} is not empty; export into a new or empty folder`);
  mkdirSync(out, { recursive: true, mode: 0o700 });
  chmodSync(out, 0o700); // an existing empty folder keeps its own mode otherwise
  const secret = path.join(out, 'secret');
  copyFileSync(p.secret, secret, constants.COPYFILE_EXCL);
  chmodSync(secret, 0o600); // copyFileSync keeps the source's mode, not the umask
  const db = new Database(p.db, { readonly: true, fileMustExist: true });
  try {
    db.pragma('busy_timeout = 5000'); // wait out the server's write lock rather than fail
    // By default the backup copies 100 pages per step, and a write by the server between steps restarts it.
    // Asking for every page in the next step copies the whole database under one read lock: one snapshot.
    await db.backup(path.join(out, 'authwapi.db'), { progress: () => 0x7fffffff });
  } finally {
    db.close();
  }
  chmodSync(path.join(out, 'authwapi.db'), 0o600);
  checkIntegrity(path.join(out, 'authwapi.db'));
  return out;
}

/**
 * `authwapi import <dir>`: restores an export into a data folder that has no database yet. A server running on
 * a folder has a database in it, so the refusal also keeps import away from a running server.
 */
export function importData(dataDir: string, dir: string): DataPaths {
  const from = dataPaths(path.resolve(dir));
  if (!existsSync(from.db) || !existsSync(from.secret)) {
    throw new Error(`${from.root} is not an AuthWAPI export: it needs authwapi.db and secret`);
  }
  checkIntegrity(from.db); // before anything is created in the data folder
  const p = prepareDataDir(dataDir);
  for (const file of [p.db, p.secret]) {
    if (existsSync(file)) throw new Error(`${p.root} already has a database or secret; import only into a new or empty data folder`);
  }
  // The secret first, so a database never sits in the folder without it. EXCL: never overwrite.
  copyFileSync(from.secret, p.secret, constants.COPYFILE_EXCL);
  chmodSync(p.secret, 0o600);
  copyFileSync(from.db, p.db, constants.COPYFILE_EXCL);
  chmodSync(p.db, 0o600);
  checkIntegrity(p.db); // the copy is what the server will boot from
  return p;
}

function checkIntegrity(file: string): void {
  let result: unknown;
  try {
    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      result = db.pragma('integrity_check', { simple: true });
    } finally {
      db.close();
    }
  } catch (err) {
    throw new Error(`${file} failed the integrity check: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
  }
  if (result !== 'ok') throw new Error(`${file} failed the integrity check: ${String(result)}`);
}
