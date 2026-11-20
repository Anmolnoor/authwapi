// The data folder layout. Everything AuthWAPI keeps lives under one directory.
import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import {
  accessSync, chmodSync, closeSync, constants, copyFileSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync,
  readFileSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
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
  return readSecret(file);
}

function readSecret(file: string): string {
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
  const made = mkdirSync(out, { recursive: true, mode: 0o700 }); // the first folder this call created, if any
  try {
    chmodSync(out, 0o700); // an existing empty folder keeps its own mode otherwise
    const secret = path.join(out, 'secret');
    copyFileSync(p.secret, secret, constants.COPYFILE_EXCL);
    chmodSync(secret, 0o600); // copyFileSync keeps the source's mode, not the umask
    const copy = path.join(out, 'authwapi.db');
    const db = new Database(p.db, { readonly: true, fileMustExist: true });
    let pages: number;
    try {
      db.pragma('busy_timeout = 5000'); // wait out the server's write lock rather than fail
      // By default the backup copies 100 pages per step, and a write by the server between steps restarts it.
      // Asking for every page in the next step copies the whole database under one read lock: one snapshot.
      ({ totalPages: pages } = await db.backup(copy, { progress: () => 0x7fffffff }));
    } finally {
      db.close();
    }
    // If the first step can't get a read lock within the busy timeout, better-sqlite3 resolves with 0 pages and
    // deletes the copy instead of failing. An empty database file looks the same.
    if (pages === 0) throw new Error(`The backup of ${p.db} copied nothing (the database was busy, or is empty); retry`);
    chmodSync(copy, 0o600);
    checkDb(copy);
    return out;
  } catch (err) {
    // Undo this call, so the folder isn't left half-written and a retry isn't refused as "not empty".
    if (made) rmSync(made, { recursive: true, force: true });
    else for (const name of readdirSync(out)) rmSync(path.join(out, name), { recursive: true, force: true }); // it was empty
    throw err;
  }
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
  readSecret(from.secret); // the server's own check at boot
  checkDb(from.db);
  // Refuse before touching the data folder at all. lstat, so a dangling link counts as taken too.
  const target = dataPaths(path.resolve(dataDir));
  for (const file of [target.db, target.secret]) {
    if (lstatSync(file, { throwIfNoEntry: false })) {
      throw new Error(`${target.root} already has a database or secret; import only into a new or empty data folder`);
    }
  }
  const p = prepareDataDir(dataDir);
  // Stage both files under temporary names and check the staged database. Then rename the database first and the
  // secret last: a crash in between never leaves a secret-only folder, which would boot an empty instance and
  // refuse a retry. A crashed import's staged files are simply overwritten by the next one.
  const staged = { db: path.join(p.root, '.import.db'), secret: path.join(p.root, '.import.secret') };
  try {
    for (const [src, dst] of [[from.db, staged.db], [from.secret, staged.secret]]) {
      copyFileSync(src, dst);
      chmodSync(dst, 0o600); // copyFileSync keeps the source's mode, not the umask
      fsync(dst); // on disk before a rename makes it visible
    }
    checkDb(staged.db);
    renameSync(staged.db, p.db);
    renameSync(staged.secret, p.secret);
    fsync(p.root); // the renames themselves
  } catch (err) {
    // None of these existed before this call (checked above), so removing them undoes it and a retry works.
    for (const file of [staged.db, staged.secret, p.db, p.secret]) rmSync(file, { force: true });
    throw err;
  }
  return p;
}

function fsync(file: string): void {
  const fd = openSync(file, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Passes PRAGMA integrity_check and has had at least one AuthWAPI migration (an empty file passes the check). */
function checkDb(file: string): void {
  let result: unknown;
  let migrations = 0;
  try {
    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      result = db.pragma('integrity_check', { simple: true });
      const table = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_authwapi_migrations'").get();
      if (result === 'ok' && table) migrations = db.prepare('SELECT count(*) FROM _authwapi_migrations').pluck().get() as number;
    } finally {
      db.close();
    }
  } catch (err) {
    throw new Error(`${file} failed the integrity check: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
  }
  if (result !== 'ok') throw new Error(`${file} failed the integrity check: ${String(result)}`);
  if (migrations === 0) throw new Error(`${file} is not an AuthWAPI database: its _authwapi_migrations table is missing or empty`);
}
