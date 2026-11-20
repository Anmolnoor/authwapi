// The data folder layout. Everything AuthWAPI keeps lives under one directory.
import { randomBytes } from 'node:crypto';
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export interface DataPaths {
  root: string;
  db: string;
  secret: string;
  bootstrapKey: string; // one-time admin key (src/admin.ts); deleted once spent
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
    bootstrapKey: path.join(root, 'bootstrap-admin-key'),
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
