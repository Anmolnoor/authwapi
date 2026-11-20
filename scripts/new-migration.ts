// Usage: node scripts/new-migration.ts <name>
// Applies every existing migration to a fresh database, then asks Better Auth what's missing
// (the same plan `auth generate` prints) and writes it as the next numbered migration.
import { getMigrations } from 'better-auth/db/migration';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { authOptions } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { prepareDataDir } from '../src/data.ts';
import { openDb } from '../src/db.ts';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';

const name = process.argv[2];
if (!name || !/^[a-z0-9_]+$/.test(name)) {
  console.error('Usage: node scripts/new-migration.ts <name>   (lowercase letters, digits, _)');
  process.exit(1);
}

const tmp = mkdtempSync(path.join(tmpdir(), 'authwapi-migration-'));
try {
  const paths = prepareDataDir(tmp);
  const db = openDb(paths.db);
  await migrate(db, MIGRATIONS_DIR, paths, () => {});
  const options = authOptions({
    config: loadConfig({ DATA_DIR: tmp }),
    db,
    secret: 'x'.repeat(32),
    sendMail: async () => {},
  });
  const plan = await getMigrations(options);
  const changes = plan.toBeCreated.length + plan.toBeAdded.length + plan.toBeAddedIndexes.length;
  const sql = changes > 0 ? (await plan.compileMigrations()).trim() : '';
  db.close();
  if (plan.unsafeChanges.length > 0) {
    throw new Error(`Better Auth refused unsafe changes:\n${plan.unsafeChanges.join('\n')}`);
  }
  if (!sql) {
    console.log('No schema changes; nothing written.');
  } else {
    const next = readdirSync(MIGRATIONS_DIR).filter((f) => /^\d{4}_/.test(f)).length + 1;
    const file = path.join(MIGRATIONS_DIR, `${String(next).padStart(4, '0')}_${name}.sql`);
    writeFileSync(file, sql + '\n');
    console.log(`Wrote ${file}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
