// Reads an AuthWAPI database for scripts/upgrade-check.sh, inside a container (the host may have no SQLite).
// Prints JSON for the caller to compare; the output includes password and client-secret hashes, so never print it.
//   node check-db.mjs dump <db>                     schema and every row
//   node check-db.mjs rows <db> <email> <client-id> the user, credential account, OAuth client and sessions
import { DatabaseSync } from 'node:sqlite';

const [mode, file, email, clientId] = process.argv.slice(2);
const db = new DatabaseSync(file, { readOnly: true });
const check = db.prepare('PRAGMA quick_check').all();
if (check.length !== 1 || check[0].quick_check !== 'ok') {
  console.error('database failed PRAGMA quick_check');
  process.exit(1);
}

let out;
if (mode === 'dump') {
  // SQLite's online backup can change internal page metadata, so compare schema and rows, not bytes.
  const schema = db.prepare('SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name').all();
  const tables = Object.fromEntries(schema.filter((s) => s.type === 'table' && !s.name.startsWith('sqlite_'))
    .map((s) => [s.name, db.prepare(`SELECT * FROM "${s.name}" ORDER BY rowid`).all()]));
  out = { schema, tables };
} else if (mode === 'rows') {
  // Fixed columns, so columns added by later migrations don't count as a difference.
  const user = db.prepare('SELECT id, name, email, emailVerified, image, createdAt, updatedAt FROM user WHERE email = ?')
    .all(email);
  const userId = user[0]?.id ?? null;
  out = {
    user,
    account: db.prepare(`SELECT id, accountId, providerId, userId, password, createdAt, updatedAt FROM account
      WHERE userId = ? AND providerId = 'credential'`).all(userId),
    oauthClient: db.prepare(`SELECT id, clientId, clientSecret, name, userId, redirectUris, scopes, grantTypes,
      responseTypes, tokenEndpointAuthMethod, requirePKCE, disabled, createdAt FROM oauthClient WHERE clientId = ?`)
      .all(clientId),
    session: db.prepare('SELECT id, token, userId, expiresAt, createdAt FROM session WHERE userId = ? ORDER BY id')
      .all(userId),
  };
  for (const [table, rows] of Object.entries(out)) {
    if (rows.length === 0) {
      console.error(`no ${table} row for the check user or client`);
      process.exit(1);
    }
  }
} else {
  console.error('usage: check-db.mjs dump <db> | rows <db> <email> <client-id>');
  process.exit(2);
}
process.stdout.write(`${JSON.stringify(out)}\n`);
