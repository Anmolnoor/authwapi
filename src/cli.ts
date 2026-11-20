// Operator CLI, on the same data folder as the server (DATA_DIR). Registers OAuth clients (dynamic registration
// is off), reissues the admin MCP bootstrap key, and moves the data folder:
//   node src/cli.ts clients create --name <name> --redirect-uri <uri> [--redirect-uri <uri> ...] [--resource <uri> ...]
//   node src/cli.ts clients list
//   node src/cli.ts resource add <url>
//   node src/cli.ts resource link <client_id> <resource>
//   node src/cli.ts resource unlink <client_id> <resource>
//   node src/cli.ts bootstrap-key
//   node src/cli.ts export <dir>    (safe while the server runs)
//   node src/cli.ts import <dir>    (into a data folder with no database; then start the server)
// In the container: docker exec authwapi node src/cli.ts ...
// The client secret is printed once, to stdout, and stored only as a hash. It never goes to the log.
import { validateClientIdUrl } from '@better-auth/cimd';
import type { oauthProvider } from '@better-auth/oauth-provider';
import { betterAuth, type InferAPI } from 'better-auth';
import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { reissueBootstrapKey } from './admin.ts';
import { authOptions } from './auth.ts';
import { loadConfig } from './config.ts';
import { dataPaths, exportData, importData, loadOrCreateSecret, prepareDataDir, type DataPaths } from './data.ts';
import { openDb } from './db.ts';
import { createLogger } from './log.ts';
import { MIGRATIONS_DIR } from './migrate.ts';

const USAGE = `Usage:
  node src/cli.ts clients create --name <name> --redirect-uri <uri> [--redirect-uri <uri> ...] [--resource <uri> ...]
  node src/cli.ts clients list
  node src/cli.ts resource add <url>
  node src/cli.ts resource link <client_id> <resource>
  node src/cli.ts resource unlink <client_id> <resource>
  node src/cli.ts bootstrap-key
  node src/cli.ts export <dir>
  node src/cli.ts import <dir>

export copies the database and secret of DATA_DIR into <dir> (new or empty), safely while the server runs.
import restores such a folder into DATA_DIR, which must not have a database yet; then start the server on it.

--resource names an API the app may request access tokens for (RFC 8707). Tokens requested with
resource=<uri> are JWTs with aud=<uri>. A resource that doesn't exist yet is created.

resource add registers an API or MCP server (its URL, exactly as clients send it in resource=).
resource link lets a client get tokens for it. For an MCP client the client_id is the https URL of its
Client ID Metadata Document; AuthWAPI fetches that document only after it is linked, when a user signs in.
resource unlink takes that away; an MCP client linked to no resource is refused at once (no sign-in, no refresh).

bootstrap-key writes a new one-time admin MCP key to bootstrap-admin-key in the data folder (valid 24 hours)
and revokes any unused earlier one. Use it when the bootstrap key is lost or expired, or no write key is left.`;

class UsageError extends Error {}

/** authOptions() is typed as plain BetterAuthOptions, so auth.api doesn't list the oauth-provider endpoints. */
type OAuthAdminApi = InferAPI<ReturnType<typeof oauthProvider>['endpoints']>;

async function main(argv: string[]): Promise<void> {
  const [group, command, ...rest] = argv;
  if (group === 'export' || group === 'import') {
    if (!command || rest.length > 0) throw new UsageError(`${group} takes one folder`);
    process.umask(0o077);
    // Only DATA_DIR, not loadConfig(): a restore shouldn't be blocked by mail or BASE_URL settings.
    const dataDir = process.env.DATA_DIR ?? '/data';
    if (group === 'import') {
      if (process.getuid?.() === 0) {
        throw new Error(
          "import won't run as root: the server never runs as root and couldn't read the files. " +
            'Run it as the data folder\'s owner, e.g. docker run --user "$(id -u):$(id -g)" ...'
        );
      }
      const paths = importData(dataDir, command);
      console.log(`Imported ${path.resolve(command)} into ${paths.root}. Start the server on that data folder.`);
      return;
    }
    const out = await exportData(findDataFolder(dataDir), command);
    console.log(`Exported ${path.resolve(dataDir)} to ${out}. It holds the instance secret: keep it private.`);
    return;
  }
  const bootstrap = group === 'bootstrap-key';
  if (bootstrap && argv.length > 1) throw new UsageError('bootstrap-key takes no options');
  const resource = group === 'resource';
  if (resource && !((command === 'add' && rest.length === 1) || ((command === 'link' || command === 'unlink') && rest.length === 2))) {
    throw new UsageError('resource add takes a URL; resource link and unlink take a client_id and a resource');
  }
  if (!bootstrap && !resource && (group !== 'clients' || (command !== 'create' && command !== 'list'))) throw new UsageError('unknown command');
  const { values } = parseArgs({
    args: bootstrap || resource ? [] : rest,
    options: {
      name: { type: 'string' },
      'redirect-uri': { type: 'string', multiple: true },
      resource: { type: 'string', multiple: true },
    },
    strict: true,
  });
  if (command === 'list' && Object.keys(values).length > 0) throw new UsageError('clients list takes no options');
  if (command === 'create') {
    if (!values.name?.trim()) throw new UsageError('--name is required');
    if (!values['redirect-uri']?.length) throw new UsageError('at least one --redirect-uri is required');
  }

  process.umask(0o077);
  const config = loadConfig(process.env);
  findDataFolder(config.dataDir);
  const paths = prepareDataDir(config.dataDir);
  const db = openDb(paths.db);
  try {
    const applied = new Set(db.prepare('SELECT name FROM _authwapi_migrations').pluck().all() as string[]);
    const pending = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql') && !applied.has(f));
    if (pending.length > 0) {
      throw new Error(`This database hasn't had ${pending.join(', ')} applied. Start the server (it applies migrations), then run this again.`);
    }

    if (bootstrap) {
      const expiresAt = reissueBootstrapKey(db, paths);
      createLogger(paths.logs)('info', 'bootstrap admin key reissued by the operator CLI', { file: paths.bootstrapKey, expiresAt });
      console.log(`Wrote a new one-time bootstrap key to ${paths.bootstrapKey}, valid until ${expiresAt}. Any earlier unused one no longer works.`);
      console.log('An agent uses it once, with mint_agent_key over /mcp, to get a write key.');
      return;
    }

    if (command === 'list') {
      const rows = db
        .prepare('SELECT clientId, name, redirectUris, createdAt FROM oauthClient ORDER BY createdAt')
        .all() as { clientId: string; name: string | null; redirectUris: string; createdAt: string }[];
      const links = db.prepare('SELECT resourceId FROM oauthClientResource WHERE clientId = ? ORDER BY resourceId').pluck();
      if (rows.length === 0) console.log('No clients. Create one with: node src/cli.ts clients create --name <name> --redirect-uri <uri>');
      for (const r of rows) {
        console.log(`${r.clientId}  ${r.name ?? ''}`);
        console.log(`  redirect URIs: ${(JSON.parse(r.redirectUris) as string[]).join(' ')}`);
        const resources = links.all(r.clientId) as string[];
        if (resources.length > 0) console.log(`  resources: ${resources.join(' ')}`);
        console.log(`  created: ${new Date(r.createdAt).toISOString()}`);
      }
      return;
    }

    const log = createLogger(paths.logs);
    const sendMail = async () => {
      throw new Error('The CLI does not send email');
    };
    const auth = betterAuth(authOptions({ config, db, secret: loadOrCreateSecret(paths.secret), sendMail, log }));
    const api = auth.api as unknown as OAuthAdminApi;
    const headers = new Headers(); // Better Auth's admin endpoints require a headers object
    const context = await auth.$context;
    // The provider exempts its own userinfo endpoint from resource checks; it must never be a registered resource.
    const userinfo = `${context.baseURL}/oauth2/userinfo`;
    for (const identifier of resource ? rest.slice(-1) : (values.resource ?? [])) {
      if (identifier === userinfo) throw new Error(`${identifier} is reserved: it is AuthWAPI's own userinfo endpoint`);
    }
    if (resource && command === 'add') {
      const identifier = rest[0];
      await api.adminCreateOAuthResource({ headers, body: { identifier, name: identifier } });
      log('info', 'oauth resource created', { identifier });
      console.log(`Added resource ${identifier}. Let a client use it with: node src/cli.ts resource link <client_id> ${identifier}`);
      return;
    }
    if (resource) {
      const [clientId, identifier] = rest;
      // Path parameters, which Better Auth decodes. Checked first so a failed link leaves no client row behind.
      const params = { identifier: encodeURIComponent(identifier), client_id: encodeURIComponent(clientId) };
      if (command === 'unlink') {
        await api.adminUnlinkClientResource({ headers, params });
        log('info', 'oauth client unlinked from resource', { clientId, resource: identifier });
        console.log(`Unlinked ${clientId} from ${identifier}.`);
        return;
      }
      await api.adminGetOAuthResource({ headers, params });
      if (URL.canParse(clientId)) {
        const problem = validateClientIdUrl(clientId);
        if (problem) throw new Error(problem);
        // The client row the link needs, written with the link in one transaction. It holds no metadata yet: the
        // server fetches the document (only while the URL is linked) when a user first signs in through this client.
        await context.adapter.transaction(async (trx) => {
          const now = new Date();
          const where = [{ field: 'clientId', value: clientId }];
          if (!(await trx.findOne({ model: 'oauthClient', where }))) {
            await trx.create({ model: 'oauthClient', data: { clientId, clientDiscoveryId: 'cimd', redirectUris: [], createdAt: now, updatedAt: now } });
          }
          if (!(await trx.findOne({ model: 'oauthClientResource', where: [...where, { field: 'resourceId', value: identifier }] }))) {
            await trx.create({ model: 'oauthClientResource', data: { clientId, resourceId: identifier, createdAt: now } });
          }
        });
      } else {
        await api.adminLinkClientResource({ headers, params });
      }
      log('info', 'oauth client linked to resource', { clientId, resource: identifier });
      console.log(`Linked ${clientId} to ${identifier}.`);
      return;
    }
    const resources = [...new Set(values.resource ?? [])];
    const known = new Set((await api.adminListOAuthResources({ headers })).map((r) => r.identifier));
    for (const identifier of resources.filter((r) => !known.has(r))) {
      await api.adminCreateOAuthResource({ headers, body: { identifier, name: identifier } });
      log('info', 'oauth resource created', { identifier });
    }
    const client = await api.adminCreateOAuthClient({
      headers,
      body: {
        client_name: values.name!.trim(),
        redirect_uris: values['redirect-uri']!,
        token_endpoint_auth_method: 'client_secret_basic',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        enable_end_session: true, // RP-initiated logout with id_token_hint (also puts sid in ID tokens)
        ...(resources.length > 0 ? { resources } : {}),
      },
    });
    if (!client.client_secret) throw new Error('Better Auth created the client without a secret; this is a bug, please report it.');
    log('info', 'oauth client created', { clientId: client.client_id, name: client.client_name, redirectUris: client.redirect_uris, resources });
    console.log(`Created client "${client.client_name}". The secret is shown only this once; store it now.`);
    console.log(`client_id:     ${client.client_id}`);
    console.log(`client_secret: ${client.client_secret}`);
    if (resources.length > 0) console.log(`resources:     ${resources.join(' ')}`);
  } finally {
    db.close();
  }
}

/**
 * The server's data folder, which must already have a database. Run as root, becomes the database's owner.
 * It changes nothing in the folder: export runs beside a live server, whose journal file comes and goes.
 */
function findDataFolder(dataDir: string): DataPaths {
  const paths = dataPaths(path.resolve(dataDir));
  const db0 = paths.db;
  if (!existsSync(db0)) throw new Error(`No database at ${db0}. Start the server once on this data folder (DATA_DIR), then run this again.`);
  // `docker exec` runs as root; become the data folder's owner so nothing in it ends up owned by root.
  if (process.getuid?.() === 0) {
    const owner = statSync(db0);
    if (owner.uid === 0) throw new Error(`${db0} is owned by root; the server never runs as root. Fix the data folder's owner first.`);
    process.setgroups!([owner.gid]); // drop root's supplementary groups too
    process.setgid!(owner.gid);
    process.setuid!(owner.uid);
  }
  return paths;
}

try {
  await main(process.argv.slice(2));
} catch (err) {
  const usage = err instanceof UsageError || (err as { code?: string }).code?.startsWith('ERR_PARSE_ARGS');
  // Better Auth's errors carry the reason in body.error_description (e.g. an invalid redirect URI).
  const body = (err as { body?: { error_description?: string; message?: string } }).body;
  const reason = body?.error_description ?? body?.message ?? (err instanceof Error ? err.message : String(err));
  process.stderr.write(`authwapi: ${reason}\n${usage ? `\n${USAGE}\n` : ''}`);
  process.exit(usage ? 2 : 1);
}
