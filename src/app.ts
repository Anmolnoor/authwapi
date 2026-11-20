import { getConnInfo } from '@hono/node-server/conninfo';
import type Database from 'better-sqlite3';
import type { AuthContext } from 'better-auth';
import { Hono, type Context } from 'hono';
import path from 'node:path';
import { adminRoutes } from './admin.ts';
import { CLIENT_IP_HEADER } from './auth.ts';
import type { Config } from './config.ts';
import type { DataPaths } from './data.ts';
import type { Logger } from './log.ts';
import { wellKnownRoutes } from './oauth.ts';
import { pageRoutes } from './pages.ts';

interface AuthHandler {
  handler: (request: Request) => Promise<Response>;
  $context: Promise<AuthContext>;
}

/**
 * Sends a request to Better Auth on behalf of the client behind `c`: the client IP header (rate limits) is set
 * from the TCP peer, and anything the client sent in X-Forwarded-For or that header is replaced.
 * Pages and well-known routes use this to call Better Auth endpoints internally.
 */
export type AuthCall = (c: Context, request: Request) => Promise<Response>;

export interface AppDeps {
  auth: AuthHandler;
  config: Config;
  db: Database.Database;
  log: Logger;
  paths: DataPaths;
  secret: string;
}

export function createApp({ auth, config, db, log, paths, secret }: AppDeps): Hono {
  const app = new Hono();
  const callAuth: AuthCall = (c, request) => {
    const headers = new Headers(request.headers);
    headers.delete('x-forwarded-for');
    headers.set(CLIENT_IP_HEADER, getConnInfo(c).remote.address ?? 'unknown');
    return auth.handler(new Request(request, { headers }));
  };

  // Before the Host check so the container's own HEALTHCHECK (Host: 127.0.0.1) works. Reveals nothing.
  app.get('/health', (c) => c.json({ status: 'ok' }));

  // Only answer to BASE_URL's host and ALLOWED_HOSTS. This blocks DNS rebinding, and a port
  // mapping that doesn't match BASE_URL fails here loudly instead of producing broken links.
  app.use('*', async (c, next) => {
    const host = c.req.header('host');
    if (host === undefined || !config.allowedHosts.has(host)) {
      return c.json(
        { error: 'unknown_host', host, hint: 'Set BASE_URL to the address you use, or add the name to ALLOWED_HOSTS.' },
        421
      );
    }
    await next();
  });

  // A browser request from a site that isn't ours is refused before it reaches Better Auth, which only
  // checks Origin when a cookie is sent. Requests with no Origin (curl, server-to-server) pass.
  app.use('*', async (c, next) => {
    const origin = c.req.header('origin');
    if (origin !== undefined && !config.trustedOrigins.includes(origin)) {
      return c.json({ error: 'untrusted_origin', origin }, 403);
    }
    await next();
  });

  app.route('/', wellKnownRoutes({ callAuth, config })); // lane A
  app.route('/', pageRoutes({ callAuth, config, db, log, secret })); // lane B; before the catch-all so it can intercept
  app.route('/', adminRoutes({ authContext: auth.$context, config, db, auditFile: path.join(paths.logs, 'audit.jsonl'), bootstrapFile: paths.bootstrapKey }));
  app.on(['GET', 'POST'], '/api/auth/*', (c) => callAuth(c, c.req.raw));

  return app;
}
