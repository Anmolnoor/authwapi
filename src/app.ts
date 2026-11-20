import { getConnInfo } from '@hono/node-server/conninfo';
import { Hono } from 'hono';
import { CLIENT_IP_HEADER } from './auth.ts';
import type { Config } from './config.ts';

interface AuthHandler {
  handler: (request: Request) => Promise<Response>;
}

export function createApp(auth: AuthHandler, config: Config): Hono {
  const app = new Hono();

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

  app.on(['GET', 'POST'], '/api/auth/*', (c) => {
    // Rate limits key on this header. It comes from the TCP peer; anything the client sent is replaced.
    const headers = new Headers(c.req.raw.headers);
    headers.delete('x-forwarded-for');
    headers.set(CLIENT_IP_HEADER, getConnInfo(c).remote.address ?? 'unknown');
    return auth.handler(new Request(c.req.raw, { headers }));
  });

  return app;
}
