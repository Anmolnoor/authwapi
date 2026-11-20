// LANE B owns this file. Hosted pages (sign-in, sign-up, reset, magic link, OAuth consent) and the Risk 8 fix.
// See .solofounder/slice3-spec.md.
import type Database from 'better-sqlite3';
import { Hono } from 'hono';
import type { AuthCall } from './app.ts';
import type { Config } from './config.ts';
import type { Logger } from './log.ts';

export interface PageDeps {
  callAuth: AuthCall;
  config: Config;
  db: Database.Database;
  log: Logger;
}

/**
 * Mounted BEFORE the /api/auth/* catch-all, so routes here can intercept Better Auth paths
 * (GET /api/auth/verify-email, GET /api/auth/magic-link/verify).
 */
export function pageRoutes(_deps: PageDeps): Hono {
  return new Hono();
}
