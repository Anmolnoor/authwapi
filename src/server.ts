import { serve } from '@hono/node-server';
import { betterAuth } from 'better-auth';
import type { AddressInfo } from 'node:net';
import { createApp } from './app.ts';
import { authOptions } from './auth.ts';
import { loadConfig } from './config.ts';
import { loadOrCreateSecret, prepareDataDir, type DataPaths } from './data.ts';
import { openDb } from './db.ts';
import { createLogger } from './log.ts';
import { createMailer, sweepOutbox, type SendMail } from './mailer.ts';
import { migrate, MIGRATIONS_DIR } from './migrate.ts';

export interface Running {
  port: number;
  paths: DataPaths;
  close: () => Promise<void>;
}

/** `sendMail` is for tests (a slow or failing mailer); the server always builds its own. */
export async function start(env: NodeJS.ProcessEnv, overrides: { sendMail?: SendMail } = {}): Promise<Running> {
  process.umask(0o077); // every file AuthWAPI creates is private to its user
  const config = loadConfig(env);
  const paths = prepareDataDir(config.dataDir);
  const log = createLogger(paths.logs);
  const secret = loadOrCreateSecret(paths.secret);
  const db = openDb(paths.db);
  await migrate(db, MIGRATIONS_DIR, paths, log);
  await sweepOutbox(paths.outbox); // at boot, in either email mode

  const sendMail = overrides.sendMail ?? createMailer(config.email, paths.outbox, log);
  const auth = betterAuth(authOptions({ config, db, secret, sendMail, log }));
  const app = createApp({ auth, config, db, log });

  const server = serve({ fetch: app.fetch, hostname: config.host, port: config.port });
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const port = (server.address() as AddressInfo).port;
  log('info', 'listening', { port, baseUrl: config.baseUrl.origin, email: config.email.mode, data: paths.root });

  const close = () =>
    new Promise<void>((resolve) =>
      server.close(() => {
        db.close();
        resolve();
      })
    );
  return { port, paths, close };
}

if (import.meta.main) {
  try {
    const running = await start(process.env);
    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      process.once(signal, () => void running.close().then(() => process.exit(0)));
    }
  } catch (err) {
    process.stderr.write(`AuthWAPI failed to start: ${err instanceof Error ? err.message : String(err)}\n`);
    if (err instanceof Error && err.cause) process.stderr.write(`  cause: ${String(err.cause)}\n`);
    process.exit(1);
  }
}
