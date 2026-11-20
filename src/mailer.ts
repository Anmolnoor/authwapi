// Email goes to Resend, or (localhost without Resend) to <data>/outbox as 0600 JSON files kept 24h.
// Emails carry sign-in links, so they never go to the logs.
import { randomBytes } from 'node:crypto';
import { lstatSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Resend } from 'resend';
import type { EmailConfig } from './config.ts';
import type { Logger } from './log.ts';

export interface Mail {
  to: string;
  subject: string;
  text: string;
}
export type SendMail = (mail: Mail) => Promise<void>;

const OUTBOX_TTL_MS = 24 * 60 * 60 * 1000;

/** Deletes outbox emails older than 24h. Runs at boot, hourly, and before each write. */
export function sweepOutbox(dir: string, now = Date.now()): void {
  for (const name of readdirSync(dir)) {
    const file = path.join(dir, name);
    const st = lstatSync(file);
    if (st.isFile() && now - st.mtimeMs > OUTBOX_TTL_MS) unlinkSync(file);
  }
}

export function createMailer(email: EmailConfig, outboxDir: string, log: Logger): SendMail {
  // Sweep in both modes: switching to Resend must not strand old outbox mail. A failed hourly sweep (e.g. the
  // folder was removed) is logged, not thrown: an uncaught error in a timer would kill the server.
  sweepOutbox(outboxDir);
  setInterval(() => {
    try {
      sweepOutbox(outboxDir);
    } catch (err) {
      log('error', 'outbox sweep failed', { error: err instanceof Error ? err.message : String(err) });
    }
  }, 60 * 60 * 1000).unref();
  if (email.mode === 'resend') {
    const resend = new Resend(email.apiKey);
    return async ({ to, subject, text }) => {
      const { error } = await resend.emails.send({ from: email.from, to, subject, text });
      if (error) throw new Error(`Resend rejected the email: ${error.name}: ${error.message}`);
    };
  }
  return async (mail) => {
    const now = Date.now();
    sweepOutbox(outboxDir, now);
    const name = `${new Date(now).toISOString().replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}.json`;
    writeFileSync(path.join(outboxDir, name), JSON.stringify({ ...mail, sentAt: new Date(now).toISOString() }, null, 2), {
      mode: 0o600,
      flag: 'wx',
    });
  };
}
