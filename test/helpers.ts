import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { SendMail } from '../src/mailer.ts';
import { start, type Running } from '../src/server.ts';

export const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });

type Mail = { to: string; subject: string; text: string };

export interface TestServer extends Running {
  base: string;
  outbox: () => Mail[];
  /** Waits (up to 2s) for an email: delivery runs in the background, after the response. */
  mail: (to: string, subject: string) => Promise<Mail>;
  stop: () => Promise<void>;
}

/** A real AuthWAPI on a free port with a throwaway data folder (outbox email). */
export async function startTestServer(env: NodeJS.ProcessEnv = {}, sendMail?: SendMail): Promise<TestServer> {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'authwapi-test-'));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const running = await start({ BASE_URL: base, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: dataDir, ...env }, { sendMail });
  const outbox = (): Mail[] =>
    readdirSync(running.paths.outbox)
      .sort()
      .map((f) => JSON.parse(readFileSync(path.join(running.paths.outbox, f), 'utf8')));
  return {
    ...running,
    base,
    outbox,
    mail: async (to, subject) => {
      for (let i = 0; i < 40; i++) {
        const found = outbox().find((m) => m.to === to && m.subject === subject);
        if (found) return found;
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error(`no "${subject}" email to ${to} within 2s`);
    },
    stop: async () => {
      await running.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export const linkIn = (text: string): URL => new URL(/(https?:\/\/\S+)/.exec(text)![1]);
