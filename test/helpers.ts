import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { start, type Running } from '../src/server.ts';

export const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });

export interface TestServer extends Running {
  base: string;
  outbox: () => { to: string; subject: string; text: string }[];
  stop: () => Promise<void>;
}

/** A real AuthWAPI on a free port with a throwaway data folder (outbox email). */
export async function startTestServer(env: NodeJS.ProcessEnv = {}): Promise<TestServer> {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'authwapi-test-'));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const running = await start({ BASE_URL: base, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: dataDir, ...env });
  return {
    ...running,
    base,
    outbox: () =>
      readdirSync(running.paths.outbox)
        .sort()
        .map((f) => JSON.parse(readFileSync(path.join(running.paths.outbox, f), 'utf8'))),
    stop: async () => {
      await running.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export const linkIn = (text: string): URL => new URL(/(https?:\/\/\S+)/.exec(text)![1]);
