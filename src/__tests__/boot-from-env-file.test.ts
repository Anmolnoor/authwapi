// Regression test for bug 5: the server must boot with settings only in ./.env.
// Needs a throwaway MongoDB: TEST_DATABASE_URL=mongodb://127.0.0.1:27099 npm test
import { spawn } from 'child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) throw new Error('TEST_DATABASE_URL is required (a throwaway MongoDB)');

test('boots when JWT_SECRET and DATABASE_URL come only from ./.env', async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'authwapi-env-'));
  writeFileSync(
    path.join(cwd, '.env'),
    `DATABASE_URL=${dbUrl}/authwapi-boot-test\nJWT_SECRET=from-dotenv\nPORT=0\n`
  );
  const env = { ...process.env };
  delete env.JWT_SECRET;
  delete env.DATABASE_URL;
  delete env.PORT;
  const root = path.resolve(__dirname, '../..');
  const child = spawn(
    process.execPath,
    ['-r', 'ts-node/register/transpile-only', path.join(root, 'src/server.ts')],
    {
      cwd,
      env: {
        ...env,
        NODE_PATH: path.join(root, 'node_modules'),
        TS_NODE_PROJECT: path.join(root, 'tsconfig.json'),
      },
    }
  );
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  try {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 30000);
      const done = () => {
        clearTimeout(timer);
        resolve();
      };
      child.stdout.on('data', () => out.includes('Server is running') && done());
      child.on('exit', done);
    });
    expect(out).toContain('Server is running');
  } finally {
    child.kill('SIGKILL');
    rmSync(cwd, { recursive: true, force: true });
  }
}, 40000);
