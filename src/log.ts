// JSON-lines log to <data>/logs/app.jsonl and stdout. Never pass tokens, links or keys in fields.
import { appendFileSync } from 'node:fs';
import path from 'node:path';

type Level = 'info' | 'warn' | 'error';
export type Logger = (level: Level, msg: string, fields?: Record<string, unknown>) => void;

export function createLogger(logsDir: string): Logger {
  const file = path.join(logsDir, 'app.jsonl');
  return (level, msg, fields = {}) => {
    const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields });
    appendFileSync(file, line + '\n', { mode: 0o600 });
    (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
  };
}
