// JSON-lines log to <data>/logs/app.jsonl and stdout. Never pass tokens, links or keys in fields.
import { appendFileSync } from 'node:fs';
import path from 'node:path';

type Level = 'info' | 'warn' | 'error';
export type Logger = (level: Level, msg: string, fields?: Record<string, unknown>) => void;

// Never throws: a log write that fails (full disk, folder removed) is reported on stderr instead, so logging
// can't crash the server or turn a handled error into an unhandled one.
export function createLogger(logsDir: string): Logger {
  const file = path.join(logsDir, 'app.jsonl');
  return (level, msg, fields = {}) => {
    const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields });
    try {
      appendFileSync(file, line + '\n', { mode: 0o600 });
    } catch (err) {
      process.stderr.write(`AuthWAPI: couldn't write ${file}: ${err instanceof Error ? err.message : String(err)}\n`);
    }
    (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
  };
}
