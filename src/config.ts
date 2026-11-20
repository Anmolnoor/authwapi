// Every setting comes from the environment and is checked once, at boot. A bad value stops the server.

export type EmailConfig =
  | { mode: 'resend'; apiKey: string; from: string }
  | { mode: 'outbox' };

export interface Config {
  baseUrl: URL;
  host: string; // interface to listen on; 0.0.0.0 inside the container
  port: number;
  dataDir: string;
  allowedHosts: Set<string>; // Host header values accepted, e.g. "localhost:4000"
  trustedOrigins: string[]; // browser Origins accepted: BASE_URL's, plus each ALLOWED_HOSTS name with its scheme
  email: EmailConfig;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export const isLoopback = (url: URL): boolean =>
  LOOPBACK.has(url.hostname) || url.hostname.endsWith('.localhost');

const fail = (msg: string): never => {
  throw new Error(`Config error: ${msg}`);
};

export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const rawBase = env.BASE_URL ?? 'http://localhost:4000';
  if (!URL.canParse(rawBase)) fail(`BASE_URL is not a URL: ${rawBase}`);
  const baseUrl = new URL(rawBase);
  if (!['http:', 'https:'].includes(baseUrl.protocol)) fail('BASE_URL must be http(s)');
  if (baseUrl.pathname !== '/' || baseUrl.search || baseUrl.hash) {
    fail('BASE_URL must be an origin with no path, query or fragment, e.g. http://localhost:4000');
  }

  const port = Number(env.PORT ?? 4000);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`PORT is not a port: ${env.PORT}`);

  // Host values: BASE_URL's own host plus ALLOWED_HOSTS (e.g. authwapi, host.docker.internal).
  // A name without a port is allowed on the listening port.
  const allowedHosts = new Set([baseUrl.host]);
  for (const name of (env.ALLOWED_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    allowedHosts.add(name.includes(':') ? name : `${name}:${port}`);
  }

  let email: EmailConfig;
  if (env.RESEND_API_KEY) {
    if (!env.EMAIL_FROM) fail('EMAIL_FROM is required with RESEND_API_KEY (a sender on a domain verified in Resend)');
    email = { mode: 'resend', apiKey: env.RESEND_API_KEY, from: env.EMAIL_FROM! };
  } else if (isLoopback(baseUrl)) {
    email = { mode: 'outbox' };
  } else {
    email = fail('RESEND_API_KEY and EMAIL_FROM are required when BASE_URL is not localhost');
  }

  const trustedOrigins = [...allowedHosts].map((h) => `${baseUrl.protocol}//${h}`);
  return { baseUrl, host: env.HOST ?? '0.0.0.0', port, dataDir: env.DATA_DIR ?? '/data', allowedHosts, trustedOrigins, email };
}
