import type Database from 'better-sqlite3';
import type { BetterAuthOptions } from 'better-auth';
import { magicLink } from 'better-auth/plugins';
import type { Config } from './config.ts';
import type { Logger } from './log.ts';
import type { SendMail } from './mailer.ts';

type RateLimitStorage = NonNullable<NonNullable<BetterAuthOptions['rateLimit']>['customStorage']>;

export const CLIENT_IP_HEADER = 'x-authwapi-client-ip';

/** Logs keep only a URL's origin: paths and query strings can carry tokens or attacker-chosen text. */
export const redactUrls = (text: string): string =>
  text.replace(/\bhttps?:\/\/[^\s"'<>]+/gi, (u) => (URL.canParse(u) ? `${new URL(u).origin}/[redacted]` : '[url]'));

/**
 * Rate-limit counters owned by this auth instance (Better Auth's built-in memory store is shared by
 * every instance in the process). Single-threaded, so check-and-increment is atomic. Bounded: past
 * `maxKeys` the oldest bucket is evicted (Map keeps insertion order), and expired buckets are cleared
 * every minute off the request path.
 * ponytail: in-memory, resets on restart; move to the database if restarts become a bypass. Eviction walks
 * past deleted slots until V8 compacts the Map, so worst case is a few thousand skips per insert at the cap.
 */
export function memoryRateLimit(maxKeys = 10_000): RateLimitStorage {
  const hits = new Map<string, { resetAt: number; count: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, h] of hits) if (h.resetAt <= now) hits.delete(k);
  }, 60_000).unref();
  return {
    consume: async (key, { window, max }) => {
      const now = Date.now();
      const h = hits.get(key);
      if (h === undefined || h.resetAt <= now) {
        hits.delete(key);
        if (hits.size >= maxKeys) hits.delete(hits.keys().next().value!);
        hits.set(key, { resetAt: now + window * 1000, count: 1 });
        return { allowed: true, retryAfter: null };
      }
      if (h.count >= max) return { allowed: false, retryAfter: Math.ceil((h.resetAt - now) / 1000) };
      h.count += 1;
      return { allowed: true, retryAfter: null };
    },
  };
}

export interface AuthDeps {
  config: Config;
  db: Database.Database;
  secret: string;
  sendMail: SendMail;
  log: Logger;
}

export function authOptions({ config, db, secret, sendMail, log }: AuthDeps): BetterAuthOptions {
  const findAccount = db.prepare('SELECT email FROM "user" WHERE email = ?');
  const recentMagicLink = new Map<string, number>(); // address → last send time, for the per-address cooldown
  const MAGIC_LINK_COOLDOWN_MS = 60_000;
  // Every email is sent after the response: setImmediate defers even the outbox's synchronous file write, so a
  // request never waits on mail and its timing and status can't reveal whether an account exists. Failures are
  // logged. (Some Better Auth routes await these callbacks directly, so returning early here is what counts.)
  const deliver = (what: string, mail: Parameters<SendMail>[0]): void => {
    setImmediate(() =>
      sendMail(mail).catch((err: unknown) =>
        log('error', `${what} email failed`, { error: err instanceof Error ? redactUrls(err.message) : 'unknown error' })
      )
    );
  };
  return {
    appName: 'AuthWAPI',
    baseURL: config.baseUrl.origin,
    secret,
    database: db,
    trustedOrigins: config.trustedOrigins,
    // Better Auth's warnings and errors go to our log (app.jsonl), not only the console. Errors are
    // recorded by message, without stack traces.
    logger: {
      level: 'warn',
      log: (level, message, ...args) =>
        // Better Auth logs a refused value as "Invalid callbackURL: <value>"; blank the whole value, whatever
        // shape it has (//host, javascript:, uppercase schemes), then cut any remaining URL to its origin.
        log(level === 'error' ? 'error' : 'warn', `better-auth: ${redactUrls(message.replace(/(URL:\s*)\S+/gi, '$1[redacted]'))}`, {
          detail: redactUrls(args.map((a) => (a instanceof Error ? a.message : String(a))).join(' ')),
        }),
    },
    // Rate limits apply everywhere (Better Auth's default is production only), keyed on the client IP
    // that app.ts sets from the TCP connection. X-Forwarded-For is client-controlled, so it's ignored.
    rateLimit: { enabled: true, customStorage: memoryRateLimit() },
    advanced: {
      ipAddress: { ipAddressHeaders: [CLIENT_IP_HEADER] },
    },
    // Reset and verification tokens are stored hashed, so a copy of the database can't be used to reset.
    verification: { storeIdentifier: 'hashed' },
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: true,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user, url }) =>
        deliver('password reset', {
          to: user.email,
          subject: 'Reset your password',
          text: `Someone asked to reset your password. To choose a new one, open:\n\n${url}\n\nIf it wasn't you, ignore this email.`,
        }),
    },
    plugins: [
      magicLink({
        expiresIn: 5 * 60,
        disableSignUp: true, // a magic link signs in an existing account; it never creates one
        storeToken: 'hashed',
        // Better Auth would email any address and refuse at sign-in; we only email existing accounts, so
        // AuthWAPI can't send mail to strangers. Sending happens after the response (deliver), so known and
        // unknown addresses get the same answer in the same time.
        // A magic link also verifies the email and removes any password set before verification (Better
        // Auth's revokeUnprovenAccountAccess): that's what locks out someone who signed up with your address.
        sendMagicLink: ({ email, url }) => {
          const account = findAccount.get(email.toLowerCase()) as { email: string } | undefined;
          if (account === undefined) {
            log('info', 'magic link not sent: no account for that email');
            return;
          }
          const now = Date.now();
          if (now - (recentMagicLink.get(account.email) ?? 0) < MAGIC_LINK_COOLDOWN_MS) {
            log('info', 'magic link not sent: one was sent to that address in the last minute');
            return;
          }
          recentMagicLink.delete(account.email); // re-insert at the end: Map order = age, for the cap below
          recentMagicLink.set(account.email, now);
          if (recentMagicLink.size > 10_000) recentMagicLink.delete(recentMagicLink.keys().next().value!);
          deliver('magic link', {
            to: account.email, // the stored address, not the spelling in the request
            subject: 'Your sign-in link',
            text: `To sign in, open this link within 5 minutes:\n\n${url}\n\nIf you didn't ask for it, ignore this email.`,
          });
        },
      }),
    ],
    emailVerification: {
      sendOnSignUp: true,
      // Off: opening someone else's verification link must not switch your browser into their account.
      autoSignInAfterVerification: false,
      sendVerificationEmail: async ({ user, url }) =>
        deliver('verification', {
          to: user.email,
          subject: 'Verify your email',
          text:
            `Someone created an AuthWAPI account with this email address. If it was you, open this link to verify it:\n\n${url}\n\n` +
            "If you didn't create this account, don't open the link: verifying would let whoever did sign in as you.",
        }),
    },
  };
}
