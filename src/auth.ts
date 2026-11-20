import type Database from 'better-sqlite3';
import type { BetterAuthOptions } from 'better-auth';
import type { Config } from './config.ts';
import type { SendMail } from './mailer.ts';

type RateLimitStorage = NonNullable<NonNullable<BetterAuthOptions['rateLimit']>['customStorage']>;

export const CLIENT_IP_HEADER = 'x-authwapi-client-ip';

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
}

export function authOptions({ config, db, secret, sendMail }: AuthDeps): BetterAuthOptions {
  return {
    appName: 'AuthWAPI',
    baseURL: config.baseUrl.origin,
    secret,
    database: db,
    trustedOrigins: config.trustedOrigins,
    // Rate limits apply everywhere (Better Auth's default is production only), keyed on the client IP
    // that app.ts sets from the TCP connection. X-Forwarded-For is client-controlled, so it's ignored.
    rateLimit: { enabled: true, customStorage: memoryRateLimit() },
    advanced: { ipAddress: { ipAddressHeaders: [CLIENT_IP_HEADER] } },
    // Reset and verification tokens are stored hashed, so a copy of the database can't be used to reset.
    verification: { storeIdentifier: 'hashed' },
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: true,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: ({ user, url }) =>
        sendMail({
          to: user.email,
          subject: 'Reset your password',
          text: `Someone asked to reset your password. To choose a new one, open:\n\n${url}\n\nIf it wasn't you, ignore this email.`,
        }),
    },
    emailVerification: {
      sendOnSignUp: true,
      // Off: opening someone else's verification link must not switch your browser into their account.
      autoSignInAfterVerification: false,
      sendVerificationEmail: ({ user, url }) =>
        sendMail({
          to: user.email,
          subject: 'Verify your email',
          text: `To verify your email address, open:\n\n${url}`,
        }),
    },
  };
}
