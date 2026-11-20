// LANE A owns this file. OAuth 2.1 / OIDC provider for apps (plan D9). See .solofounder/slice3-spec.md.
import type { BetterAuthOptions } from 'better-auth';
import { Hono } from 'hono';
import type { AuthDeps } from './auth.ts';
import type { AuthCall } from './app.ts';
import type { Config } from './config.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];

/** Better Auth plugins for the OAuth/OIDC provider (oauthProvider + jwt). Added to authOptions().plugins. */
export function oauthPlugins(_deps: AuthDeps): Plugin[] {
  return [];
}

/** Routes outside /api/auth, e.g. BASE_URL/.well-known/openid-configuration (issuer = BASE_URL). */
export function wellKnownRoutes(_deps: { callAuth: AuthCall; config: Config }): Hono {
  return new Hono();
}
