// An in-process stand-in for Google and GitHub. The test server runs in this process, so wrapping globalThis.fetch
// answers Better Auth's calls to their token and profile endpoints here: no credentials, no network.
import { randomBytes } from 'node:crypto';

export interface Profile {
  id: string;
  email: string;
  emailVerified: boolean;
  name: string;
}

type Provider = 'google' | 'github';

const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');

export function mockOAuth() {
  const real = globalThis.fetch;
  /** Who signs in at each provider next. Tests change these. */
  const profiles: Record<Provider, Profile> = {
    google: { id: 'google-sub-1', email: 'ada@example.com', emailVerified: true, name: 'Ada G' },
    github: { id: '4242', email: 'ada@example.com', emailVerified: true, name: 'Ada H' },
  };
  const codes = new Map<string, { profile: Profile; nonce: string | null; clientId: string }>();
  const tokens = new Map<string, Profile>();

  globalThis.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const form = () => new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''));
    const bearer = () => new Headers(init?.headers).get('authorization')?.replace(/^Bearer /i, '') ?? '';
    switch (url.host + url.pathname) {
      case 'oauth2.googleapis.com/token': {
        const grant = codes.get(form().get('code') ?? '');
        if (!grant) return json({ error: 'invalid_grant' });
        const now = Math.floor(Date.now() / 1000);
        const { profile: p } = grant;
        const claims = { iss: 'https://accounts.google.com', aud: grant.clientId, sub: p.id, email: p.email, email_verified: p.emailVerified, name: p.name, iat: now, exp: now + 3600, ...(grant.nonce ? { nonce: grant.nonce } : {}) };
        // Better Auth reads a code-flow ID token without checking its signature (it came straight from Google over TLS).
        return json({ access_token: 'g-at', token_type: 'Bearer', expires_in: 3600, scope: 'openid email profile', id_token: `${b64({ alg: 'RS256', kid: 'k' })}.${b64(claims)}.sig` });
      }
      case 'github.com/login/oauth/access_token': {
        const grant = codes.get(form().get('code') ?? '');
        if (!grant) return json({ error: 'bad_verification_code' });
        const token = randomBytes(8).toString('hex');
        tokens.set(token, grant.profile);
        return json({ access_token: token, token_type: 'bearer', scope: 'read:user,user:email' });
      }
      case 'api.github.com/user': {
        const p = tokens.get(bearer());
        if (!p) return new Response('{}', { status: 401 });
        return json({ id: Number(p.id), login: 'ada', name: p.name, email: null, avatar_url: null });
      }
      case 'api.github.com/user/emails': {
        const p = tokens.get(bearer());
        if (!p) return new Response('[]', { status: 401 });
        return json([{ email: p.email, primary: true, verified: p.emailVerified }]);
      }
    }
    return real(input, init);
  };

  return {
    profiles,
    /** The provider's consent screen: approves at once. Returns AuthWAPI's callback URL with a code for the current profile. */
    approve(authorizationUrl: string): string {
      const auth = new URL(authorizationUrl);
      const provider: Provider = auth.host === 'accounts.google.com' ? 'google' : 'github';
      const code = randomBytes(8).toString('hex');
      codes.set(code, { profile: { ...profiles[provider] }, nonce: auth.searchParams.get('nonce'), clientId: auth.searchParams.get('client_id')! });
      const back = new URL(auth.searchParams.get('redirect_uri')!);
      back.searchParams.set('code', code);
      back.searchParams.set('state', auth.searchParams.get('state')!);
      return back.toString();
    },
    restore: () => {
      globalThis.fetch = real;
    },
  };
}
