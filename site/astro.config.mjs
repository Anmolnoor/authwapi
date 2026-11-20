// @ts-check
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';

// Absolute links (llms.txt, sitemap, canonical URLs) need the public address. On Vercel it is the project's
// production domain; Vercel only exposes it when "Automatically expose System Environment Variables" is on.
if (process.env.VERCEL && !process.env.VERCEL_PROJECT_PRODUCTION_URL) {
  throw new Error('VERCEL_PROJECT_PRODUCTION_URL is not set: turn on "Automatically expose System Environment Variables" in the Vercel project settings.');
}
const site = process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : 'http://localhost:4321';

export default defineConfig({
  site,
  integrations: [
    starlight({
      title: 'AuthWAPI',
      description: 'Self-hosted auth server in one container: sign-up, sign-in, magic links and an OAuth 2.1 / OpenID Connect provider, with all its data in one folder.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/Anmolnoor/authwapi' }],
      editLink: { baseUrl: 'https://github.com/Anmolnoor/authwapi/edit/main/site/' },
      customCss: ['./src/styles/custom.css'],
      plugins: [
        starlightOpenAPI([{ base: 'api', schema: './public/openapi.json', sidebar: { label: 'API reference' } }]),
        starlightLlmsTxt({
          projectName: 'AuthWAPI',
          description:
            'AuthWAPI is a self-hosted auth server that runs as one Docker container with all its data in one folder. It gives apps email + password sign-up with verification, magic links, password reset, sessions, hosted sign-in pages and an OAuth 2.1 / OpenID Connect provider. It is built on Better Auth, Hono and SQLite.',
          details: [
            'Facts an agent needs before acting:',
            '',
            '- Status: early (M1). The admin MCP server and export/import are not built yet. Do not put real users on it.',
            '- Start it (no published image yet): `git clone https://github.com/Anmolnoor/authwapi.git && cd authwapi && docker build -t authwapi .` then `docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" authwapi`. Health: `GET http://localhost:4000/health` returns `{"status":"ok"}`.',
            '- Every request needs a Host header equal to BASE_URL\'s host (default `localhost:4000`) or a name in ALLOWED_HOSTS, else 421 `unknown_host`. A request with an Origin header must send BASE_URL\'s origin, else 403 `untrusted_origin`.',
            '- Without Resend configured, emails (verification, reset, magic links) are written as JSON files to `<data folder>/outbox/`. They contain credentials: never print or log their links.',
            '- HTTP API: Better Auth routes under `BASE_URL/api/auth`. Machine-readable reference: the OpenAPI 3.1 file linked below.',
            '- Apps sign users in with OAuth 2.1 authorization code + PKCE (S256). Clients are created only with `docker exec authwapi node src/cli.ts clients create ...`; dynamic client registration is off.',
          ].join('\n'),
          optionalLinks: [
            { label: 'OpenAPI 3.1 reference', url: `${site}/openapi.json`, description: 'every supported HTTP route with request and response schemas' },
            { label: 'Source code', url: 'https://github.com/Anmolnoor/authwapi', description: 'README.md has the same facts as these docs' },
          ],
          customSets: [
            { label: 'Run it', paths: ['docs/quick-start', 'docs/configuration'], description: 'start the container, the data folder, email and every setting' },
            { label: 'Integrate an app', paths: ['docs/integrate-an-app', 'docs/http-api'], description: 'OAuth 2.1 / OIDC sign-in for apps, tokens, revocation, and the session API' },
          ],
          promote: ['index', 'docs/quick-start', 'docs/for-ai-agents', 'docs/integrate-an-app', 'docs/http-api'],
          exclude: ['index'], // llms-small.txt only: the landing page repeats the quick start
        }),
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Quick start', slug: 'docs/quick-start' },
            { label: 'For AI agents', slug: 'docs/for-ai-agents' },
            { label: 'Status and roadmap', slug: 'docs/status' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Integrate an app (OAuth / OIDC)', slug: 'docs/integrate-an-app' },
            { label: 'HTTP API (sessions)', slug: 'docs/http-api' },
            { label: 'Hosted pages', slug: 'docs/hosted-pages' },
            { label: 'Configuration', slug: 'docs/configuration' },
          ],
        },
        ...openAPISidebarGroups,
      ],
    }),
  ],
});
