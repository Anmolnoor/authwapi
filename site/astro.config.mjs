// @ts-check
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';

// Absolute links (llms.txt, sitemap, canonical URLs) need this deployment's public address: on Vercel, the
// production domain for production builds and the deployment's own URL for previews. Vercel only exposes these when
// "Automatically expose System Environment Variables" is on; vercel.json sets AUTHWAPI_SITE_ON_VERCEL so a Vercel build
// without them fails instead of linking to localhost. Off Vercel (npm run dev/build) it is localhost.
const host = process.env.VERCEL_ENV === 'production' ? process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.VERCEL_URL;
if (process.env.AUTHWAPI_SITE_ON_VERCEL && !host) {
  throw new Error('Vercel system environment variables are missing: turn on "Automatically expose System Environment Variables" in the project settings.');
}
const site = host ? `https://${host}` : 'http://localhost:4321';

export default defineConfig({
  site,
  integrations: [
    starlight({
      title: 'AuthWAPI',
      description: 'Self-hosted auth server in one container: sign-in, passkeys, 2FA, OAuth 2.1 / OpenID Connect, SAML SSO, and MCP auth, with all its data in one folder.',
      favicon: '/favicon.svg',
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#09090b', media: '(prefers-color-scheme: dark)' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#fafafa', media: '(prefers-color-scheme: light)' } },
      ],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/Anmolnoor/authwapi' }],
      editLink: { baseUrl: 'https://github.com/Anmolnoor/authwapi/edit/main/site/' },
      customCss: [
        '@fontsource-variable/inter',
        '@fontsource-variable/jetbrains-mono',
        './src/styles/tokens.css',
        './src/styles/custom.css',
      ],
      components: {
        Header: './src/components/starlight/Header.astro',
        SiteTitle: './src/components/starlight/SiteTitle.astro',
        ThemeSelect: './src/components/starlight/ThemeSelect.astro',
      },
      plugins: [
        starlightOpenAPI([{ base: 'api', schema: './public/openapi.json', sidebar: { label: 'API reference' } }]),
        starlightLlmsTxt({
          projectName: 'AuthWAPI',
          description:
            'AuthWAPI is a self-hosted auth server that runs as one Docker container with all its data in one folder. It gives apps email + password sign-up with verification, magic links, Google/GitHub sign-in, TOTP 2FA, passkeys, organizations, OIDC & SAML SSO, hosted sign-in pages, an OAuth 2.1 / OpenID Connect provider, and MCP authorization. It is built on Better Auth, Hono and SQLite.',
          details: [
            'Facts an agent needs before acting:',
            '',
            '- Status: early pre-1.0 (M1–M6 built: core auth, social sign-in, 2FA/passkeys, orgs, OIDC/SAML SSO, OAuth for MCP servers, admin MCP server, and export/import). Do not put real users on it yet.',
            '- Start it (from source; the published image is `ghcr.io/anmolnoor/authwapi:0.3.1`): `git clone https://github.com/Anmolnoor/authwapi.git && cd authwapi && docker build -t authwapi .` then `docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" authwapi`. Health: `GET http://localhost:4000/health` returns `{"status":"ok"}`.',
            '- Every request except `GET /health` needs a Host header equal to BASE_URL\'s host (default `localhost:4000`) or a name in ALLOWED_HOSTS, else 421 `unknown_host`. An Origin header, if sent, must be BASE_URL\'s origin (or an ALLOWED_HOSTS name), else 403 `untrusted_origin`. A POST to a Better Auth route that sends any cookie (such as the session cookie) must send that Origin, else 403 `MISSING_OR_NULL_ORIGIN` and nothing happens.',
            '- Without Resend configured, emails (verification, reset, magic links) are written as JSON files to `<data folder>/outbox/`. They contain credentials, as do session cookies, sign-in responses and the client secret the CLI prints: never print or log them.',
            `- HTTP API: Better Auth routes under \`BASE_URL/api/auth\`. Machine-readable reference (OpenAPI 3.1): ${site}/openapi.json`,
            `- Step-by-step runbook (start, sign up, verify from the outbox, sign in, create an OAuth client, then the admin MCP) with no human: ${site}/docs/for-ai-agents/`,
            `- Admin MCP for agents at \`BASE_URL/mcp\`: read the one-time bootstrap key from \`<data folder>/bootstrap-admin-key\` (ends with a newline; trim it), use it once to mint a write key with \`mint_agent_key\`, then administer with that key. Never print a key. Runbook: ${site}/docs/for-ai-agents/#admin-mcp`,
            '- Apps sign users in with OAuth 2.1 authorization code + PKCE (S256). Clients are created only with `docker exec -u 1000 authwapi node src/cli.ts clients create ...`; dynamic client registration is off.',
            `- Your own MCP servers can use AuthWAPI as their authorization server: \`resource add <url>\`, then \`resource link <client_id> <url>\` (an MCP client's client_id is its metadata document URL). Guide: ${site}/docs/protect-your-mcp-server/`,
          ].join('\n'),
          optionalLinks: [
            { label: 'Source code', url: 'https://github.com/Anmolnoor/authwapi', description: 'the server, its tests and README.md' },
          ],
          promote: ['docs/quick-start', 'docs/for-ai-agents', 'docs/integrate-an-app', 'docs/protect-your-mcp-server', 'docs/http-api'],
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
            { label: 'Protect your MCP server', slug: 'docs/protect-your-mcp-server' },
            { label: 'HTTP API (sessions)', slug: 'docs/http-api' },
            { label: 'Hosted pages', slug: 'docs/hosted-pages' },
            { label: 'SSO for your organization', slug: 'docs/sso' },
            { label: 'Configuration', slug: 'docs/configuration' },
          ],
        },
        ...openAPISidebarGroups,
      ],
    }),
  ],
});
