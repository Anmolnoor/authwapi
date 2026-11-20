# AuthWAPI website

The landing page and docs, built with [Astro Starlight](https://starlight.astro.build). Pages are Markdown in
`src/content/docs/`. The build also produces `/llms.txt`, `/llms-full.txt` and `/llms-small.txt` (starlight-llms-txt)
and an API reference from `public/openapi.json` (starlight-openapi).

```bash
cd site
npm ci
npm run dev        # http://localhost:4321
npm run build      # static site in dist/
```

Node 26 (Astro 7 needs 22.23.4 or newer).

## The API reference

`public/openapi.json` is generated from the server's Better Auth config, so request and response schemas match the
code. The list of supported routes and their notes are in `scripts/openapi.ts`. From the repo root, after `npm ci`
there:

```bash
node site/scripts/openapi.ts           # regenerate
node site/scripts/openapi.ts --check   # fails if the committed file is out of date
```

Run it after changing `src/auth.ts`, `src/oauth.ts` or the Better Auth version.

## Deploying on Vercel

Import the repository in Vercel and set **Root Directory** to `site`. Vercel detects Astro. Keep **Automatically
expose System Environment Variables** on: for absolute links in `llms.txt` and the sitemap, production builds read
`VERCEL_PROJECT_PRODUCTION_URL` and previews read `VERCEL_URL`. `vercel.json` marks the build as a Vercel one, so
it fails when they're missing instead of linking to localhost.
