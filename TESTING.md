# Testing Guide

This document describes how to run, understand, and extend the AuthWAPI test
suite.

## Overview

- Test runner: Jest (ts-jest)
- HTTP testing: supertest
- Database: mongodb-memory-server (no external DB required)
- Scope: End-to-end tests for auth flows (register, login, user-info, token
  validation)

## Prerequisites

- Node.js and npm installed
- Project dependencies installed:

```bash
npm install
```

## Run the test suite

```bash
npm test
```

What happens:

- Spins up an in-memory MongoDB
- Starts the Express app in test mode (no external network calls)
- Executes E2E tests in `__tests__/auth.e2e.test.ts`

## What is covered

- Register: `POST /api/v1/auth/register` returns `201` with `user` and `token`,
  and sets the `jwt` cookie
- Login: `POST /api/v1/auth/login` returns `201` with `token`
- User info: `GET /api/v1/auth/user-info` with `Authorization: Bearer <token>`
  returns `200` and user profile
- Validate token: `POST /api/v1/auth/validate-token` returns
  `{ valid: true, user }`
- Handle availability: `POST /api/v1/auth/check-handle` and
  `GET /api/v1/auth/check-handle/:handle?` return `200` when available, `409`
  when taken, `400/403` on invalid/reserved

## Run a single test file

```bash
npx jest __tests__/auth.e2e.test.ts
```

## Watch mode (rerun on changes)

```bash
npx jest --watch
```

## Coverage report

```bash
npx jest --coverage
```

## Project-specific configuration

- Path aliases are configured via `ts-jest` + `tsconfig.json`.

  - See `jest.config.js` for `moduleNameMapper` generated from
    `compilerOptions.paths`.
  - Example alias: `@/types/*` → `<rootDir>/src/types/*`

- JWT config in tests:

  - `JWT_SECRET` and `JWT_EXPIRES_IN` are set in the test `beforeAll` hook.

- Database in tests:
  - Uses `mongodb-memory-server` so tests do not require a running MongoDB.

## Adding new tests

1. Create a `*.test.ts` file under `__tests__/`.
2. Import `app` from `src/app` and use `supertest` to issue HTTP requests.
3. If your tests need DB state, create records using your Mongoose models inside
   the test.
4. Keep tests independent (set up required data within each test or use
   `beforeEach`).

Example snippet:

```ts
import request from 'supertest';
import app from '../src/app';

test('should reject missing token', async () => {
  await request(app).get('/api/v1/auth/user-info').expect(401);
});
```

## Troubleshooting

- Cannot find module '@/...' in tests:
  - Ensure `jest.config.js` contains `moduleNameMapper` mapped from
    `tsconfig.json` paths.
- `mongodb-memory-server` fails to start:
  - Ensure your environment allows binaries to be downloaded or add a local
    mirror if needed.
- Test timeouts:
  - Increase Jest timeout with `jest.setTimeout(30000);` in your test file if
    necessary.
- TypeScript typing issues:
  - Ensure `ts-jest`, `@types/jest`, and `@types/supertest` are installed if you
    add TypeScript tests.

## CI recommendation

Run in CI:

```bash
npm ci
npm run build
npm test
```

Optionally cache npm deps and `mongodb-memory-server` binaries to speed up
builds.
