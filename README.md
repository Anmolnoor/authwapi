# AuthWAPI

> **Simplified authentication, maximized development.**

A drop-in, batteries-included **authentication-as-a-service API** built with
TypeScript, Express and MongoDB. Register users, log them in, reset forgotten
passwords over email, and upload compressed profile images to S3 — without
writing the auth layer yourself.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Express](https://img.shields.io/badge/Express-4.x-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Mongoose%208-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](#-docker)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Running Locally](#running-locally)
- [Docker](#-docker)
- [API Documentation](#api-documentation)
- [Authentication Flow](#authentication-flow)
- [Password Reset Flow](#password-reset-flow)
- [Image Upload Flow](#image-upload-flow)
- [Security Features](#security-features)
- [Scripts Reference](#scripts-reference)
- [Environment Variables Reference](#environment-variables-reference)
- [Known Gaps & Roadmap](#known-gaps--roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

AuthWAPI is a self-hostable REST API that owns the whole identity surface of a
product: signup, login, session issuance, password rotation, forgotten-password
recovery, and avatar storage.

It ships as a single Express application. Sessions are stateless — the server
signs a JWT and hands it back both as an `httpOnly` cookie and as a bearer
token, so the same backend serves browser clients and native/mobile clients
without a second code path. User records live in MongoDB via Mongoose, password
hashes are produced by bcrypt inside a schema pre-save hook (so a password can
never be written in plaintext by accident), and uploaded images are compressed
with Sharp before being streamed to an S3 bucket.

Every response is wrapped in a consistent envelope, and every error — thrown,
rejected, or unhandled — funnels through one global error handler that switches
between verbose stack traces in development and sanitized messages in
production.

---

## Features

- 🔐 **JWT authentication** — signed tokens delivered as an `httpOnly`,
  `sameSite=strict` cookie *and* accepted as an `Authorization: Bearer` header.
- 👤 **Full account lifecycle** — register, login (by email *or* username),
  logout, fetch profile.
- 🔁 **Password rotation** — authenticated password change that re-issues a
  fresh token.
- 📧 **Forgot / reset password over email** — SHA-256-hashed, single-use,
  10-minute reset tokens delivered by Nodemailer.
- 🛡️ **Token invalidation on password change** — JWTs issued before a password
  change are rejected automatically.
- 🖼️ **Image uploads to AWS S3** — Multer in-memory buffering, MIME allow-list,
  Sharp compression + resize, randomized object keys.
- 📉 **Automatic image compression** — JPEG (mozjpeg), PNG, and HEIF→PNG
  conversion, with the compression ratio reported back in the response.
- 🚦 **Rate limiting** — 500 requests per IP per hour across the whole surface.
- 🧯 **Centralized error handling** — one `CustomErrorHandler` class, one global
  error middleware, dev/prod-aware output.
- 📝 **Structured logging** — Winston with colorized console output plus
  `app.log`, `exceptions.log` and `rejections.log` file transports.
- ♻️ **Graceful shutdown** — `SIGTERM`/`SIGINT` handling, uncaught-exception and
  unhandled-rejection traps, each with a 10s forced-exit fallback.
- 🔒 **Hardened by default** — Helmet, CORS, XSS sanitization, body-size limits.
- 🐳 **Docker-ready** — single-stage `node:22-slim` image included.
- 🧪 **Typed end to end** — TypeScript `strict` mode, ESLint + Prettier, Jest via
  `ts-jest`.

---

## Tech Stack

| Layer | Technology | Notes |
| --- | --- | --- |
| Language | [TypeScript](https://www.typescriptlang.org/) 5.5 | `strict: true`, `target: es2016`, CommonJS output |
| Runtime | [Node.js](https://nodejs.org) | Container image is `node:22-slim` |
| Framework | [Express](https://expressjs.com/) 4 | Routers mounted under `/api/v1` |
| Database | [MongoDB](https://www.mongodb.com/) + [Mongoose](https://mongoosejs.com/) 8 | Schema hooks for hashing & timestamps |
| Auth | [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) 9 | HS256, 30-day default expiry |
| Hashing | [bcryptjs](https://github.com/dcodeIO/bcrypt.js) | Cost factor 12 |
| Crypto | Node `crypto` | `randomBytes` + SHA-256 for reset tokens |
| Email | [Nodemailer](https://nodemailer.com/) 6 | SMTP transport |
| File uploads | [Multer](https://github.com/expressjs/multer) 1.4 | `memoryStorage`, 1 MB / 1 file limit |
| Image processing | [Sharp](https://sharp.pixelplumbing.com/) 0.33 | Resize + re-encode before upload |
| Object storage | [@aws-sdk/client-s3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/s3/) v3 | `PutObject` / `DeleteObject` |
| Security | Helmet, cors, xss-clean, express-rate-limit | See [Security Features](#security-features) |
| Logging | [Winston](https://github.com/winstonjs/winston) 3 + [Morgan](https://github.com/expressjs/morgan) | Console + rotating-free file transports |
| Config | [dotenv](https://github.com/motdotla/dotenv) | Loaded from `./.env` |
| Testing | [Jest](https://jestjs.io/) 29 + ts-jest | `testEnvironment: node` |
| Tooling | ESLint 9, Prettier, ts-node-dev | Hot reload in dev |
| Package manager | Yarn | `yarn.lock` is the committed lockfile |

---

## Project Structure

```
authwapi/
├── src/
│   ├── app.ts                      # Express app: middleware chain + route mounting
│   ├── server.ts                   # Bootstrap: DB connect, listen, graceful shutdown
│   │
│   ├── routes/
│   │   ├── index.ts                # Re-exports { auth, User } routers
│   │   ├── auth.router.ts          # /api/v1/auth/*
│   │   ├── user.router.ts          # /api/v1/user/*
│   │   └── router.ts               # /api/test health-check route
│   │
│   ├── controllers/
│   │   ├── index.ts                # Re-exports { Auth, User, globalErrorHandler }
│   │   ├── auth.controller.ts      # register / login / logout / protect / reset flows
│   │   ├── user.controller.ts      # getUserDetails / uploadImage
│   │   ├── s3.controller.ts        # Legacy S3 middleware variants (not mounted)
│   │   └── error.controller.ts     # Global error handler (dev vs prod output)
│   │
│   ├── models/
│   │   └── user.model.ts           # User schema, pre-save hooks, instance methods
│   │
│   ├── types/
│   │   └── model.type.ts           # IUser, ID, Multer file aliases
│   │
│   └── utils/
│       ├── jwt.ts                  # sign / verify / cookie issuance
│       ├── encryptDecrypt.ts       # bcrypt hashing + SHA-256 reset tokens
│       ├── email.ts                # Nodemailer transport + sendMail()
│       ├── s3services.ts           # s3UploadSingle / s3UploadMultipleFiles / s3Delete
│       ├── multerService.ts        # Multer memory storage + image filter
│       ├── helper.ts               # CatchAsync, ResponseGenerator, FileNameGenerator
│       ├── errorHandler.ts         # CustomErrorHandler (operational error class)
│       └── logger.ts               # Winston logger
│
├── dockerfile                      # node:22-slim build (note: lowercase filename)
├── .dockerignore
├── tsconfig.json                   # strict, outDir ./build, path aliases
├── jest.config.js                  # ts-jest preset
├── .eslintrc.json                  # standard-with-typescript + prettier
├── .prettierrc
├── package.json
└── yarn.lock
```

> **Note:** `tsconfig.json` and `package.json` also declare `@/services/*` and
> `@/middlewares/*` path aliases. Those directories do not exist yet — the
> aliases are reserved for future use, and all middleware currently lives in
> `src/controllers/auth.controller.ts` (`Auth.protect`) and `src/utils/`.

---

## Prerequisites

| Requirement | Why | Minimum |
| --- | --- | --- |
| **Node.js** | Runtime | 18+ (the Docker image uses 22) |
| **Yarn** | Package manager — the repo commits `yarn.lock` | 1.x |
| **MongoDB** | User persistence. Local instance or MongoDB Atlas | 5.0+ |
| **AWS S3 bucket + IAM credentials** | Required *only* for `POST /api/v1/user/upload-image` | — |
| **SMTP account** | Required *only* for the forgot-password email. Gmail, Mailtrap, SendGrid, SES… | — |
| **libvips** | Sharp's native dependency — installed automatically via prebuilt binaries on common platforms | — |
| **Docker** | Optional, for containerized runs | 20.10+ |

The API boots fine without AWS or SMTP credentials; only the image-upload and
forgot-password endpoints will fail until they are configured.

---

## Installation & Setup

### 1. Clone

```bash
git clone https://github.com/Anmolnoor/authwapi.git
cd authwapi
```

### 2. Install dependencies

```bash
yarn install
```

<details>
<summary>Using npm instead?</summary>

`yarn.lock` is the committed lockfile, and the Dockerfile runs `yarn install`.
`npm install` works but will generate a competing `package-lock.json` — don't
commit it.

</details>

### 3. Create your `.env`

`dotenv` is configured to read `./.env` from the project root. Copy the
committed template:

```bash
cp .env.example .env
```

Then populate it — every variable the codebase reads:

```dotenv
# ---- Runtime ----
NODE_ENV=development
PORT=8000
LOG_LEVEL=info

# ---- Database ----
DATABASE_URL=mongodb://127.0.0.1:27017/authwapi

# ---- JWT ----
JWT_SECRET=replace-me-with-a-long-random-string
JWT_EXPIRES_IN=30d

# ---- Email (SMTP, used by the forgot-password flow) ----
EMAIL_HOST=smtp.mailtrap.io
EMAIL_PORT=2525
EMAIL_USERNAME=your-smtp-username
EMAIL_PASSWORD=your-smtp-password
EMAIL_URL=localhost:8000/api/v1/auth/reset-password/

# ---- AWS S3 (used by the image-upload flow) ----
AWS_REGION=ap-south-1
AWS_BUCKET_NAME=your-bucket-name
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=your-secret-access-key
```

> ⚠️ **Two things that will bite you:**
>
> 1. `JWT_SECRET` is **required** — `src/utils/jwt.ts` throws
>    `JWT_SECRET environment variable is required` at import time if it is
>    unset, so the process will not boot without it.
> 2. `EMAIL_URL` is **host + path without a scheme and with a trailing slash**.
>    The reset link is built as
>    `` `${req.protocol}://${process.env.EMAIL_URL}${resetToken}` ``, so
>    `localhost:8000/api/v1/auth/reset-password/` produces
>    `http://localhost:8000/api/v1/auth/reset-password/<token>`.

See the full [Environment Variables Reference](#environment-variables-reference)
below for defaults and fallback behaviour.

### 4. Make sure MongoDB is reachable

```bash
# local daemon
mongod --dbpath /path/to/data

# …or just point DATABASE_URL at an Atlas cluster
```

`server.ts` refuses to start if `DATABASE_URL` is unset — it throws
`DATABASE_URL is not defined` and exits with code 1.

---

## Running Locally

### Development (hot reload)

```bash
yarn dev
```

Runs `ts-node-dev --respawn --transpile-only src/server.ts`. Files are
transpiled without type-checking for speed, and the process respawns on every
save. With `NODE_ENV=development` you also get Morgan's `dev` request log and
full stack traces in error responses.

### Production

```bash
yarn build   # tsc → ./build
yarn start   # node build/server.js
```

Set `NODE_ENV=production` for the production build. That switches Morgan to the
`short` format, forces the `secure` flag on the JWT cookie (so you **must** be
behind HTTPS), and makes the global error handler return sanitized messages
instead of stack traces.

### Type-check / lint / test

```bash
npx tsc --noEmit   # type-check without emitting
yarn lint          # eslint . --ext .ts
yarn test          # jest
```

### Smoke test

```bash
curl http://localhost:8000/api/test
# {"status":"success","data":"Welcome to the API"}
```

---

## 🐳 Docker

The repo contains a single-stage Dockerfile. **The file is named `dockerfile`
in lowercase**, so on case-sensitive filesystems you must pass `-f` explicitly —
`docker build .` alone will not find it.

```bash
# Build
docker build -f dockerfile -t authwapi:latest .

# Run
docker run --rm -p 8000:8000 --env-file .env authwapi:latest
```

What the image does:

| Step | Detail |
| --- | --- |
| Base | `node:22-slim` |
| Workdir | `/usr/src/app` |
| Deps | Copies `package.json` + `yarn.lock`, runs `yarn install` |
| Build | Copies source, runs `yarn build` (TypeScript → `build/`) |
| Port | `EXPOSE 8000` |
| Entrypoint | `CMD ["node", "build/server.js"]` |

`.dockerignore` keeps `node_modules`, `dist`, `.git`, `.vscode`, `.env` and
`.DS_Store` out of the build context — so secrets are **not** baked into the
image. Supply them at runtime with `--env-file` or `-e`.

### Optional: Compose with a local MongoDB

There is no `docker-compose.yml` in the repo. If you want one for local
development, this is a working starting point — save it as
`docker-compose.yml`:

```yaml
services:
  api:
    build:
      context: .
      dockerfile: dockerfile
    ports:
      - '8000:8000'
    env_file: .env
    environment:
      DATABASE_URL: mongodb://mongo:27017/authwapi
    depends_on:
      - mongo

  mongo:
    image: mongo:7
    ports:
      - '27017:27017'
    volumes:
      - mongo-data:/data/db

volumes:
  mongo-data:
```

```bash
docker compose up --build
```

---

## API Documentation

**Base URL:** `http://localhost:8000`

All successful and failed responses share one envelope, produced by
`ResponseGenerator`:

```json
{
  "status": "success",   // "success" for 2xx, "fail" otherwise
  "data": { }            // payload, or { msg, err } on handled failures
}
```

Errors raised through the global handler use a slightly different shape:

```json
// production
{ "status": "fail", "msg": "You are not logged in! Please log in to get access." }

// development — adds the stack and raw error object
{ "status": "fail", "msg": "...", "errstack": "Error: ...", "err": { } }
```

### Endpoints

| Method | Path | Description | Auth |
| --- | --- | --- | :---: |
| `GET` | `/api/test` | Health check / liveness probe | ❌ |
| `POST` | `/api/v1/auth/register` | Create an account and receive a JWT cookie | ❌ |
| `POST` | `/api/v1/auth/login` | Log in with email **or** username | ❌ |
| `GET` | `/api/v1/auth/logout` | Overwrite the JWT cookie with a 1-second dummy | ❌ |
| `POST` | `/api/v1/auth/forget-password` | Email a 10-minute password-reset token | ❌ |
| `PATCH` | `/api/v1/auth/reset-password/:token` | Consume a reset token and set a new password | ❌ |
| `GET` | `/api/v1/user/me` | Fetch the authenticated user's profile | ✅ |
| `POST` | `/api/v1/user/update-password` | Change password while logged in | ✅ |
| `POST` | `/api/v1/user/upload-image` | Upload + compress an avatar to S3 | ✅ |

Anything else returns `404` with `Can't found <url> on this server!!!`.

---

### `GET /api/test`

Health check. No auth, no body.

```json
{ "status": "success", "data": "Welcome to the API" }
```

---

### `POST /api/v1/auth/register`

Creates a user, hashes the password, and sets the `jwt` cookie.

**Request**

```json
{
  "firstName": "Anmol",
  "lastName": "Noor",
  "username": "anmolnoor",
  "email": "anmolnoor59@gmail.com",
  "password": "supersecret",
  "passwordConfirm": "supersecret"
}
```

| Field | Type | Required | Constraints |
| --- | --- | :---: | --- |
| `firstName` | string | ✅ | trimmed, ≤ 32 chars |
| `lastName` | string | ✅ | trimmed, ≤ 32 chars |
| `email` | string | ✅ | trimmed, ≤ 32 chars, **unique** |
| `password` | string | ✅ | trimmed, ≤ 32 chars |
| `passwordConfirm` | string | ✅ | must equal `password` |
| `username` | string | ❌ | trimmed, ≤ 64 chars, **unique** |
| `image` | string | ❌ | S3 object key |

**Response — `201 Created`** (plus `Set-Cookie: jwt=…; HttpOnly`)

```json
{ "status": "success", "data": { "user": { "_id": "…", "email": "…", "…": "…" } } }
```

**Failure modes:** `400` if `password !== passwordConfirm` (`"password does't
match"`), `500` on a duplicate `email`/`username` (Mongo `E11000`).

---

### `POST /api/v1/auth/login`

`username` accepts **either** the username or the email address — the query is
`{ $or: [{ email: username }, { username }] }`.

**Request**

```json
{ "username": "anmolnoor", "password": "supersecret" }
```

**Response — `201`** (plus the `jwt` cookie). `data` is the user document.

**Failure — `401`**

```json
{ "status": "fail", "data": { "msg": "Login Failed", "err": "Incorrect email or password" } }
```

The same generic message is returned whether the user doesn't exist or the
password is wrong, so the endpoint doesn't leak account existence.

---

### `GET /api/v1/auth/logout`

Replaces the `jwt` cookie with the literal string `loggedOut`, expiring in one
second.

**Response — `200`**: `{ "status": "success", "data": {} }`

---

### `POST /api/v1/auth/forget-password`

**Request**

```json
{ "email": "anmolnoor59@gmail.com" }
```

**Response — `201`**

```json
{ "status": "success", "data": { "msg": "Token sent to email!" } }
```

**Failure modes:** `404` `"There is no user with this E-mail address."`; `500`
`"There was an error while sending the email. Try again later!"` — in which case
the stored token is scrambled and expired so the half-finished attempt can't be
replayed.

---

### `PATCH /api/v1/auth/reset-password/:token`

`:token` is the **plaintext** token from the emailed link. The server hashes it
with SHA-256 and looks up the match.

**Request**

```json
{ "password": "newsecret", "passwordConfirm": "newsecret" }
```

**Response — `201`** (plus a fresh `jwt` cookie — the user is logged straight
in)

```json
{ "status": "success", "data": { "user": { "…": "…" } } }
```

**Failure — `400`** `"Token is invalid or has Expired"` for an unknown token, an
expired token, or a token that was already consumed.

---

### `GET /api/v1/user/me` 🔒

Returns the authenticated user with sensitive fields projected out.

**Response — `200`**

```json
{
  "status": "success",
  "data": {
    "_id": "66b1…",
    "firstName": "Anmol",
    "lastName": "Noor",
    "username": "anmolnoor",
    "email": "anmolnoor59@gmail.com",
    "image": "9f2c…a41.jpeg",
    "createdAt": "2026-07-29T10:12:44.001Z"
  }
}
```

---

### `POST /api/v1/user/update-password` 🔒

Verifies the current password, writes the new one, and re-issues a JWT (the old
one is invalidated by the `passwordChangedAt` check — see
[Authentication Flow](#authentication-flow)).

**Request**

```json
{
  "password": "supersecret",
  "newPassword": "evenmoresecret",
  "newPasswordConfirm": "evenmoresecret"
}
```

**Response — `201`**: `{ "status": "success", "data": {} }`

**Failure modes:** `400` `"Password is incorrect"`, `400` `"User does not
exist"`, `400` `"password does't match"` if the confirmation doesn't match.

---

### `POST /api/v1/user/upload-image` 🔒

`multipart/form-data` with a single field named **`image`**.

```bash
curl -X POST http://localhost:8000/api/v1/user/upload-image \
  -H "Authorization: Bearer $TOKEN" \
  -F "image=@./avatar.jpg"
```

| Constraint | Value | Enforced by |
| --- | --- | --- |
| Field name | `image` | `upload.fields([{ name: 'image', maxCount: 1 }])` |
| Max files | 1 | Multer `limits.files` |
| Max size | 1 MB | Multer `limits.fileSize` |
| Coarse type filter | `image/*` | Multer `fileFilter` |
| Accepted MIME types | `image/jpeg`, `image/png`, `image/heif` | `user.controller.ts` |

**Response — `200`**

```json
{
  "status": "success",
  "data": {
    "msg": "Image uploaded successfully",
    "imageName": "3f9a…c7d.jpeg",
    "originalSize": 842103,
    "compressedSize": 214877,
    "compressionRatio": "74.48%",
    "fileType": "image/jpeg",
    "allowedTypes": ["image/jpeg", "image/png", "image/heif"]
  }
}
```

The user document's `image` field is updated with `imageName`; the object lives
at `s3://$AWS_BUCKET_NAME/uploads/<imageName>`.

**Failure modes:** `400` `"Invalid file type. Only JPG, PNG, and HEIF images are
allowed"`; `500` `"Error processing image"` if Sharp can't decode the buffer;
`500` `"SomeThing went wrong!! try again"` if no file was attached.

---

## Authentication Flow

AuthWAPI issues **stateless JWTs**. There is no session store — the token is the
session.

### Token issuance

`createTokenwithCookie(id, res)` in `src/utils/jwt.ts` runs after register,
login, password update, and password reset:

1. `sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })` — the payload holds
   only the Mongo `_id`.
2. The token is written to a cookie named `jwt` with:

   | Option | Value | Purpose |
   | --- | --- | --- |
   | `httpOnly` | `true` | JavaScript can't read it — blocks XSS token theft |
   | `sameSite` | `strict` | Blocks CSRF from third-party origins |
   | `secure` | `NODE_ENV === 'production'` | HTTPS-only in production |
   | `maxAge` | 30 days | Matches the default `JWT_EXPIRES_IN` |
   | `path` | `/` | Sent to every route |

Browser clients get the cookie automatically. API/mobile clients can read the
token from the `Set-Cookie` header and send it back as a bearer token instead.

### The `protect` middleware

`Auth.protect` (`src/controllers/auth.controller.ts`) guards every private
route. Mount it before the handler:

```ts
router.get('/me', Auth.protect, User.getUserDetails);
```

It runs four checks, in order:

1. **Extract the token.** Prefers `Authorization: Bearer <token>`; falls back to
   the `jwt` cookie. Missing both → `401 "You are not logged in! Please log in
   to get access."`
2. **Verify the signature and expiry** via `verifyJWTToken`. A bad signature
   raises `JsonWebTokenError` → `401 "Invalid Token. Please login again"`; an
   expired token raises `TokenExpiredError` → `401 "Token expired. Please login
   again"`. Both are normalized by the global error handler.
3. **Confirm the user still exists.** A token for a deleted account →
   `401 "The user belonging to the token does not exist"`.
4. **Confirm the password hasn't changed since the token was issued.**
   `changedPasswordAfter(iat, passwordChangedAt)` compares the JWT's issued-at
   claim against the user's `passwordChangedAt` timestamp. If the password is
   newer → `401 "User changed the password. please login again"`. This is what
   makes a password change retroactively kill every outstanding token.

On success it attaches `req.user` (the full document) and `req.id` (the
`ObjectId`) and calls `next()`.

```
Client ──▶ Bearer header or jwt cookie
             │
             ├─ missing? ───────────────────────▶ 401
             ├─ invalid / expired signature? ───▶ 401
             ├─ user deleted? ──────────────────▶ 401
             ├─ password changed after iat? ────▶ 401
             │
             └─ ✅ req.user / req.id set ───────▶ handler
```

### Using the token

```bash
# Cookie (browsers do this for you)
curl --cookie "jwt=$TOKEN" http://localhost:8000/api/v1/user/me

# Bearer header
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/user/me
```

> A `restrictTo(role)` role-guard is sketched but commented out in
> `auth.controller.ts` — there is no RBAC yet. See
> [Known Gaps](#known-gaps--roadmap).

---

## Password Reset Flow

Reset tokens are **random, hashed at rest, single-use, and short-lived**. The
plaintext token exists only in the user's inbox; the database stores nothing
that can be replayed if it leaks.

### 1. Request a reset — `POST /api/v1/auth/forget-password`

1. Look up the user by email. No user → `404`.
2. `resetTokenGenerator()` produces a pair:
   - `resetToken` — 32 random bytes as hex (64 chars), sent to the user.
   - `encryptedResetToken` — `sha256(resetToken)`, stored in the DB.
3. Persist `resetToken: <hash>` and `resetTokenTimer: now + 10 minutes`.
4. Build the link: `` `${req.protocol}://${EMAIL_URL}${resetToken}` `` and send
   it via Nodemailer with the subject *"Your password reset token (valid for 10
   minutes)"*.
5. If the send throws, the stored token is overwritten with a random 64-byte
   string and the timer is backdated 100 minutes — so a failed send leaves no
   usable token behind.

### 2. Consume the reset — `PATCH /api/v1/auth/reset-password/:token`

1. Hash the incoming plaintext token with SHA-256.
2. Find the user whose stored `resetToken` matches that hash. No match →
   `400 "Token is invalid or has Expired"`.
3. Check `resetTokenTimer > now`. Expired → same `400`, same message.
4. Assign `password` / `passwordConfirm` and `save()` — the pre-save hook
   re-validates the confirmation and re-hashes with bcrypt.
5. Burn the token: `resetToken` is replaced with fresh randomness and
   `resetTokenTimer` is backdated 100 minutes, so the link can't be reused.
6. Issue a new JWT cookie — the user is logged in immediately.

```
forget-password              email                reset-password/:token
      │                        │                          │
  sha256(t) ──▶ DB             │                          │  sha256(t) ──▶ lookup
      │                    plaintext t                    │       │
      └── timer = +10min ──────┘                          │  timer valid? ──▶ save
                                                          │       │
                                                          │  burn token + new JWT
```

Because the database only ever holds the hash, a leaked database dump yields no
usable reset links.

---

## Image Upload Flow

`POST /api/v1/user/upload-image` chains three layers: **Multer → Sharp → S3**.

### 1. Multer — buffer in memory

`src/utils/multerService.ts` configures `multer.memoryStorage()`, so the file
never touches disk. A `fileFilter` rejects anything whose MIME type doesn't
start with `image/` (raising `LIMIT_UNEXPECTED_FILE`), and limits cap the upload
at **1 file, 1 MB**.

### 2. Controller — validate the exact type

`user.controller.ts` re-checks the MIME type against a strict allow-list —
`image/jpeg`, `image/png`, `image/heif` — because the Multer filter only
verifies the `image/*` prefix. Anything else → `400`.

### 3. Sharp — compress and resize

| Input | Transform |
| --- | --- |
| `image/jpeg` | `.jpeg({ quality: 80, mozjpeg: true })` |
| `image/png` | `.png({ quality: 80, compressionLevel: 9 })` |
| `image/heif` | `.png({ quality: 80, compressionLevel: 9 })` — converted to PNG, and the recorded MIME type is rewritten to `image/png` |

All images are then resized with
`.resize(1920, 1080, { fit: 'inside', withoutEnlargement: true })` — the aspect
ratio is preserved, the image is scaled down to fit within 1920×1080, and images
already smaller than that are left alone. A decode failure → `500 "Error
processing image"`.

### 4. S3 — upload under a random key

`FileNameGenerator` builds `<32 random bytes as hex>.<ext>` from the file's MIME
subtype, so the original filename never reaches the bucket (no path traversal,
no collisions, no PII in object keys). `s3UploadSingle` then issues a
`PutObjectCommand` with `Key: uploads/<imageName>`.

### 5. Persist and report

The user document's `image` field is set to the generated key, and the response
reports `originalSize`, `compressedSize` and a human-readable
`compressionRatio`.

```
multipart/form-data
      │
      ▼
  Multer (memory, 1 MB, image/*)
      │  Buffer
      ▼
  MIME allow-list  ──▶ 400 on jpg/png/heif miss
      │
      ▼
  Sharp: re-encode @ q80 + resize ≤1920×1080
      │  compressed Buffer
      ▼
  S3 PutObject → uploads/<random>.<ext>
      │
      ▼
  User.image = <key>   +   compression stats in the response
```

`src/utils/s3services.ts` also exports `s3UploadMultipleFiles` and `s3Delete`
for batch operations — neither is wired to a route yet.

---

## Security Features

| Control | Implementation | What it buys you |
| --- | --- | --- |
| **Helmet** | `app.use(helmet())` | Sets `X-Content-Type-Options`, `X-Frame-Options`, HSTS, CSP defaults and friends |
| **CORS** | `app.use(cors())` | Cross-origin requests enabled (currently permissive — see below) |
| **XSS sanitization** | `app.use(xss())` (`xss-clean`) | Strips HTML/script payloads from `req.body`, `req.query`, `req.params` |
| **Rate limiting** | `express-rate-limit`: 500 requests / IP / hour, mounted at `/` | Blunts credential stuffing and brute force. Exceeding it returns *"Too many request from this IP, Please try again in an Hour!"* |
| **Password hashing** | bcrypt, cost factor 12, in a Mongoose `pre('save')` hook | Passwords are hashed on the way in — no controller can accidentally persist plaintext |
| **Confirmation check** | Same pre-save hook compares `password` vs `passwordConfirm` | Mismatches are rejected before hashing |
| **Reset tokens hashed at rest** | `crypto.randomBytes(32)` → SHA-256 | A DB dump exposes no usable reset link |
| **Reset token expiry** | 10 minutes, single-use, burned after consumption | Narrow replay window |
| **Token invalidation** | `changedPasswordAfter()` compares JWT `iat` to `passwordChangedAt` | Changing a password logs out every existing session |
| **`httpOnly` cookies** | `jwt.ts` cookie options | JavaScript — and therefore XSS payloads — can't exfiltrate the token |
| **`sameSite=strict`** | `jwt.ts` cookie options | CSRF protection for cookie-authenticated requests |
| **`secure` in production** | `NODE_ENV === 'production'` | Cookie is never sent over plaintext HTTP |
| **Body size limit** | `express.json({ limit: '4096kb' })` | Caps JSON payload DoS |
| **Upload limits** | Multer: 1 file, 1 MB, `image/*` only | Caps upload abuse before the buffer is even processed |
| **Randomized object keys** | 32-byte hex + extension | No user-controlled filenames reach S3 |
| **Generic auth failures** | `"Incorrect email or password"` for both branches | No account-existence oracle on login |
| **Error sanitization** | `error.controller.ts` splits dev/prod output | Stack traces and internals never reach production clients |
| **`trust proxy`** | `app.set('trust proxy', 1)` | Correct client IPs behind one reverse proxy, so rate limiting isn't bypassed |
| **Field projection** | `getUserDetails` excludes `password`, `__v`, `passwordConfirm`, … | Hashes aren't returned to clients |

### Hardening checklist before you go to production

- [ ] **Set `JWT_SECRET` to a long random string.** There is no fallback — the
      app refuses to start without it — but a weak or shared secret is still
      forgeable.
- [ ] **Restrict CORS.** `cors()` with no options allows every origin. Pass an
      explicit `origin` allow-list, and `credentials: true` if you rely on the
      cookie.
- [ ] **Terminate TLS.** The `secure` cookie flag is only meaningful over HTTPS.
- [ ] **Add request-body validation.** See [Known Gaps](#known-gaps--roadmap).
- [ ] **Tighten the rate limiter on `/api/v1/auth/*`.** 500/hour is generous for
      a login endpoint; consider a second, stricter limiter scoped to auth
      routes.
- [ ] **Scope your IAM policy** to `s3:PutObject` / `s3:DeleteObject` on
      `arn:aws:s3:::<bucket>/uploads/*` only.

---

## Scripts Reference

| Script | Command | Description |
| --- | --- | --- |
| `yarn dev` | `ts-node-dev --respawn --transpile-only src/server.ts` | Development server with hot reload. Skips type-checking for speed |
| `yarn build` | `tsc` | Compiles `src/` to `build/` with `.d.ts` declarations |
| `yarn start` | `node build/server.js` | Runs the compiled production build. Requires `yarn build` first |
| `yarn lint` | `eslint . --ext .ts` | Lints with `standard-with-typescript` + Prettier |
| `yarn test` | `jest` | Runs the Jest suite (`ts-jest`, `**/__tests__/**/*.ts`, `*.spec.ts`, `*.test.ts`) |

Useful one-offs that aren't wired to a script:

```bash
npx tsc --noEmit        # type-check only
npx prettier --write .  # format
```

---

## Environment Variables Reference

Every variable read anywhere in the codebase:

| Variable | Required | Default / Fallback | Used in | Description |
| --- | :---: | --- | --- | --- |
| `DATABASE_URL` | ✅ | — (startup **fails** without it) | `src/server.ts` | MongoDB connection string |
| `PORT` | ❌ | `8000` | `src/server.ts` | HTTP listen port |
| `NODE_ENV` | ➖ | *(logged as "{Not Defined environment}")* | `app.ts`, `jwt.ts`, `error.controller.ts` | `development` \| `production`. Controls Morgan format, cookie `secure` flag, and error verbosity |
| `LOG_LEVEL` | ❌ | `info` | `src/utils/logger.ts` | Winston level: `error`, `warn`, `info`, `verbose`, `debug`, `silly` |
| `JWT_SECRET` | ✅ | — (import of `jwt.ts` **throws** without it) | `src/utils/jwt.ts` | HMAC signing key. Use a long random string |
| `JWT_EXPIRES_IN` | ❌ | `30d` | `src/utils/jwt.ts` | Token lifetime (`zeit/ms` format). The cookie `maxAge` is fixed at 30 days |
| `EMAIL_HOST` | 📧 | — | `src/utils/email.ts` | SMTP hostname |
| `EMAIL_PORT` | 📧 | — | `src/utils/email.ts` | SMTP port (coerced with `Number()`) |
| `EMAIL_USERNAME` | 📧 | — | `src/utils/email.ts` | SMTP username |
| `EMAIL_PASSWORD` | 📧 | — | `src/utils/email.ts` | SMTP password / app password |
| `EMAIL_URL` | 📧 | — | `src/controllers/auth.controller.ts` | Host **+ path, no scheme, trailing slash** — e.g. `localhost:8000/api/v1/auth/reset-password/` |
| `AWS_REGION` | 🖼️ | — | `src/utils/s3services.ts` | S3 bucket region |
| `AWS_BUCKET_NAME` | 🖼️ | — | `src/utils/s3services.ts` | Target bucket. Objects land under `uploads/` |
| `AWS_ACCESS_KEY_ID` | 🖼️ | `''` | `src/utils/s3services.ts` | IAM access key ID |
| `AWS_SECRET_ACCESS_KEY` | 🖼️ | `''` | `src/utils/s3services.ts` | IAM secret access key |

**Legend** — ✅ required to boot · 📧 required only for the forgot-password
flow · 🖼️ required only for image uploads · ➖ optional but strongly
recommended · ❌ optional

> `.env` is git-ignored (along with `.env.*`), and `.dockerignore` excludes it
> from the image build context. `.env.example` is explicitly un-ignored and
> committed as the canonical template — copy it to `.env` and fill it in.

---

## Known Gaps & Roadmap

Documented honestly so you know what you're adopting:

- **No request-body validation.** `register`, `login`, `forgotPassword` and
  `resetPassword` all carry `// TODO: validate` comments. Malformed bodies
  currently surface as Mongoose validation errors or `500`s. Adding Zod (or
  `express-validator`) at the router boundary is the highest-value next change.
- **No RBAC.** `restrictTo(role)` is written but commented out in
  `auth.controller.ts`, and the `User` schema has no `role` field.
- **`phone` isn't persisted.** It exists on the `IUser` interface and is read in
  `register`, but there is no matching field in `userSchema`, so it is silently
  dropped.
- **`getUserDetails` projection is stale.** It excludes `passwordResetToken` /
  `passwordResetExpires` / `active`, but the schema's actual fields are named
  `resetToken`, `resetTokenTimer` and `isActive` — so the hashed reset token is
  returned to the authenticated owner. Harmless-ish (it's hashed, and only the
  owner sees it), but worth correcting.
- **`isActive` vs the query hook.** The `pre(/^find/)` hook filters on
  `active: { $ne: false }`, but the schema field is `isActive` — the soft-delete
  filter is effectively a no-op.
- **Module-alias / outDir mismatch.** `_moduleAliases` in `package.json` points
  at `dist/*` while `tsconfig.json` emits to `build/`. Source files use relative
  imports, so nothing breaks today, but the aliases won't resolve if you start
  using them.
- **`src/controllers/s3.controller.ts` is legacy.** It holds the earlier
  middleware-based upload approach, superseded by the logic in
  `user.controller.ts`. Not mounted on any route.
- **`console.log` in the upload controller.** Should go through the Winston
  logger (ESLint's `no-console` rule already flags it).
- **No test suite yet.** Jest and ts-jest are configured; there are no spec
  files.
- **No CI/CD configuration** is committed — no `.github/workflows`, no
  `vercel.json`. The `app.set('trust proxy', 1)` line hints at a Vercel
  deployment history.

---

## Contributing

Contributions are welcome — issues, bug reports, and pull requests all help.

1. **Fork** the repository and create a feature branch off `main`:
   ```bash
   git checkout -b feat/short-description
   ```
2. **Install and set up** as described in
   [Installation & Setup](#installation--setup).
3. **Make your change.** Keep the existing conventions:
   - Wrap every async route handler in `CatchAsync` so rejections reach the
     global error handler.
   - Return responses through `ResponseGenerator` so the envelope stays
     consistent.
   - Throw operational errors as `new CustomErrorHandler(message, statusCode)`
     via `next(...)` — never `res.status().json()` directly for errors.
   - Log through the Winston logger, not `console`.
4. **Verify before you push:**
   ```bash
   npx tsc --noEmit
   yarn lint
   yarn test
   ```
5. **Commit** with a clear, imperative message
   (`feat: add zod validation to auth routes`).
6. **Open a pull request** against `main` describing what changed, why, and how
   you tested it. If you touched an endpoint's contract, update the
   [API Documentation](#api-documentation) table in this README in the same PR.

Picking something up? The [Known Gaps](#known-gaps--roadmap) list is a
ready-made backlog — request validation and a test suite are the most useful
places to start.

---

## License

Distributed under the **MIT License**, as declared in `package.json`.

```
MIT License — Copyright (c) Anmol Noor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the above copyright notice and this
permission notice being included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

> A standalone `LICENSE` file is not yet committed to the repository — adding
> the full MIT text is a good first contribution.

---

## Author

**Anmol Noor**

- GitHub: [@Anmolnoor](https://github.com/Anmolnoor)
- Email: [anmolnoor59@gmail.com](mailto:anmolnoor59@gmail.com)
- Repository: [github.com/Anmolnoor/authwapi](https://github.com/Anmolnoor/authwapi)

If AuthWAPI saved you from writing another auth layer, a ⭐ on the repo is
appreciated.
