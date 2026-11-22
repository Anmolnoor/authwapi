---
title: Quick start
description: Build and run AuthWAPI, create an account, verify it from the outbox and sign in.
---

You need Docker (or podman) and git. These steps build the image from source, so you get what these docs describe.
The latest release is published as `ghcr.io/anmolnoor/authwapi:0.3.0`: to use it instead, skip `docker build` and
put `ghcr.io/anmolnoor/authwapi:0.3.0` in place of the last `authwapi` in `docker run`.

## 1. Build and start

```bash
git clone https://github.com/Anmolnoor/authwapi.git && cd authwapi
docker build -t authwapi .
docker run -d --name authwapi -p 127.0.0.1:4000:4000 -v "$PWD/authwapi-data:/data" authwapi
curl http://localhost:4000/health
```

```json
{"status":"ok"}
```

It takes a few seconds to start; if `curl` fails, try again. Everything AuthWAPI keeps goes into `./authwapi-data` (see [the data folder](/docs/configuration/#the-data-folder)).
The port is published on `127.0.0.1` only, so nothing outside your machine can reach it.

**Podman, SELinux, another port or another user ID?** See [Running on other setups](/docs/configuration/#running-on-other-setups).

## 2. Create an account

Open [http://localhost:4000/sign-up](http://localhost:4000/sign-up) in a browser, or use the API:

```bash
curl -X POST http://localhost:4000/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name":"Ada","email":"ada@example.com","password":"correct-horse-battery"}'
```

```json
{"token":null,"user":{"name":"Ada","email":"ada@example.com","emailVerified":false,"image":null,"createdAt":"…","updatedAt":"…","id":"dNSJ48si6OD0IFPmTkMfQOLbhNIgdEep"}}
```

The account can't sign in until its email is verified. Signing in now returns
`403 {"message":"Email not verified","code":"EMAIL_NOT_VERIFIED"}`.

## 3. Verify the email

With no email provider configured, AuthWAPI writes each email as a JSON file in `authwapi-data/outbox/`, a moment
after the request:

```bash
cat authwapi-data/outbox/*.json
```

```json
{
  "to": "ada@example.com",
  "subject": "Verify your email",
  "text": "Someone created an AuthWAPI account with this email address. If it was you, open this link to verify it:\n\nhttp://localhost:4000/api/auth/verify-email?token=eyJhbGciOi…&callbackURL=%2F\n\n…",
  "sentAt": "…"
}
```

Open the link in a browser. The page asks for the password you chose at sign-up; enter it and the email is
verified. (Why a password? See [Hosted pages](/docs/hosted-pages/#verifying-an-email).) The link works for one hour.

Outbox files are readable only by their owner and are deleted after 24 hours. Treat them as passwords: anyone with
a link can use it.

## 4. Sign in

In the browser: [http://localhost:4000/sign-in](http://localhost:4000/sign-in). With the API, keep the session
cookie in a cookie jar:

```bash
curl -c jar -X POST http://localhost:4000/api/auth/sign-in/email \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'
curl -b jar http://localhost:4000/api/auth/get-session
```

The second call returns the session and user. Sessions last 7 days.

## Next

- [Sign users in to your own app](/docs/integrate-an-app/) with OAuth 2.1 / OpenID Connect.
- [Send real email](/docs/configuration/#email) through Resend.
- [Every setting](/docs/configuration/).
