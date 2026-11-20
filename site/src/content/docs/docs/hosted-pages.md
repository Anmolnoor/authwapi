---
title: Hosted pages
description: The sign-in, sign-up, reset, verification, magic-link and consent pages AuthWAPI serves, and the safety rules behind them.
---

AuthWAPI serves its own pages, so your app needs no login UI. They are server-rendered HTML with no JavaScript,
follow the system light or dark theme, can't be framed by another site, and are never cached.

| Page | What it is |
| --- | --- |
| `/` | Shows who is signed in, with a sign-out button |
| `/sign-in` | Password sign-in, "Sign in with SSO" (your organization's identity provider), or "Email me a link" (a magic link). Also the OAuth sign-in page. |
| `/sign-up` | Create an account |
| `/forgot-password` | Ask for a reset link |
| `/reset-password` | Choose a new password (opened from the reset email) |
| `/consent` | An app asking for access: lists what it wants in plain words, with Allow and Deny |
| `/select-org` | An app asked for the `organization` scope: pick which of your organizations it's for, or none |
| `/accept-invitation` | The link in an organization invitation email: accept it while signed in with that address |
| `/signed-out` | After signing out |
| `/api/auth/verify-email` | The link in the verification email |
| `/api/auth/magic-link/verify` | The link in the magic-link email |

## Verifying an email

**Verifying an email asks for the password chosen at sign-up.** Opening the link only shows that form. This stops
an account takeover: if someone signs up with *your* address and their own password, and you click the
verification link they caused to be sent, you won't know their password, so their account never becomes a verified
account in your name. "Forgot password?" on that page replaces the password and ends every session.

## Magic links

**A magic link asks "Sign in as you@example.com?"** before it signs you in. So an email scanner that opens links
can't use it up, and a link someone else sent you can't sign you in without you seeing whose account it is.

## Consent

When an app sends a user to sign in, the consent page names the app and lists, in plain words, what it asked for.
For an MCP client whose `client_id` is a metadata URL, it leads with that URL's host, which is where the client
really comes from, and shows the name only as what the client calls itself.

| Scope | Shown as |
| --- | --- |
| `openid` | Confirm who you are |
| `email` | See your email address and whether it is verified |
| `offline_access` | Stay signed in to the app while you're away |
| `organization` | See which organization you sign in for and your role in it (plus the organization picked) |
| `resource=<api>` | Access *&lt;api&gt;* on your behalf |
