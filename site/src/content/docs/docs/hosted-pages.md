---
title: Hosted pages
description: The sign-in, sign-up, reset, verification, magic-link and consent pages AuthWAPI serves, and the safety rules behind them.
---

AuthWAPI serves its own pages, so your app needs no login UI. They are server-rendered HTML (the only script is `/passkey.js`, on
pages with a passkey button), follow the system light or dark theme, can't be framed by another site, and are never cached.

| Page | What it is |
| --- | --- |
| `/` | Shows who is signed in, with a sign-out button |
| `/sign-in` | Password sign-in, "Sign in with SSO" (your organization's identity provider), or "Email me a link" (a magic link). Also the OAuth sign-in page: during an app's sign-in it names the app, as the consent page does. |
| `/sign-up` | Create an account |
| `/forgot-password` | Ask for a reset link |
| `/reset-password` | Choose a new password (opened from the reset email) |
| `/consent` | An app asking for access: lists what it wants in plain words, with Allow and Deny |
| `/select-org` | An app asked for the `organization` scope: pick which of your organizations it's for, or none |
| `/accept-invitation` | The link in an organization invitation email: accept it while signed in with that address (signed out, it links to sign-in and sign-up) |
| `/two-factor/setup` | Turn on TOTP: a QR code for the authenticator app, the key and link to type or open instead, and backup codes |
| `/signed-out` | After signing out |
| `/error` | Where a browser lands after an error (a bad app request, an expired sign-in): the error code in plain words |
| `/api/auth/oauth2/end-session` | An app signing you out (RP-initiated logout): confirm, signed out, or why it failed |
| `/api/auth/verify-email` | The link in the verification email |
| `/api/auth/magic-link/verify` | The link in the magic-link email |

## Visual examples

Every screenshot below is captured directly from AuthWAPI's server-rendered HTML (click any image to open full-size). Pages follow the browser's `prefers-color-scheme` automatically.

### Sign in and sign up

<div class="aw-shot-grid not-content">
  <figure class="aw-shot">
    <a href="/images/hosted-pages/sign-in-dark.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/sign-in-dark.png" alt="AuthWAPI sign-in page in dark mode with OAuth app banner, password, passkey, Google, GitHub, SSO, and magic-link options" loading="lazy" />
    </a>
    <figcaption><code>/sign-in</code><span>Dark mode (OAuth + social)</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/sign-in-light.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/sign-in-light.png" alt="AuthWAPI sign-in page in light mode" loading="lazy" />
    </a>
    <figcaption><code>/sign-in</code><span>Light mode</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/sign-up-dark.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/sign-up-dark.png" alt="AuthWAPI create an account page in dark mode" loading="lazy" />
    </a>
    <figcaption><code>/sign-up</code><span>Dark mode</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/sign-up-light.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/sign-up-light.png" alt="AuthWAPI create an account page in light mode" loading="lazy" />
    </a>
    <figcaption><code>/sign-up</code><span>Light mode</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/check-email.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/check-email.png" alt="AuthWAPI check your email confirmation page after sign-up" loading="lazy" />
    </a>
    <figcaption><code>POST /sign-up</code><span>Check your email</span></figcaption>
  </figure>
</div>

### Account, verification and recovery

<div class="aw-shot-grid not-content">
  <figure class="aw-shot">
    <a href="/images/hosted-pages/home-signed-out.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/home-signed-out.png" alt="AuthWAPI home page when signed out" loading="lazy" />
    </a>
    <figcaption><code>/</code><span>Signed out</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/home-signed-in.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/home-signed-in.png" alt="AuthWAPI account page when signed in with links to 2FA and passkeys" loading="lazy" />
    </a>
    <figcaption><code>/</code><span>Signed in</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/verify-email.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/verify-email.png" alt="AuthWAPI email verification page asking for the sign-up password" loading="lazy" />
    </a>
    <figcaption><code>/api/auth/verify-email</code><span>Verify email</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/magic-link.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/magic-link.png" alt="AuthWAPI magic link confirmation screen asking Sign in as ada@example.com?" loading="lazy" />
    </a>
    <figcaption><code>/api/auth/magic-link/verify</code><span>Magic-link confirm</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/forgot-password.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/forgot-password.png" alt="AuthWAPI forgot password page" loading="lazy" />
    </a>
    <figcaption><code>/forgot-password</code><span>Request reset</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/reset-password.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/reset-password.png" alt="AuthWAPI choose a new password page" loading="lazy" />
    </a>
    <figcaption><code>/reset-password</code><span>Choose new password</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/signed-out.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/signed-out.png" alt="AuthWAPI signed out confirmation page" loading="lazy" />
    </a>
    <figcaption><code>/signed-out</code><span>Signed out</span></figcaption>
  </figure>
</div>

### Two-factor authentication and passkeys

<div class="aw-shot-grid not-content">
  <figure class="aw-shot aw-shot-tall">
    <a href="/images/hosted-pages/two-factor-setup.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/two-factor-setup.png" alt="AuthWAPI two-factor setup page with QR code, manual secret key, backup codes, and confirmation code input" loading="lazy" />
    </a>
    <figcaption><code>/two-factor/setup</code><span>QR code &amp; backup codes</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/two-factor-challenge.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/two-factor-challenge.png" alt="AuthWAPI two-factor challenge page with 6-digit code input and backup code disclosure" loading="lazy" />
    </a>
    <figcaption><code>/two-factor</code><span>2FA challenge</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/passkeys.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/passkeys.png" alt="AuthWAPI passkeys management page" loading="lazy" />
    </a>
    <figcaption><code>/passkeys</code><span>Add a passkey</span></figcaption>
  </figure>
</div>

### OAuth consent, organizations and errors

<div class="aw-shot-grid not-content">
  <figure class="aw-shot">
    <a href="/images/hosted-pages/select-org.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/select-org.png" alt="AuthWAPI choose an organization page with selectable role cards" loading="lazy" />
    </a>
    <figcaption><code>/select-org</code><span>Organization picker</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/consent.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/consent.png" alt="AuthWAPI OAuth consent page showing scopes, API resource access, organization badge, and Allow or Deny buttons" loading="lazy" />
    </a>
    <figcaption><code>/consent</code><span>OAuth &amp; MCP consent</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/accept-invitation.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/accept-invitation.png" alt="AuthWAPI organization invitation acceptance page" loading="lazy" />
    </a>
    <figcaption><code>/accept-invitation</code><span>Org invitation</span></figcaption>
  </figure>
  <figure class="aw-shot">
    <a href="/images/hosted-pages/error.png" target="_blank" rel="noopener noreferrer">
      <img src="/images/hosted-pages/error.png" alt="AuthWAPI error page displaying a plain-language message and error code" loading="lazy" />
    </a>
    <figcaption><code>/error</code><span>Error page</span></figcaption>
  </figure>
</div>

## Errors

Better Auth sends a browser that hit an error to `/error?error=<code>`. The page shows the code, in plain words
where it knows it. It never shows `error_description` or any other text from the URL: anyone can write a link to
the page, and text shown there would look like it came from AuthWAPI.

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
