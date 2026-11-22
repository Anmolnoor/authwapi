// The look of the hosted pages: one layout, its stylesheet and inline SVG icons. No script, no external fonts or
// images: the pages' CSP allows scripts only from our origin, and nothing here loads from the network.
// Every template is hono/html, so interpolated values are escaped; the icons are static markup.
import { html } from 'hono/html';

export type Html = ReturnType<typeof html>;

export interface LayoutOptions {
  /** A line under the heading. */
  subtitle?: string;
  /** An icon (from `icons`) shown in a badge above the heading. */
  icon?: Html;
}

/** Icons are decorative (aria-hidden): every one sits next to text that says the same. */
export const icons = {
  passkey: html`<svg class="aw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M10.85 12.15 19 4M17.5 5.5l2 2M14.5 8.5l2 2"/></svg>`,
  google: html`<svg class="aw-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09Z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23Z"/><path fill="#FBBC05" d="M5.84 14.1a6.6 6.6 0 0 1 0-4.2V7.07H2.18a11 11 0 0 0 0 9.86l3.66-2.84Z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15A10.6 10.6 0 0 0 12 1 11 11 0 0 0 2.18 7.07l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38Z"/></svg>`,
  github: html`<svg class="aw-icon" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>`,
  mail: html`<svg class="aw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg>`,
  shield: html`<svg class="aw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3Z"/><circle cx="12" cy="11" r="1.75"/><path d="M12 12.75V15.5"/></svg>`,
  check: html`<svg class="aw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>`,
  building: html`<svg class="aw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16M16 9h2a2 2 0 0 1 2 2v10M3 21h18M8 7h4M8 11h4M8 15h4"/></svg>`,
  chevron: html`<svg class="aw-icon aw-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>`,
};

/** The AuthWAPI mark (site/public/favicon.svg), coloured by the theme. */
const mark = html`<svg class="aw-mark" width="24" height="24" viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect x="2.5" y="2.5" width="27" height="27" rx="6.5" stroke="currentColor" stroke-width="2" fill="currentColor" fill-opacity="0.12"/><path class="aw-mark-key" d="M16 9.2a3.7 3.7 0 0 1 3.7 3.7c0 1.44-.83 2.7-2.04 3.31l.83 5.99h-4.98l.83-5.99A3.7 3.7 0 0 1 16 9.2Z"/></svg>`;

export const alert = (message: string | undefined) => (message ? html`<p role="alert">${message}</p>` : html``);

export const layout = (title: string, body: Html, passkeyScript: boolean, { subtitle, icon }: LayoutOptions = {}) => html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${title} · AuthWAPI</title>
<style>
:root{--bg:#fafafa;--card:#fff;--line:#e4e4e7;--text:#09090b;--muted:#52525b;--accent:#1f4fd1;--accent-hover:#1a42b3;--btn-bg:#1f4fd1;--btn-hover:#1a42b3;--link:#1f4fd1;--visited:#5b21b6;
--tint:rgba(31,79,209,.08);--tint-line:rgba(31,79,209,.22);--ring:rgba(31,79,209,.2);--field:#fff;--field-line:#8a8a93;--soft:#f4f4f5;
--danger:#b42318;--danger-bg:#fef3f2;--danger-line:#fecdca;--ok:#067647;--ok-bg:#ecfdf3;--ok-line:#abefc6;
--shadow:0 1px 2px rgba(9,9,11,.04),0 12px 32px -12px rgba(9,9,11,.12);
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--texture:radial-gradient(rgba(9,9,11,.07) 1px,transparent 1px) 0 0/20px 20px}
@media (prefers-color-scheme:dark){:root{--bg:#09090b;--card:#111216;--line:rgba(255,255,255,.09);--text:#f4f4f5;--muted:#a1a1aa;
--accent:#3b82f6;--accent-hover:#2563eb;--btn-bg:#2563eb;--btn-hover:#1d4ed8;--link:#60a5fa;--visited:#c58af9;--tint:rgba(59,130,246,.1);--tint-line:rgba(59,130,246,.3);--ring:rgba(59,130,246,.35);
--field:#0c0d10;--field-line:#686872;--soft:rgba(255,255,255,.04);
--danger:#fda29b;--danger-bg:rgba(240,68,56,.1);--danger-line:rgba(240,68,56,.32);--ok:#75e0a7;--ok-bg:rgba(23,178,106,.1);--ok-line:rgba(23,178,106,.32);
--shadow:inset 0 1px 0 rgba(255,255,255,.04),0 24px 48px -16px rgba(0,0,0,.7);
--texture:radial-gradient(60rem 28rem at 50% -8rem,rgba(59,130,246,.16),transparent 70%),linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px) 0 0/32px 32px,linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px) 0 0/32px 32px}}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;font:15px/1.55 var(--sans);color:var(--text);background:var(--texture),var(--bg);background-attachment:fixed;-webkit-font-smoothing:antialiased}
.aw-shell{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2.5rem 1rem}
.aw-brand{display:inline-flex;align-items:center;gap:.5rem;margin-bottom:1.5rem;color:var(--text);font-weight:650;font-size:1rem;letter-spacing:-.01em;text-decoration:none}
.aw-brand:hover{text-decoration:none}
.aw-mark{color:var(--accent);flex:none}.aw-mark-key{fill:var(--link)}
.aw-card{width:100%;max-width:26.5rem;padding:2.25rem 2rem;background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.aw-foot{margin-top:1.5rem;font-size:.8125rem;color:var(--muted)}
.aw-head{margin-bottom:1.5rem}
h1{margin:0;font-size:1.375rem;line-height:1.3;font-weight:650;letter-spacing:-.02em}
.aw-sub{margin:.375rem 0 0;color:var(--muted)}
p{margin:.75rem 0}
a{color:var(--link);font-weight:500;text-decoration:none}
a:visited{color:var(--visited)}
a:hover{text-decoration:underline;text-underline-offset:2px}
p a{text-decoration:underline;text-underline-offset:2px}
.aw-brand:visited,.aw-nav a:visited{color:var(--text)}
.aw-button:visited{color:#fff}
.aw-button.secondary:visited{color:var(--text)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.aw-icon{width:1.125rem;height:1.125rem;flex:none}
.aw-icon-badge{display:inline-flex;align-items:center;justify-content:center;width:2.75rem;height:2.75rem;margin-bottom:1rem;border:1px solid var(--tint-line);border-radius:10px;background:var(--tint);color:var(--accent)}
.aw-icon-badge .aw-icon{width:1.375rem;height:1.375rem}
form{margin:0}
label{display:block;margin-top:1rem;font-size:.875rem;font-weight:550}
form>label:first-of-type{margin-top:0}
.aw-label-row{display:flex;align-items:baseline;justify-content:space-between;gap:1rem;margin-top:1rem}
.aw-label-row label{margin:0}.aw-label-row a{font-size:.8125rem}
.aw-hint{color:var(--muted);font-weight:400}
input{display:block;width:100%;height:2.625rem;margin-top:.375rem;padding:0 .75rem;font:inherit;color:var(--text);background:var(--field);border:1px solid var(--field-line);border-radius:8px;transition:border-color .15s,box-shadow .15s}
input::placeholder{color:var(--muted)}
input:focus{outline:2px solid transparent;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
input:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
input[type=radio],input[type=checkbox]{display:inline;width:auto;height:auto;margin:0 .5rem 0 0;accent-color:var(--accent)}
button,.aw-button{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;min-height:2.625rem;margin-top:1.25rem;padding:.5rem 1rem;font:inherit;font-weight:600;color:#fff;background:var(--btn-bg);border:1px solid transparent;border-radius:8px;cursor:pointer;text-decoration:none;box-shadow:inset 0 1px 0 rgba(255,255,255,.12),0 1px 2px rgba(9,9,11,.12);transition:background-color .15s,border-color .15s}
button:hover,.aw-button:hover{background:var(--btn-hover);text-decoration:none}
button.secondary,.aw-button.secondary{color:var(--text);background:var(--card);border-color:var(--field-line);font-weight:550;box-shadow:0 1px 2px rgba(9,9,11,.05)}
button.secondary:hover,.aw-button.secondary:hover{background:var(--soft)}
.aw-stack{display:grid;gap:.625rem}
.aw-stack button,.aw-stack .aw-button{margin-top:0}
.divider{display:flex;align-items:center;gap:.75rem;margin:1.5rem 0;font-size:.75rem;font-weight:550;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.divider::before,.divider::after{content:"";flex:1;border-top:1px solid var(--line)}
[role=alert],.ok{position:relative;margin:0 0 1.25rem;padding:.75rem .875rem .75rem 1.125rem;font-size:.875rem;border:1px solid;border-radius:8px;overflow:hidden}
[role=alert]::before,.ok::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
[role=alert]{color:var(--danger);background:var(--danger-bg);border-color:var(--danger-line)}[role=alert]::before{background:var(--danger)}
.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line)}.ok::before{background:var(--ok)}
.ok a{color:inherit;text-decoration:underline}
#passkey-status{margin:0;font-size:.875rem;color:var(--muted);text-align:center}
#passkey-status:empty{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.aw-disclosure{margin-top:.625rem;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.aw-disclosure>summary{display:flex;align-items:center;gap:.625rem;padding:.75rem 1rem;font-weight:550;cursor:pointer;list-style:none;border-radius:10px}
.aw-disclosure>summary::-webkit-details-marker{display:none}
.aw-disclosure>summary:hover{background:var(--soft)}
.aw-disclosure>summary .aw-icon{color:var(--muted)}
.aw-disclosure>summary .aw-chevron{margin-left:auto;transition:transform .15s}
.aw-disclosure[open]>summary .aw-chevron{transform:rotate(90deg)}
.aw-disclosure[open]>summary{border-bottom-left-radius:0;border-bottom-right-radius:0}
.aw-disclosure-body{padding:.25rem 1rem 1rem}
.aw-disclosure-body button{margin-top:.875rem}
.aw-disclosure-body>p:first-child{margin-top:0}
.aw-foot-link{margin:1.5rem 0 0;font-size:.875rem;color:var(--muted);text-align:center}
.aw-account{display:flex;align-items:center;gap:.75rem;padding:.875rem 1rem;border:1px solid var(--line);border-radius:10px;background:var(--soft)}
.aw-account p{margin:0;min-width:0;overflow-wrap:anywhere;font-size:.875rem;color:var(--muted)}
.aw-account strong{display:block;font-size:.9375rem;font-weight:600;color:var(--text)}
.aw-account-ask strong{display:inline;font-size:inherit}
.aw-note{margin:1.25rem 0 0;padding:.75rem .875rem;font-size:.8125rem;color:var(--muted);background:var(--soft);border:1px solid var(--line);border-radius:8px}
.aw-avatar{display:inline-flex;align-items:center;justify-content:center;flex:none;width:2.5rem;height:2.5rem;border-radius:999px;background:var(--tint);border:1px solid var(--tint-line);color:var(--accent);font-weight:650}
.aw-nav{display:grid;gap:.5rem;margin-top:1.25rem}
.aw-nav a{display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;color:var(--text);border:1px solid var(--line);border-radius:10px;transition:background-color .15s,border-color .15s}
.aw-nav a:hover{text-decoration:none;background:var(--soft);border-color:var(--tint-line)}
.aw-nav a>.aw-icon:first-child{color:var(--accent)}
.aw-nav span{display:block;font-weight:550}
.aw-nav small{display:block;font-size:.8125rem;font-weight:400;color:var(--muted)}
.aw-nav .aw-chevron{margin-left:auto;color:var(--muted)}
.aw-code-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:.375rem;margin:.75rem 0;padding:.75rem;list-style:none;font:500 .875rem/1.6 var(--mono);background:var(--soft);border:1px solid var(--line);border-radius:10px}
.aw-code-grid li{padding:.25rem .5rem;text-align:center;letter-spacing:.04em}
.aw-code-grid code{padding:0;background:none;border:0}
.aw-radio-card{display:flex;align-items:center;gap:.25rem;margin-top:.5rem;padding:.75rem 1rem;border:1px solid var(--line);border-radius:10px;cursor:pointer;font-weight:500}
.aw-radio-card:hover{background:var(--soft)}
.aw-radio-card:has(input:checked){border-color:var(--accent);background:var(--tint)}
.aw-perm-list{margin:.75rem 0;padding:0;list-style:none}
.aw-perm-list li{position:relative;padding:.5rem 0 .5rem 1.75rem;border-bottom:1px solid var(--line)}
.aw-perm-list li:last-child{border-bottom:0}
.aw-perm-list li::before{content:"";position:absolute;left:.375rem;top:.85rem;width:.35rem;height:.65rem;border:solid var(--accent);border-width:0 2px 2px 0;transform:rotate(45deg)}
.aw-radio-name{flex:1;min-width:0;overflow-wrap:anywhere}
.aw-role-badge{flex:none;padding:.0625rem .5rem;font-size:.75rem;font-weight:550;color:var(--muted);background:var(--soft);border:1px solid var(--line);border-radius:999px}
.aw-consent-lead{margin:0;font-weight:500}
.aw-actions{display:grid;grid-template-columns:1fr 1fr;gap:.625rem;margin-top:1.5rem}
.aw-actions button{margin-top:0}
.aw-note strong{color:var(--text)}
.aw-note+form>label:first-of-type{margin-top:1.25rem}
.aw-otp{font:600 1.125rem/1 var(--mono);letter-spacing:.3em;text-align:center}
.aw-secret-box{margin:.75rem 0;padding:.875rem 1rem;text-align:center;background:var(--soft);border:1px solid var(--line);border-radius:10px}
.aw-secret-box code{font-size:.9375rem;font-weight:600;letter-spacing:.04em;background:none;border:0;user-select:all}
.aw-qr-box{display:flex;justify-content:center;margin:.75rem 0 1rem;padding:1rem;background:#fff;border:1px solid var(--line);border-radius:12px}
.qr{display:block;width:100%;max-width:13.5rem;height:auto}
.aw-app-banner{margin:0 0 1.25rem;font-size:.875rem;color:var(--muted);background:var(--tint);border-color:var(--tint-line)}
.aw-disclosure-body>code{display:block;padding:.5rem .625rem}
code{padding:.1rem .35rem;font:.8125rem/1.5 var(--mono);background:var(--soft);border:1px solid var(--line);border-radius:5px;overflow-wrap:anywhere}
ul{padding-left:1.25rem}
hr{margin:1.5rem 0;border:0;border-top:1px solid var(--line)}
strong{font-weight:600}
@media (max-width:30rem){.aw-shell{justify-content:flex-start;padding:1.5rem .75rem}.aw-card{padding:1.75rem 1.25rem;border-radius:12px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
${passkeyScript ? html`<script src="/passkey.js" defer></script>` : ''}
</head>
<body>
<div class="aw-shell">
<a class="aw-brand" href="/">${mark}<span>AuthWAPI</span></a>
<main class="aw-card">
<div class="aw-head">
${icon ? html`<div class="aw-icon-badge">${icon}</div>` : ''}
<h1>${title}</h1>
${subtitle ? html`<p class="aw-sub">${subtitle}</p>` : ''}
</div>
${body}
</main>
<p class="aw-foot">Secured by AuthWAPI</p>
</div>
</body>
</html>`;
