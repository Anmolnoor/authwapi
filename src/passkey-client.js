// Passkey buttons on the hosted pages (served as /passkey.js): [data-passkey="sign-in"] and [data-passkey="add"].
// The browser's own WebAuthn JSON helpers (PublicKeyCredential.parse*OptionsFromJSON, credential.toJSON()) do the
// encoding, so there is no library. Browsers without them don't show the buttons.
const api = async (path, body) => {
  const init = body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify(body) };
  const res = await fetch(`/api/auth${path}`, init);
  return { ok: res.ok, data: await res.json().catch(() => null) };
};

for (const button of document.querySelectorAll('[data-passkey]')) {
  const status = document.getElementById(button.dataset.status);
  const say = (text) => { if (status) status.textContent = text; };
  if (!window.PublicKeyCredential?.parseRequestOptionsFromJSON) {
    button.hidden = true;
    continue;
  }
  button.addEventListener('click', async () => {
    try {
      if (button.dataset.passkey === 'sign-in') {
        const options = await api('/passkey/generate-authenticate-options');
        const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.data) });
        // During an OAuth sign-in the signed request goes along, and the answer says where the app's request continues.
        const query = button.dataset.oauthQuery;
        const r = await api('/passkey/verify-authentication', { response: credential.toJSON(), ...(query ? { oauth_query: query } : {}) });
        if (!r.ok) return say(r.data?.message ?? "That passkey didn't work.");
        location.assign(r.data?.url ?? '/');
      } else {
        const options = await api('/passkey/generate-register-options');
        if (!options.ok) return say(options.data?.message ?? "Couldn't start adding a passkey.");
        const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.data) });
        const r = await api('/passkey/verify-registration', { response: credential.toJSON() });
        say(r.ok ? 'Passkey added.' : (r.data?.message ?? "That passkey couldn't be added."));
      }
    } catch (err) {
      say(err?.name === 'NotAllowedError' ? 'Cancelled.' : "Passkeys didn't work in this browser.");
    }
  });
}
