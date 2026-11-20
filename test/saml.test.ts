// M4b: SAML SSO per organization (plan flow.md, M4b in "Rev 9 execution"). The identity provider is in-process:
// samlify writes its metadata and signs the responses this file builds (a throwaway key pair per test), so every
// negative case is a response a real IdP, or someone holding one of its assertions, could send.
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import * as x509 from '@peculiar/x509';
import { execFile } from 'node:child_process';
import { randomUUID, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { inflateRawSync } from 'node:zlib';
import { afterEach, beforeEach, test } from 'node:test';
import samlify from 'samlify';
import { SignedXml } from 'xml-crypto';
import { startTestServer, type TestServer } from './helpers.ts';
import { currentUser, db, enableTotp, Jar, send, totp, verifiedUser } from './signin-helpers.ts';

let sp: TestServer;
beforeEach(async () => {
  sp = await startTestServer();
});
afterEach(async () => {
  await sp.stop();
});

const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const SHA1_DIGEST = 'http://www.w3.org/2000/09/xmldsig#sha1';
/** Where real IdPs post from: another site, not in ALLOWED_HOSTS. */
const IDP_ORIGIN = 'https://idp.example';

// ── MCP on the AuthWAPI under test ──
async function connect(key: string) {
  const client = new Client({ name: 'test-agent', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${sp.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${key}` } } }));
  return client;
}
async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, data: JSON.parse((r.content as { text: string }[])[0].text) };
}
const ok = async (p: ReturnType<typeof call>) => {
  const r = await p;
  assert.equal(r.isError, false, JSON.stringify(r.data));
  return r.data;
};
async function writeAgent() {
  const boot = await connect(readFileSync(sp.paths.bootstrapKey, 'utf8').trim());
  const write = await connect((await call(boot, 'mint_agent_key', { scope: 'write' })).data.key);
  await boot.close();
  return write;
}
async function org(write: Client, slug: string) {
  const owner = await ok(call(write, 'create_user', { email: `owner@${slug}.test`, name: 'Owner', password: 'correct horse', emailVerified: true }));
  return (await ok(call(write, 'create_org', { name: slug, slug, ownerUserId: owner.user.id }))).organization.id as string;
}

const row = (sql: string, ...args: unknown[]) => {
  const d = db(sp);
  try {
    return d.prepare(sql).get(...args) as Record<string, any> | undefined;
  } finally {
    d.close();
  }
};
const count = (sql: string, ...args: unknown[]) => Object.values(row(sql, ...args)!)[0] as number;

// ── The identity provider ──
interface Idp {
  entityID: string;
  ssoUrl: string;
  privateKey: string;
  cert: string;
  metadata: string;
}
/** A SAML IdP with a fresh RSA key and self-signed certificate; samlify writes its metadata. */
async function makeIdp(name: string): Promise<Idp> {
  const alg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
  const keys = (await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const now = Date.now();
  const certificate = await x509.X509CertificateGenerator.createSelfSigned(
    { serialNumber: '01', name: `CN=${name}`, notBefore: new Date(now - 86400e3), notAfter: new Date(now + 86400e3), signingAlgorithm: alg, keys },
    webcrypto as Crypto
  );
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
  const privateKey = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`;
  const entityID = `https://${name}.example/saml`;
  const ssoUrl = `https://${name}.example/sso`; // never fetched: the browser goes there, and the tests stand in for it
  const cert = certificate.toString('pem');
  const metadata = samlify
    .IdentityProvider({ entityID, signingCert: cert, singleSignOnService: [{ Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: ssoUrl }] })
    .getMetadata();
  return { entityID, ssoUrl, privateKey, cert, metadata };
}

interface Assertion {
  nameId: string;
  email?: string;
  format?: string;
  inResponseTo?: string; // omitted: IdP-initiated
  audience?: string;
  recipient?: string;
  timestamps?: 'valid' | 'expired' | 'none'; // none: no NotBefore/NotOnOrAfter in Conditions (the bearer confirmation keeps its own)
  sign?: 'assertion' | 'response' | 'both' | 'none';
  algorithm?: string;
  digest?: string; // the assertion signature's DigestMethod, when not the signature algorithm's own
  issuer?: string;
}
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

/** A SAML Response from `idp`, signed as asked, base64 for the ACS form. */
function samlResponse(idp: Idp, p: { acsUrl: string; spEntityId: string }, a: Assertion): string {
  const id = randomUUID().replaceAll('-', '');
  const recipient = a.recipient ?? p.acsUrl;
  const irt = a.inResponseTo ? ` InResponseTo="${a.inResponseTo}"` : '';
  const issuer = a.issuer ?? idp.entityID;
  const [notBefore, notOnOrAfter] = a.timestamps === 'expired' ? [iso(-3600e3), iso(-1800e3)] : [iso(-60e3), iso(300e3)];
  const conditionTimes = a.timestamps === 'none' ? '' : ` NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"`;
  const email = a.email === undefined ? '' : `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${a.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`;
  let xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${id}" Version="2.0" IssueInstant="${iso(0)}" Destination="${recipient}"${irt}>` +
    `<saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_a${id}" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>${issuer}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${a.format ?? PERSISTENT}">${a.nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${recipient}" NotOnOrAfter="${notOnOrAfter}"${irt}/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions${conditionTimes}><saml:AudienceRestriction><saml:Audience>${a.audience ?? p.spEntityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_s${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `${email}</saml:Assertion></samlp:Response>`;
  const sign = a.sign ?? 'assertion';
  const signing = { privateKey: idp.privateKey, signingCert: idp.cert.replace(/-----[^-]+-----|\s/g, ''), signatureAlgorithm: a.algorithm ?? SHA256, isBase64Output: false };
  if (a.digest) {
    // samlify always pairs the digest with the signature algorithm; xml-crypto signs with any pair.
    const sig = new SignedXml({ privateKey: idp.privateKey });
    sig.addReference({
      xpath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']",
      transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
      digestAlgorithm: a.digest,
    });
    sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    sig.signatureAlgorithm = a.algorithm ?? SHA256;
    sig.computeSignature(xml, { prefix: 'ds', location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' } });
    xml = sig.getSignedXml();
  } else if (sign === 'assertion' || sign === 'both') {
    xml = samlify.SamlLib.constructSAMLSignature({
      ...signing,
      rawSamlMessage: xml,
      referenceTagXPath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']",
      signatureConfig: { prefix: 'ds', location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' } },
    });
  }
  if (sign === 'response' || sign === 'both') {
    xml = samlify.SamlLib.constructSAMLSignature({
      ...signing,
      rawSamlMessage: xml,
      isMessageSigned: true,
      signatureConfig: { prefix: 'ds', location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' } },
    });
  }
  return Buffer.from(xml).toString('base64');
}

interface Provider {
  providerId: string;
  organizationId: string;
  acsUrl: string;
  spEntityId: string;
}
/** An organization `slug` whose SAML provider (registered from the IdP's metadata) routes `domain`. */
async function samlOrg(write: Client, slug: string, domain: string, idp: Idp): Promise<Provider> {
  const organizationId = await org(write, slug);
  const { provider } = await ok(call(write, 'register_sso_provider', { protocol: 'saml', organizationId, slug, domain, idpMetadata: idp.metadata }));
  return { ...provider, organizationId };
}

/** SP-initiated sign-in: AuthWAPI's redirect to the IdP, with the AuthnRequest it carries. */
async function start(jar: Jar, by: { providerId: string } | { email: string }) {
  const r = await send(sp, jar, 'POST', '/api/auth/sign-in/sso', { json: { ...by, callbackURL: '/', errorCallbackURL: '/sign-in' } });
  assert.equal(r.status, 200, r.body);
  const url = new URL(r.json().url);
  const request = inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest')!, 'base64')).toString();
  return { url, request, requestId: /\sID="([^"]+)"/.exec(request)![1], relayState: url.searchParams.get('RelayState')! };
}
/** The browser's form POST of the IdP's response to the ACS: cross-site, from the IdP's page. */
const post = (jar: Jar, providerId: string, SAMLResponse: string, RelayState?: string) =>
  send(sp, jar, 'POST', `/api/auth/sso/saml2/sp/acs/${providerId}`, { form: { SAMLResponse, ...(RelayState ? { RelayState } : {}) }, navigate: true, origin: IDP_ORIGIN });

/** A full SP-initiated round trip; the assertion answers the request unless told otherwise. */
async function signIn(jar: Jar, idp: Idp, p: Provider, a: Assertion) {
  const s = await start(jar, { providerId: p.providerId });
  const SAMLResponse = samlResponse(idp, p, { inResponseTo: s.requestId, ...a });
  return { back: await post(jar, p.providerId, SAMLResponse, s.relayState), SAMLResponse, relayState: s.relayState };
}
const errorOf = (location: string | undefined) => new URL(location ?? '/', sp.base).searchParams.get('error');

test("org A's SAML provider signs in a new user: a member of A, email unverified, bound to (A's provider, NameID)", async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  assert.equal(a.providerId, 'sso-a');
  assert.equal(a.acsUrl, `${sp.base}/api/auth/sso/saml2/sp/acs/sso-a`);
  assert.equal(a.spEntityId, `${sp.base}/api/auth/sso/saml2/sp/metadata?providerId=sso-a`);

  // The SP metadata the IdP admin imports: signed assertions wanted, persistent NameIDs, this provider's ACS.
  const meta = await fetch(a.spEntityId);
  assert.equal(meta.status, 200);
  const xml = await meta.text();
  assert.match(xml, /WantAssertionsSigned="true"/);
  assert.match(xml, new RegExp(`entityID="${a.spEntityId.replace(/[?.]/g, '\\$&')}"`));
  assert.ok(xml.includes(`Location="${a.acsUrl}"`));
  assert.ok(xml.includes(`<NameIDFormat>${PERSISTENT}</NameIDFormat>`) || xml.includes(`NameIDFormat>${PERSISTENT}<`));

  // The hosted page routes by email domain to the IdP; the AuthnRequest asks for a persistent NameID.
  const page = await send(sp, new Jar(), 'POST', '/sign-in', { form: { method: 'sso', email: 'alice@a.example', oauth_query: '' } });
  assert.equal(page.status, 303, page.body);
  assert.ok(page.location?.startsWith(`${idp.ssoUrl}?SAMLRequest=`), String(page.location));
  const jar = new Jar();
  const s = await start(jar, { email: 'alice@a.example' });
  assert.match(s.request, new RegExp(`NameIDPolicy[^>]*Format="${PERSISTENT}"`));

  const back = await post(jar, a.providerId, samlResponse(idp, a, { nameId: 'u-1001', email: 'Alice@a.example', inResponseTo: s.requestId }), s.relayState);
  assert.equal(back.status, 302, back.body);
  assert.equal(back.location, '/');
  assert.equal(await currentUser(sp, jar), 'alice@a.example');
  const user = row('SELECT id, emailVerified FROM user WHERE email = ?', 'alice@a.example')!;
  assert.equal(user.emailVerified, 0);
  assert.equal(row('SELECT role FROM member WHERE userId = ? AND organizationId = ?', user.id, a.organizationId)?.role, 'member');
  assert.deepEqual(row('SELECT providerId, accountId FROM account WHERE userId = ?', user.id), { providerId: 'sso-a', accountId: 'u-1001' });

  // Again, with a different email attribute: the NameID binding decides who signs in.
  const again = new Jar();
  assert.equal((await signIn(again, idp, a, { nameId: 'u-1001', email: 'alice.renamed@a.example' })).back.location, '/');
  assert.equal(await currentUser(sp, again), 'alice@a.example');
  assert.equal(count("SELECT count(*) FROM user WHERE email LIKE '%@a.example'"), 1);
});

// One test per case: each starts a sign-in, and Better Auth allows 3 sign-in starts per 10 seconds per client.
const forged: [string, Assertion, ((idp: Idp) => Promise<Idp>)?][] = [
  ['an unsigned assertion', { nameId: 'u-1', email: 'u1@a.example', sign: 'none' }],
  ['a signed response around an unsigned assertion', { nameId: 'u-1', email: 'u1@a.example', sign: 'response' }],
  ['an assertion signed by another key', { nameId: 'u-1', email: 'u1@a.example' }, async (idp) => ({ ...(await makeIdp('other')), entityID: idp.entityID })],
  ['the wrong audience', { nameId: 'u-1', email: 'u1@a.example', audience: 'https://another-sp.example' }],
  ['the wrong recipient', { nameId: 'u-1', email: 'u1@a.example', recipient: 'http://127.0.0.1:1/api/auth/sso/saml2/sp/acs/sso-a' }],
  ['an expired assertion', { nameId: 'u-1', email: 'u1@a.example', timestamps: 'expired' }],
  ['Conditions without timestamps', { nameId: 'u-1', email: 'u1@a.example', timestamps: 'none' }],
  ['an RSA-SHA1 signature', { nameId: 'u-1', email: 'u1@a.example', algorithm: SHA1 }],
  ['RSA-SHA1 on assertion and response', { nameId: 'u-1', email: 'u1@a.example', algorithm: SHA1, sign: 'both' }],
  ['a transient NameID', { nameId: 'u1@a.example', email: 'u1@a.example', format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' }],
  ['an email NameID', { nameId: 'u1@a.example', email: 'u1@a.example', format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' }],
  ['an unspecified NameID', { nameId: 'u1@a.example', email: 'u1@a.example', format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified' }],
  ['no email attribute', { nameId: 'u-1' }],
  ['a SHA-1 digest under an RSA-SHA256 signature', { nameId: 'u-1', email: 'u1@a.example', digest: SHA1_DIGEST }],
];
for (const [name, assertion, signer] of forged) {
  test(`refused: ${name}`, async () => {
    const write = await writeAgent();
    const idp = await makeIdp('idp-a');
    const a = await samlOrg(write, 'a', 'a.example', idp);
    const jar = new Jar();
    const { back } = await signIn(jar, signer ? await signer(idp) : idp, a, assertion);
    assert.equal(back.status, 302, back.body);
    assert.notEqual(back.location, '/');
    assert.ok(errorOf(back.location), String(back.location));
    assert.equal(await currentUser(sp, jar), null);
    assert.equal(count('SELECT count(*) FROM user'), 1, 'only the org owner');
    assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-a'"), 0);
    // The same IdP, signing properly, gets in.
    assert.equal((await signIn(new Jar(), idp, a, { nameId: 'u-1', email: 'u1@a.example' })).back.location, '/');
  });
}

test('the refusal codes our checks add: SHA-1, a NameID that is not persistent, no email attribute', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const sha1 = await signIn(new Jar(), idp, a, { nameId: 'u-1', email: 'u1@a.example', algorithm: SHA1 });
  assert.equal(errorOf(sha1.back.location), 'saml_deprecated_algorithm');
  const transient = await signIn(new Jar(), idp, a, { nameId: 'u-1', email: 'u1@a.example', format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' });
  assert.equal(errorOf(transient.back.location), 'nameid_not_persistent');
  const noEmail = await signIn(new Jar(), idp, a, { nameId: 'u-1' });
  assert.equal(errorOf(noEmail.back.location), 'email_missing');
});

test('the refusal code for a SHA-1 digest under an RSA-SHA256 signature', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const digest = await signIn(new Jar(), idp, a, { nameId: 'u-1', email: 'u1@a.example', digest: SHA1_DIGEST });
  assert.equal(errorOf(digest.back.location), 'saml_deprecated_algorithm');
  assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-a'"), 0);
});

test("login CSRF: the attacker's signed response, posted from the victim's browser (with or without RelayState), is refused", async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  for (const withRelay of [true, false]) {
    // The attacker starts a sign-in and gets the IdP's response for their own account...
    const s = await start(new Jar(), { providerId: a.providerId });
    const response = samlResponse(idp, a, { nameId: 'u-evil', email: 'mallory@a.example', inResponseTo: s.requestId });
    // ...and has the victim's browser post it.
    const victim = new Jar();
    const back = await post(victim, a.providerId, response, withRelay ? s.relayState : undefined);
    assert.equal(back.status, 302, back.body);
    assert.equal(errorOf(back.location), 'saml_request_not_from_this_browser', String(back.location));
    assert.equal(await currentUser(sp, victim), null);
  }
  assert.equal(count("SELECT count(*) FROM user WHERE email = 'mallory@a.example'"), 0);
});

test('login CSRF: a browser that started its own sign-in gets only its own response; the cookie is cleared after', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const s = await start(new Jar(), { providerId: a.providerId }); // the attacker's
  const browser = new Jar();
  const s2 = await start(browser, { providerId: a.providerId });
  const theirs = await post(browser, a.providerId, samlResponse(idp, a, { nameId: 'u-evil', email: 'mallory@a.example', inResponseTo: s.requestId }), s2.relayState);
  assert.equal(errorOf(theirs.location), 'saml_request_not_from_this_browser', String(theirs.location));
  const s3 = await start(browser, { providerId: a.providerId });
  const own = await post(browser, a.providerId, samlResponse(idp, a, { nameId: 'u-2', email: 'u2@a.example', inResponseTo: s3.requestId }), s3.relayState);
  assert.equal(own.location, '/');
  assert.equal(await currentUser(sp, browser), 'u2@a.example');
  assert.ok(own.setCookies.some((c) => /^authwapi_saml_request=;/.test(c) && /max-age=0/i.test(c)), own.setCookies.join(' | '));
});

test('the SAML request cookie: SameSite=None, Secure, HttpOnly, the hash of the AuthnRequest ID, only on the ACS path', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const r = await send(sp, new Jar(), 'POST', '/api/auth/sign-in/sso', { json: { providerId: a.providerId, callbackURL: '/' } });
  const cookie = r.setCookies.find((c) => c.startsWith('authwapi_saml_request='));
  assert.ok(cookie, r.setCookies.join(' | '));
  for (const attr of [/;\s*SameSite=None/i, /;\s*Secure/i, /;\s*HttpOnly/i, /;\s*Path=\/api\/auth\/sso\/saml2\/sp\/acs/i]) assert.match(cookie!, attr);
  const id = /\sID="([^"]+)"/.exec(inflateRawSync(Buffer.from(new URL(r.json().url).searchParams.get('SAMLRequest')!, 'base64')).toString())![1];
  assert.ok(!cookie!.includes(id), 'the cookie holds a hash, not the request ID');
  // The hosted page's SSO start sets it too.
  const page = await send(sp, new Jar(), 'POST', '/sign-in', { form: { method: 'sso', email: 'alice@a.example', oauth_query: '' } });
  assert.ok(page.setCookies.some((c) => c.startsWith('authwapi_saml_request=')), page.setCookies.join(' | '));
});

test('an IdP on another site posts to the ACS (no Origin refusal there); other routes still refuse that Origin', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const jar = new Jar();
  const { back } = await signIn(jar, idp, a, { nameId: 'u-1', email: 'u1@a.example' }); // posted with Origin https://idp.example
  assert.equal(back.status, 302, back.body);
  assert.equal(back.location, '/');
  const elsewhere = await send(sp, new Jar(), 'POST', '/api/auth/sign-in/sso', { json: { providerId: a.providerId, callbackURL: '/' }, origin: IDP_ORIGIN });
  assert.equal(elsewhere.status, 403);
  const metadata = await send(sp, new Jar(), 'POST', `/api/auth/sso/saml2/sp/acs-other/${a.providerId}`, { form: {}, origin: IDP_ORIGIN });
  assert.equal(metadata.status, 403);
});

test('sign-in through a provider registered by hand (entity ID, SSO URL, certificate)', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const organizationId = await org(write, 'a');
  const { provider } = await ok(
    call(write, 'register_sso_provider', { protocol: 'saml', organizationId, slug: 'a', domain: 'a.example', idpEntityId: idp.entityID, idpSsoUrl: idp.ssoUrl, idpSigningCert: idp.cert })
  );
  const a: Provider = { ...provider, organizationId };
  const jar = new Jar();
  const s = await start(jar, { email: 'u1@a.example' });
  assert.ok(s.url.href.startsWith(`${idp.ssoUrl}?`), s.url.href);
  const back = await post(jar, a.providerId, samlResponse(idp, a, { nameId: 'u-1', email: 'u1@a.example', inResponseTo: s.requestId }), s.relayState);
  assert.equal(back.location, '/');
  assert.equal(await currentUser(sp, jar), 'u1@a.example');
  // Another key is refused for it, as with metadata.
  const other = await makeIdp('other');
  const forged = await signIn(new Jar(), { ...other, entityID: idp.entityID }, a, { nameId: 'u-2', email: 'u2@a.example' });
  assert.ok(errorOf(forged.back.location), String(forged.back.location));
});

test('refused: a replayed assertion, with its own RelayState and against a fresh request', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const first = await signIn(new Jar(), idp, a, { nameId: 'u-1', email: 'alice@a.example' });
  assert.equal(first.back.location, '/');
  const sessions = count('SELECT count(*) FROM session');
  assert.ok(errorOf((await post(new Jar(), a.providerId, first.SAMLResponse, first.relayState)).location));
  const freshJar = new Jar();
  const fresh = await start(freshJar, { providerId: a.providerId });
  assert.ok(errorOf((await post(freshJar, a.providerId, first.SAMLResponse, fresh.relayState)).location));
  assert.equal(count('SELECT count(*) FROM session'), sessions);
});

test('refused: an InResponseTo AuthWAPI never sent or already answered, and an unsolicited (IdP-initiated) response', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const unknown = await signIn(new Jar(), idp, a, { nameId: 'u-2', email: 'bob@a.example', inResponseTo: '_not-a-request' });
  assert.equal(errorOf(unknown.back.location), 'invalid_saml_response');
  const browser = new Jar();
  const s = await start(browser, { providerId: a.providerId });
  const answered = samlResponse(idp, a, { nameId: 'u-3', email: 'carol@a.example', inResponseTo: s.requestId });
  assert.equal((await post(browser, a.providerId, answered, s.relayState)).location, '/');
  const again = samlResponse(idp, a, { nameId: 'u-4', email: 'dave@a.example', inResponseTo: s.requestId });
  assert.equal(errorOf((await post(browser, a.providerId, again, s.relayState)).location), 'invalid_saml_response');
  // IdP-initiated: no request, no RelayState.
  const unsolicited = await post(new Jar(), a.providerId, samlResponse(idp, a, { nameId: 'u-5', email: 'erin@a.example' }));
  assert.equal(unsolicited.status, 302);
  assert.equal(errorOf(unsolicited.location), 'unsolicited_response');
  assert.equal(count('SELECT count(*) FROM session'), 1); // carol's
  assert.equal(count("SELECT count(*) FROM user WHERE email IN ('bob@a.example', 'dave@a.example', 'erin@a.example')"), 0);
});

test("cross-provider: org B's IdP assertion posted to org A's ACS, and A's request answered at B's ACS", async () => {
  const write = await writeAgent();
  const idpA = await makeIdp('idp-a');
  const idpB = await makeIdp('idp-b');
  const a = await samlOrg(write, 'a', 'a.example', idpA);
  const b = await samlOrg(write, 'b', 'b.example', idpB);

  // B's IdP, signing for B's SP, answering a request A made: posted to A's ACS.
  const jar = new Jar();
  const sa = await start(jar, { providerId: a.providerId });
  const forB = samlResponse(idpB, b, { nameId: 'u-1', email: 'mallory@a.example', inResponseTo: sa.requestId });
  assert.ok(errorOf((await post(jar, a.providerId, forB, sa.relayState)).location));
  // B's IdP, addressed to A (audience, recipient), answering A's request: B's key isn't trusted for A.
  const jar2 = new Jar();
  const sa2 = await start(jar2, { providerId: a.providerId });
  const forged = samlResponse(idpB, a, { nameId: 'u-2', email: 'mallory@a.example', inResponseTo: sa2.requestId, issuer: idpA.entityID });
  assert.ok(errorOf((await post(jar2, a.providerId, forged, sa2.relayState)).location));
  // A's request, A's IdP, posted to B's ACS.
  const jar3 = new Jar();
  const sa3 = await start(jar3, { providerId: a.providerId });
  const toB = samlResponse(idpA, a, { nameId: 'u-3', email: 'mallory@a.example', inResponseTo: sa3.requestId });
  assert.ok(errorOf((await post(jar3, b.providerId, toB, sa3.relayState)).location));
  assert.equal(count('SELECT count(*) FROM session'), 0);
  assert.equal(count("SELECT count(*) FROM user WHERE email = 'mallory@a.example'"), 0);
});

test('an existing verified account with the same email is not linked', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const userId = await verifiedUser(sp, 'victim@a.example');
  const jar = new Jar();
  const { back } = await signIn(jar, idp, a, { nameId: 'u-1', email: 'victim@a.example' });
  assert.equal(errorOf(back.location), 'account_exists');
  assert.equal(await currentUser(sp, jar), null);
  assert.equal(count("SELECT count(*) FROM account WHERE userId = ? AND providerId != 'credential'", userId), 0);
  assert.equal(count('SELECT count(*) FROM member WHERE userId = ?', userId), 0);
});

test('a user with 2FA signing in through SAML is asked for the second factor', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const a = await samlOrg(write, 'a', 'a.example', idp);
  const jar = new Jar();
  assert.equal((await signIn(jar, idp, a, { nameId: 'u-1', email: 'alice@a.example' })).back.location, '/');
  const { secret } = await enableTotp(sp, jar, undefined);
  const next = new Jar();
  assert.equal((await signIn(next, idp, a, { nameId: 'u-1', email: 'alice@a.example' })).back.location, '/two-factor');
  assert.equal(await currentUser(sp, next), null, 'no session before the second factor');
  assert.equal((await send(sp, next, 'POST', '/api/auth/two-factor/verify-totp', { json: { code: totp(secret) } })).status, 200);
  assert.equal(await currentUser(sp, next), 'alice@a.example');
});

test('MCP: SAML registration refuses an http SSO URL (unless a trusted loopback), metadata without a signing certificate, and mixed fields', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const organizationId = await org(write, 'a');
  const base = { protocol: 'saml', organizationId, slug: 'a', domain: 'a.example' };
  const manual = { idpEntityId: idp.entityID, idpSsoUrl: idp.ssoUrl, idpSigningCert: idp.cert };
  const refusals: [string, Record<string, unknown>][] = [
    ['http SSO URL', { ...base, ...manual, idpSsoUrl: 'http://idp-a.example/sso' }],
    ['metadata and manual fields', { ...base, ...manual, idpMetadata: idp.metadata }],
    ['manual, no certificate', { ...base, idpEntityId: idp.entityID, idpSsoUrl: idp.ssoUrl }],
    ['manual, not a certificate', { ...base, ...manual, idpSigningCert: 'not a certificate' }],
    ['OIDC fields on a SAML provider', { ...base, idpMetadata: idp.metadata, clientId: 'x' }],
    ['metadata with an http SSO URL', { ...base, idpMetadata: idp.metadata.replace(idp.ssoUrl, 'http://idp-a.example/sso') }],
    ['metadata without a signing certificate', { ...base, idpMetadata: samlify.IdentityProvider({ entityID: idp.entityID, singleSignOnService: [{ Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: idp.ssoUrl }] }).getMetadata() }],
    ['not metadata', { ...base, idpMetadata: '<hello/>' }],
  ];
  for (const [name, args] of refusals) {
    const r = await call(write, 'register_sso_provider', args);
    assert.equal(r.isError, true, name);
  }
  assert.equal(count('SELECT count(*) FROM ssoProvider'), 0);
  // Plain http only on a loopback origin AuthWAPI trusts (a test IdP): its own origin here.
  const local = await ok(call(write, 'register_sso_provider', { ...base, slug: 'local', domain: 'local.example', ...manual, idpSsoUrl: `${sp.base}/test-idp/sso` }));
  await ok(call(write, 'delete_sso_provider', { providerId: local.provider.providerId }));
  // Registered manually: stored with signed assertions required and persistent NameIDs asked for.
  const { provider } = await ok(call(write, 'register_sso_provider', { ...base, ...manual }));
  assert.deepEqual(Object.keys(provider).sort(), ['acsUrl', 'domain', 'issuer', 'organizationId', 'protocol', 'providerId', 'spEntityId']);
  assert.equal(provider.issuer, idp.entityID);
  const config = JSON.parse(row('SELECT samlConfig FROM ssoProvider')!.samlConfig);
  assert.equal(config.wantAssertionsSigned, true);
  assert.equal(config.identifierFormat, PERSISTENT);
  const listed = await ok(call(write, 'list_sso_providers'));
  assert.deepEqual(listed.providers, [provider]);
});

const run = promisify(execFile);
const cli = (args: string[], input?: string) => {
  const child = run(process.execPath, ['src/cli.ts', ...args], { env: { PATH: process.env.PATH, DATA_DIR: sp.paths.root, BASE_URL: sp.base } });
  if (input !== undefined) child.child.stdin!.end(input);
  return child;
};

test('CLI: the operator registers a SAML provider from metadata on stdin; deleting it ends its sessions', async () => {
  const write = await writeAgent();
  const idp = await makeIdp('idp-a');
  const organizationId = await org(write, 'a');
  const registered = await cli(['sso', 'register', '--protocol', 'saml', '--org', organizationId, '--slug', 'a', '--domain', 'a.example'], idp.metadata);
  assert.match(registered.stdout, /sso-a/);
  assert.ok(registered.stdout.includes(`${sp.base}/api/auth/sso/saml2/sp/acs/sso-a`), registered.stdout);
  assert.ok(registered.stdout.includes(`${sp.base}/api/auth/sso/saml2/sp/metadata?providerId=sso-a`), registered.stdout);
  const a: Provider = { providerId: 'sso-a', organizationId, acsUrl: `${sp.base}/api/auth/sso/saml2/sp/acs/sso-a`, spEntityId: `${sp.base}/api/auth/sso/saml2/sp/metadata?providerId=sso-a` };
  const jar = new Jar();
  assert.equal((await signIn(jar, idp, a, { nameId: 'u-1', email: 'alice@a.example' })).back.location, '/');
  assert.match((await cli(['sso', 'list'])).stdout, /sso-a\s+a\.example/);
  await cli(['sso', 'delete', 'sso-a']);
  assert.equal(await currentUser(sp, jar), null);
  assert.equal(count("SELECT count(*) FROM account WHERE providerId = 'sso-a'"), 0);
});
