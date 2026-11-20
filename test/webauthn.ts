// A software WebAuthn authenticator: an ES256 key, "none" attestation, and the JSON a browser's credential.toJSON()
// sends. `uv` sets the user-verified flag, so tests can present a passkey that skipped the PIN or biometric.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

// Just enough CBOR for an attestation object and a COSE key: small ints, byte and text strings, maps.
const head = (major: number, n: number) =>
  n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
function cbor(v: unknown): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error('cbor: unsupported value');
}
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};

export function softAuthenticator(origin: string) {
  const rpIdHash = createHash('sha256').update(new URL(origin).hostname).digest();
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const rawId = randomBytes(16);
  const id = rawId.toString('base64url');
  let counter = 0;
  const flags = (uv: boolean, attested = false) => 0x01 | (uv ? 0x04 : 0) | (attested ? 0x40 : 0); // UP, UV, AT
  const clientData = (type: string, challenge: string) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

  return {
    id,
    /** navigator.credentials.create() for options from /passkey/generate-register-options. */
    register(options: { challenge: string }, { uv = true } = {}) {
      const coseKey = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(rawId.length);
      const authData = Buffer.concat([rpIdHash, Buffer.from([flags(uv, true)]), u32(counter), Buffer.alloc(16), idLength, rawId, coseKey]);
      const attestationObject = cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      return {
        id,
        rawId: id,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientData('webauthn.create', options.challenge).toString('base64url'),
          attestationObject: attestationObject.toString('base64url'),
          transports: ['internal'],
        },
      };
    },
    /** navigator.credentials.get() for options from /passkey/generate-authenticate-options. */
    authenticate(options: { challenge: string }, { uv = true } = {}) {
      counter += 1;
      const authData = Buffer.concat([rpIdHash, Buffer.from([flags(uv)]), u32(counter)]);
      const data = clientData('webauthn.get', options.challenge);
      const signature = sign('sha256', Buffer.concat([authData, createHash('sha256').update(data).digest()]), privateKey);
      return {
        id,
        rawId: id,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
        response: {
          clientDataJSON: data.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
      };
    },
  };
}
