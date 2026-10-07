import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

// A minimal software FIDO2 authenticator (ES256, "none" attestation) so the
// WebAuthn ceremonies can be exercised end to end in tests without hardware.

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const sha256 = (b: Uint8Array | string) => createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly privateKey: KeyObject;
  private readonly jwk: { x: string; y: string };
  private counter = 0;

  constructor(private readonly origin: string, private readonly rpId: string) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  }

  private authData(flags: number, attested?: Uint8Array): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(++this.counter);
    return Buffer.concat([sha256(this.rpId), Buffer.from([flags]), counter, ...(attested ? [Buffer.from(attested)] : [])]);
  }

  private clientData(type: string, challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }

  /** navigator.credentials.create() */
  register(options: { challenge: string }) {
    const cose = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(this.jwk.x, 'base64url')],
        [-3, Buffer.from(this.jwk.y, 'base64url')],
      ]),
    );
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLen, this.credentialId, Buffer.from(cose)]);
    const authData = this.authData(0x01 | 0x04 | 0x40, attested); // UP | UV | AT
    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', new Uint8Array(authData)],
      ]) as never,
    );
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(this.clientData('webauthn.create', options.challenge)),
        attestationObject: b64u(attestationObject),
        transports: ['usb'],
      },
      clientExtensionResults: {},
    };
  }

  /** navigator.credentials.get() */
  authenticate(options: { challenge: string }) {
    const authData = this.authData(0x01 | 0x04);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
      },
      clientExtensionResults: {},
    };
  }
}
