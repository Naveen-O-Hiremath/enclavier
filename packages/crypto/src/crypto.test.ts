import { describe, expect, it } from 'vitest';
import {
  createAccount,
  decryptBytes,
  decryptItem,
  DecryptionError,
  encryptBytes,
  encryptItem,
  fromB64,
  generateKeyPair,
  generatePassword,
  InvalidPasswordError,
  type KdfParams,
  parseTotp,
  rewrapUserKey,
  totpCode,
  verifyTotp,
  base32Encode,
  base32Decode,
  splitSecret,
  combineShares,
  encodeShare,
  decodeShare,
  randomBytes,
  generateOrgKey,
  createOrgRecoveryKeyPair,
  openOrgRecoveryPrivateKey,
  sealUserKeyForRecovery,
  openRecoveredUserKey,
  orgKeyVerifier,
  seal,
  toB64,
  unlockAccount,
  unseal,
  updateItem,
  utf8,
  uuid,
} from './index';

// Minimum-cost params keep the suite fast; production uses DEFAULT_KDF.
const FAST_KDF: KdfParams = { algorithm: 'argon2id', memory: 19 * 1024, iterations: 2, parallelism: 1 };

describe('encoding', () => {
  it('round-trips base64url for all lengths', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      expect(fromB64(toB64(bytes))).toEqual(bytes);
    }
  });
});

describe('symmetric', () => {
  const key = new Uint8Array(32).fill(7);

  it('encrypts and decrypts', () => {
    const enc = encryptBytes(key, utf8.encode('hello'), 'ctx');
    expect(utf8.decode(decryptBytes(key, enc, 'ctx'))).toBe('hello');
  });

  it('rejects wrong AAD (ciphertext swapped between contexts)', () => {
    const enc = encryptBytes(key, utf8.encode('hello'), 'item:a');
    expect(() => decryptBytes(key, enc, 'item:b')).toThrow(DecryptionError);
  });

  it('rejects tampered ciphertext', () => {
    const enc = encryptBytes(key, utf8.encode('hello'));
    const last = enc.at(-1) === 'A' ? 'B' : 'A';
    expect(() => decryptBytes(key, enc.slice(0, -1) + last)).toThrow(DecryptionError);
  });

  it('uses a fresh nonce every time', () => {
    const pt = utf8.encode('same');
    expect(encryptBytes(key, pt)).not.toBe(encryptBytes(key, pt));
  });
});

describe('account', () => {
  it('creates, unlocks, rejects wrong password and survives password change', async () => {
    const { payload, keys } = await createAccount('correct horse battery staple', FAST_KDF);
    expect(payload.authHash).not.toContain('correct');

    const unlocked = await unlockAccount('correct horse battery staple', payload);
    expect(unlocked.userKey).toEqual(keys.userKey);
    expect(unlocked.privateKey).toEqual(keys.privateKey);

    await expect(unlockAccount('wrong password', payload)).rejects.toBeInstanceOf(InvalidPasswordError);

    const change = await rewrapUserKey(unlocked, 'new master password!', FAST_KDF);
    const after = await unlockAccount('new master password!', { ...payload, ...change });
    expect(after.userKey).toEqual(keys.userKey);
    expect(change.authHash).not.toBe(payload.authHash);
  });
});

describe('vault items', () => {
  it('encrypts per item and binds ciphertext to item id', () => {
    const userKey = new Uint8Array(32).fill(3);
    const id = uuid();
    const item = encryptItem(userKey, id, null, { name: 'GitHub', password: 's3cret' });
    expect(decryptItem(userKey, item)).toEqual({ name: 'GitHub', password: 's3cret' });

    const data = updateItem(userKey, item, { name: 'GitHub', password: 'rotated' });
    expect(decryptItem(userKey, { ...item, data })).toEqual({ name: 'GitHub', password: 'rotated' });

    // A server moving ciphertext onto another item id must be detected.
    expect(() => decryptItem(userKey, { ...item, id: uuid() })).toThrow(DecryptionError);
  });
});

describe('sealed boxes', () => {
  it('seals to a public key', () => {
    const recipient = generateKeyPair();
    const sealed = seal(recipient.publicKey, utf8.encode('org key'), 'org:1');
    expect(utf8.decode(unseal(recipient.privateKey, sealed, 'org:1'))).toBe('org key');
    expect(() => unseal(generateKeyPair().privateKey, sealed, 'org:1')).toThrow();
  });
});

describe('totp', () => {
  it('matches the RFC 6238 SHA1 test vector', () => {
    // Secret "12345678901234567890" in base32; T = 59s → 94287082 (8 digits).
    const cfg = parseTotp('otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8');
    expect(totpCode(cfg, 59_000).code).toBe('94287082');
    expect(totpCode(cfg, 1_111_111_109_000).code).toBe('07081804');
  });
});

describe('generator', () => {
  it('honours length and character sets', () => {
    for (let i = 0; i < 50; i++) {
      const pw = generatePassword({ length: 16, lowercase: true, uppercase: true, digits: true, symbols: false, avoidAmbiguous: true });
      expect(pw).toHaveLength(16);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).not.toMatch(/[^a-zA-Z0-9]/);
      expect(pw).not.toMatch(/[0O1lI]/);
    }
  });
});

describe('totp verification', () => {
  it('accepts codes within the skew window and returns the counter', () => {
    const secret = randomBytes(20);
    expect(base32Decode(base32Encode(secret))).toEqual(secret);
    const cfg = parseTotp(base32Encode(secret));
    const now = 1_700_000_000_000;
    const prev = totpCode(cfg, now - 30_000).code;
    expect(verifyTotp(cfg, prev, now)).toBe(Math.floor(now / 30_000) - 1);
    expect(verifyTotp(cfg, totpCode(cfg, now - 90_000).code, now)).toBeNull();
    expect(verifyTotp(cfg, 'abcdef', now)).toBeNull();
  });
});

describe('shamir secret sharing', () => {
  it('reconstructs from any threshold subset and not from fewer', () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 5, 3);
    expect(combineShares([shares[0]!, shares[2]!, shares[4]!])).toEqual(secret);
    expect(combineShares([shares[3]!, shares[1]!, shares[0]!])).toEqual(secret);
    expect(combineShares(shares)).toEqual(secret);
    expect(combineShares([shares[0]!, shares[1]!])).not.toEqual(secret);
  });

  it('encodes shares with a typo-detecting checksum', () => {
    const shares = splitSecret(randomBytes(32), 3, 2);
    const text = encodeShare('kit12345', 2, shares[1]!);
    // Whitespace and line breaks (from printed kits) are ignored.
    const decoded = decodeShare(text.replace(/(.{16})/g, '$1\n '));
    expect(decoded).toMatchObject({ kitId: 'kit12345', threshold: 2, share: { x: 2, y: shares[1]!.y } });
    const i = text.lastIndexOf('.') - 3;
    const typo = text.slice(0, i) + (text[i] === 'A' ? 'B' : 'A') + text.slice(i + 1);
    expect(() => decodeShare(typo)).toThrow(/checksum/);
  });
});

describe('account recovery', () => {
  it('lets org admins recover a member user key', () => {
    const orgKey = generateOrgKey();
    const rec = createOrgRecoveryKeyPair(orgKey, 'org-1');
    const userKey = randomBytes(32);
    const sealed = sealUserKeyForRecovery(rec.publicKey, userKey, 'org-1', 'user-1');
    const priv = openOrgRecoveryPrivateKey(orgKey, 'org-1', rec.protectedPrivateKey);
    expect(openRecoveredUserKey(priv, sealed, 'org-1', 'user-1')).toEqual(userKey);
    // Bound to the user id: can't be replayed onto another member.
    expect(() => openRecoveredUserKey(priv, sealed, 'org-1', 'user-2')).toThrow();
    expect(orgKeyVerifier(orgKey, 'org-1')).not.toBe(orgKeyVerifier(orgKey, 'org-2'));
  });
});
