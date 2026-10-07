import { generateKeyPair, seal, unseal } from './asymmetric';
import { fromB64, toB64, utf8 } from './encoding';
import { hkdfExpand } from './kdf';
import { decryptBytes, encryptBytes, type EncString } from './symmetric';

// ---- organization account recovery (admin-assisted master password reset) -----

const orgRecoveryAad = (orgId: string) => `org-recovery-key:${orgId}`;
const accountRecoveryAad = (orgId: string, userId: string) => `account-recovery:${orgId}:${userId}`;

/** A key pair whose private half is readable only with the org key (i.e. by org admins). */
export function createOrgRecoveryKeyPair(orgKey: Uint8Array, orgId: string): { publicKey: string; protectedPrivateKey: EncString } {
  const pair = generateKeyPair();
  try {
    return { publicKey: toB64(pair.publicKey), protectedPrivateKey: encryptBytes(orgKey, pair.privateKey, orgRecoveryAad(orgId)) };
  } finally {
    pair.privateKey.fill(0);
  }
}

export function openOrgRecoveryPrivateKey(orgKey: Uint8Array, orgId: string, protectedPrivateKey: EncString): Uint8Array {
  return decryptBytes(orgKey, protectedPrivateKey, orgRecoveryAad(orgId));
}

/** Member enrollment: seals the member's user key to the org recovery public key. */
export function sealUserKeyForRecovery(recoveryPublicKey: string, userKey: Uint8Array, orgId: string, userId: string): string {
  return seal(fromB64(recoveryPublicKey), userKey, accountRecoveryAad(orgId, userId));
}

export function openRecoveredUserKey(recoveryPrivateKey: Uint8Array, sealed: string, orgId: string, userId: string): Uint8Array {
  const key = unseal(recoveryPrivateKey, sealed, accountRecoveryAad(orgId, userId));
  if (key.length !== 32) throw new Error('Invalid recovered key');
  return key;
}

// ---- emergency access -----------------------------------------------------------

const emergencyAad = (grantId: string) => `emergency-access:${grantId}`;

export function sealUserKeyForEmergency(granteePublicKey: string, userKey: Uint8Array, grantId: string): string {
  return seal(fromB64(granteePublicKey), userKey, emergencyAad(grantId));
}

export function openEmergencyUserKey(granteePrivateKey: Uint8Array, sealed: string, grantId: string): Uint8Array {
  const key = unseal(granteePrivateKey, sealed, emergencyAad(grantId));
  if (key.length !== 32) throw new Error('Invalid emergency key');
  return key;
}

// ---- trusted devices (SSO key release) ---------------------------------------------

const deviceAad = (userId: string, deviceId: string) => `device-key:${userId}:${deviceId}`;

/** Seals the user key to a device key pair whose private half never leaves that device. */
export function sealUserKeyForDevice(devicePublicKey: string, userKey: Uint8Array, userId: string, deviceId: string): string {
  return seal(fromB64(devicePublicKey), userKey, deviceAad(userId, deviceId));
}

export function openDeviceUserKey(devicePrivateKey: Uint8Array, sealed: string, userId: string, deviceId: string): Uint8Array {
  const key = unseal(devicePrivateKey, sealed, deviceAad(userId, deviceId));
  if (key.length !== 32) throw new Error('Invalid device key');
  return key;
}

// ---- break-glass verifier ---------------------------------------------------------

/**
 * One-way proof of possession of an org key. The server stores only its hash,
 * so it can check a break-glass recovery without ever learning the key.
 */
export function orgKeyVerifier(orgKey: Uint8Array, orgId: string): string {
  return toB64(hkdfExpand(orgKey, 'enclavier/v1/org-verifier', utf8.encode(orgId)));
}
