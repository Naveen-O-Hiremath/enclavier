import { startAuthentication, startRegistration, type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import {
  combineShares,
  createOrgRecoveryKeyPair,
  decodeShare,
  decryptItem,
  encodeShare,
  openEmergencyUserKey,
  openOrgRecoveryPrivateKey,
  openRecoveredUserKey,
  orgKeyVerifier,
  randomBytes,
  rewrapUserKey,
  sealOrgKey,
  sealUserKeyForEmergency,
  sealUserKeyForRecovery,
  splitSecret,
  toB64,
  wipe,
} from '@enclavier/crypto';
import type {
  EmergencyGrant,
  EmergencyOverview,
  EmergencyVault,
  ItemData,
  MemberRecoveryMaterial,
  OrgPolicies,
  RecoveryKitInfo,
  TotpSetupResponse,
  TwoFactorStatus,
} from '@enclavier/shared';
import { api } from './api';
import { requireAccountKeys, requireOrgKey, useSession, type VaultOrg } from './session';

// ---- two-step login management ------------------------------------------------------

export const getTwoFactorStatus = () => api<TwoFactorStatus>('GET', '/api/account/2fa');
export const startTotpSetup = () => api<TotpSetupResponse>('POST', '/api/account/2fa/totp/setup');
export const enableTotp = (setupToken: string, code: string) =>
  api<{ recoveryCodes: string[] | null }>('POST', '/api/account/2fa/totp/enable', { setupToken, code });

export async function disableTotp(password: string) {
  const authHash = await useSession.getState().verifyPassword(password);
  await api('POST', '/api/account/2fa/totp/disable', { authHash });
}

/** Runs the browser's WebAuthn registration ceremony (security key, Windows Hello, Touch ID, phone passkey). */
export async function addSecurityKey(name: string): Promise<string[] | null> {
  const { options, ceremonyToken } = await api<{ options: PublicKeyCredentialCreationOptionsJSON; ceremonyToken: string }>(
    'POST',
    '/api/account/2fa/webauthn/register/options',
  );
  const response = await startRegistration({ optionsJSON: options });
  const res = await api<{ recoveryCodes: string[] | null }>('POST', '/api/account/2fa/webauthn/register/finish', { ceremonyToken, name, response });
  return res.recoveryCodes;
}

export async function removeSecurityKey(id: string, password: string) {
  const authHash = await useSession.getState().verifyPassword(password);
  await api('POST', `/api/account/2fa/webauthn/${encodeURIComponent(id)}/delete`, { authHash });
}

export async function regenerateRecoveryCodes(password: string): Promise<string[]> {
  const authHash = await useSession.getState().verifyPassword(password);
  return (await api<{ recoveryCodes: string[] }>('POST', '/api/account/2fa/recovery-codes', { authHash })).recoveryCodes;
}

/** Second step of sign-in with a security key. */
export async function assertSecurityKey(options: unknown): Promise<Record<string, unknown>> {
  const response = await startAuthentication({ optionsJSON: options as PublicKeyCredentialRequestOptionsJSON });
  return response as unknown as Record<string, unknown>;
}

export async function resendVerification() {
  await api('POST', '/api/account/verify-email/resend');
}

export async function verifyEmail(userId: string, token: string) {
  await api('POST', '/api/auth/verify-email', { userId, token }, { auth: false });
}

// ---- organization policies & account recovery --------------------------------------------

export async function setRequire2fa(orgId: string, enabled: boolean): Promise<OrgPolicies> {
  const res = await api<OrgPolicies>('PUT', `/api/orgs/${orgId}/policies`, { type: 'require_2fa', enabled });
  await useSession.getState().sync();
  return res;
}

export async function setAccountRecovery(org: VaultOrg, enabled: boolean, autoEnroll: boolean): Promise<OrgPolicies> {
  // The first time, the admin's browser creates the org recovery key pair (private half encrypted with the org key).
  const recoveryKeyPair = enabled && !org.recoveryPublicKey ? createOrgRecoveryKeyPair(requireOrgKey(org.id), org.id) : undefined;
  const res = await api<OrgPolicies>('PUT', `/api/orgs/${org.id}/policies`, { type: 'account_recovery', enabled, autoEnroll, recoveryKeyPair });
  await useSession.getState().sync();
  return res;
}

export const getPolicies = (orgId: string) => api<OrgPolicies>('GET', `/api/orgs/${orgId}/policies`);

export async function enrollAccountRecovery(org: VaultOrg): Promise<void> {
  if (!org.recoveryPublicKey) throw new Error('Account recovery is not enabled for this organization');
  const keys = requireAccountKeys();
  const profile = useSession.getState().profile!;
  await api('POST', `/api/orgs/${org.id}/recovery/enroll`, {
    recoveryKey: sealUserKeyForRecovery(org.recoveryPublicKey, keys.userKey, org.id, profile.id),
  });
  await useSession.getState().sync();
}

export async function withdrawAccountRecovery(orgId: string): Promise<void> {
  await api('POST', `/api/orgs/${orgId}/recovery/withdraw`);
  await useSession.getState().sync();
}

/** Admin side: unseal the member's user key with the org recovery key and re-wrap it under a temporary password. */
export async function recoverMemberAccount(orgId: string, memberId: string, temporaryPassword: string): Promise<void> {
  const material = await api<MemberRecoveryMaterial>('GET', `/api/orgs/${orgId}/members/${memberId}/recovery`);
  const recoveryPrivate = openOrgRecoveryPrivateKey(requireOrgKey(orgId), orgId, material.protectedRecoveryPrivateKey);
  const userKey = openRecoveredUserKey(recoveryPrivate, material.recoveryKey, orgId, material.userId);
  try {
    const payload = await rewrapUserKey({ userKey }, temporaryPassword);
    await api('POST', `/api/orgs/${orgId}/members/${memberId}/recover`, payload);
  } finally {
    wipe(recoveryPrivate, userKey);
  }
}

// ---- break-glass recovery kit ---------------------------------------------------------------

export const getRecoveryKit = (orgId: string) => api<RecoveryKitInfo>('GET', `/api/orgs/${orgId}/recovery-kit`);
export const deleteRecoveryKit = (orgId: string) => api('DELETE', `/api/orgs/${orgId}/recovery-kit`);

/** Splits the org key into printable shares. Registering a new kit invalidates older shares. */
export async function createRecoveryKit(orgId: string, shares: number, threshold: number): Promise<string[]> {
  const orgKey = requireOrgKey(orgId);
  const kitId = Array.from(randomBytes(4), (b) => b.toString(16).padStart(2, '0')).join('');
  const parts = splitSecret(orgKey, shares, threshold);
  await api('POST', `/api/orgs/${orgId}/recovery-kit`, { verifier: orgKeyVerifier(orgKey, orgId), shares, threshold });
  return parts.map((p) => encodeShare(kitId, threshold, p));
}

/** Rebuilds the org key from shares and claims ownership (the server checks only a one-way verifier). */
export async function breakGlassRecover(orgId: string, shareTexts: string[]): Promise<string> {
  const decoded = shareTexts.map(decodeShare);
  const kitIds = new Set(decoded.map((d) => d.kitId));
  if (kitIds.size !== 1) throw new Error('These shares come from different recovery kits');
  const threshold = decoded[0]!.threshold;
  if (decoded.length < threshold) throw new Error(`This kit needs ${threshold} shares; you entered ${decoded.length}`);
  const orgKey = combineShares(decoded.map((d) => d.share));
  try {
    const keys = requireAccountKeys();
    const res = await api<{ orgName: string }>('POST', '/api/orgs/break-glass', {
      orgId,
      verifier: orgKeyVerifier(orgKey, orgId),
      protectedOrgKey: sealOrgKey(toB64(keys.publicKey), orgKey, orgId),
    });
    await useSession.getState().sync();
    return res.orgName;
  } finally {
    wipe(orgKey);
  }
}

// ---- emergency access ------------------------------------------------------------------------

export const getEmergencyOverview = () => api<EmergencyOverview>('GET', '/api/emergency');
export const inviteEmergencyContact = (email: string, waitDays: number) => api('POST', '/api/emergency/invite', { email, waitDays });
export const acceptEmergencyInvite = (id: string, token: string) => api('POST', '/api/emergency/accept', { id, token });
export const initiateEmergency = (id: string) => api('POST', `/api/emergency/${id}/initiate`);
export const decideEmergency = (id: string, approve: boolean) => api('POST', `/api/emergency/${id}/${approve ? 'approve' : 'reject'}`);
export const removeEmergency = (id: string) => api('DELETE', `/api/emergency/${id}`);

export async function confirmEmergencyContact(grant: EmergencyGrant): Promise<void> {
  if (!grant.publicKey) throw new Error('This contact has not accepted yet');
  await api('POST', `/api/emergency/${grant.id}/confirm`, {
    keySealed: sealUserKeyForEmergency(grant.publicKey, requireAccountKeys().userKey, grant.id),
  });
}

export async function openEmergencyVault(id: string): Promise<{ grantorEmail: string; items: { id: string; data: ItemData }[]; unreadable: number }> {
  const vault = await api<EmergencyVault>('GET', `/api/emergency/${id}/vault`);
  const userKey = openEmergencyUserKey(requireAccountKeys().privateKey, vault.keySealed, id);
  try {
    const items: { id: string; data: ItemData }[] = [];
    let unreadable = 0;
    for (const it of vault.items) {
      try {
        items.push({ id: it.id, data: decryptItem<ItemData>(userKey, it) });
      } catch {
        unreadable++;
      }
    }
    return { grantorEmail: vault.grantorEmail, items, unreadable };
  } finally {
    wipe(userKey);
  }
}
