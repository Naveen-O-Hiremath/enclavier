import { openOrgRecoveryPrivateKey, openRecoveredUserKey, sealUserKeyForDevice, wipe } from '@enclavier/crypto';
import type { AdminDeviceRequest, MemberRecoveryMaterial, OrgDomain, ScimToken, SsoAdminView, SsoConfigUpdate } from '@enclavier/shared';
import { api } from './api';
import { requireOrgKey } from './session';

export const getSso = (orgId: string) => api<SsoAdminView>('GET', `/api/orgs/${orgId}/sso`);
export const saveSso = (orgId: string, body: SsoConfigUpdate) => api('PUT', `/api/orgs/${orgId}/sso`, body);

export const addDomain = (orgId: string, domain: string) => api<OrgDomain>('POST', `/api/orgs/${orgId}/domains`, { domain });
export const verifyDomain = (orgId: string, id: string) => api<OrgDomain>('POST', `/api/orgs/${orgId}/domains/${id}/verify`);
export const removeDomain = (orgId: string, id: string) => api('DELETE', `/api/orgs/${orgId}/domains/${id}`);

export const listScimTokens = (orgId: string) => api<ScimToken[]>('GET', `/api/orgs/${orgId}/scim-tokens`);
export const createScimToken = (orgId: string, name: string) => api<ScimToken>('POST', `/api/orgs/${orgId}/scim-tokens`, { name });
export const revokeScimToken = (orgId: string, id: string) => api('DELETE', `/api/orgs/${orgId}/scim-tokens/${id}`);

export const listDeviceRequests = (orgId: string) => api<AdminDeviceRequest[]>('GET', `/api/orgs/${orgId}/device-requests`);
export const denyDeviceRequest = (orgId: string, id: string) => api('POST', `/api/orgs/${orgId}/device-requests/${id}/deny`);

/**
 * Admin approval: the admin's browser opens the member's escrowed user key with
 * the org recovery key and seals it to the requesting device. The server only
 * ever sees sealed boxes.
 */
export async function approveDeviceRequest(orgId: string, request: AdminDeviceRequest): Promise<void> {
  const material = await api<MemberRecoveryMaterial>('GET', `/api/orgs/${orgId}/members/${request.memberId}/recovery`);
  const recoveryPrivate = openOrgRecoveryPrivateKey(requireOrgKey(orgId), orgId, material.protectedRecoveryPrivateKey);
  const userKey = openRecoveredUserKey(recoveryPrivate, material.recoveryKey, orgId, material.userId);
  try {
    await api('POST', `/api/orgs/${orgId}/device-requests/${request.id}/approve`, {
      protectedUserKey: sealUserKeyForDevice(request.publicKey, userKey, material.userId, request.id),
    });
  } finally {
    wipe(userKey, recoveryPrivate);
  }
}
