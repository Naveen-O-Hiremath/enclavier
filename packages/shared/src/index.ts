import { z } from 'zod';

// ---- primitives -----------------------------------------------------------

const b64 = z.string().regex(/^[A-Za-z0-9_-]+$/, 'base64url expected');
export const encString = z.string().max(1_000_000).regex(/^e1\.x\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'EncString expected');
const uuid = z.string().uuid();
const email = z.string().trim().toLowerCase().email().max(254);

export const kdfParams = z.object({
  algorithm: z.literal('argon2id'),
  memory: z.number().int().min(19 * 1024).max(1024 * 1024),
  iterations: z.number().int().min(2).max(20),
  parallelism: z.number().int().min(1).max(16),
});
export type KdfParamsDto = z.infer<typeof kdfParams>;

// ---- auth -----------------------------------------------------------------

export const preloginRequest = z.object({ email });
export const preloginResponse = z.object({ kdf: kdfParams, salt: b64 });
export type PreloginResponse = z.infer<typeof preloginResponse>;

export const registerRequest = z.object({
  email,
  name: z.string().trim().min(1).max(100),
  kdf: kdfParams,
  salt: b64.length(22), // 16 bytes
  authHash: b64.length(43), // 32 bytes
  protectedUserKey: encString,
  publicKey: b64.length(43),
  protectedPrivateKey: encString,
  /** Lets invited users register when self-service sign-up is disabled. */
  invite: z.object({ orgId: uuid, memberId: uuid, token: z.string().min(20).max(100) }).optional(),
});
export type RegisterRequest = z.infer<typeof registerRequest>;

export const loginRequest = z.object({
  email,
  authHash: b64.length(43),
  deviceName: z.string().max(100).optional(),
});
export type LoginRequest = z.infer<typeof loginRequest>;

export const accountKeys = z.object({
  kdf: kdfParams,
  salt: b64,
  protectedUserKey: encString,
  publicKey: b64,
  protectedPrivateKey: encString,
});

export const profile = z.object({
  id: uuid,
  email: z.string(),
  name: z.string(),
  createdAt: z.string(),
  emailVerified: z.boolean(),
  twoFactorEnabled: z.boolean(),
  /** Set after an admin account recovery: the user must choose a new master password. */
  forcePasswordChange: z.boolean(),
});
export type Profile = z.infer<typeof profile>;

export const tokenResponse = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  expiresIn: z.number(),
});
export type TokenResponse = z.infer<typeof tokenResponse>;

export const loginResponse = tokenResponse.extend({
  profile,
  keys: accountKeys,
  /** SSO logins on a trusted device: the user key sealed to this device's key pair. */
  deviceKey: z.string().nullable().optional(),
});
export type LoginResponse = z.infer<typeof loginResponse>;

// ---- two-factor authentication ---------------------------------------------

export const twoFactorMethod = z.enum(['totp', 'webauthn', 'recovery']);
export type TwoFactorMethod = z.infer<typeof twoFactorMethod>;

/** Returned by /auth/login instead of tokens when a second factor is required. */
export interface TwoFactorChallenge {
  twoFactorRequired: true;
  challengeToken: string;
  methods: TwoFactorMethod[];
  /** PublicKeyCredentialRequestOptionsJSON when a security key is registered. */
  webauthnOptions: unknown | null;
}

export type LoginResult = LoginResponse | TwoFactorChallenge;

export const twoFactorLoginRequest = z.object({
  challengeToken: z.string().min(20).max(4000),
  method: twoFactorMethod,
  code: z.string().max(20).optional(),
  webauthnResponse: z.record(z.unknown()).optional(),
  deviceName: z.string().max(100).optional(),
});

export interface WebAuthnCredentialInfo {
  id: string;
  name: string;
  deviceType: string | null;
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface TwoFactorStatus {
  totpEnabled: boolean;
  webauthn: WebAuthnCredentialInfo[];
  recoveryCodesRemaining: number;
}

export interface TotpSetupResponse {
  secret: string;
  uri: string;
  setupToken: string;
}

export const totpEnableRequest = z.object({ setupToken: z.string().min(20).max(4000), code: z.string().min(6).max(10) });
export const webauthnRegisterFinishRequest = z.object({
  ceremonyToken: z.string().min(20).max(4000),
  name: z.string().trim().min(1).max(60),
  response: z.record(z.unknown()),
});
export const verifyEmailRequest = z.object({ userId: uuid, token: z.string().min(20).max(100) });

export const refreshRequest = z.object({ refreshToken: z.string().min(20).max(200) });

export const changePasswordRequest = z.object({
  currentAuthHash: b64.length(43),
  kdf: kdfParams,
  salt: b64.length(22),
  authHash: b64.length(43),
  protectedUserKey: encString,
});
export type ChangePasswordRequest = z.infer<typeof changePasswordRequest>;

// ---- vault ----------------------------------------------------------------

export const folderUpsert = z.object({ id: uuid, name: encString });
export const folder = folderUpsert.extend({ revisionDate: z.string() });
export type Folder = z.infer<typeof folder>;

export const itemCreate = z.object({
  id: uuid,
  folderId: uuid.nullable(),
  key: encString,
  data: encString,
});
export const itemUpdate = z.object({
  folderId: uuid.nullable(),
  data: encString,
  /** Optimistic concurrency: the revision the client edited. */
  revision: z.number().int().min(1),
});
export const item = itemCreate.extend({
  /** Set for organization items; the item key is then wrapped by the org key. */
  orgId: uuid.nullable(),
  collectionId: uuid.nullable(),
  revision: z.number().int(),
  createdAt: z.string(),
  revisionDate: z.string(),
  deletedAt: z.string().nullable(),
});
export type Item = z.infer<typeof item>;

// ---- organizations ----------------------------------------------------------

/** Sealed box (X25519 → XChaCha20) produced by `seal()` in @enclavier/crypto. */
export const sealed = z.string().max(4096).regex(/^s1\.[A-Za-z0-9_-]+\.e1\.x\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'sealed key expected');

export const orgRole = z.enum(['owner', 'admin', 'member']);
export type OrgRole = z.infer<typeof orgRole>;

/** Collection permissions, weakest first. `use` = masked: secrets are hidden in the UI. */
export const permission = z.enum(['use', 'view', 'edit', 'manage']);
export type Permission = z.infer<typeof permission>;
export const PERMISSION_RANK: Record<Permission, number> = { use: 1, view: 2, edit: 3, manage: 4 };

export const memberStatus = z.enum(['invited', 'accepted', 'confirmed']);
export type MemberStatus = z.infer<typeof memberStatus>;

const orgName = z.string().trim().min(1).max(100);
const collectionGrant = z.object({ id: uuid, permission });

export const createOrgRequest = z.object({
  id: uuid,
  name: orgName,
  /** Org key sealed to the creator's own public key. */
  protectedOrgKey: sealed,
  defaultCollection: z.object({ id: uuid, name: encString }),
});
export const renameOrgRequest = z.object({ name: orgName });
export const confirmAuthRequest = z.object({ authHash: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });

export const inviteRequest = z.object({
  emails: z.array(email).min(1).max(50),
  role: orgRole,
  collections: z.array(collectionGrant).max(500).default([]),
  groups: z.array(uuid).max(200).default([]),
});
export type InviteRequest = z.infer<typeof inviteRequest>;

export const acceptInviteRequest = z.object({ orgId: uuid, memberId: uuid, token: z.string().min(20).max(100) });
export type AcceptInviteRequest = z.infer<typeof acceptInviteRequest>;

export const confirmMemberRequest = z.object({ protectedOrgKey: sealed });

export const updateMemberRequest = z.object({
  role: orgRole,
  collections: z.array(collectionGrant).max(500),
  groups: z.array(uuid).max(200),
});

export const groupUpsert = z.object({
  name: z.string().trim().min(1).max(100),
  collections: z.array(collectionGrant).max(500),
  memberIds: z.array(uuid).max(5000),
  /** Identity-provider group (ID or name). Set = membership is managed by SSO/SCIM group sync. */
  externalId: z.string().trim().max(200).nullable().optional(),
});
export type GroupUpsert = z.infer<typeof groupUpsert>;

export const collectionUpsert = z.object({
  name: encString,
  members: z.array(z.object({ memberId: uuid, permission })).max(5000),
  groups: z.array(z.object({ groupId: uuid, permission })).max(500),
});
export const collectionCreate = collectionUpsert.extend({ id: uuid });
export type CollectionUpsert = z.infer<typeof collectionUpsert>;

export const orgItemCreate = z.object({ id: uuid, collectionId: uuid, key: encString, data: encString });
export const orgItemUpdate = z.object({ collectionId: uuid, data: encString, revision: z.number().int().min(1) });
/** Moves a personal item into a collection: only its item key is re-wrapped with the org key. */
export const shareItemRequest = z.object({ orgId: uuid, collectionId: uuid, key: encString, revision: z.number().int().min(1) });

export interface MasterPasswordPolicy {
  minLength: number;
  /** 0–4 strength score (zxcvbn scale). */
  minScore: number;
}

export interface GeneratorPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigits: boolean;
  requireSymbols: boolean;
}

export interface OrgPolicies {
  require2fa: boolean;
  accountRecovery: boolean;
  /** When account recovery is on: enroll members automatically instead of asking. */
  accountRecoveryAutoEnroll: boolean;
  /** Enforced by clients on unlock (the server never sees the master password). */
  masterPassword: MasterPasswordPolicy | null;
  passwordGenerator: GeneratorPolicy | null;
  /** Maximum inactivity before the vault locks. */
  vaultTimeout: { maxMinutes: number } | null;
  /** Maximum seconds before copied secrets are cleared. */
  clipboard: { maxSeconds: number } | null;
  /** Members may not export their vault in plaintext. */
  disableExport: boolean;
}

export interface OrgSummary {
  id: string;
  name: string;
  role: OrgRole;
  status: MemberStatus;
  memberId: string;
  /** Present once an admin has confirmed the membership. */
  protectedOrgKey: string | null;
  policies: OrgPolicies;
  /** Org recovery public key; members seal their user key to it to enroll. */
  recoveryPublicKey: string | null;
  recoveryEnrolled: boolean;
  /** True when a policy (e.g. required 2FA) currently blocks this member's access. */
  blockedByPolicy: string | null;
}

export const updatePolicyRequest = z.discriminatedUnion('type', [
  z.object({ type: z.literal('require_2fa'), enabled: z.boolean() }),
  z.object({
    type: z.literal('account_recovery'),
    enabled: z.boolean(),
    autoEnroll: z.boolean().default(false),
    /** Required the first time the policy is enabled. */
    recoveryKeyPair: z.object({ publicKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/), protectedPrivateKey: encString }).optional(),
  }),
  z.object({
    type: z.literal('master_password'),
    enabled: z.boolean(),
    minLength: z.number().int().min(8).max(128).default(14),
    minScore: z.number().int().min(0).max(4).default(3),
  }),
  z.object({
    type: z.literal('password_generator'),
    enabled: z.boolean(),
    minLength: z.number().int().min(8).max(128).default(16),
    requireUppercase: z.boolean().default(true),
    requireLowercase: z.boolean().default(true),
    requireDigits: z.boolean().default(true),
    requireSymbols: z.boolean().default(false),
  }),
  z.object({ type: z.literal('vault_timeout'), enabled: z.boolean(), maxMinutes: z.number().int().min(1).max(1440).default(15) }),
  z.object({ type: z.literal('clipboard'), enabled: z.boolean(), maxSeconds: z.number().int().min(5).max(600).default(30) }),
  z.object({ type: z.literal('disable_export'), enabled: z.boolean() }),
]);
export type PolicyType = UpdatePolicyRequest['type'];
export type UpdatePolicyRequest = z.infer<typeof updatePolicyRequest>;

export const recoveryEnrollRequest = z.object({ recoveryKey: sealed });

/** Admin-assisted reset: the admin's client re-wraps the member's user key under a temporary password. */
export const accountRecoveryRequest = z.object({
  kdf: kdfParams,
  salt: b64.length(22),
  authHash: b64.length(43),
  protectedUserKey: encString,
});

export interface MemberRecoveryMaterial {
  userId: string;
  recoveryKey: string;
  protectedRecoveryPrivateKey: string;
}

export const recoveryKitRequest = z.object({
  verifier: b64.length(43),
  shares: z.number().int().min(2).max(20),
  threshold: z.number().int().min(2).max(20),
});

export const breakGlassRequest = z.object({
  orgId: uuid,
  verifier: b64.length(43),
  /** The recovered org key sealed to the requester's own public key. */
  protectedOrgKey: sealed,
});

export interface RecoveryKitInfo {
  exists: boolean;
  shares: number | null;
  threshold: number | null;
  createdAt: string | null;
}

// ---- emergency access -------------------------------------------------------

export const emergencyStatus = z.enum(['invited', 'accepted', 'confirmed', 'recovery_initiated', 'recovery_approved']);
export type EmergencyStatus = z.infer<typeof emergencyStatus>;

export const emergencyInviteRequest = z.object({ email, waitDays: z.number().int().min(1).max(90) });
export const emergencyAcceptRequest = z.object({ id: uuid, token: z.string().min(20).max(100) });
export const emergencyConfirmRequest = z.object({ keySealed: sealed });

export interface EmergencyGrant {
  id: string;
  /** The other party: the grantee (for grants I gave) or the grantor (for grants I received). */
  email: string;
  name: string | null;
  status: EmergencyStatus;
  waitDays: number;
  recoveryInitiatedAt: string | null;
  /** When access unlocks automatically, if recovery was initiated. */
  autoApproveAt: string | null;
  /** Grantee public key (grants I gave, once accepted). */
  publicKey: string | null;
}

export interface EmergencyOverview {
  granted: EmergencyGrant[];
  trustedBy: EmergencyGrant[];
}

export interface EmergencyVault {
  grantorEmail: string;
  keySealed: string;
  items: Item[];
}

export interface CollectionSummary {
  id: string;
  orgId: string;
  name: string;
  permission: Permission;
}

export interface OrgMember {
  id: string;
  userId: string | null;
  email: string;
  name: string | null;
  role: OrgRole;
  status: MemberStatus;
  revoked: boolean;
  /** Only for accepted/confirmed members; admins verify its fingerprint before confirming. */
  publicKey: string | null;
  inviteExpiresAt: string | null;
  twoFactorEnabled: boolean;
  recoveryEnrolled: boolean;
  groups: string[];
  collections: { id: string; permission: Permission }[];
  createdAt: string;
  /** Provisioned by the identity provider over SCIM. */
  scimManaged: boolean;
  /** Has signed in with the organization's SSO at least once. */
  ssoLinked: boolean;
}

export interface OrgGroup {
  id: string;
  name: string;
  memberIds: string[];
  collections: { id: string; permission: Permission }[];
  externalId: string | null;
}

export interface OrgCollection {
  id: string;
  name: string;
  itemCount: number;
  members: { memberId: string; permission: Permission }[];
  groups: { groupId: string; permission: Permission }[];
}

export interface OrgEvent {
  id: number;
  action: string;
  actorEmail: string | null;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  /** Position in the organization's own hash chain (null for pre-Phase-4 events). */
  orgSeq: number | null;
}

export const auditQuery = z.object({
  action: z.string().max(100).optional(),
  actor: z.string().max(254).optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

export interface AuditVerifyResult {
  ok: boolean;
  checked: number;
  legacy: number;
  head: { seq: number; hash: string } | null;
  brokenAtSeq?: number;
  reason?: string;
  verifiedAt: string;
}

// ---- log streaming (SIEM) ------------------------------------------------------

export type DestinationType = 'webhook' | 'splunk' | 'datadog' | 'sentinel' | 'sumologic' | 'syslog';

export interface LogDestination {
  id: string;
  name: string;
  type: DestinationType;
  enabled: boolean;
  /** Config with credentials masked (e.g. "••••abcd"). */
  config: Record<string, unknown>;
  lastSuccessAt: string | null;
  lastError: string | null;
  failures: number;
  /** Events not yet delivered. */
  backlog: number;
}

export const destinationCreate = z.object({
  name: z.string().trim().min(1).max(100),
  config: z.record(z.unknown()),
  /** Replay the organization's existing history (otherwise start from now). */
  backfill: z.boolean().default(false),
});
export const destinationUpdate = z.object({
  name: z.string().trim().min(1).max(100),
  enabled: z.boolean(),
  /** Omitted or masked credential fields keep their stored value. */
  config: z.record(z.unknown()),
});

// ---- compliance -------------------------------------------------------------------

export type ControlStatus = 'pass' | 'warn' | 'fail' | 'info';
export type Framework = 'SOC 2' | 'ISO 27001' | 'HIPAA' | 'PCI DSS' | 'NIST 800-63B';

export interface ComplianceControl {
  id: string;
  title: string;
  status: ControlStatus;
  evidence: string;
  recommendation: string | null;
  references: { framework: Framework; control: string }[];
}

export interface ComplianceReport {
  organization: { id: string; name: string };
  generatedAt: string;
  generatedBy: string;
  summary: Record<ControlStatus, number>;
  frameworks: { framework: Framework; pass: number; total: number }[];
  controls: ComplianceControl[];
  auditChainHead: { seq: number; hash: string } | null;
  disclaimer: string;
}

// ---- breach monitoring -------------------------------------------------------------

export interface BreachedAccount {
  name: string;
  domain: string;
  breachDate: string;
  dataClasses: string[];
}

// ---- enterprise identity: SSO, trusted devices, SCIM ----------------------------------

/** base64url SHA-256 of a random secret kept in the browser tab that started SSO (login-CSRF binding). */
const binding = b64.length(43);

export const ssoDiscoverRequest = z.object({ email: email.optional(), identifier: z.string().trim().toLowerCase().max(64).optional() });
export interface SsoDiscovery {
  available: boolean;
  orgName?: string;
  identifier?: string;
}

export const ssoStartRequest = ssoDiscoverRequest.extend({ binding });

export const ssoExchangeRequest = z.object({
  code: z.string().min(20).max(100),
  /** The secret whose hash was sent to /sso/start. */
  bindingSecret: z.string().min(20).max(100),
  deviceId: uuid.optional(),
  deviceName: z.string().max(100).optional(),
  /** The refresh token of a locked session on this device, revoked when SSO signs in again. */
  previousRefreshToken: z.string().min(20).max(200).optional(),
});

/** The organization whose SSO was used (kept on the device for "Unlock with SSO"). */
export interface SsoOrg {
  id: string;
  name: string;
  identifier: string;
}

export type SsoExchangeResult =
  | { status: 'authenticated'; login: LoginResponse; org: SsoOrg }
  | { status: 'two_factor'; challenge: TwoFactorChallenge; org: SsoOrg }
  /** An account with this e-mail exists but isn't linked: prove the master password once to link it. */
  | { status: 'link_required'; email: string; orgName: string; linkToken: string; org: SsoOrg }
  /** No account yet: choose a master password to create one (just-in-time provisioning). */
  | { status: 'provision'; email: string; name: string; orgName: string; provisionToken: string; org: SsoOrg };

export const ssoLinkRequest = z.object({ linkToken: z.string().min(20).max(4000) });
export const ssoProvisionRequest = registerRequest.omit({ email: true, invite: true }).extend({
  provisionToken: z.string().min(20).max(4000),
  deviceName: z.string().max(100).optional(),
});

export type SsoType = 'oidc' | 'saml';

const httpsUrl = z.string().trim().url().max(2000);
const pem = z.string().trim().min(100).max(20000);

export const oidcSettings = z.object({
  type: z.literal('oidc'),
  issuer: httpsUrl,
  clientId: z.string().trim().min(1).max(500),
  /** Omitted or masked keeps the stored secret. */
  clientSecret: z.string().max(2000).optional(),
  scopes: z.string().trim().max(500).default('openid email profile'),
  /** Claim holding the e-mail address (Entra ID often uses preferred_username). */
  emailClaim: z.string().trim().min(1).max(100).default('email'),
  groupsClaim: z.string().trim().max(100).default(''),
});
export const samlSettings = z.object({
  type: z.literal('saml'),
  idpEntityId: z.string().trim().min(1).max(2000),
  ssoUrl: httpsUrl,
  /** IdP signing certificate(s), PEM or bare base64. */
  certificate: pem,
  /** Attribute with the e-mail address; empty = NameID. */
  emailAttribute: z.string().trim().max(300).default(''),
  nameAttribute: z.string().trim().max(300).default(''),
  groupsAttribute: z.string().trim().max(300).default(''),
});
export const ssoSettings = z.discriminatedUnion('type', [oidcSettings, samlSettings]);
export type SsoSettings = z.infer<typeof ssoSettings>;

export const ssoConfigUpdate = z.object({
  enabled: z.boolean(),
  /** Short name users can type on the SSO sign-in page. */
  identifier: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9-]{1,62}$/, 'Use 2–63 lowercase letters, digits or dashes'),
  /** Create accounts on first SSO sign-in for verified domains and invited addresses. */
  jitProvisioning: z.boolean(),
  /** Members (not owners or admins) must sign in with SSO instead of e-mail + master password. */
  enforce: z.boolean(),
  /** Sync membership of IdP-managed groups from the groups claim at each sign-in. */
  groupSync: z.boolean(),
  settings: ssoSettings,
});
export type SsoConfigUpdate = z.infer<typeof ssoConfigUpdate>;

export interface OrgDomain {
  id: string;
  domain: string;
  verified: boolean;
  verifiedAt: string | null;
  lastCheckedAt: string | null;
  /** DNS TXT record to publish. */
  record: { name: string; value: string };
}

export interface SsoAdminView {
  config: (Omit<SsoConfigUpdate, 'settings'> & { settings: Record<string, unknown> }) | null;
  serviceProvider: { entityId: string; acsUrl: string; metadataUrl: string; redirectUri: string };
  domains: OrgDomain[];
  scimBaseUrl: string;
}

export const domainCreate = z.object({
  domain: z
    .string()
    .trim()
    .toLowerCase()
    .max(253)
    .regex(/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, 'Enter a domain like example.com'),
});

export interface ScimToken {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  /** Only in the response that creates it. */
  token?: string;
}
export const scimTokenCreate = z.object({ name: z.string().trim().min(1).max(100) });

export type DeviceStatus = 'pending' | 'trusted' | 'denied';

export interface TrustedDevice {
  id: string;
  name: string;
  publicKey: string;
  status: DeviceStatus;
  /** Organization whose admins were asked to approve (pending requests). */
  adminApprovalOrg: { id: string; name: string } | null;
  createdAt: string;
  trustedAt: string | null;
  lastUsedAt: string | null;
  /** Present once approved: the user key sealed to this device. */
  protectedUserKey: string | null;
}

export const deviceTrustRequest = z.object({
  id: uuid,
  name: z.string().trim().min(1).max(100),
  publicKey: b64.length(43),
  protectedUserKey: sealed,
});
export const deviceApprovalRequest = z.object({
  id: uuid,
  name: z.string().trim().min(1).max(100),
  publicKey: b64.length(43),
  /** Ask the admins of this organization (requires account recovery enrollment). */
  adminOrgId: uuid.optional(),
});
export const deviceApproveRequest = z.object({ protectedUserKey: sealed });

export interface AdminDeviceRequest {
  id: string;
  memberId: string;
  email: string;
  name: string;
  deviceName: string;
  publicKey: string;
  createdAt: string;
}

export interface InvitePreview {
  orgName: string;
  email: string;
  inviterName: string | null;
}

export const syncResponse = z.object({
  profile,
  keys: accountKeys,
  folders: z.array(folder),
  items: z.array(item),
  organizations: z.array(z.custom<OrgSummary>()),
  collections: z.array(z.custom<CollectionSummary>()),
  serverTime: z.string(),
});
export type SyncResponse = z.infer<typeof syncResponse>;

// ---- sessions & audit -----------------------------------------------------

export const session = z.object({
  id: uuid,
  deviceName: z.string().nullable(),
  userAgent: z.string().nullable(),
  ip: z.string().nullable(),
  createdAt: z.string(),
  lastUsedAt: z.string(),
  current: z.boolean(),
});
export type Session = z.infer<typeof session>;

export const auditEvent = z.object({
  id: z.number(),
  action: z.string(),
  targetType: z.string().nullable(),
  targetId: z.string().nullable(),
  ip: z.string().nullable(),
  userAgent: z.string().nullable(),
  createdAt: z.string(),
});
export type AuditEvent = z.infer<typeof auditEvent>;

export interface ApiError {
  error: string;
  message: string;
}

// ---- decrypted item model (client-side only, never sent in plaintext) ------

export type ItemType = 'login' | 'note' | 'card' | 'identity';

export interface ItemData {
  type: ItemType;
  name: string;
  favorite?: boolean;
  notes?: string;
  login?: { username?: string; password?: string; uris?: string[]; totp?: string };
  card?: { cardholder?: string; number?: string; expMonth?: string; expYear?: string; code?: string; brand?: string };
  identity?: { fullName?: string; email?: string; phone?: string; address?: string; company?: string };
  fields?: { name: string; value: string; hidden: boolean }[];
  passwordHistory?: { password: string; changedAt: string }[];
}
