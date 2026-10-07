import type { SsoSettings } from '@enclavier/shared';
import type { Config } from '../config';
import type { Queryable } from '../db';
import type { SecretBox } from '../security';

export interface SsoConfigRow {
  orgId: string;
  orgName: string;
  enabled: boolean;
  identifier: string;
  jitProvisioning: boolean;
  enforce: boolean;
  groupSync: boolean;
  settings: SsoSettings;
}

interface RawRow {
  org_id: string;
  org_name: string;
  enabled: boolean;
  identifier: string;
  settings_enc: string;
  jit_provisioning: boolean;
  enforce: boolean;
  group_sync: boolean;
}

const SELECT = `SELECT c.*, o.name AS org_name FROM sso_configs c JOIN organizations o ON o.id = c.org_id`;

function toRow(secrets: SecretBox, r: RawRow): SsoConfigRow {
  return {
    orgId: r.org_id,
    orgName: r.org_name,
    enabled: r.enabled,
    identifier: r.identifier,
    jitProvisioning: r.jit_provisioning,
    enforce: r.enforce,
    groupSync: r.group_sync,
    settings: JSON.parse(secrets.open(r.settings_enc)) as SsoSettings,
  };
}

export async function loadSsoConfig(client: Queryable, secrets: SecretBox, orgId: string): Promise<SsoConfigRow | null> {
  const { rows } = await client.query<RawRow>(`${SELECT} WHERE c.org_id = $1`, [orgId]);
  return rows[0] ? toRow(secrets, rows[0]) : null;
}

/**
 * Finds the organization whose SSO a user should use: by the identifier they
 * typed, or by the verified domain of their e-mail address. Runs as the table
 * owner (pre-authentication, no tenant context yet).
 */
export async function findSsoOrg(client: Queryable, secrets: SecretBox, by: { email?: string; identifier?: string }): Promise<SsoConfigRow | null> {
  let rows: RawRow[] = [];
  if (by.identifier) {
    rows = (await client.query<RawRow>(`${SELECT} WHERE c.identifier = $1 AND c.enabled`, [by.identifier])).rows;
  } else if (by.email) {
    const domain = by.email.split('@')[1] ?? '';
    rows = (
      await client.query<RawRow>(
        `${SELECT} JOIN org_domains d ON d.org_id = c.org_id AND d.verified_at IS NOT NULL WHERE d.domain = $1 AND c.enabled`,
        [domain],
      )
    ).rows;
  }
  return rows[0] ? toRow(secrets, rows[0]) : null;
}

export async function isVerifiedDomain(client: Queryable, orgId: string, email: string): Promise<boolean> {
  const domain = email.split('@')[1] ?? '';
  const { rowCount } = await client.query('SELECT 1 FROM org_domains WHERE org_id = $1 AND domain = $2 AND verified_at IS NOT NULL', [orgId, domain]);
  return !!rowCount;
}

/** An organization that requires this user to sign in with SSO (owners and admins are exempt as a break-glass path). */
export async function ssoEnforcedFor(client: Queryable, userId: string): Promise<{ name: string; identifier: string } | null> {
  const { rows } = await client.query<{ name: string; identifier: string }>(
    `SELECT o.name, c.identifier FROM org_members m
       JOIN sso_configs c ON c.org_id = m.org_id AND c.enabled AND c.enforce
       JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = $1 AND m.role = 'member' AND m.revoked_at IS NULL
      LIMIT 1`,
    [userId],
  );
  return rows[0] ?? null;
}

export function serviceProvider(config: Config, orgId: string) {
  const base = config.PUBLIC_URL.replace(/\/$/, '');
  return {
    entityId: `${base}/api/sso/saml/${orgId}`,
    acsUrl: `${base}/api/sso/saml/${orgId}/acs`,
    metadataUrl: `${base}/api/sso/saml/${orgId}/metadata`,
    redirectUri: `${base}/api/sso/oidc/callback`,
  };
}

/** Secret fields are never returned to the browser. */
export function maskSettings(s: SsoSettings): Record<string, unknown> {
  if (s.type === 'oidc') {
    const { clientSecret, ...rest } = s;
    return { ...rest, clientSecret: clientSecret ? `••••${clientSecret.slice(-4)}` : '' };
  }
  return { ...s };
}
