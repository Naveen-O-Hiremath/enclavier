import type { KdfParamsDto, Profile } from '@enclavier/shared';
import type { Queryable } from './db';

export interface UserRow {
  id: string;
  email: string;
  name: string;
  auth_hash: string;
  kdf: KdfParamsDto;
  salt: string;
  protected_user_key: string;
  public_key: string;
  protected_private_key: string;
  failed_logins: number;
  locked_until: Date | null;
  created_at: Date;
  updated_at: Date;
  email_verified_at: Date | null;
  email_verify_token_hash: Buffer | null;
  email_verify_expires_at: Date | null;
  totp_secret_enc: string | null;
  totp_enabled_at: Date | null;
  totp_last_counter: string | null;
  force_password_change: boolean;
  /** Derived by USER_SELECT. */
  two_factor_enabled?: boolean;
}

/** Selects a user together with derived flags. Append a WHERE clause on alias `u`. */
export const USER_SELECT = `
  SELECT u.*, (u.totp_enabled_at IS NOT NULL
               OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)) AS two_factor_enabled
    FROM users u`;

export async function findUser(client: Queryable, where: 'id' | 'email', value: string): Promise<UserRow | undefined> {
  const { rows } = await client.query<UserRow>(`${USER_SELECT} WHERE u.${where} = $1`, [value]);
  return rows[0];
}

export function toProfile(u: UserRow): Profile {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    createdAt: u.created_at.toISOString(),
    emailVerified: !!u.email_verified_at,
    twoFactorEnabled: !!u.two_factor_enabled,
    forcePasswordChange: u.force_password_change,
  };
}

export function toKeys(u: UserRow) {
  return {
    kdf: u.kdf,
    salt: u.salt,
    protectedUserKey: u.protected_user_key,
    publicKey: u.public_key,
    protectedPrivateKey: u.protected_private_key,
  };
}
