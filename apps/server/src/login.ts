import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { LoginResponse, TokenResponse } from '@enclavier/shared';
import { recordAudit } from './audit';
import { withTx, type Queryable } from './db';
import { newRefreshToken, sha256 } from './security';
import { toKeys, toProfile, type UserRow } from './users';

export async function issueTokens(
  app: FastifyInstance,
  client: Queryable,
  req: FastifyRequest,
  userId: string,
  deviceName?: string,
): Promise<TokenResponse> {
  const sessionId = randomUUID();
  const refreshToken = newRefreshToken();
  await client.query(
    `INSERT INTO sessions (id, user_id, token_hash, device_name, user_agent, ip, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7))`,
    [sessionId, userId, sha256(refreshToken), deviceName ?? null, req.headers['user-agent']?.slice(0, 300) ?? null, req.ip, app.config.REFRESH_TOKEN_TTL_DAYS],
  );
  return { accessToken: await app.tokens.sign({ sub: userId, sid: sessionId }), refreshToken, expiresIn: app.tokens.ttl };
}

export interface LoginOptions {
  deviceName?: string;
  method: string;
  /** SSO sign-ins only: release the user key sealed to this trusted device. */
  deviceId?: string;
  /** SSO re-sign-in from a locked session: that session is ended. */
  replacesSessionId?: string;
  orgId?: string;
}

/** Resets lockout counters, audits the login and issues a new session. */
export async function completeLogin(app: FastifyInstance, user: UserRow, req: FastifyRequest, opts: LoginOptions): Promise<LoginResponse> {
  return withTx(app.db, async (client) => {
    await client.query('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1', [user.id]);
    if (opts.replacesSessionId) {
      await client.query('UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL', [
        opts.replacesSessionId,
        user.id,
      ]);
    }
    let deviceKey: string | null = null;
    if (opts.deviceId) {
      const { rows } = await client.query<{ protected_user_key: string }>(
        `UPDATE devices SET last_used_at = now() WHERE id = $1 AND user_id = $2 AND status = 'trusted' RETURNING protected_user_key`,
        [opts.deviceId, user.id],
      );
      deviceKey = rows[0]?.protected_user_key ?? null;
    }
    await recordAudit(client, req, {
      userId: user.id,
      action: 'user.login',
      targetType: 'user',
      targetId: user.id,
      metadata: { method: opts.method, ...(opts.orgId ? { orgId: opts.orgId } : {}), ...(deviceKey ? { trustedDevice: true } : {}) },
    });
    const tokenSet = await issueTokens(app, client, req, user.id, opts.deviceName);
    return { ...tokenSet, profile: toProfile(user), keys: toKeys(user), deviceKey };
  });
}
