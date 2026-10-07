import type { Db } from './db';

// Migrations are embedded (not read from disk) so the bundled server and
// air-gapped images are self-contained. Never edit a released migration.
export const migrations: { id: string; sql: string }[] = [
  {
    id: '001_init',
    sql: /* sql */ `
      CREATE TABLE users (
        id                     uuid PRIMARY KEY,
        email                  text NOT NULL UNIQUE CHECK (email = lower(email)),
        name                   text NOT NULL,
        auth_hash              text NOT NULL,
        kdf                    jsonb NOT NULL,
        salt                   text NOT NULL,
        protected_user_key     text NOT NULL,
        public_key             text NOT NULL,
        protected_private_key  text NOT NULL,
        failed_logins          integer NOT NULL DEFAULT 0,
        locked_until           timestamptz,
        created_at             timestamptz NOT NULL DEFAULT now(),
        updated_at             timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE sessions (
        id               uuid PRIMARY KEY,
        user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash       bytea NOT NULL UNIQUE,
        prev_token_hash  bytea,
        device_name      text,
        user_agent       text,
        ip               text,
        created_at       timestamptz NOT NULL DEFAULT now(),
        last_used_at     timestamptz NOT NULL DEFAULT now(),
        expires_at       timestamptz NOT NULL,
        revoked_at       timestamptz
      );
      CREATE INDEX sessions_user_idx ON sessions (user_id);
      CREATE INDEX sessions_prev_token_idx ON sessions (prev_token_hash);

      CREATE TABLE folders (
        id             uuid PRIMARY KEY,
        user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name           text NOT NULL,
        created_at     timestamptz NOT NULL DEFAULT now(),
        revision_date  timestamptz NOT NULL DEFAULT now(),
        UNIQUE (id, user_id)
      );

      CREATE TABLE items (
        id             uuid PRIMARY KEY,
        user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        folder_id      uuid,
        key            text NOT NULL,
        data           text NOT NULL,
        revision       integer NOT NULL DEFAULT 1,
        created_at     timestamptz NOT NULL DEFAULT now(),
        revision_date  timestamptz NOT NULL DEFAULT now(),
        deleted_at     timestamptz,
        -- An item can only live in a folder owned by the same user.
        FOREIGN KEY (folder_id, user_id) REFERENCES folders (id, user_id) ON DELETE SET NULL (folder_id)
      );
      CREATE INDEX items_user_idx ON items (user_id);

      -- Append-only, hash-chained audit trail. user_id has no FK so the trail
      -- outlives deleted accounts.
      CREATE TABLE audit_events (
        id           bigserial PRIMARY KEY,
        user_id      uuid,
        action       text NOT NULL,
        target_type  text,
        target_id    text,
        ip           text,
        user_agent   text,
        metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
        created_at   timestamptz NOT NULL,
        prev_hash    bytea NOT NULL,
        hash         bytea NOT NULL
      );
      CREATE INDEX audit_events_user_idx ON audit_events (user_id, id DESC);

      CREATE FUNCTION audit_events_append_only() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'audit_events is append-only';
      END;
      $$ LANGUAGE plpgsql;

      CREATE TRIGGER audit_events_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
      CREATE TRIGGER audit_events_no_truncate
        BEFORE TRUNCATE ON audit_events
        FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
    `,
  },
  {
    id: '002_organizations',
    sql: /* sql */ `
      CREATE TABLE organizations (
        id          uuid PRIMARY KEY,
        name        text NOT NULL,
        created_at  timestamptz NOT NULL DEFAULT now(),
        updated_at  timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE org_members (
        id                 uuid PRIMARY KEY,
        org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        user_id            uuid REFERENCES users(id) ON DELETE CASCADE,
        email              text NOT NULL CHECK (email = lower(email)),
        role               text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
        status             text NOT NULL CHECK (status IN ('invited', 'accepted', 'confirmed')),
        revoked_at         timestamptz,
        -- Org key sealed to the member's public key by an admin client. Never plaintext.
        protected_org_key  text,
        invite_token_hash  bytea,
        invite_expires_at  timestamptz,
        invited_by         uuid,
        created_at         timestamptz NOT NULL DEFAULT now(),
        updated_at         timestamptz NOT NULL DEFAULT now(),
        UNIQUE (org_id, email),
        UNIQUE (id, org_id),
        CHECK (status <> 'confirmed' OR protected_org_key IS NOT NULL),
        CHECK (status = 'invited' OR user_id IS NOT NULL)
      );
      CREATE UNIQUE INDEX org_members_org_user_idx ON org_members (org_id, user_id) WHERE user_id IS NOT NULL;
      CREATE INDEX org_members_user_idx ON org_members (user_id);

      CREATE TABLE groups (
        id          uuid PRIMARY KEY,
        org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name        text NOT NULL,
        created_at  timestamptz NOT NULL DEFAULT now(),
        UNIQUE (id, org_id)
      );

      CREATE TABLE group_members (
        group_id   uuid NOT NULL,
        member_id  uuid NOT NULL,
        org_id     uuid NOT NULL,
        PRIMARY KEY (group_id, member_id),
        FOREIGN KEY (group_id, org_id) REFERENCES groups (id, org_id) ON DELETE CASCADE,
        FOREIGN KEY (member_id, org_id) REFERENCES org_members (id, org_id) ON DELETE CASCADE
      );
      CREATE INDEX group_members_member_idx ON group_members (member_id);

      CREATE TABLE collections (
        id             uuid PRIMARY KEY,
        org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name           text NOT NULL, -- encrypted with the org key
        created_at     timestamptz NOT NULL DEFAULT now(),
        revision_date  timestamptz NOT NULL DEFAULT now(),
        UNIQUE (id, org_id)
      );

      CREATE TABLE collection_access (
        collection_id  uuid NOT NULL,
        org_id         uuid NOT NULL,
        member_id      uuid,
        group_id       uuid,
        permission     text NOT NULL CHECK (permission IN ('use', 'view', 'edit', 'manage')),
        CHECK ((member_id IS NULL) <> (group_id IS NULL)),
        FOREIGN KEY (collection_id, org_id) REFERENCES collections (id, org_id) ON DELETE CASCADE,
        FOREIGN KEY (member_id, org_id) REFERENCES org_members (id, org_id) ON DELETE CASCADE,
        FOREIGN KEY (group_id, org_id) REFERENCES groups (id, org_id) ON DELETE CASCADE
      );
      CREATE UNIQUE INDEX collection_access_member_idx ON collection_access (collection_id, member_id) WHERE member_id IS NOT NULL;
      CREATE UNIQUE INDEX collection_access_group_idx ON collection_access (collection_id, group_id) WHERE group_id IS NOT NULL;

      -- Items are owned either by a user (personal vault) or by an org collection.
      ALTER TABLE items
        ALTER COLUMN user_id DROP NOT NULL,
        ADD COLUMN org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
        ADD COLUMN collection_id uuid,
        ADD FOREIGN KEY (collection_id, org_id) REFERENCES collections (id, org_id) ON DELETE CASCADE,
        ADD CONSTRAINT items_single_owner CHECK (
          (user_id IS NOT NULL AND org_id IS NULL AND collection_id IS NULL)
          OR (user_id IS NULL AND org_id IS NOT NULL AND collection_id IS NOT NULL AND folder_id IS NULL)
        );
      CREATE INDEX items_org_collection_idx ON items (org_id, collection_id);

      ALTER TABLE audit_events ADD COLUMN org_id uuid;
      CREATE INDEX audit_events_org_idx ON audit_events (org_id, id DESC) WHERE org_id IS NOT NULL;

      -- ---- Tenant isolation (defence in depth) ---------------------------------
      -- Org-scoped requests run as the unprivileged role enclavier_app with
      -- app.org_id / app.user_id set for the transaction; these policies then make
      -- other tenants' rows invisible even if a query forgets an org filter.
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'enclavier_app') THEN
          CREATE ROLE enclavier_app NOLOGIN;
        END IF;
      END
      $$;
      GRANT enclavier_app TO CURRENT_USER;

      CREATE FUNCTION app_org_id() RETURNS uuid LANGUAGE sql STABLE
        AS $$ SELECT nullif(current_setting('app.org_id', true), '')::uuid $$;
      CREATE FUNCTION app_user_id() RETURNS uuid LANGUAGE sql STABLE
        AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

      ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
      ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
      ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
      ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
      ALTER TABLE collections ENABLE ROW LEVEL SECURITY;
      ALTER TABLE collection_access ENABLE ROW LEVEL SECURITY;
      ALTER TABLE items ENABLE ROW LEVEL SECURITY;
      ALTER TABLE folders ENABLE ROW LEVEL SECURITY;

      CREATE POLICY tenant_isolation ON organizations TO enclavier_app USING (id = app_org_id());
      CREATE POLICY tenant_isolation ON org_members TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON groups TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON group_members TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON collections TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON collection_access TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON items TO enclavier_app
        USING (org_id = app_org_id() OR (org_id IS NULL AND user_id = app_user_id()));
      CREATE POLICY owner_only ON folders TO enclavier_app USING (user_id = app_user_id());
    `,
  },
  {
    id: '003_strong_auth_and_recovery',
    sql: /* sql */ `
      ALTER TABLE users
        ADD COLUMN email_verified_at        timestamptz,
        ADD COLUMN email_verify_token_hash  bytea,
        ADD COLUMN email_verify_expires_at  timestamptz,
        -- TOTP secret encrypted at rest with a key derived from SERVER_SECRET.
        ADD COLUMN totp_secret_enc          text,
        ADD COLUMN totp_enabled_at          timestamptz,
        ADD COLUMN totp_last_counter        bigint,
        -- Set after an admin recovery: the user must choose a new master password.
        ADD COLUMN force_password_change    boolean NOT NULL DEFAULT false;

      CREATE TABLE webauthn_credentials (
        id            text PRIMARY KEY,          -- base64url credential id
        user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key    bytea NOT NULL,
        counter       bigint NOT NULL DEFAULT 0,
        transports    text[] NOT NULL DEFAULT '{}',
        name          text NOT NULL,
        device_type   text,
        backed_up     boolean NOT NULL DEFAULT false,
        created_at    timestamptz NOT NULL DEFAULT now(),
        last_used_at  timestamptz
      );
      CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

      CREATE TABLE recovery_codes (
        user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash  bytea NOT NULL,
        used_at    timestamptz,
        PRIMARY KEY (user_id, code_hash)
      );

      CREATE TABLE org_policies (
        org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        type        text NOT NULL CHECK (type IN ('require_2fa', 'account_recovery')),
        enabled     boolean NOT NULL DEFAULT false,
        data        jsonb NOT NULL DEFAULT '{}'::jsonb,
        updated_at  timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, type)
      );
      ALTER TABLE org_policies ENABLE ROW LEVEL SECURITY;
      CREATE POLICY tenant_isolation ON org_policies TO enclavier_app USING (org_id = app_org_id());

      ALTER TABLE organizations
        ADD COLUMN recovery_public_key       text,
        ADD COLUMN recovery_private_key      text,  -- encrypted with the org key
        ADD COLUMN break_glass_verifier_hash bytea,
        ADD COLUMN break_glass_threshold     integer,
        ADD COLUMN break_glass_shares        integer,
        ADD COLUMN break_glass_created_at    timestamptz;

      ALTER TABLE org_members
        ADD COLUMN recovery_key          text,      -- user key sealed to the org recovery public key
        ADD COLUMN recovery_enrolled_at  timestamptz;

      CREATE TABLE emergency_access (
        id                     uuid PRIMARY KEY,
        grantor_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        grantee_email          text NOT NULL CHECK (grantee_email = lower(grantee_email)),
        grantee_id             uuid REFERENCES users(id) ON DELETE CASCADE,
        status                 text NOT NULL CHECK (status IN ('invited', 'accepted', 'confirmed', 'recovery_initiated', 'recovery_approved')),
        wait_days              integer NOT NULL CHECK (wait_days BETWEEN 1 AND 90),
        key_sealed             text,               -- grantor user key sealed to the grantee public key
        invite_token_hash      bytea,
        recovery_initiated_at  timestamptz,
        created_at             timestamptz NOT NULL DEFAULT now(),
        updated_at             timestamptz NOT NULL DEFAULT now(),
        UNIQUE (grantor_id, grantee_email),
        CHECK (status IN ('invited', 'accepted') OR key_sealed IS NOT NULL)
      );
      CREATE INDEX emergency_access_grantee_idx ON emergency_access (grantee_id);
    `,
  },
  {
    id: '004_audit_compliance_monitoring',
    sql: /* sql */ `
      -- Per-organization hash chain, so each tenant can verify its own trail
      -- without seeing other tenants' events. (Events before this migration
      -- are covered by the global chain only.)
      ALTER TABLE audit_events
        ADD COLUMN org_seq        bigint,
        ADD COLUMN org_prev_hash  bytea,
        ADD COLUMN org_hash       bytea;
      CREATE UNIQUE INDEX audit_events_org_seq_idx ON audit_events (org_id, org_seq) WHERE org_seq IS NOT NULL;

      -- SIEM / log streaming destinations. Config (tokens, keys) is encrypted
      -- with the server SecretBox: the server must use these credentials.
      CREATE TABLE log_destinations (
        id               uuid PRIMARY KEY,
        org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name             text NOT NULL,
        type             text NOT NULL CHECK (type IN ('webhook', 'splunk', 'datadog', 'sentinel', 'sumologic', 'syslog')),
        config_enc       text NOT NULL,
        enabled          boolean NOT NULL DEFAULT true,
        cursor_event_id  bigint NOT NULL DEFAULT 0,
        failures         integer NOT NULL DEFAULT 0,
        next_attempt_at  timestamptz NOT NULL DEFAULT now(),
        last_success_at  timestamptz,
        last_error       text,
        created_at       timestamptz NOT NULL DEFAULT now(),
        UNIQUE (id, org_id)
      );
      ALTER TABLE log_destinations ENABLE ROW LEVEL SECURITY;
      CREATE POLICY tenant_isolation ON log_destinations TO enclavier_app USING (org_id = app_org_id());

      -- More policy types for the policy engine.
      ALTER TABLE org_policies DROP CONSTRAINT org_policies_type_check;
      ALTER TABLE org_policies ADD CONSTRAINT org_policies_type_check CHECK (type IN (
        'require_2fa', 'account_recovery', 'master_password', 'password_generator', 'vault_timeout', 'clipboard', 'disable_export'
      ));
    `,
  },
  {
    id: '005_enterprise_identity',
    sql: /* sql */ `
      -- Domains an organization has proven it controls (DNS TXT). A verified
      -- domain routes its users to the org's SSO and allows JIT provisioning.
      CREATE TABLE org_domains (
        id                  uuid PRIMARY KEY,
        org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        domain              text NOT NULL CHECK (domain = lower(domain)),
        verification_token  text NOT NULL,
        verified_at         timestamptz,
        last_checked_at     timestamptz,
        created_at          timestamptz NOT NULL DEFAULT now(),
        UNIQUE (org_id, domain)
      );
      -- Only one organization can own a verified domain.
      CREATE UNIQUE INDEX org_domains_verified_idx ON org_domains (domain) WHERE verified_at IS NOT NULL;

      CREATE TABLE sso_configs (
        org_id           uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
        enabled          boolean NOT NULL DEFAULT false,
        identifier       text NOT NULL UNIQUE CHECK (identifier = lower(identifier)),
        type             text NOT NULL CHECK (type IN ('oidc', 'saml')),
        settings_enc     text NOT NULL,  -- SecretBox: may contain the OIDC client secret
        jit_provisioning boolean NOT NULL DEFAULT true,
        enforce          boolean NOT NULL DEFAULT false,
        group_sync       boolean NOT NULL DEFAULT false,
        updated_at       timestamptz NOT NULL DEFAULT now()
      );

      -- Link between an IdP subject and an Enclavier account.
      CREATE TABLE sso_identities (
        org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        subject        text NOT NULL,
        user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        email          text NOT NULL,
        created_at     timestamptz NOT NULL DEFAULT now(),
        last_login_at  timestamptz,
        PRIMARY KEY (org_id, subject),
        UNIQUE (org_id, user_id)
      );

      -- In-flight SSO logins (one row per attempt, single use, short-lived).
      CREATE TABLE sso_transactions (
        id               text PRIMARY KEY,           -- OIDC state / SAML RelayState
        org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        binding_hash     text NOT NULL,              -- ties the result to the browser tab that started it
        nonce            text,
        code_verifier    text,
        saml_request_id  text,
        result           jsonb,                      -- verified identity after the IdP callback
        code_hash        bytea UNIQUE,               -- one-time code handed to the web vault
        created_at       timestamptz NOT NULL DEFAULT now(),
        expires_at       timestamptz NOT NULL,
        consumed_at      timestamptz
      );
      CREATE INDEX sso_transactions_expiry_idx ON sso_transactions (expires_at);

      CREATE TABLE scim_tokens (
        id            uuid PRIMARY KEY,
        org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name          text NOT NULL,
        token_hash    bytea NOT NULL UNIQUE,
        created_by    uuid,
        created_at    timestamptz NOT NULL DEFAULT now(),
        last_used_at  timestamptz
      );

      ALTER TABLE org_members
        ADD COLUMN external_id   text,
        ADD COLUMN display_name  text;      -- name from the IdP, before the user registers
      CREATE UNIQUE INDEX org_members_external_idx ON org_members (org_id, external_id) WHERE external_id IS NOT NULL;

      ALTER TABLE groups ADD COLUMN external_id text;
      CREATE UNIQUE INDEX groups_external_idx ON groups (org_id, external_id) WHERE external_id IS NOT NULL;

      -- Devices that can receive the user key without the master password
      -- (after a fresh SSO sign-in). The private key never leaves the device.
      CREATE TABLE devices (
        id                  uuid PRIMARY KEY,
        user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name                text NOT NULL,
        public_key          text NOT NULL,
        status              text NOT NULL CHECK (status IN ('pending', 'trusted', 'denied')),
        protected_user_key  text,           -- user key sealed to public_key
        admin_org_id        uuid REFERENCES organizations(id) ON DELETE SET NULL,
        approved_by         uuid,
        created_at          timestamptz NOT NULL DEFAULT now(),
        trusted_at          timestamptz,
        last_used_at        timestamptz,
        CHECK (status <> 'trusted' OR protected_user_key IS NOT NULL)
      );
      CREATE INDEX devices_user_idx ON devices (user_id);
      CREATE INDEX devices_admin_org_idx ON devices (admin_org_id) WHERE status = 'pending';

      ALTER TABLE org_domains ENABLE ROW LEVEL SECURITY;
      ALTER TABLE sso_configs ENABLE ROW LEVEL SECURITY;
      ALTER TABLE sso_identities ENABLE ROW LEVEL SECURITY;
      ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
      CREATE POLICY tenant_isolation ON org_domains TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON sso_configs TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON sso_identities TO enclavier_app USING (org_id = app_org_id());
      CREATE POLICY tenant_isolation ON scim_tokens TO enclavier_app USING (org_id = app_org_id());
    `,
  },
];

/** Re-applied after every migration run so new tables are usable by the restricted role. */
const GRANTS = /* sql */ `
  GRANT USAGE ON SCHEMA public TO enclavier_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO enclavier_app;
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO enclavier_app;
`;

export async function migrate(db: Db, log: (msg: string) => void = () => {}): Promise<void> {
  const client = await db.connect();
  try {
    // Serialise concurrent migrators (several replicas starting at once).
    await client.query('SELECT pg_advisory_lock(727001)');
    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
    );
    const { rows } = await client.query<{ id: string }>('SELECT id FROM schema_migrations');
    const applied = new Set(rows.map((r) => r.id));
    for (const m of migrations) {
      if (applied.has(m.id)) continue;
      log(`Applying migration ${m.id}`);
      await client.query('BEGIN');
      try {
        await client.query(m.sql);
        await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [m.id]);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      }
    }
    await client.query(GRANTS);
  } finally {
    await client.query('SELECT pg_advisory_unlock(727001)').catch(() => {});
    client.release();
  }
}
