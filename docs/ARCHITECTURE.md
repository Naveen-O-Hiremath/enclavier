# Enclavier — Architecture & Cryptography

## Principles

1. **Zero knowledge.** Keys are derived and used only on the client. The server
   stores ciphertext, public keys and non-secret metadata (ids, timestamps,
   revision numbers). It never receives the master password, the master key,
   or any plaintext secret.
2. **One crypto implementation.** `packages/crypto` is shared by every client
   (web, extension, desktop, mobile, CLI) so there is a single codebase to audit.
3. **Audited primitives only.** `@noble/ciphers`, `@noble/hashes`,
   `@noble/curves` (audited, dependency-free) and `hash-wasm` (Argon2id in WASM).
4. **Ciphertext is bound to its context.** Every encryption uses associated
   data (AAD) such as `item:<uuid>` so a malicious server cannot swap blobs
   between items or users.

## Key hierarchy

```
master password ──Argon2id(salt, m=64 MiB, t=3, p=4)──► masterKey (32 B)
                                                            │
                         ┌──────────HKDF-SHA256─────────────┤
                         ▼                                  ▼
              kek  (info "enclavier/v1/kek")     authKey (info "enclavier/v1/auth")
                         │                                  │
                         │                     sent to server as "authHash";
                         │                     server stores scrypt(authHash, salt2)
                         ▼
   userKey (random 32 B) ── wrapped by kek ──► protectedUserKey   (stored on server)
        │
        ├── wraps X25519 private key ──► protectedPrivateKey     (stored on server)
        │                                 publicKey (plain)       (stored on server)
        ├── wraps folder names
        └── wraps per-item itemKey ──► item.key                   (stored on server)
                                  itemKey encrypts item JSON ──► item.data
```

- **Changing the master password** only re-wraps `userKey`; the vault is not
  re-encrypted. All other sessions are revoked.
- **The salt** is 16 random bytes per user, returned by `/auth/prelogin`. For
  unknown e-mails the server returns a deterministic fake salt
  (`HMAC(server secret, email)`) so the endpoint cannot be used to enumerate
  accounts.
- **Per-item keys** let a single item be moved into an organization collection
  (Phase 2) by re-wrapping one 32-byte key instead of re-encrypting the item.
- **X25519 key pair** is created at registration so organization keys can be
  shared with a user via sealed boxes (ephemeral X25519 → HKDF → XChaCha20)
  in Phase 2.

## Encrypted string format

```
e1.<alg>.<base64url nonce>.<base64url ciphertext+tag>
```

`alg = x` → XChaCha20-Poly1305 (24-byte random nonce, 16-byte tag). The
version prefix allows algorithm agility (e.g. AES-256-GCM for FIPS builds).

## Sessions

- Access token: 15-minute JWT (HS256).
- Refresh token: 256-bit random value, stored as SHA-256 in `sessions`,
  rotated on every use. Presenting an already-rotated token revokes the
  whole session (refresh-token theft detection).
- **Lock vs. log out.** Locking wipes keys from memory but keeps the session;
  unlocking re-derives the master key locally (no network round trip).
  Logging out revokes the session on the server.

## Audit log

`audit_events` is append-only and hash-chained:
`hash = SHA-256(prev_hash ‖ canonical_json(event))`. Writes take a
transaction-scoped advisory lock so the chain is strictly ordered. Any
modification or deletion breaks the chain, which can be verified offline.
Phase 4 adds per-tenant chains, verification UI and SIEM streaming.

## Organizations (Phase 2)

```
owner's browser: orgKey = random 32 B
     ├── seal(owner.publicKey, orgKey, aad "org-key:<orgId>") ─► org_members.protected_org_key
     ├── encrypts collection names                (aad "collection:<id>")
     └── wraps item keys of org items             (aad "item-key:<id>")
```

**Membership lifecycle:** `invited → accepted → confirmed`.

1. An admin invites an e-mail address. The server stores `SHA-256(token)`
   and e-mails a link (SMTP). The link expires after `INVITE_TTL_DAYS`.
2. The invitee signs in (or registers) with *that* address and accepts.
   Their account already has an X25519 key pair.
3. An admin's client seals the org key to the member's public key and
   uploads the sealed box. **The server cannot do this step**, because it never
   holds the org key. Admins can compare the member's key fingerprint
   (shown in the member's *Settings → Account*) out of band. That defeats a
   malicious server substituting its own public key.

**Sharing a personal item** re-wraps only its 32-byte item key from the user
key to the org key. The item's data ciphertext is unchanged.

**Roles:** `owner` (everything, incl. managing owners and deleting the org),
`admin` (members, groups, all collections), `member` (only granted collections).
The last owner cannot leave, be demoted, revoked or removed, or delete their account.

**Collection permissions** are granted directly or through groups. The strongest grant wins:

| Permission | Read | Reveal/copy secrets | Create/edit/trash | Manage access, delete forever |
|---|---|---|---|---|
| `use` (masked) | ✓ | – | – | – |
| `view` | ✓ | ✓ | – | – |
| `edit` | ✓ | ✓ | ✓ | – |
| `manage` | ✓ | ✓ | ✓ | ✓ |

### Security boundaries (read before selling to regulated customers)

- **The cryptographic boundary is the organization.** Every confirmed member
  holds the org key. Collection access is enforced by the server (and RLS),
  not cryptographically. A confirmed member colluding with a compromised
  server could decrypt collections they were not granted. Per-collection keys
  are planned for Phase 10.
- **`use` (masked) is a UI control.** The member's client can technically
  decrypt the secret. It is meant for autofill-only access (Phase 6), not for
  hiding secrets from a determined insider.
- **Removing a member does not rotate the org key.** They lose server access
  immediately, but anything they already synced or copied is exposed. Rotate
  the credentials they could see. Org-key rotation is planned for Phase 10.
- Organization names (they appear in invitation e-mails), group names, member
  e-mails and roles are stored in plaintext. Collection names and all item
  data are encrypted.

## Strong authentication & recovery (Phase 3)

### Two-step login

`POST /auth/login` checks the master password (authHash). If the user has a
second factor, it returns a 5-minute signed **challenge token** instead of
session tokens. **The encrypted key bundle is not released until
`POST /auth/login/2fa` succeeds**, so a stolen password alone yields nothing.

| Factor | Storage | Notes |
|---|---|---|
| FIDO2 / WebAuthn (security keys, Windows Hello, Touch ID, passkeys) | public key + signature counter | Phishing-resistant: the browser binds assertions to the origin. The RP ID defaults to the `PUBLIC_URL` host. |
| TOTP (RFC 6238) | seed encrypted with AES-256-GCM under a key derived from `SERVER_SECRET` | ±1 step skew. Each time step is accepted once (replay protection). |
| Recovery codes | 10 × 50-bit codes, stored as SHA-256 | Single use. Issued when the first factor is added. |

Failed second factors count toward the same account lockout as bad passwords.
Removing a factor or regenerating codes requires the master password, and
factor changes are e-mailed to the user.

*Passwordless passkey sign-in* (no master password) needs the WebAuthn PRF
extension to derive the vault key. It is deliberately not offered yet.

### E-mail verification

A 48-hour single-use link (SHA-256 stored) is sent on registration. Accounts
created from an organization invitation are verified automatically, because
the invite token was delivered to that address.

### Organization policies

- **Require two-step login.** Non-compliant members receive neither
  collections nor their sealed org key until they enroll a factor. The admin
  enabling the policy must already have 2FA.
- **Account recovery.** When first enabled, the admin's browser creates an org
  recovery X25519 key pair, with the private key encrypted by the org key.
  Members enroll by sealing their user key to the recovery public key
  (AAD `account-recovery:<org>:<user>`). Enrollment is opt-in, or automatic
  if the policy says so. On a reset, the admin's browser unseals the member's
  user key and re-wraps it under a temporary password. The server then
  replaces the member's credentials, ends all their sessions, forces a
  password change and e-mails them. Turning the policy off deletes every
  escrowed key.

  **Trade-off:** enrolled members' personal vaults are readable by org admins.
  The enrollment dialog says so explicitly.

### Emergency access

`invited → accepted → confirmed → recovery_initiated → recovery_approved`.
On confirmation, the grantor's browser seals their user key to the grantee's
public key (fingerprint shown for out-of-band checks). A request unlocks
automatically after the grantor-chosen wait (1–90 days) unless the grantor
rejects it. The grantee then gets **read-only** access to the grantor's
personal vault, and every access is audited.

**Trust note:** the server enforces the waiting period. A fully compromised
server could release the sealed key early, but only to the chosen grantee.

### Break-glass organization recovery

An owner splits the org key with **Shamir's Secret Sharing over GF(256)**
(k-of-n, 2 ≤ k ≤ n ≤ 20) into printable shares with typo-detecting
checksums. The server stores only `SHA-256(HKDF(orgKey, "org-verifier", orgId))`.
Anyone who reconstructs the key from k shares proves it with the verifier and
becomes an owner. All existing owners are e-mailed. Creating a new kit
invalidates the old shares.

## Audit, compliance & monitoring (Phase 4)

### Two hash chains

Every event is linked into the **global** chain (whole database, verified with
`verify-audit.js`). Organization events are *also* linked into a **per-org
chain**: `org_hash = SHA-256(org_prev_hash ‖ "org-seq:<n>|" ‖ canonical(event))`,
with contiguous `org_seq`. Org admins can therefore verify their own trail
completely (**Audit log → Verify integrity**) without seeing other tenants'
events. Gaps are reported as deleted events, mismatches as modified ones.
Stream or record the chain **head hash** externally (the SIEM does this
implicitly) to detect truncation of the newest events. Events recorded before
Phase 4 are covered by the global chain only.

### SIEM streaming

`log_destinations` stores each destination's credentials encrypted with the
server SecretBox. A background worker picks due destinations with
`FOR UPDATE SKIP LOCKED` (safe with multiple replicas) and ships up to 500
events past the destination's cursor, advancing the cursor only after the
receiver accepts. Delivery is at-least-once: de-duplicate on `id`. Failures back off
exponentially (10 s → 1 h), and the error is shown in the console.

| Type | Transport |
|---|---|
| Webhook / SOAR | JSON, `X-Enclavier-Signature: t=<unix>,v1=HMAC_SHA256(secret, "<t>.<body>")` |
| Splunk | HEC, `Authorization: Splunk <token>` |
| Microsoft Sentinel | Azure Monitor Logs Ingestion API (Entra client credentials → DCE/DCR stream) |
| Datadog | Logs intake v2 |
| Sumo Logic | HTTP source |
| Syslog | RFC 5424 over TLS (RFC 5425), TCP (octet framing) or UDP |

**SSRF protection:** destination hosts resolving to loopback, private, CGNAT,
link-local (including 169.254.169.254) or multicast addresses are refused,
redirects are not followed, and HTTPS is required. Self-hosted operators set
`ALLOW_PRIVATE_LOG_DESTINATIONS=true` to reach internal SIEMs.

### Breach monitoring

Password exposure uses the Pwned Passwords **k-anonymity** range API. The
browser computes SHA-1, sends only the 5-hex-char prefix to our server (which
proxies it, with response padding, and caches ranges for 24 h), and matches
the suffix locally. Neither our server nor HIBP learns which password was
checked. `HIBP_API_URL` may point at an offline mirror (air-gapped) or be empty
to disable checks. With `HIBP_API_KEY`, users can also check *their own*
e-mail address against known breaches.

### Vault health

Computed entirely in the browser on decrypted data: exposed (HIBP), reused,
weak (zxcvbn with the item's name and username as context), older than a year,
and `http://` URLs. Admins can run it over all org collections (Admin →
Health). Items a member only has `use` access to are excluded.

### Policy engine

| Policy | Enforced by |
|---|---|
| Require two-step login, account recovery | Server |
| Master password length / strength | **Client**: measured with zxcvbn at unlock; non-compliant users must change it before continuing. The server cannot check it without seeing the password. |
| Generator minimums, max vault timeout, max clipboard time | Client (strictest value across the user's orgs) |
| Disable export | Client (org items are never exportable) |

Client-enforced policies stop honest mistakes, not a modified client. That is
the inherent trade-off of zero-knowledge.

### Compliance posture report

Admin → Compliance evaluates 15 live controls (MFA enforcement and coverage,
phishing-resistant MFA, password policy, session timeout, clipboard, audit
integrity, SIEM forwarding, stale access, least privilege, continuity, export,
encryption, recovery, generator). Each maps to SOC 2, ISO/IEC 27001:2022,
HIPAA, PCI DSS v4.0 and NIST SP 800-63B references, with evidence and a
recommendation. Generating a report is itself audited. It is a readiness aid,
not a certification.

## Enterprise identity (Phase 5)

### SSO proves identity, not the vault key

An SSO sign-in replaces the *authentication* half of the master password
(the `authHash`). It does not replace the key: the IdP never sees anything that
can decrypt a vault. After SSO the session starts **locked**, and the vault
opens with one of:

1. the master password (as before);
2. a **trusted device** key: the user key sealed (`s1.`) to an X25519 key pair
   generated in that browser. The private key is stored wrapped with a
   non-extractable WebCrypto AES key in IndexedDB. The server releases the
   sealed key only in the response to a fresh SSO sign-in that names the device
   id, never on a password login, a token refresh or a device listing;
3. **approval from another device**: the new browser registers a pending
   device public key; an unlocked device, after the user compares the
   fingerprint phrase, seals the user key to it;
4. **admin approval**: an admin opens the member's escrowed key with the
   organization recovery key (Phase 3 account recovery, which must be on and
   the member enrolled) and seals it to the device. The member is e-mailed and
   the approval is audited.

An approved device can collect its key for 15 minutes; after that it gets it
only through a new SSO sign-in.

### Protocols

- **OIDC**: authorization code with PKCE (S256), `state` and `nonce`, ID-token
  signature and claims checked by `openid-client`. `email_verified: false` is
  refused. Discovery and token requests go through the SSRF guard (https only,
  no private addresses) unless `ALLOW_PRIVATE_SSO_ENDPOINTS=true`.
- **SAML 2.0**: HTTP-Redirect AuthnRequest, HTTP-POST response. Assertions must
  be signed by the configured certificate(s). Audience, issuer, recipient,
  validity window and `InResponseTo` are checked. The only accepted
  `InResponseTo` is the request id stored with this sign-in's transaction, so
  IdP-initiated, replayed or cross-session responses are rejected.
- **Login CSRF**: `/sso/start` takes the SHA-256 of a random secret held in the
  starting tab's `sessionStorage`. The IdP callback hands the browser a
  single-use code, and `/sso/exchange` requires the matching secret, so a
  callback link can't sign a victim into someone else's account.

### Account linking and JIT provisioning

| Situation | Result |
|---|---|
| IdP subject already linked | Signed in (Enclavier 2FA, if enabled, still applies) |
| Account exists, e-mail domain verified by the org | Linked automatically |
| Account exists, domain **not** verified | `link_required`: the owner must sign in with their master password once |
| No account, domain verified or address invited, JIT on | Account created with a new master password; joins as *accepted* |
| Otherwise | Refused |

The org still **confirms** JIT and SCIM members (sealing the org key to them)
before they see shared items. That step is cryptographic and can't be
automated by the server.

### SCIM 2.0

`/api/scim/v2` with a per-organization bearer token (only its SHA-256 is
stored). Users map to memberships: create = invitation, `active: false` =
revoke, delete = remove. Groups map to groups (marked IdP-managed). Supports
the filters and PATCH forms Okta and Entra ID send (including `"False"`
strings and `members[value eq "…"]` paths). The last owner can never be
deactivated or removed through SCIM.

### Group sync

Groups with an identity-provider ID follow the groups claim or attribute at each
SSO sign-in. Groups without one are never touched.

## Windows desktop app (Phase 7)

The desktop app is an Electron shell around the same web vault. Design choices:

- **The vault code ships in the app.** Files are served from a private origin (`app://vault`) by the main process. The server is never a source of executable code, so a compromised server can't push a malicious client to desktop users.
- **API proxy.** The page calls `/api/...` on its own origin; the main process forwards those calls to the configured server with only the `content-type`, `authorization` and `accept` headers. No cookies or ambient credentials exist.
- **Lockdown.** The renderer is sandboxed with context isolation and no Node integration. The only bridge is `connect(serverUrl)`, which the main process accepts solely from the first-run setup page. Navigation away from `app://vault` is blocked, new windows are denied (http/https links open in the default browser), and the content security policy matches the hosted vault.
- **Single sign-on** runs in a separate modal window with its own throwaway storage partition. When the identity provider returns to the server's `/sso/callback`, only the URL fragment (the one-time code) is passed to the vault window, where the usual binding check applies.
- **Locking.** `lock-screen` and `suspend` events from Windows lock the vault.
- **Limits.** WebAuthn second factors are tied to the web vault's domain and don't work on `app://vault`. Keys are held in renderer memory as in the browser; there is no Windows Hello unlock yet.

## First account on a fresh install

With `SIGNUPS_ENABLED=false` (the installer's default) registration is refused, except that the very first account may register while the user table is empty. The check is repeated under a transaction-level advisory lock, so concurrent attempts can't create two. `GET /api/server-info` reports `setupRequired` so clients can guide the first user.

## Tenant isolation

Every tenant-owned table carries `org_id`, and composite foreign keys
(`(collection_id, org_id)`, `(member_id, org_id)`, …) make cross-tenant
references impossible at the schema level. Org-scoped requests run in
`withOrgTx`, which switches to the unprivileged `enclavier_app` role and sets
`app.org_id` / `app.user_id`. Row-level security policies then hide every
other tenant's rows even from a query that forgets its `org_id` filter (this
is covered by an integration test). Even then, a cross-tenant bug would
expose only ciphertext.

## Repository layout

```
packages/crypto   shared zero-knowledge crypto (all clients)
packages/shared   API contracts (zod schemas + TS types)
apps/server       Fastify API + Postgres migrations
apps/web          React web vault
deploy/           docker-compose + Dockerfiles for self-hosting
```
