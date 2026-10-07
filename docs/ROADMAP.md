# Enclavier — Delivery Roadmap

Enclavier is built phase by phase. Each phase ships something usable and
self-hostable; later phases build on the cryptographic foundation of Phase 1
without re-encrypting user data.

| Phase | Theme | Key deliverables | Status |
|------:|-------|------------------|--------|
| 1 | **Foundation** | Monorepo, zero-knowledge crypto core, API server, Postgres schema, master-password auth, personal encrypted vault (items, folders, trash), password generator, clipboard auto-clear, auto-lock, hash-chained audit log, Docker self-host | **Done** |
| 2 | **Organizations** | Tenants/orgs with Postgres row-level security, owners/admins/members, groups, collections, invitation e-mails (SMTP), public-key sharing of the org key, RBAC down to collection (use/view/edit/manage), admin console, org event log | **Done** |
| 3 | **Strong auth & recovery** | TOTP, FIDO2/WebAuthn hardware keys and passkeys, enforced-MFA policy, e-mail verification, account recovery via org key escrow, emergency access, Shamir split-key recovery for org owners | **Done** |
| 4 | **Audit, compliance, monitoring** | Tamper-evident audit explorer + verification, SIEM streaming (webhook, syslog, Splunk HEC, Datadog, Sentinel), HIBP k-anonymity breach checks, weak/reused reports, policy engine (length, entropy, auto-lock, sharing), SOC 2 / ISO 27001 / HIPAA / PCI / NIST 800-63 posture reports | **Done** |
| 5 | **Enterprise identity** | SAML 2.0 + OIDC SSO (Okta, Entra ID, Google, Ping), trusted-device key release, SCIM 2.0 provisioning / deprovisioning, group mapping | **Done** |
| 6 | **Browser extension** | Chrome / Edge / Firefox / Safari (MV3), autofill, save-on-submit, view-only (masked) autofill for shared credentials | **Done** for Chrome/Edge/Firefox (SSO sign-in in the extension and Safari to follow) |
| 7 | **Desktop** | Windows app (Electron shell around the web vault; installer), locks with Windows, screen-capture blocking | **Done** for Windows (Windows Hello unlock, auto-update, code signing, macOS/Linux to follow) |
| 8 | **Mobile** | iOS / Android (React Native), biometric unlock, OS autofill providers | Planned |
| 9 | **Machine secrets** | Service accounts, `enclavier` CLI + SDK, GitHub Actions / GitLab CI / Terraform / Kubernetes / Ansible integrations, dynamic DB & cloud credentials with TTL, scheduled rotation, secret scanning | Planned |
| 10 | **Just-in-time access & hardening** | Per-collection keys, org-key rotation on member removal, time-bound grants, four-eyes approvals, expiring shares, external sharing, air-gapped packaging (offline bundles, Helm chart), HSM/KMS integration, third-party pentest checklist | Planned |

## Open source and distribution

- Licensed under AGPL-3.0, with contribution, security and conduct policies in the repository root.
- CI runs type checks and all tests on every push. Tagging `vX.Y.Z` publishes Docker images, the self-host bundles (online and offline), the browser extension and the Windows installer.
- Self-hosting is one command (`install.sh` / `install.ps1`) with built-in HTTPS, backups, restore and updates. See [SELF_HOSTING.md](SELF_HOSTING.md).

## Deployment targets

- **SaaS / dedicated cloud** — multi-tenant, one Postgres cluster, tenant isolation
  enforced by RLS (Phase 2) plus per-tenant encryption keys that the server never sees.
- **Self-hosted** — the installer in `deploy/` runs Postgres + API + web vault (and optional HTTPS proxy) on
  the customer's own server. No outbound calls are required (HIBP checks and
  SMTP are optional and configurable), so it also works air-gapped.
