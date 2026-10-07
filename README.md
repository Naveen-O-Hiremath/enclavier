<p align="center"><img src="assets/brand/icon-128.png" width="96" alt="Enclavier logo"></p>

<h1 align="center">Enclavier</h1>

<p align="center">
  <strong>Open-source, zero-knowledge password and secrets manager for teams.</strong><br>
  Host it on your own server with one command, or run it fully air-gapped.
</p>

<p align="center">
  <a href="docs/SELF_HOSTING.md">Self-hosting guide</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="docs/ROADMAP.md">Roadmap</a> ·
  <a href="SECURITY.md">Security policy</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

![The Enclavier web vault](docs/images/vault.png)

Enclavier keeps your team's passwords, cards, notes and other secrets encrypted on each person's device. The server stores only ciphertext: it never sees a master password, a vault key or anything you store. You run the server yourself, so the data never leaves your infrastructure.

> **Status:** version 0.1.0, pre-release. The features below are built and covered by automated tests, but the project has not had an independent security audit yet. Evaluate it before trusting it with production secrets.

## Contents

- [What you get](#what-you-get)
- [Screenshots](#screenshots)
- [Quick start](#quick-start)
- [Apps](#apps)
- [Features](#features)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Self-hosting](#self-hosting)
- [Configuration](#configuration)
- [Development](#development)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Licence](#licence)

## What you get

| | |
|---|---|
| **Zero-knowledge encryption** | Everything is encrypted and decrypted on the device. A stolen database or backup reveals no passwords. |
| **Built for teams** | Organizations, groups, shared collections with four permission levels, policies and an admin console. |
| **Enterprise sign-in** | Single sign-on (OpenID Connect and SAML 2.0), SCIM provisioning, two-step login with authenticator apps and security keys. |
| **Audit and compliance** | A tamper-evident audit log, streaming to your SIEM, and a posture report mapped to common frameworks. |
| **Yours to run** | One-command installer for Linux and Windows Server, built-in HTTPS, backups, updates, and an offline bundle for air-gapped networks. |
| **Clients** | Web vault, browser extension with autofill, and a Windows desktop app. |

## Screenshots

| Sign in | Browser extension |
|---|---|
| ![Sign-in screen](docs/images/sign-in.png) | <img src="docs/images/extension.png" width="320" alt="Browser extension popup showing logins for the current site"> |

| Invitation e-mail |
|---|
| <img src="docs/images/invitation-email.png" width="520" alt="Invitation e-mail"> |

## Quick start

You need [Docker](https://docs.docker.com/get-docker/) (Docker Engine with Compose v2, or Docker Desktop).

```bash
git clone https://github.com/Naveen-O-Hiremath/enclavier.git
cd enclavier/deploy

./install.sh            # Linux / macOS
.\install.ps1           # Windows (PowerShell)
```

The installer creates the configuration with fresh random secrets, builds and starts the database, API server and web vault, and waits until everything is healthy. Then:

1. Open **http://localhost:8080**. A new server shows **Create the first account**.
2. Choose a strong master password. It cannot be recovered by the server, so don't lose it.
3. Create an organization from the sidebar and invite your team.

For a real deployment, give it your domain and it sets up HTTPS with an automatic certificate:

```bash
./install.sh --domain vault.example.com
```

See [Self-hosting](#self-hosting) for the other options.

## Apps

| App | Platforms | Notes |
|---|---|---|
| **Web vault** | Any modern browser | Served by your server. Includes the admin console. |
| **Browser extension** | Chrome, Edge, Brave, Opera, Firefox 115+ | Autofill, save logins after sign-in, password generator. See [apps/extension](apps/extension/README.md). |
| **Windows app** | Windows 10 and 11 (x64) | Its own window; locks when Windows locks. See [apps/desktop](apps/desktop/README.md). |

Mobile apps and a command-line tool for machine secrets are on the [roadmap](docs/ROADMAP.md).

## Features

### Vault

- Logins, cards, identities and secure notes, with folders, favourites, trash and password history
- One-time-code (TOTP) generator for stored logins
- Password generator with adjustable rules
- **Vault health:** finds weak, reused, old and exposed passwords, computed in the browser
- **Breach checks** against Have I Been Pwned using k-anonymity, so the password itself is never sent
- Launch a login's website from the vault
- Clipboard auto-clear and auto-lock after inactivity
- Export of your personal vault (admins can turn this off by policy)

### Teams and sharing

- Organizations with owners, admins and members
- Groups, and collections with **use / view / edit / manage** permissions
- **Use-only sharing:** a member can autofill a shared login without being able to see or copy the password
- Invitations by e-mail
- Policies: required two-step login, master-password strength, generator rules, vault timeout, clipboard clearing, export restriction

### Sign-in and identity

- Two-step login with authenticator apps (TOTP), security keys and passkeys (WebAuthn), and one-time recovery codes
- Single sign-on with **OpenID Connect** and **SAML 2.0**: Okta, Microsoft Entra ID, Google Workspace, Ping, OneLogin, Keycloak
- Domain verification, just-in-time accounts, and "require SSO" for members
- **SCIM 2.0** provisioning and deprovisioning of users and groups; group sync at sign-in
- **Trusted devices:** after SSO, a trusted browser opens the vault without the master password; new devices are approved from another device or by an admin

### Recovery

- Admin-assisted account recovery (opt-in, with the organization's recovery key)
- Emergency access for a trusted contact after a waiting period
- A split-key recovery kit for organization owners (Shamir secret sharing)

### Audit, monitoring and compliance

- Hash-chained, append-only audit log with filters, CSV/JSON export and integrity verification
- Log streaming to Splunk, Microsoft Sentinel, Datadog, Sumo Logic, syslog and signed webhooks
- Compliance posture report with evidence, mapped to SOC 2, ISO 27001, HIPAA, PCI DSS and NIST 800-63B (a readiness aid, not a certification)

### Browser extension

- Autofill from the popup, from an icon inside login fields, or with **Ctrl+Shift+L**
- Launch a site and fill it; offer to save or update a login after you sign in
- Fills only on the matching site (public-suffix aware), never downgrades https logins to http pages

## How it works

```mermaid
flowchart LR
  subgraph Device["Your device (browser, extension or desktop app)"]
    MP["Master password"] -->|Argon2id| MK["Master key"]
    MK -->|HKDF| KEK["Key-encryption key"]
    MK -->|HKDF| AH["Sign-in value"]
    KEK -->|unwraps| UK["User key"]
    UK -->|unwraps| IK["Per-item keys"]
    IK -->|XChaCha20-Poly1305| CT["Encrypted items"]
  end
  subgraph Server["Your Enclavier server"]
    API["API server"] --> DB[("PostgreSQL<br>ciphertext only")]
  end
  AH -->|proves identity| API
  CT -->|stored as ciphertext| API
```

- **Key derivation:** the master password is stretched with Argon2id on the device. The result is split into a key that unlocks the vault and a separate value used only to sign in. The server stores a salted hash of that sign-in value.
- **Item encryption:** each item has its own random key and is encrypted with XChaCha20-Poly1305. Ciphertext is bound to its item, so it can't be swapped between items.
- **Sharing:** every account has an X25519 key pair. An organization key is sealed to each member's public key by an admin's device; the server only stores sealed boxes.
- **Tenant isolation:** organization data is protected by PostgreSQL row-level security in addition to application checks.

The formats, key hierarchy and each protocol are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security model

**What the server can never do**

- Read vault items, their names or notes
- Learn or reset a master password
- Decrypt organization keys or shared items

**What you should know**

- Some policies (master-password strength, clipboard and timeout limits, export restriction) are enforced by the apps, because the server cannot see what they govern. A modified client could ignore them. This is documented in the architecture guide.
- Account recovery is opt-in per organization. When enabled, organization admins can reset an enrolled member's access; members are told this when they enrol.
- The web vault is served by your server. Anyone who controls that server could serve altered code, as with any web application. The desktop app and extension ship their own code and are not affected.
- No independent audit has been done yet.

Found a vulnerability? Please report it privately. See [SECURITY.md](SECURITY.md).

## Self-hosting

The full guide is [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md). In short:

| Goal | Command |
|---|---|
| Trial on one machine | `./install.sh` |
| Production with built-in HTTPS | `./install.sh --domain vault.example.com` |
| Behind your own load balancer or proxy | `./install.sh --public-url https://vault.example.com` |
| Air-gapped server | Build the offline bundle (`npm run bundle`), copy it over, `./install.sh --offline` |

On Windows Server use `.\install.ps1` with the matching parameters (`-Domain`, `-PublicUrl`, `-Offline`).

Day-to-day management is one script, `./enclavier` (or `.\enclavier.ps1`):

| Command | What it does |
|---|---|
| `status` | Containers, version and health |
| `logs [service]` | Follow logs |
| `update [version]` | Back up, then move to a new version |
| `backup [dir]` | Write a backup archive (database and configuration) |
| `restore <file>` | Replace all data with a backup |
| `verify-audit` | Check the tamper-evident audit log |
| `test-mail <address>` | Send a test e-mail |

**Requirements:** 1 CPU core and 1 GB of memory is enough to start; 2 cores and 4 GB is comfortable for a few hundred users.

## Configuration

The installer writes `deploy/.env`. The settings you are most likely to change:

| Setting | Meaning |
|---|---|
| `PUBLIC_URL` | The address users type. Used in e-mail links, for security keys and SSO callbacks. |
| `SIGNUPS_ENABLED` | `false` (default): only the first account can sign up, then invitations and SSO. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Outgoing e-mail for invitations and security notices. Without them, e-mails are written to the server log. |
| `HIBP_API_URL` | Breach-check service or an internal mirror. Empty turns breach checks off. |
| `ALLOW_PRIVATE_SSO_ENDPOINTS`, `ALLOW_PRIVATE_LOG_DESTINATIONS` | Allow an identity provider or SIEM on your internal network. |

The complete list is in the [self-hosting guide](docs/SELF_HOSTING.md#settings-reference-env).

## Development

You need Node.js 20 or newer and Docker.

```bash
npm install

# a database for development and tests
docker run -d --name enclavier-dev-pg -p 5433:5432 \
  -e POSTGRES_USER=enclavier -e POSTGRES_PASSWORD=enclavier -e POSTGRES_DB=enclavier_test postgres:16-alpine

cp apps/server/.env.example apps/server/.env   # point DATABASE_URL at your database
npm run dev:server        # API on :8080 (runs migrations on start)
npm run dev:web           # web vault on :5173 (proxies /api)
```

| Command | What it does |
|---|---|
| `npm run typecheck` | Type-check every package |
| `npm test` | All tests. Set `TEST_DATABASE_URL=postgres://enclavier:enclavier@localhost:5433/enclavier_test`; server tests run against a real PostgreSQL. |
| `npm run build:extension` | Browser extension into `apps/extension/dist` |
| `npm run build:desktop` | Windows installer into `apps/desktop/release` |
| `npm run bundle` | Self-host bundles (online and offline) into `release/` |

### Tech stack

- **Language:** TypeScript everywhere, in one npm-workspaces repository
- **Cryptography:** Argon2id (`hash-wasm`), XChaCha20-Poly1305, X25519 and HKDF (`@noble`), all in `packages/crypto`
- **Server:** Fastify, PostgreSQL 16 with row-level security, `jose`, `openid-client`, `node-saml`
- **Web:** React, Vite, Tailwind CSS, Zustand
- **Extension:** Manifest V3, React popup
- **Desktop:** Electron shell around the bundled web vault
- **Deployment:** Docker Compose, nginx, optional Caddy for HTTPS

## Project layout

```
packages/crypto    all cryptography, shared by every client
packages/shared    API contracts (zod schemas and types)
apps/server        API server, database migrations, audit tooling
apps/web           web vault and admin console
apps/extension     browser extension
apps/desktop       Windows app
deploy/            Docker images, installer, management scripts, HTTPS proxy config
docs/              architecture, roadmap, self-hosting guide
assets/brand/      logo and generated icons
```

## Roadmap

Done: the foundation, organizations, strong authentication and recovery, audit and compliance, enterprise identity, the browser extension and the Windows app.

Planned next:

- Mobile apps (iOS and Android)
- Machine secrets: service accounts, a CLI and CI integrations
- Just-in-time access, approvals and expiring shares
- Windows Hello unlock, automatic updates and signed installers for the desktop app
- SSO sign-in inside the browser extension; Safari

Details are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first: it explains how to run the project and lists the rules that keep it zero-knowledge. Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Enclavier is licensed under the [GNU Affero General Public License v3.0](LICENSE). You can use, modify and self-host it freely. If you offer a modified version to others over a network, you must make your source code available to them under the same licence.
