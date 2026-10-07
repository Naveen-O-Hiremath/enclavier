# Self-hosting Enclavier

Enclavier runs on your own server with Docker. Nothing leaves your network unless you turn it on (outgoing e-mail, breach checks, log streaming).

## What you need

| | Minimum | Comfortable for ~500 users |
|---|---|---|
| CPU | 1 core | 2 cores |
| Memory | 1 GB | 4 GB |
| Disk | 5 GB | 20 GB (vault data is small; backups take most of it) |
| Software | Docker Engine 24+ with Compose v2 (Linux), or Docker Desktop (Windows Server / macOS) | |

For production you also need a DNS name (for example `vault.example.com`) and HTTPS. Browsers only allow the clipboard and security keys on HTTPS pages.

## Install

1. Download a release bundle and unpack it:
   - `enclavier-<version>.tar.gz` pulls the images from the registry.
   - `enclavier-<version>-offline.tar.gz` includes every image, for servers without internet access.
2. Run the installer from the unpacked folder.

**Linux**

```bash
./install.sh --domain vault.example.com
```

**Windows Server (PowerShell)**

```powershell
.\install.ps1 -Domain vault.example.com
```

The installer:

- checks Docker,
- creates `.env` with fresh random secrets (it never overwrites an existing one),
- starts the database, the API server and the web vault,
- waits until the server is healthy and prints the address.

### Installer options

| Linux | Windows | What it does |
|---|---|---|
| `--domain NAME` | `-Domain NAME` | Built-in HTTPS with an automatic Let's Encrypt certificate. DNS for `NAME` must point at the server and ports 80 and 443 must be reachable. |
| `--public-url URL` | `-PublicUrl URL` | You already have a load balancer or reverse proxy that terminates TLS. Point it at the local port. |
| `--port N` | `-Port N` | Local port of the web vault (default 8080). |
| `--registry PREFIX` | `-Registry PREFIX` | Pull images from your own registry mirror. |
| `--version TAG` | `-Version TAG` | Run a specific version. |
| `--open-signups` | `-OpenSignups` | Let anyone who can reach the server sign up. |
| `--offline` | `-Offline` | Load images from `images.tar.gz` (the offline bundle does this automatically). |

Without a domain or public URL the vault runs on `http://localhost:8080`. That is fine for a trial, not for production.

### From source

Clone the repository and run the same installer from `deploy/`. It notices the source tree and builds the images locally.

## First steps after installing

1. Open the vault address. A new server shows **Create the first account**.
   - By default only this first account can sign up. Everyone else joins by invitation or single sign-on.
2. Create your organization (the account that creates it is its owner).
3. Set up outgoing e-mail so invitations can be sent: edit `SMTP_*` in `.env`, run `./enclavier restart`, then `./enclavier test-mail you@example.com`.
4. In the admin console, consider turning on: required two-step login, account recovery, a recovery kit for owners, and single sign-on.
5. Schedule backups (below).

## Day-to-day commands

Run these from the install folder. On Windows use `.\enclavier.ps1` with the same commands.

| Command | What it does |
|---|---|
| `./enclavier status` | Containers, version and health |
| `./enclavier logs [service]` | Follow logs (`server`, `web`, `db`, `proxy`) |
| `./enclavier restart` | Apply changes made to `.env` |
| `./enclavier update [version]` | Back up, then move to a new version |
| `./enclavier backup [dir]` | Write a backup archive |
| `./enclavier restore <file>` | Replace all data with a backup |
| `./enclavier verify-audit` | Check the tamper-evident audit log |
| `./enclavier test-mail <address>` | Send a test e-mail |
| `./enclavier stop` / `start` | Stop or start everything |

## Backups

`./enclavier backup` writes one archive containing:

- a full database dump (accounts, encrypted vaults, organizations, audit log),
- your `.env` (the server secrets).

Keep both together. Without `SERVER_SECRET`, stored authenticator seeds, SSO client secrets and log-streaming credentials can't be read after a restore.

- **What a backup exposes:** vault contents stay encrypted with keys only your users hold, so a stolen backup does not reveal passwords. It does contain server secrets, so store it encrypted and off the server.
- **Schedule it:** for example, nightly with cron on Linux:

  ```cron
  15 2 * * * /opt/enclavier/enclavier backup /var/backups/enclavier
  ```

  On Windows, create a Task Scheduler task that runs `powershell -File C:\enclavier\enclavier.ps1 backup D:\Backups`.
- **Test a restore** on a spare machine before you rely on it: install the same version, copy the archive's `env` file to `.env`, then run `./enclavier restore <file>`.

## Updating

```bash
./enclavier update            # newest version of the configured images
./enclavier update 1.4.0      # a specific version
```

The command backs up first. Database changes are applied automatically when the new server starts. To go back, restore the backup taken by the update and set `ENCLAVIER_VERSION` to the previous version.

For an offline server: unpack the new offline bundle over the install folder (keep your `.env`), run `./install.sh --offline`, and the new images are loaded and started.

## HTTPS options

- **Built-in (simplest):** `--domain vault.example.com`. A Caddy container obtains and renews the certificate. The web vault itself is then bound to `127.0.0.1`.
- **Your own proxy or load balancer:** `--public-url https://vault.example.com`, then forward to the local port. Pass the `Host`, `X-Forwarded-For` and `X-Forwarded-Proto` headers.
- **Internal certificate authority:** use your own proxy with a certificate from your CA.

`PUBLIC_URL` must be the exact address users type. It is used in e-mail links, for security keys and for single sign-on callbacks.

## Air-gapped servers

1. Copy the offline bundle to the server and unpack it.
2. Run `./install.sh --offline --public-url https://vault.internal.example`.
3. In `.env`:
   - leave `SMTP_HOST` empty to write e-mails to the server log, or point it at an internal mail relay;
   - leave `HIBP_API_URL` empty (breach checks off) or point it at an internal mirror of the Pwned Passwords range API.

No other outbound connections are made.

## Settings reference (`.env`)

| Setting | Meaning |
|---|---|
| `POSTGRES_PASSWORD`, `JWT_SECRET`, `SERVER_SECRET` | Generated secrets. Do not change `SERVER_SECRET` after installing. |
| `PUBLIC_URL` | Address of the vault as users see it. |
| `ENCLAVIER_PORT`, `ENCLAVIER_BIND` | Local port and interface of the web vault. |
| `ENCLAVIER_DOMAIN`, `COMPOSE_PROFILES=tls` | Built-in HTTPS. |
| `SIGNUPS_ENABLED` | `false`: only the first account, then invitations and SSO. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Outgoing e-mail. |
| `ALLOW_PRIVATE_LOG_DESTINATIONS` | Allow log streaming to internal addresses (your own SIEM). |
| `ALLOW_PRIVATE_SSO_ENDPOINTS` | Allow an identity provider on your internal network. |
| `HIBP_API_URL`, `HIBP_API_KEY` | Breach checks; empty URL disables them. |
| `ENCLAVIER_VERSION`, `ENCLAVIER_SERVER_IMAGE`, `ENCLAVIER_WEB_IMAGE` | Which images to run. |

Run `./enclavier restart` after changing any of them.

## Hardening checklist

- [ ] HTTPS only; `PUBLIC_URL` starts with `https://`.
- [ ] `.env` readable only by the service account (the installer sets this).
- [ ] Firewall: only 80 and 443 open to users; the database is never exposed (it has no published port).
- [ ] Nightly backups copied off the server, and a restore tested.
- [ ] Sign-ups closed (`SIGNUPS_ENABLED=false`).
- [ ] Required two-step login policy on; at least two organization owners; a recovery kit created and stored offline.
- [ ] Audit log streamed to your SIEM, and `./enclavier verify-audit` run on a schedule.
- [ ] Host OS and Docker patched; Enclavier updated when releases are published.

## Troubleshooting

| Symptom | Check |
|---|---|
| Installer says the server did not become healthy | `./enclavier logs server`. A wrong `POSTGRES_PASSWORD` after reusing an old data volume is the usual cause. |
| No certificate with `--domain` | DNS must resolve to this server and ports 80/443 must be open. See `./enclavier logs proxy`. |
| Invitations don't arrive | `./enclavier test-mail you@example.com`, then `./enclavier logs server` and look for `E-mail handed to SMTP server`. |
| "Copy" buttons or security keys don't work | The vault must be opened over HTTPS at exactly `PUBLIC_URL`. |
| SSO fails with "private or internal address" | Set `ALLOW_PRIVATE_SSO_ENDPOINTS=true` for an internal identity provider. |
