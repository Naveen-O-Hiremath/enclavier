# Security policy

Enclavier is a password manager, so security reports get priority over everything else.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

- E-mail **team@codearrive.in** with the subject `SECURITY: <short summary>`.
- Or use GitHub's **Report a vulnerability** button on the repository's Security tab (private advisory).

Include, as far as you can:

- what is affected (server, web vault, browser extension, desktop app, crypto package) and the version or commit,
- how to reproduce it, or a proof of concept,
- what an attacker gains.

### What to expect

| Step | Target |
|---|---|
| We confirm we received your report | within 3 working days |
| First assessment (accepted, need more detail, or not a vulnerability) | within 10 working days |
| Fix for critical and high severity issues | as fast as we can, normally within 30 days |
| Public advisory and credit to you (if you want it) | when a fixed release is available |

Please give us a reasonable time to ship a fix before you publish details.

### Safe harbour

We will not take legal action against, or ask for the suspension of, researchers who:

- test only against their own installation or accounts,
- do not access, change or delete other people's data,
- do not degrade a service for others (no denial-of-service or spam),
- report what they find to us promptly and privately.

## Supported versions

Security fixes are made for the latest release. If you self-host, run `./enclavier update` when a release is published.

## Scope

In scope:

- anything that exposes vault contents, keys or master passwords,
- authentication or authorization bypass, cross-tenant access,
- weaknesses in the cryptographic design or its implementation (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)),
- the browser extension filling credentials into the wrong site,
- tampering with the audit log without detection.

Out of scope:

- attacks that need a fully compromised device or browser profile,
- missing rate limits on endpoints that reveal nothing,
- issues in third-party services you connect (your identity provider, SMTP server, SIEM),
- the limits already documented under "Security boundaries" in the architecture document, such as policies that only the client can enforce.

## Verifying a download

Each release publishes SHA-256 checksums (`enclavier-<version>.sha256`) next to the bundles. Check them before installing:

```bash
sha256sum -c enclavier-<version>.sha256
```
