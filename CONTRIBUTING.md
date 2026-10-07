# Contributing to Enclavier

Thanks for helping. This page explains how to get the project running, what we expect in a pull request, and the rules that are specific to a password manager.

Found a security problem? Do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Getting started

You need Node.js 20 or newer and Docker.

```bash
git clone <your fork>
cd enclavier
npm install

# a database for development and tests
docker run -d --name enclavier-dev-pg -p 5433:5432 \
  -e POSTGRES_USER=enclavier -e POSTGRES_PASSWORD=enclavier -e POSTGRES_DB=enclavier_test postgres:16-alpine

npm run dev:server     # API on http://localhost:8080 (needs apps/server/.env, see the README)
npm run dev:web        # web vault on http://localhost:5173
```

## Repository layout

| Path | What it is |
|---|---|
| `packages/crypto` | All cryptography. Runs in browsers, Node and the extension. |
| `packages/shared` | API contracts (zod schemas and types) shared by server and clients. |
| `apps/server` | API server (Fastify, PostgreSQL). |
| `apps/web` | Web vault (React). |
| `apps/extension` | Browser extension (Chrome, Edge, Firefox). |
| `apps/desktop` | Windows desktop app (Electron shell around the web vault). |
| `deploy` | Docker images, installer and management scripts for self-hosting. |
| `docs` | Architecture, roadmap and the self-hosting guide. |

## Before you open a pull request

```bash
npm run typecheck
TEST_DATABASE_URL=postgres://enclavier:enclavier@localhost:5433/enclavier_test npm test
```

- Add or update tests for what you changed. Server behaviour is tested against a real PostgreSQL, not mocks.
- Keep pull requests focused. One change, explained in the description: what it does and why.
- Match the style of the code around you. There is no separate style guide.
- New database changes go in a **new** migration in `apps/server/src/migrations.ts`. Never edit a released one.

## Rules that are specific to this project

These are not negotiable, because they are what "zero-knowledge" means:

1. **The server never sees plaintext secrets or keys.** Vault data, master passwords, user keys and organization keys must be encrypted or derived on the client. A change that sends any of them to the server will not be merged.
2. **No new cryptography outside `packages/crypto`.** Use the existing primitives. If you think a new one is needed, open an issue first and explain the design.
3. **Nothing sensitive in logs.** No request bodies, tokens, or key material.
4. **Every organization-scoped query runs inside `withOrgTx`**, so row-level security applies.
5. **Security-relevant actions are audited** with `recordAudit`.
6. **No third-party scripts, fonts or analytics in the clients.** The content security policy forbids them on purpose.
7. **New outbound requests from the server** to admin-supplied addresses must go through the SSRF guard in `apps/server/src/net.ts`.

## Commit messages and sign-off

Write a short summary line and explain the reason in the body when it is not obvious.

By contributing you agree that your contribution is licensed under the project's licence (AGPL-3.0, see [LICENSE](LICENSE)) and you confirm you have the right to submit it. Add a sign-off line to each commit to state this:

```bash
git commit -s
```

## Reporting bugs and asking for features

Use the issue templates. For bugs, include the version (`./enclavier status` or the web vault's Settings page), what you did, what you expected and what happened. Never paste secrets, tokens or your `.env`.

## Code of conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
