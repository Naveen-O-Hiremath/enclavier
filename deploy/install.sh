#!/usr/bin/env bash
# Enclavier self-host installer (Linux / macOS). Safe to run again: it never
# overwrites an existing .env, so secrets and data are kept.
set -euo pipefail

usage() {
  cat <<'EOF'
Install Enclavier on this server with Docker.

  ./install.sh [options]

  --domain NAME        Public host name, e.g. vault.example.com. Turns on built-in
                       HTTPS (automatic Let's Encrypt certificate). Needs DNS for
                       NAME pointing here and ports 80/443 open.
  --public-url URL     Use when your own load balancer / reverse proxy terminates
                       TLS, e.g. https://vault.example.com (no built-in HTTPS).
  --port N             Local port of the web vault (default 8080).
  --registry PREFIX    Pull images from a registry, e.g. ghcr.io/your-org
                       (images PREFIX/enclavier-server and PREFIX/enclavier-web).
  --version TAG        Image version to run (default: latest).
  --open-signups       Let anyone who can reach the server create an account.
                       Default: only the first account, then invitations and SSO.
  --offline            Load images from images.tar.gz in this folder (air-gapped).
  -h, --help           Show this help.

Without --domain or --public-url the vault is served on http://localhost:PORT,
which is fine for a trial but not for production (browsers need HTTPS for the
clipboard and security keys).
EOF
}

DOMAIN="" PUBLIC_URL="" PORT="8080" REGISTRY="" VERSION="" OPEN_SIGNUPS="false" OFFLINE="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:?--public-url needs a value}"; shift 2 ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    --registry) REGISTRY="${2:?--registry needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --open-signups) OPEN_SIGNUPS="true"; shift ;;
    --offline) OFFLINE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")"
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- prerequisites ---------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "Docker is not installed. See https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (the 'docker compose' command)."
docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon. Is it running, and may this user use it?"
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
if [ -n "$DOMAIN" ] && [ -n "$PUBLIC_URL" ]; then die "Use either --domain (built-in HTTPS) or --public-url (your own proxy), not both."; fi

secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 64 | tr -d '/+=\n' | cut -c1-48
  else head -c 64 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-48; fi
}

# ---- where do the images come from? ------------------------------------------
SOURCE="false"
[ -f ../apps/server/package.json ] && [ -f docker-compose.build.yml ] && SOURCE="true"
if [ "$OFFLINE" = "true" ] || { [ -f images.tar.gz ] && [ -z "$REGISTRY" ] && [ "$SOURCE" = "false" ]; }; then
  [ -f images.tar.gz ] || die "--offline needs images.tar.gz next to this script (from the offline bundle)."
  say "Loading images from images.tar.gz"
  gunzip -c images.tar.gz | docker load
  SOURCE="false"; REGISTRY=""
fi
# Release bundles carry their version (and, for the online bundle, their registry).
if [ -f VERSION ] && [ -z "$VERSION" ]; then VERSION="$(cat VERSION)"; fi

# ---- configuration -----------------------------------------------------------
if [ -f .env ]; then
  say "Keeping the existing .env (secrets and settings are unchanged)"
else
  say "Creating .env with new secrets"
  if [ -n "$DOMAIN" ]; then URL="https://$DOMAIN"
  elif [ -n "$PUBLIC_URL" ]; then URL="${PUBLIC_URL%/}"
  else URL="http://localhost:$PORT"; fi
  SIGNUPS="false"; [ "$OPEN_SIGNUPS" = "true" ] && SIGNUPS="true"
  umask 077
  {
    echo "# Enclavier configuration. Created by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo "# Keep this file secret and include it in your backups: without SERVER_SECRET,"
    echo "# stored authenticator seeds and SIEM credentials can't be read after a restore."
    echo "POSTGRES_PASSWORD=$(secret)"
    echo "JWT_SECRET=$(secret)"
    echo "SERVER_SECRET=$(secret)"
    echo
    echo "PUBLIC_URL=$URL"
    echo "ENCLAVIER_PORT=$PORT"
    echo "# false: only the first account can sign up; everyone else is invited or uses SSO."
    echo "SIGNUPS_ENABLED=$SIGNUPS"
    echo "LOG_LEVEL=info"
    if [ -n "$DOMAIN" ]; then
      echo
      echo "# Built-in HTTPS (Caddy + Let's Encrypt)."
      echo "ENCLAVIER_DOMAIN=$DOMAIN"
      echo "COMPOSE_PROFILES=tls"
      echo "ENCLAVIER_BIND=127.0.0.1"
    fi
    if [ "$SOURCE" = "true" ]; then
      echo
      echo "# Build images from this source checkout."
      echo "COMPOSE_PATH_SEPARATOR=:"
      echo "COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml"
    fi
    if [ -n "$REGISTRY" ]; then
      echo
      echo "ENCLAVIER_SERVER_IMAGE=${REGISTRY%/}/enclavier-server"
      echo "ENCLAVIER_WEB_IMAGE=${REGISTRY%/}/enclavier-web"
    fi
    if [ -z "$REGISTRY" ] && [ "$SOURCE" = "false" ] && [ "$OFFLINE" = "false" ] && [ ! -f images.tar.gz ] && [ -f registry.env ]; then
      echo
      cat registry.env
    fi
    [ -n "$VERSION" ] && echo "ENCLAVIER_VERSION=$VERSION"
    echo
    echo "# ---- Outgoing e-mail (invitations, security notices) ----"
    echo "# Leave SMTP_HOST empty to write e-mails to the server log instead."
    echo "SMTP_HOST="
    echo "SMTP_PORT=465"
    echo "SMTP_SECURE=true"
    echo "SMTP_USER="
    echo "SMTP_PASS="
    echo "SMTP_FROM=Enclavier <no-reply@${DOMAIN:-example.com}>"
    echo
    echo "# Self-hosted: allow log streaming and identity providers on your internal network."
    echo "ALLOW_PRIVATE_LOG_DESTINATIONS=true"
    echo "ALLOW_PRIVATE_SSO_ENDPOINTS=true"
    echo "# Breach checks. Point at an offline mirror, or leave empty to disable (air-gapped)."
    if [ "$OFFLINE" = "true" ]; then echo "HIBP_API_URL="; else echo "HIBP_API_URL=https://api.pwnedpasswords.com"; fi
  } > .env
  chmod 600 .env
fi

# ---- start -------------------------------------------------------------------
if [ "$SOURCE" = "true" ]; then
  say "Building and starting Enclavier (first build takes a few minutes)"
  docker compose up -d --build
else
  if [ -n "$REGISTRY" ] || grep -q '^ENCLAVIER_SERVER_IMAGE=' .env; then say "Pulling images"; docker compose pull; fi
  say "Starting Enclavier"
  docker compose up -d
fi

PORT_NOW="$(grep -E '^ENCLAVIER_PORT=' .env | tail -1 | cut -d= -f2)"; PORT_NOW="${PORT_NOW:-8080}"
URL_NOW="$(grep -E '^PUBLIC_URL=' .env | tail -1 | cut -d= -f2-)"
say "Waiting for the server to become healthy"
ok="false"
for _ in $(seq 1 60); do
  if docker compose exec -T server wget -qO- http://127.0.0.1:8080/health >/dev/null 2>&1; then ok="true"; break; fi
  sleep 2
done
[ "$ok" = "true" ] || die "The server did not become healthy. Check: ./enclavier logs"

cat <<EOF

Enclavier is running.

  Vault:        $URL_NOW
  Local port:   http://localhost:$PORT_NOW
  Config:       $(pwd)/.env   (back this file up; it holds your secrets)

Next steps
  1. Open the vault and create the first account. It becomes the first user;
     create your organization from there and invite the team.
  2. Set SMTP_* in .env so invitations can be e-mailed, then: ./enclavier restart
  3. Schedule backups:  ./enclavier backup     (see docs/SELF_HOSTING.md)

Manage:  ./enclavier status | logs | update | backup | restore <file> | stop
EOF
if [ -z "$(grep -E '^ENCLAVIER_DOMAIN=' .env || true)" ] && ! echo "$URL_NOW" | grep -q '^https://'; then
  echo
  echo "Note: $URL_NOW is not HTTPS. Use --domain (built-in HTTPS) or put your own TLS"
  echo "proxy in front before real use."
fi
