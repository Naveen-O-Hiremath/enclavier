#!/usr/bin/env bash
# Builds the downloadable self-host bundles from this source checkout:
#
#   release/enclavier-<version>.tar.gz           scripts + compose (images come from a registry)
#   release/enclavier-<version>-offline.tar.gz   the same plus every image, for air-gapped servers
#
#   ./make-bundle.sh [version] [--registry ghcr.io/your-org] [--skip-build]
set -euo pipefail
cd "$(dirname "$0")"

VERSION="" REGISTRY="" SKIP_BUILD="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="${2:?}"; shift 2 ;;
    --skip-build) SKIP_BUILD="true"; shift ;;
    -*) echo "Unknown option: $1" >&2; exit 2 ;;
    *) VERSION="$1"; shift ;;
  esac
done
[ -n "$VERSION" ] || VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' ../package.json | head -1)"
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

SERVER_IMAGE="enclavier/server:$VERSION"
WEB_IMAGE="enclavier/web:$VERSION"
if [ "$SKIP_BUILD" = "false" ]; then
  say "Building images for version $VERSION"
  docker build -f server.Dockerfile --build-arg "ENCLAVIER_VERSION=$VERSION" -t "$SERVER_IMAGE" ..
  docker build -f web.Dockerfile -t "$WEB_IMAGE" ..
fi

OUT="$(cd .. && pwd)/release"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
DIR="$STAGE/enclavier-$VERSION"
mkdir -p "$DIR" "$OUT"

cp docker-compose.yml Caddyfile install.sh install.ps1 enclavier enclavier.ps1 .env.example "$DIR/"
chmod +x "$DIR/install.sh" "$DIR/enclavier"
mkdir -p "$DIR/docs"
cp ../docs/SELF_HOSTING.md "$DIR/docs/" 2>/dev/null || true
cp ../LICENSE "$DIR/" 2>/dev/null || true
echo "$VERSION" > "$DIR/VERSION"
cat > "$DIR/README.txt" <<EOF
Enclavier $VERSION, self-hosted
===============================

Linux:    ./install.sh --domain vault.example.com
Windows:  .\\install.ps1 -Domain vault.example.com

Leave out the domain for a local trial on http://localhost:8080.
Full guide: docs/SELF_HOSTING.md
EOF

# ---- online bundle: images are pulled from a registry -------------------------------
say "Writing the online bundle"
if [ -n "$REGISTRY" ]; then
  printf 'ENCLAVIER_SERVER_IMAGE=%s/enclavier-server\nENCLAVIER_WEB_IMAGE=%s/enclavier-web\n' "${REGISTRY%/}" "${REGISTRY%/}" > "$DIR/registry.env"
fi
tar -czf "$OUT/enclavier-$VERSION.tar.gz" -C "$STAGE" "enclavier-$VERSION"
rm -f "$DIR/registry.env"

# ---- offline bundle: every image included -----------------------------------------------
say "Saving images (this takes a minute)"
docker pull -q postgres:16-alpine >/dev/null
docker pull -q caddy:2-alpine >/dev/null
docker save "$SERVER_IMAGE" "$WEB_IMAGE" postgres:16-alpine caddy:2-alpine | gzip > "$DIR/images.tar.gz"
say "Writing the offline bundle"
tar -czf "$OUT/enclavier-$VERSION-offline.tar.gz" -C "$STAGE" "enclavier-$VERSION"

( cd "$OUT" && sha256sum "enclavier-$VERSION.tar.gz" "enclavier-$VERSION-offline.tar.gz" > "enclavier-$VERSION.sha256" )
say "Done:"
ls -lh "$OUT" | sed 's/^/    /'
