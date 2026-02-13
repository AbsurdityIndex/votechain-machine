#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./scripts/install-ingest.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${1:-$ROOT_DIR/dist/votechain-ingest-linux-amd64}"

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC"
  exit 1
fi

useradd --system --home /var/lib/votechain-ingest --shell /usr/sbin/nologin votechain || true
mkdir -p /etc/votechain-ingest /var/lib/votechain-ingest
chown -R votechain:votechain /var/lib/votechain-ingest /etc/votechain-ingest

install -m 0755 "$BIN_SRC" /usr/local/bin/votechain-ingest
install -m 0644 "$ROOT_DIR/configs/ingest.yaml" /etc/votechain-ingest/config.yaml
install -m 0644 "$ROOT_DIR/deployments/ingest/votechain-ingest.service" /etc/systemd/system/votechain-ingest.service

cat <<MSG
Install complete.
Next:
1. Update /etc/votechain-ingest/config.yaml (DSN, auth token, CIDRs, machine registry path).
2. Place machine registry file and public keys on disk.
3. Ensure PostgreSQL is available and database/user exist.
4. systemctl daemon-reload
5. systemctl enable --now votechain-ingest
MSG
