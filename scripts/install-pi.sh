#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./scripts/install-pi.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${1:-$ROOT_DIR/dist/votechain-machine-linux-arm64}"

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC"
  exit 1
fi

useradd --system --home /var/lib/votechain-machine --shell /usr/sbin/nologin votechain || true
mkdir -p /etc/votechain-machine /etc/votechain-machine/keys /var/lib/votechain-machine/exports
chown -R votechain:votechain /var/lib/votechain-machine /etc/votechain-machine

install -m 0755 "$BIN_SRC" /usr/local/bin/votechain-machine
install -m 0644 "$ROOT_DIR/configs/polling-place.yaml" /etc/votechain-machine/config.yaml
install -m 0644 "$ROOT_DIR/deployments/raspberrypi/votechain-machine.service" /etc/systemd/system/votechain-machine.service

cat <<MSG
Install complete.
Next:
1. Update /etc/votechain-machine/config.yaml (machine IDs + Postgres DSN + key paths).
2. Place machine keys in /etc/votechain-machine/keys/.
3. Ensure PostgreSQL is installed and database/user exist.
4. systemctl daemon-reload
5. systemctl enable --now votechain-machine
MSG
