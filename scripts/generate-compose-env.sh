#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${1:-$ROOT_DIR/.env}"
FORCE="${FORCE:-false}"

if [[ -f "$OUT_FILE" && "$FORCE" != "true" ]]; then
  echo "compose env already exists: $OUT_FILE"
  echo "Set FORCE=true to regenerate."
  exit 0
fi

rand_hex() {
  local bytes="$1"
  openssl rand -hex "$bytes"
}

cat > "$OUT_FILE" <<ENV
AIRGAP_DB_PASSWORD=$(rand_hex 24)
CENTRAL_DB_PASSWORD=$(rand_hex 24)
MACHINE_API_TOKEN=$(rand_hex 32)
INGEST_TOKEN=$(rand_hex 32)
AIRGAP_INGEST_TOKEN=$(rand_hex 32)
LEDGER_WRITE_TOKEN=$(rand_hex 32)
AIRGAP_LEDGER_WRITE_TOKEN=$(rand_hex 32)
ENV

chmod 0600 "$OUT_FILE"
echo "generated compose env: $OUT_FILE"
