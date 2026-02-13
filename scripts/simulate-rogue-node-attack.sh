#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$ROOT/deployments/compose/reports"
ROGUE_CONTAINER="votechain-anchor-relay-rogue"
TMP_DIR="$(mktemp -d)"
RESTORE_RELAY=0

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

cleanup() {
  local exit_code=$?
  docker rm -f "$ROGUE_CONTAINER" >/dev/null 2>&1 || true
  if [[ "$RESTORE_RELAY" == "1" ]]; then
    docker start votechain-anchor-relay >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
  exit "$exit_code"
}
trap cleanup EXIT

require_cmd docker
require_cmd jq
require_cmd go
require_cmd curl

cd "$ROOT"

if [[ ! -f ".env" ]]; then
  "$ROOT/scripts/generate-compose-env.sh" "$ROOT/.env" >/dev/null
fi

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
set +a

mkdir -p "$REPORT_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_json="$REPORT_DIR/rogue-node-attack-$stamp.json"
report_md="$REPORT_DIR/rogue-node-attack-$stamp.md"

echo "Ensuring compose stack is running..."
docker compose up -d >/dev/null 2>&1

cat > "$TMP_DIR/relay-invalid-role.yaml" <<'YAML'
storage:
  postgres_dsn: "postgres://votechain:dummy@127.0.0.1:5432/votechain_ingest?sslmode=disable"

security:
  enforce_secure_transport: false

relay:
  poll_interval_seconds: 5
  batch_size: 10
  required_acks: 2

nodes:
  - role: "federal"
    url: "http://127.0.0.1:8301"
    write_token: "x"
    ack_key_id: "ed25519:1111111111111111"
    ack_public_key_path: "/tmp/fed.pem"
  - role: "state"
    url: "http://127.0.0.1:8302"
    write_token: "x"
    ack_key_id: "ed25519:2222222222222222"
    ack_public_key_path: "/tmp/state.pem"
  - role: "oversight"
    url: "http://127.0.0.1:8303"
    write_token: "x"
    ack_key_id: "ed25519:3333333333333333"
    ack_public_key_path: "/tmp/oversight.pem"
  - role: "rogue"
    url: "http://127.0.0.1:8399"
    write_token: "x"
    ack_key_id: "ed25519:4444444444444444"
    ack_public_key_path: "/tmp/rogue.pem"
YAML

scenario1_output="$(go run ./cmd/votechain-anchor-relay -config "$TMP_DIR/relay-invalid-role.yaml" 2>&1 || true)"
scenario1_detected=0
if [[ "$scenario1_output" == *"nodes[3].role must be one of federal|state|oversight"* ]]; then
  scenario1_detected=1
fi

echo "Generating fresh signed bundle..."
"$ROOT/scripts/simulate-ballot-box-duplicates.py" --force-machine-bypass-on-duplicate >/dev/null
bundle_file="$(ls -1t "$ROOT"/deployments/compose/exports/bundle_*.json | head -n1)"

cp "$ROOT/configs/compose/relay.yaml" "$TMP_DIR/relay-ack-spoof.yaml"
sed 's/required_acks: 2/required_acks: 3/' "$TMP_DIR/relay-ack-spoof.yaml" \
  | sed 's/ack_key_id: "ed25519:9d8a7d8ed1dcf6e4"/ack_key_id: "ed25519:0000000000000000"/' \
  > "$TMP_DIR/relay-ack-spoof.mut.yaml"
mv "$TMP_DIR/relay-ack-spoof.mut.yaml" "$TMP_DIR/relay-ack-spoof.yaml"

echo "Running spoofed relay configuration..."
docker stop votechain-anchor-relay >/dev/null
RESTORE_RELAY=1
docker rm -f "$ROGUE_CONTAINER" >/dev/null 2>&1 || true
docker run -d \
  --name "$ROGUE_CONTAINER" \
  --env-file "$ROOT/.env" \
  --network votechain_central_net \
  -v "$TMP_DIR/relay-ack-spoof.yaml:/etc/votechain-relay/config.yaml:ro" \
  -v "$ROOT/deployments/compose/keys:/run/keys:ro" \
  votechain-machine-votechain-anchor-relay \
  -config /etc/votechain-relay/config.yaml >/dev/null

jq -c '{bundle:.}' "$bundle_file" | curl -sS \
  -H "Authorization: Bearer ${INGEST_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:8181/v1/ingest/bundle" \
  --data @- >/dev/null

sleep 8

observer_during="$(curl -sS "http://127.0.0.1:8282/v1/observer/status")"
outbox_row="$(docker exec votechain-postgres-central psql -U votechain -d votechain_ingest -At -F $'\t' -c "SELECT id,status,attempts,last_error FROM anchor_outbox ORDER BY id DESC LIMIT 1;")"
relay_logs="$(docker logs --tail 30 "$ROGUE_CONTAINER" 2>&1 || true)"

observer_overall="$(echo "$observer_during" | jq -r '.overall // ""')"
observer_outbox_pending="$(echo "$observer_during" | jq -r '.ingest_data.outbox_pending // -1')"
outbox_error="$(echo "$outbox_row" | awk -F $'\t' '{print $4}')"

scenario2_detected=0
if [[ "$observer_overall" == "degraded" ]] && [[ "$observer_outbox_pending" =~ ^[0-9]+$ ]] && (( observer_outbox_pending > 0 )) && [[ "$outbox_error" == *"ack key id mismatch"* ]]; then
  scenario2_detected=1
fi

docker rm -f "$ROGUE_CONTAINER" >/dev/null 2>&1 || true
docker start votechain-anchor-relay >/dev/null
RESTORE_RELAY=0

recovered=0
observer_after=""
for _ in $(seq 1 30); do
  observer_after="$(curl -sS "http://127.0.0.1:8282/v1/observer/status" || true)"
  overall_after="$(echo "$observer_after" | jq -r '.overall // ""' 2>/dev/null || true)"
  pending_after="$(echo "$observer_after" | jq -r '.ingest_data.outbox_pending // -1' 2>/dev/null || true)"
  if [[ "$overall_after" == "ok" ]] && [[ "$pending_after" == "0" ]]; then
    recovered=1
    break
  fi
  sleep 2
done

overall_pass=0
if [[ "$scenario1_detected" == "1" && "$scenario2_detected" == "1" && "$recovered" == "1" ]]; then
  overall_pass=1
fi

jq -n \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg bundle_file "$bundle_file" \
  --arg scenario1_output "$scenario1_output" \
  --arg observer_during "$observer_during" \
  --arg observer_after "$observer_after" \
  --arg outbox_row "$outbox_row" \
  --arg relay_logs "$relay_logs" \
  --argjson scenario1_detected "$scenario1_detected" \
  --argjson scenario2_detected "$scenario2_detected" \
  --argjson recovered "$recovered" \
  --argjson overall_pass "$overall_pass" \
  '{
    timestamp_utc: $timestamp,
    bundle_file: $bundle_file,
    scenario_startup_role_validation: {
      detected: ($scenario1_detected == 1),
      output: $scenario1_output
    },
    scenario_runtime_ack_spoof: {
      detected: ($scenario2_detected == 1),
      outbox_row: $outbox_row,
      observer_status_during: ($observer_during | fromjson? // {}),
      relay_logs_tail: $relay_logs
    },
    recovery: {
      restored: ($recovered == 1),
      observer_status_after: ($observer_after | fromjson? // {})
    },
    overall_pass: ($overall_pass == 1)
  }' > "$report_json"

cat > "$report_md" <<EOF
# Rogue Node Attack Simulation Report

- Timestamp (UTC): \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`
- Bundle used: \`$bundle_file\`
- Startup invalid-role detection: \`$scenario1_detected\`
- Runtime ACK spoof detection: \`$scenario2_detected\`
- Post-attack relay recovery: \`$recovered\`
- Overall pass: \`$overall_pass\`

## Startup Validation Output

\`\`\`text
$scenario1_output
\`\`\`

## Runtime Outbox Evidence

\`\`\`text
$outbox_row
\`\`\`

## Observer During Spoof

\`\`\`json
$observer_during
\`\`\`
EOF

echo "report_json:$report_json"
echo "report_md:$report_md"
jq -c '{overall_pass, scenario_startup_role_validation: .scenario_startup_role_validation.detected, scenario_runtime_ack_spoof: .scenario_runtime_ack_spoof.detected, recovery_restored: .recovery.restored}' "$report_json"
