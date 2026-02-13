#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/deployments/compose/reports"
EXPORT_DIR="$ROOT_DIR/deployments/compose/exports"
mkdir -p "$REPORT_DIR" "$EXPORT_DIR"

if [[ ! -f "$ROOT_DIR/.env" ]]; then
  "$ROOT_DIR/scripts/generate-compose-env.sh" "$ROOT_DIR/.env" >/dev/null
fi
set -a
source "$ROOT_DIR/.env"
set +a

MACHINE_TOKEN="${MACHINE_TOKEN:-${MACHINE_API_TOKEN:-compose-machine-api-token-change-me}}"
INGEST_TOKEN="${INGEST_TOKEN:-compose-dev-token-change-me}"
AIRGAP_INGEST_TOKEN="${AIRGAP_INGEST_TOKEN:-compose-airgap-token-change-me}"

VOTERS=20
SESSION_NAME="working-group-demo"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --voters)
      VOTERS="$2"
      shift 2
      ;;
    --session)
      SESSION_NAME="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      echo "Usage: $0 [--voters N] [--session NAME]" >&2
      exit 1
      ;;
  esac
done

if ! [[ "$VOTERS" =~ ^[0-9]+$ ]] || [[ "$VOTERS" -lt 1 ]]; then
  echo "--voters must be a positive integer" >&2
  exit 1
fi

cd "$ROOT_DIR"

wait_for() {
  local name="$1"
  local url="$2"
  local auth="${3:-}"
  for _ in $(seq 1 120); do
    if [[ -n "$auth" ]]; then
      if curl -fsS "$url" -H "Authorization: Bearer $auth" >/dev/null 2>&1; then
        echo "ready: $name"
        return 0
      fi
    else
      if curl -fsS "$url" >/dev/null 2>&1; then
        echo "ready: $name"
        return 0
      fi
    fi
    sleep 2
  done
  echo "timeout waiting for $name ($url)" >&2
  return 1
}

key_id_from_pub() {
  local pub="$1"
  local hex
  hex=$(openssl pkey -pubin -in "$pub" -outform DER | tail -c 32 | openssl dgst -sha256 -binary | xxd -p -c 256 | cut -c1-16)
  echo "ed25519:$hex"
}

echo "Starting compose stack for $SESSION_NAME with $VOTERS voters..."
docker compose up -d --build

wait_for "machine" "http://127.0.0.1:8080/healthz" "$MACHINE_TOKEN"
wait_for "ingest" "http://127.0.0.1:8181/healthz" "$INGEST_TOKEN"
wait_for "observer" "http://127.0.0.1:8282/healthz"
wait_for "ledger-federal" "http://127.0.0.1:8301/healthz"
wait_for "ledger-state" "http://127.0.0.1:8302/healthz"
wait_for "ledger-oversight" "http://127.0.0.1:8303/healthz"
wait_for "airgap-ingest" "http://127.0.0.1:8182/healthz" "$AIRGAP_INGEST_TOKEN"
wait_for "airgap-observer" "http://127.0.0.1:8382/healthz"
wait_for "airgap-ledger-federal" "http://127.0.0.1:8401/healthz"
wait_for "airgap-ledger-state" "http://127.0.0.1:8402/healthz"
wait_for "airgap-ledger-oversight" "http://127.0.0.1:8403/healthz"

MACHINE1_KEY_ID="$(key_id_from_pub "$ROOT_DIR/deployments/compose/keys/machine-signing-public.pem")"

MANIFEST_FILE="$ROOT_DIR/.tmp-manifest-${SESSION_NAME}.json"
python3 <<'PY' "$SESSION_NAME" "$MACHINE1_KEY_ID" > "$MANIFEST_FILE"
import datetime, json, sys
session = sys.argv[1]
receipt_key_id = sys.argv[2]
now = datetime.datetime.now(datetime.timezone.utc)
manifest = {
  "manifest": {
    "election_id": f"demo-{session}-election",
    "jurisdiction_id": "pa-philadelphia",
    "manifest_id": f"demo-{session}-manifest-v1",
    "not_before": (now - datetime.timedelta(minutes=10)).isoformat().replace('+00:00', 'Z'),
    "not_after": (now + datetime.timedelta(hours=8)).isoformat().replace('+00:00', 'Z'),
    "receipt_key_id": receipt_key_id,
    "source_bundle_sha256": f"demo-source-{session}",
    "contests": [
      {
        "contest_id": "president",
        "type": "candidate",
        "title": "President",
        "options": [
          {"id": "cand_a", "label": "Candidate A"},
          {"id": "cand_b", "label": "Candidate B"}
        ]
      }
    ]
  }
}
print(json.dumps(manifest))
PY

curl -fsS -X POST "http://127.0.0.1:8080/v1/election/load" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MACHINE_TOKEN" \
  --data-binary "@$MANIFEST_FILE" >/dev/null
echo "Election loaded"

RECEIPT_IDS_FILE="$ROOT_DIR/.tmp-receipts-${SESSION_NAME}.txt"
: > "$RECEIPT_IDS_FILE"

for i in $(seq 1 "$VOTERS"); do
  CH_JSON=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/election/challenge" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MACHINE_TOKEN" \
    -d '{}')
  CAST_FILE="$ROOT_DIR/.tmp-cast-${SESSION_NAME}-${i}.json"
  python3 <<'PY' "$CH_JSON" "$SESSION_NAME" "$i" > "$CAST_FILE"
import base64, hashlib, json, sys
challenge = json.loads(sys.argv[1])
session = sys.argv[2]
i = int(sys.argv[3])
election_id = f"demo-{session}-election"
manifest_id = f"demo-{session}-manifest-v1"
credential_pub = f"credential-{session}-{i:04d}"
nullifier_seed = f"votechain:nullifier:v1:{credential_pub}:{election_id}".encode()
nullifier = "0x" + hashlib.sha256(nullifier_seed).hexdigest()
cipher = f"encrypted ballot payload {session} voter {i}".encode()
ciphertext = base64.urlsafe_b64encode(cipher).decode().rstrip("=")
ballot_hash = base64.urlsafe_b64encode(hashlib.sha256(cipher).digest()).decode().rstrip("=")
selection = "cand_a" if (i % 2 == 0) else "cand_b"
payload = {
  "idempotency_key": f"{session}-idem-{i}",
  "election_id": election_id,
  "manifest_id": manifest_id,
  "challenge_id": challenge["challenge_id"],
  "challenge": challenge["challenge"],
  "nullifier": nullifier,
  "eligibility_proof": {
    "credential_pub": credential_pub,
    "proof_blob": f"demo-proof-{i}"
  },
  "encrypted_ballot": {
    "ballot_id": f"ballot-{session}-{i:04d}-{selection}",
    "ciphertext": ciphertext,
    "ballot_hash": ballot_hash,
    "wrapped_ballot_key": f"wrapped-key-{session}-{i}",
    "wrapped_ballot_key_epk": f"wrapped-epk-{session}-{i}"
  }
}
print(json.dumps(payload))
PY
  CAST_JSON=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/election/cast" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MACHINE_TOKEN" \
    --data-binary "@$CAST_FILE")
  python3 <<'PY' "$CAST_JSON" >> "$RECEIPT_IDS_FILE"
import json, sys
cast = json.loads(sys.argv[1])
print(cast["cast_receipt"]["receipt_id"])
PY

  if (( i % 5 == 0 )) || (( i == VOTERS )); then
    echo "Cast progress: $i/$VOTERS"
  fi

done

CLOSE_JSON=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/election/close" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MACHINE_TOKEN" \
  -d '{}')
BUNDLE_FILE=$(python3 <<'PY' "$CLOSE_JSON"
import json, os, sys
resp = json.loads(sys.argv[1])
print(os.path.basename(resp["bundle_path"]))
PY
)
HOST_BUNDLE_PATH="$EXPORT_DIR/$BUNDLE_FILE"

for _ in $(seq 1 60); do
  if [[ -f "$HOST_BUNDLE_PATH" ]]; then
    break
  fi
  sleep 1
done
if [[ ! -f "$HOST_BUNDLE_PATH" ]]; then
  echo "bundle not found on host: $HOST_BUNDLE_PATH" >&2
  exit 1
fi

echo "Bundle exported: $HOST_BUNDLE_PATH"

INGEST_FILE="$ROOT_DIR/.tmp-ingest-${SESSION_NAME}.json"
python3 <<'PY' "$HOST_BUNDLE_PATH" > "$INGEST_FILE"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    bundle = json.load(f)
print(json.dumps({"bundle": bundle}))
PY

curl -fsS -X POST "http://127.0.0.1:8181/v1/ingest/bundle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  --data-binary "@$INGEST_FILE" >/dev/null

curl -fsS -X POST "http://127.0.0.1:8182/v1/ingest/bundle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRGAP_INGEST_TOKEN" \
  --data-binary "@$INGEST_FILE" >/dev/null

echo "Bundle ingested into central and airgap ingest"

echo "Waiting for relay and blockchain convergence..."
for _ in $(seq 1 60); do
  STATUS_JSON=$(curl -fsS "http://127.0.0.1:8282/v1/observer/status")
  AIRGAP_STATUS_JSON=$(curl -fsS "http://127.0.0.1:8382/v1/observer/status")
  READY=$(python3 <<'PY' "$STATUS_JSON"
import json, sys
s = json.loads(sys.argv[1])
ok = (s.get("ingest_data", {}).get("outbox_pending", 1) == 0) and (s.get("consistency", {}).get("status") in ["ok", "degraded"])
print("yes" if ok else "no")
PY
)
  AIRGAP_READY=$(python3 <<'PY' "$AIRGAP_STATUS_JSON"
import json, sys
s = json.loads(sys.argv[1])
ok = (s.get("ingest_data", {}).get("outbox_pending", 1) == 0) and (s.get("consistency", {}).get("status") in ["ok", "degraded"])
print("yes" if ok else "no")
PY
)
  if [[ "$READY" == "yes" && "$AIRGAP_READY" == "yes" ]]; then
    break
  fi
  sleep 2
done

STATUS_JSON=$(curl -fsS "http://127.0.0.1:8282/v1/observer/status")
REPORT_MD=$(curl -fsS "http://127.0.0.1:8282/v1/observer/report")

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_JSON_PATH="$REPORT_DIR/${SESSION_NAME}-${STAMP}.json"
REPORT_MD_PATH="$REPORT_DIR/${SESSION_NAME}-${STAMP}.md"

printf "%s\n" "$STATUS_JSON" > "$REPORT_JSON_PATH"
printf "%s\n" "$REPORT_MD" > "$REPORT_MD_PATH"

FACILITATOR_PATH="$REPORT_DIR/${SESSION_NAME}-${STAMP}-facilitator.md"
python3 <<'PY' "$STATUS_JSON" "$SESSION_NAME" "$VOTERS" "$BUNDLE_FILE" "$HOST_BUNDLE_PATH" "$RECEIPT_IDS_FILE" > "$FACILITATOR_PATH"
import json, sys, pathlib
status = json.loads(sys.argv[1])
session = sys.argv[2]
voters = int(sys.argv[3])
bundle_file = sys.argv[4]
bundle_path = sys.argv[5]
receipt_file = pathlib.Path(sys.argv[6])
receipt_count = len(receipt_file.read_text(encoding="utf-8").strip().splitlines()) if receipt_file.exists() else 0
print(f"# Working Group Session Report: {session}")
print()
print(f"- Session: `{session}`")
print(f"- Registered demo voters cast: `{voters}`")
print(f"- Recorded receipts: `{receipt_count}`")
print(f"- Bundle file: `{bundle_file}`")
print(f"- Bundle path: `{bundle_path}`")
print(f"- Overall status: `{status.get('overall')}`")
print(f"- Outbox pending: `{status.get('ingest_data',{}).get('outbox_pending')}`")
print(f"- Outbox sent: `{status.get('ingest_data',{}).get('outbox_sent')}`")
print(f"- Consistency: `{status.get('consistency',{}).get('status')}`")
print()
print("## Blockchain node heights")
for node in status.get("blockchain", {}).get("nodes", []):
    print(f"- {node.get('role')}: healthy={node.get('healthy')} latest_index={node.get('latest_index',0)}")
print()
print("## Notes")
print("- This run is for public test-election working groups only.")
print("- Do not treat this output as election certification evidence.")
PY

echo "Demo session complete."
echo "Observer status JSON: $REPORT_JSON_PATH"
echo "Observer report Markdown: $REPORT_MD_PATH"
echo "Facilitator summary: $FACILITATOR_PATH"

rm -f "$MANIFEST_FILE" "$INGEST_FILE" "$RECEIPT_IDS_FILE"
rm -f "$ROOT_DIR"/.tmp-cast-${SESSION_NAME}-*.json || true
