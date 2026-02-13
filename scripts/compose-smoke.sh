#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPORT_DIR="$ROOT_DIR/deployments/compose/exports"
mkdir -p "$EXPORT_DIR"

if [[ ! -f "$ROOT_DIR/.env" ]]; then
  "$ROOT_DIR/scripts/generate-compose-env.sh" "$ROOT_DIR/.env" >/dev/null
fi
set -a
source "$ROOT_DIR/.env"
set +a

cd "$ROOT_DIR"

MACHINE_TOKEN="${MACHINE_TOKEN:-${MACHINE_API_TOKEN:-compose-machine-api-token-change-me}}"
INGEST_TOKEN="${INGEST_TOKEN:-compose-dev-token-change-me}"
AIRGAP_INGEST_TOKEN="${AIRGAP_INGEST_TOKEN:-compose-airgap-token-change-me}"

wait_for() {
  local name="$1"
  local url="$2"
  local auth="${3:-}"
  for _ in $(seq 1 90); do
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

echo "Starting compose stack..."
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

MANIFEST_FILE="$ROOT_DIR/.tmp-manifest.json"
python3 <<'PY' "$MACHINE1_KEY_ID" > "$MANIFEST_FILE"
import datetime, json, sys
receipt_key_id = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
manifest = {
  "manifest": {
    "election_id": "compose-demo-election",
    "jurisdiction_id": "pa-philadelphia",
    "manifest_id": "compose-demo-manifest-v1",
    "not_before": (now - datetime.timedelta(minutes=10)).isoformat().replace('+00:00', 'Z'),
    "not_after": (now + datetime.timedelta(hours=8)).isoformat().replace('+00:00', 'Z'),
    "receipt_key_id": receipt_key_id,
    "source_bundle_sha256": "compose-demo-source",
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

CHALLENGE_JSON=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/election/challenge" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MACHINE_TOKEN" \
  -d '{}')

CAST_FILE="$ROOT_DIR/.tmp-cast.json"
python3 <<'PY' "$CHALLENGE_JSON" > "$CAST_FILE"
import base64, hashlib, json, sys
challenge = json.loads(sys.argv[1])
election_id = "compose-demo-election"
credential_pub = "credential-demo-001"
nullifier_seed = f"votechain:nullifier:v1:{credential_pub}:{election_id}".encode()
nullifier = "0x" + hashlib.sha256(nullifier_seed).hexdigest()
cipher = b"demo encrypted ballot payload"
ciphertext = base64.urlsafe_b64encode(cipher).decode().rstrip("=")
ballot_hash = base64.urlsafe_b64encode(hashlib.sha256(cipher).digest()).decode().rstrip("=")
payload = {
  "idempotency_key": "compose-smoke-idem-1",
  "election_id": election_id,
  "manifest_id": "compose-demo-manifest-v1",
  "challenge_id": challenge["challenge_id"],
  "challenge": challenge["challenge"],
  "nullifier": nullifier,
  "eligibility_proof": {
    "credential_pub": credential_pub,
    "proof_blob": "demo-proof"
  },
  "encrypted_ballot": {
    "ballot_id": "ballot-demo-1",
    "ciphertext": ciphertext,
    "ballot_hash": ballot_hash,
    "wrapped_ballot_key": "wrapped-key-demo",
    "wrapped_ballot_key_epk": "wrapped-epk-demo"
  }
}
print(json.dumps(payload))
PY

CAST_JSON=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/election/cast" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MACHINE_TOKEN" \
  --data-binary "@$CAST_FILE")
echo "Ballot cast"

VERIFY_FILE="$ROOT_DIR/.tmp-verify.json"
python3 <<'PY' "$CAST_JSON" > "$VERIFY_FILE"
import json, sys
cast = json.loads(sys.argv[1])
print(json.dumps({"receipt": cast["cast_receipt"]}))
PY
curl -fsS -X POST "http://127.0.0.1:8080/v1/election/verify" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MACHINE_TOKEN" \
  --data-binary "@$VERIFY_FILE" >/dev/null
echo "Receipt verified"

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

for _ in $(seq 1 30); do
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

INGEST_FILE="$ROOT_DIR/.tmp-ingest.json"
python3 <<'PY' "$HOST_BUNDLE_PATH" > "$INGEST_FILE"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    bundle = json.load(f)
print(json.dumps({"bundle": bundle}))
PY

curl -fsS -X POST "http://127.0.0.1:8182/v1/ingest/bundle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRGAP_INGEST_TOKEN" \
  --data-binary "@$INGEST_FILE" >/dev/null

echo "Bundle ingested to airgap ingest"

echo "Waiting for airgap relay to publish to airgap ledger nodes..."
sleep 8

curl -fsS "http://127.0.0.1:8401/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8402/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8403/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8382/v1/observer/status" >/dev/null

curl -fsS -X POST "http://127.0.0.1:8181/v1/ingest/bundle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  --data-binary "@$INGEST_FILE" >/dev/null

echo "Bundle ingested"

echo "Waiting for relay to publish to ledger nodes..."
sleep 8

curl -fsS "http://127.0.0.1:8301/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8302/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8303/v1/ledger/entries/1" >/dev/null
curl -fsS "http://127.0.0.1:8282/v1/observer/status" >/dev/null

echo "Smoke test passed: airgap + central flow and blockchain replication succeeded."

rm -f "$MANIFEST_FILE" "$CAST_FILE" "$VERIFY_FILE" "$INGEST_FILE"
