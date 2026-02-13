# Release Branch Demo Checklist

This checklist is the release gate for a public demo branch.

All commands assume:

```bash
cd "$(git rev-parse --show-toplevel)"
```

## 1. Baseline validation

```bash
go test ./...
python3 -m py_compile \
  ./scripts/run-mock-election-cycle.py \
  ./scripts/simulate-ballot-box-duplicates.py
```

Expected output:

- `go test` exits `0`.
- Python compile exits `0` with no traceback.

## 2. Demo mode stack (host APIs exposed)

```bash
./scripts/generate-compose-env.sh
docker compose down -v --remove-orphans
docker compose up -d --build
docker compose ps
```

Expected output:

- `votechain-machine` through `votechain-machine-5` are `Up`.
- API port mappings exist (`8080..8084`, `8181`, `8182`, `8282`, `8382`, `8301..8303`, `8401..8403`).

## 3. Election cycle run #1 (5x100, random spoils)

```bash
./scripts/run-mock-election-cycle.py \
  --machines 5 \
  --sessions-per-machine 100 \
  --spoil-rate 0.12 \
  --seed 20260211
```

Expected output:

- prints `run_report_json:...mock-election-run-<STAMP>.json`
- printed JSON includes `"verification_passed": true`

## 4. Election cycle run #2 (repeatability check)

```bash
./scripts/run-mock-election-cycle.py \
  --machines 5 \
  --sessions-per-machine 100 \
  --spoil-rate 0.12 \
  --seed 20260212
```

Expected output:

- prints `run_report_json:...mock-election-run-<STAMP>.json`
- printed JSON includes `"verification_passed": true`

## 5. Duplicate-vote simulation

```bash
./scripts/simulate-ballot-box-duplicates.py --force-machine-bypass-on-duplicate
LATEST_DUP="$(ls -1t ./deployments/compose/reports/duplicate-attempts-report-*.json | head -n1)"
jq -e '
  .summary.machine_rejected_nullifier_used > 0 and
  .summary.machine_rejected_nullifier_used == .summary.ballot_box_denied_duplicate_checkin and
  .summary.machine_rejected_other == 0
' "$LATEST_DUP"
```

Expected output:

- `jq` prints `true` and exits `0`.

## 6. Rogue-node simulation

```bash
./scripts/simulate-rogue-node-attack.sh
LATEST_ROGUE="$(ls -1t ./deployments/compose/reports/rogue-node-attack-*.json | head -n1)"
jq -e '
  .overall_pass == true and
  .scenario_startup_role_validation.detected == true and
  .scenario_runtime_ack_spoof.detected == true and
  .recovery.restored == true
' "$LATEST_ROGUE"
```

Expected output:

- `jq` prints `true` and exits `0`.

## 7. Independent signed audit verification

```bash
LATEST_RUN="$(ls -1t ./deployments/compose/reports/mock-election-run-*.json | head -n1)"
LATEST_DATA="$(ls -1t ./deployments/compose/reports/mock-election-data-*.json | head -n1)"
go run ./cmd/votechain-audit-verify \
  -dataset "$LATEST_DATA" \
  -run-report "$LATEST_RUN"
```

Expected output:

- prints `audit_report:...mock-election-audit-<STAMP>.json`
- prints `verification_passed:true`

## 8. Strict mode stack (no host API exposure)

```bash
docker compose down -v --remove-orphans
docker compose -f ./docker-compose.yml -f ./docker-compose.strict.yml up -d --build
docker compose -f ./docker-compose.yml -f ./docker-compose.strict.yml config | rg "published:" || true
docker network inspect votechain_airgap_net | jq '.[0].Internal'
docker network inspect votechain_central_net | jq '.[0].Internal'
```

Expected output:

- `rg "published:"` prints nothing.
- both `docker network inspect ... Internal` commands print `true`.

## 9. Final release assertions

```bash
LATEST_RUN="$(ls -1t ./deployments/compose/reports/mock-election-run-*.json | head -n1)"
LATEST_AUDIT="$(ls -1t ./deployments/compose/reports/mock-election-audit-*.json | head -n1)"
LATEST_ROGUE="$(ls -1t ./deployments/compose/reports/rogue-node-attack-*.json | head -n1)"

jq -e '.summary.verification_passed == true' "$LATEST_RUN"
jq -e '.summary.verification_passed == true' "$LATEST_AUDIT"
jq -e '.overall_pass == true' "$LATEST_ROGUE"
```

Expected output:

- all three `jq` commands print `true` and exit `0`.
