# Compose Stack

This stack runs a zoned VoteChain runtime locally with explicit trust boundaries:

- Airgap zone:
  - 5 polling-place machine services
  - Airgap ingest API
  - Airgap relay worker
  - 3 airgap ledger nodes (federal/state/oversight)
  - Airgap observer API
  - Airgap PostgreSQL
- Central zone:
  - Central ingest API
  - Central relay worker
  - 3 central ledger nodes (federal/state/oversight)
  - Central observer API
  - Central PostgreSQL

## Security defaults

- App containers run with read-only root filesystem.
- `no-new-privileges` and `cap_drop: [ALL]` are enabled on app services.
- Airgap and central services are on separate docker bridge networks.
- PostgreSQL services are internal-only (no host-exposed port mappings).
- Compose secrets are loaded from `.env` and expanded at runtime in service configs.
- Compose Dockerfile builds are architecture-aware for `amd64` and `arm64`.

## Start

```bash
./scripts/generate-compose-env.sh
docker compose up -d --build
```

## Start (strict operator mode)

Use this mode to run with no host API port exposure and internal-only compose networks.

```bash
docker compose -f ./docker-compose.yml -f ./docker-compose.strict.yml up -d --build
```

Validate strict mode:

```bash
docker compose -f ./docker-compose.yml -f ./docker-compose.strict.yml config | rg "published:" || true
docker network inspect votechain_airgap_net | jq '.[0].Internal'
docker network inspect votechain_central_net | jq '.[0].Internal'
```

## Stop

```bash
docker compose down
```

## Services

- Machine APIs: `http://127.0.0.1:8080..8084`
- Airgap ingest API: `http://127.0.0.1:8182`
- Central ingest API: `http://127.0.0.1:8181`
- Airgap observer API: `http://127.0.0.1:8382`
- Central observer API: `http://127.0.0.1:8282`
- Airgap ledger nodes: `http://127.0.0.1:8401..8403`
- Central ledger nodes: `http://127.0.0.1:8301..8303`

## End-to-end smoke

```bash
./scripts/compose-smoke.sh
```

The smoke test performs:

1. Load election manifest on machine.
2. Issue challenge and cast ballot.
3. Verify receipt and close polls.
4. Ingest exported bundle into airgap ingest.
5. Relay to airgap ledger nodes and verify.
6. Transfer same bundle into central ingest.
7. Relay to central ledger nodes and verify.
8. Query both observer status endpoints.

## Working group run

```bash
./scripts/demo-working-group.sh --voters 30 --session wg-demo
```

## Multi-machine cycle run

```bash
./scripts/run-mock-election-cycle.py --machines 5 --sessions-per-machine 100 --spoil-rate 0.12
```

This run:

1. Generates mock election session data (500 sessions total by default).
2. Runs 100 sessions per machine across 5 polling-place machine services.
3. Allows random spoiled sessions.
4. Resets each machine local state after each session.
5. Ingests each exported bundle into both airgap and central ingest.
6. Waits for both relay outboxes to drain.
7. Verifies both airgap and central ledger-node consistency.

## Independent signed audit

After a cycle run completes, execute:

```bash
go run ./cmd/votechain-audit-verify \
  -dataset ./deployments/compose/reports/mock-election-data-<STAMP>.json \
  -run-report ./deployments/compose/reports/mock-election-run-<STAMP>.json
```

This verifier independently checks:

1. Bundle signature/integrity against machine registry identities.
2. Bundle/receipt counts vs expected spoiled/non-spoiled sessions.
3. Observer outbox state and ledger-node index/hash consistency.
4. Winner tally from the generated mock election dataset.
5. Signed audit report output (`deployments/compose/reports/mock-election-audit-*.json`).

## Duplicate-attempt capture

```bash
./scripts/simulate-ballot-box-duplicates.py --force-machine-bypass-on-duplicate
```

This simulation captures:

1. Ballot-box verification decisions (`allowed`, `denied_not_registered`, `denied_duplicate_checkin`).
2. Machine rejections when duplicate attempts are force-forwarded (`EWP_NULLIFIER_USED`).
3. Final report artifacts in `deployments/compose/reports/duplicate-attempts-report-*.json|.md`.

## Rogue-node attack simulation

```bash
./scripts/simulate-rogue-node-attack.sh
```

This simulation captures:

1. Startup rejection of an unauthorized relay node role (`rogue`).
2. Runtime ACK-key spoof detection with `required_acks=3` and one invalid pinned key ID.
3. Outbox pending/degraded observer evidence during attack and relay recovery evidence after restoration.
