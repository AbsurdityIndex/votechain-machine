# votechain-machine

Open-source VoteChain runtime for polling-place devices, central ingest, and blockchain anchoring.
Companion repo to [votechain](https://github.com/AbsurdityIndex/votechain), containing production-style runtime code, hardened operations playbooks, and compose-based deployment flows.

## Services in this repo

- `votechain-machine`: air-gapped polling-place runtime (Raspberry Pi target).
- `votechain-airgap-ingest` (compose profile): in-airgap bundle verification + ingest API.
- `votechain-airgap-anchor-relay` (compose profile): in-airgap relay to in-airgap ledger nodes.
- `votechain-airgap-ledger-*` (compose profile): in-airgap replicated ledger nodes.
- `votechain-ingest`: central verification + ingest API for signed export bundles.
- `votechain-ingest-file`: offline CLI ingest path for bundle files.
- `votechain-ledger-node`: blockchain ledger node runtime (federal/state/oversight roles).
- `votechain-anchor-relay`: worker that relays verified ingest outbox events to ledger nodes.
- `votechain-observer`: read-only demo/working-group status and consistency API.

## Architecture split

- Polling place (`votechain-machine`): runs offline during voting, stores ballots locally, emits signed receipts, and exports signed bundles at close.
- In-airgap anchor plane (`votechain-airgap-ingest` + `votechain-airgap-anchor-relay` + `votechain-airgap-ledger-*`): anchors signed bundles inside the airgap before transfer.
- Central ingest (`votechain-ingest`): validates transferred bundle signatures/integrity, persists audited records, and writes anchor events to outbox.
- Central blockchain layer (`votechain-ledger-node` x3 + `votechain-anchor-relay`): append-only replicated ledger entries with quorum acknowledgements.

See [`docs/air-gapped-polling-place-architecture.md`](./docs/air-gapped-polling-place-architecture.md).

## Core hardening controls

- PostgreSQL-only persistence (no SQLite).
- Transactional cast finalization (challenge lock/use, leaf append, STH, receipt persistence in one DB transaction).
- Strict JSON decoding and bounded request size.
- Idempotency + uniqueness constraints for cast flow and ingest flow.
- Idempotent cast recovery by challenge on retry races.
- Signed receipts, signed tree heads, signed bundles.
- Merkle consistency/inclusion verification during ingest.
- Trusted machine registry for public key verification.
- Ingest auth boundaries: bearer token + CIDR allow list.
- Constant-time secret token verification for ingest/ledger writes.
- Transactional ingest and tamper-evident ingest hash chaining.
- Relay outbox with retry/backoff and quorum ACK requirements.
- Relay ACK signature verification against trusted ledger node public keys.
- Ledger event-id conflict detection (same event id with different payload is rejected).
- Hardened HTTP servers (`ReadHeaderTimeout`, `IdleTimeout`, `MaxHeaderBytes`).
- Restricted bundle/export permissions (directory `0700`, bundle file `0600`).
- Compose service hardening defaults (`read_only`, `no-new-privileges`, `cap_drop`).
- Wide canonical structured logs.

## APIs

### Polling-place API (`votechain-machine`)

- `GET /healthz`
- `POST /v1/election/load`
- `POST /v1/election/challenge`
- `POST /v1/election/cast`
- `POST /v1/election/verify`
- `POST /v1/election/close`

### Central ingest API (`votechain-ingest`)

- `GET /healthz`
- `POST /v1/ingest/bundle`

### Ledger node API (`votechain-ledger-node`)

- `GET /healthz`
- `POST /v1/ledger/append`
- `GET /v1/ledger/entries/{index}`

### Observer API (`votechain-observer`)

- `GET /healthz`
- `GET /v1/observer/status`
- `GET /v1/observer/report`

## Compose: full stack (machine + ingest + blockchain)

[`docker-compose.yml`](./docker-compose.yml) brings up:

- `postgres-airgap`
- `postgres-central`
- `votechain-machine`
- `votechain-machine-2`
- `votechain-machine-3`
- `votechain-machine-4`
- `votechain-machine-5`
- `votechain-airgap-ingest`
- `votechain-airgap-anchor-relay`
- `votechain-airgap-observer`
- `airgap-ledger-federal`
- `airgap-ledger-state`
- `airgap-ledger-oversight`
- `votechain-ingest`
- `votechain-anchor-relay`
- `votechain-observer`
- `ledger-federal`
- `ledger-state`
- `ledger-oversight`

Both PostgreSQL services are internal-only and are not host-exposed.

Start stack:

```bash
./scripts/generate-compose-env.sh
docker compose up -d --build
```

Start strict operator stack (no host-exposed API ports):

```bash
docker compose -f ./docker-compose.yml -f ./docker-compose.strict.yml up -d --build
```

Run full smoke flow (load election -> cast -> close -> ingest -> relay to blockchain):

```bash
./scripts/compose-smoke.sh
```

Run public working-group demo flow (multi-voter + report artifacts):

```bash
./scripts/demo-working-group.sh --voters 30 --session wg-demo
```

Run full multi-machine session cycle (5 machines x 100 sessions, random spoils, verification):

```bash
./scripts/run-mock-election-cycle.py --machines 5 --sessions-per-machine 100 --spoil-rate 0.12
```

Run independent signed audit verification for a completed cycle:

```bash
go run ./cmd/votechain-audit-verify \
  -dataset ./deployments/compose/reports/mock-election-data-<STAMP>.json \
  -run-report ./deployments/compose/reports/mock-election-run-<STAMP>.json
```

Simulate ballot-box duplicate-vote attempts and capture machine-side rejections:

```bash
./scripts/simulate-ballot-box-duplicates.py --force-machine-bypass-on-duplicate
```

Simulate rogue-node attacks and capture startup/runtime detection evidence:

```bash
./scripts/simulate-rogue-node-attack.sh
```

Compose config files:

- [`configs/compose/polling-place.yaml`](./configs/compose/polling-place.yaml)
- [`configs/compose/polling-place-2.yaml`](./configs/compose/polling-place-2.yaml)
- [`configs/compose/polling-place-3.yaml`](./configs/compose/polling-place-3.yaml)
- [`configs/compose/polling-place-4.yaml`](./configs/compose/polling-place-4.yaml)
- [`configs/compose/polling-place-5.yaml`](./configs/compose/polling-place-5.yaml)
- [`configs/compose/ingest.yaml`](./configs/compose/ingest.yaml)
- [`configs/compose/relay.yaml`](./configs/compose/relay.yaml)
- [`configs/compose/ledger-federal.yaml`](./configs/compose/ledger-federal.yaml)
- [`configs/compose/ledger-state.yaml`](./configs/compose/ledger-state.yaml)
- [`configs/compose/ledger-oversight.yaml`](./configs/compose/ledger-oversight.yaml)
- [`configs/compose/machine-registry.yaml`](./configs/compose/machine-registry.yaml)
- [`configs/compose/observer.yaml`](./configs/compose/observer.yaml)
- [`configs/compose/airgap-ingest.yaml`](./configs/compose/airgap-ingest.yaml)
- [`configs/compose/airgap-relay.yaml`](./configs/compose/airgap-relay.yaml)
- [`configs/compose/airgap-observer.yaml`](./configs/compose/airgap-observer.yaml)
- [`configs/compose/airgap-ledger-federal.yaml`](./configs/compose/airgap-ledger-federal.yaml)
- [`configs/compose/airgap-ledger-state.yaml`](./configs/compose/airgap-ledger-state.yaml)
- [`configs/compose/airgap-ledger-oversight.yaml`](./configs/compose/airgap-ledger-oversight.yaml)

Compose demo keys are in [`deployments/compose/keys/`](./deployments/compose/keys/). Rotate and replace before any non-demo deployment.
Rotate and replace before any non-demo deployment.

Compose includes unique signing keypairs for each polling-place machine service (`machine-1` through `machine-5`).

Architecture/cycle diagram for the multi-machine run:

- [`docs/multi-machine-election-cycle.md`](./docs/multi-machine-election-cycle.md)
- [`docs/rogue-node-attack-simulation.md`](./docs/rogue-node-attack-simulation.md)
- [`docs/release-branch-checklist.md`](./docs/release-branch-checklist.md)

## Local development (non-compose)

1. Create PostgreSQL role/databases:

```sql
CREATE USER votechain WITH PASSWORD 'change-me';
CREATE DATABASE votechain_machine OWNER votechain;
CREATE DATABASE votechain_ingest OWNER votechain;
CREATE DATABASE votechain_federal OWNER votechain;
CREATE DATABASE votechain_state OWNER votechain;
CREATE DATABASE votechain_oversight OWNER votechain;
```

2. Generate machine keys:

```bash
./scripts/generate-keys.sh ./keys
```

3. Run polling-place service:

```bash
go run ./cmd/votechain-machine -config ./configs/polling-place.yaml
```

4. Run ingest service:

```bash
go run ./cmd/votechain-ingest -config ./configs/ingest.yaml
```

5. Run relay worker:

```bash
go run ./cmd/votechain-anchor-relay -config ./configs/relay.yaml
```

6. Run a ledger node:

```bash
go run ./cmd/votechain-ledger-node -config ./configs/ledger-federal.yaml
```

7. Offline file ingest:

```bash
go run ./cmd/votechain-ingest-file -config ./configs/ingest.yaml -bundle /path/to/bundle.json
```

8. Observer service:

```bash
go run ./cmd/votechain-observer -config ./configs/observer.yaml
```

## Build artifacts

Raspberry Pi machine binaries:

```bash
./scripts/build-pi.sh
```

Compose image builds are architecture-aware (arm64/amd64) via Docker `TARGETARCH`.

Full release build:

```bash
./scripts/build-release.sh
```

## Deployment assets

- Polling place systemd unit: [`deployments/raspberrypi/votechain-machine.service`](./deployments/raspberrypi/votechain-machine.service)
- Ingest systemd unit: [`deployments/ingest/votechain-ingest.service`](./deployments/ingest/votechain-ingest.service)
- Polling place install script: [`scripts/install-pi.sh`](./scripts/install-pi.sh)
- Ingest install script: [`scripts/install-ingest.sh`](./scripts/install-ingest.sh)

## Repository layout

- Service binaries: `cmd/`
- Runtime logic and handlers: `internal/`
- Service/config examples: `configs/`
- Compose deployments and platform assets: `deployments/`, `deployments/compose/`
- Operations documents and threat exercises: `docs/`
- Utility scripts: `scripts/`
- Hardening policies and CI: `.github/`, `go.mod`

## Contributing

- Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before opening PRs.
- Report vulnerabilities privately through [`SECURITY.md`](./SECURITY.md).
- Use PRs for incremental, reviewable changes with focused scope.

## Validate

```bash
go test ./...
go build ./cmd/votechain-machine
go build ./cmd/votechain-ingest
go build ./cmd/votechain-ingest-file
go build ./cmd/votechain-ledger-node
go build ./cmd/votechain-anchor-relay
go build ./cmd/votechain-observer
go build ./cmd/votechain-audit-verify
```
