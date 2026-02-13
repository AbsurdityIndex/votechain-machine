# Air-Gapped Polling Place Architecture

This runtime is intended for polling-place Raspberry Pi devices that operate disconnected during voting while still integrating with server-side VoteChain systems.

## Polling-place trust boundary

The machine runtime and in-airgap services handle local polling-place responsibilities:

- election manifest load (pre-election)
- voter challenge issue
- ballot cast and receipt issuance
- local append-only bulletin board + signed tree heads
- local receipt verification
- poll close and signed export bundle generation
- in-airgap ingest validation of exported bundles
- in-airgap relay anchoring into in-airgap ledger nodes

No live dependency on central infrastructure is required while voting is in progress.

## In-airgap anchor boundary

The polling-place zone includes an in-airgap anchor plane:

1. Polling place closes polls with `POST /v1/election/close`.
2. Runtime writes signed bundle JSON to local export directory.
3. Bundle is ingested by in-airgap ingest (`votechain-airgap-ingest`).
4. In-airgap relay anchors verified events to in-airgap ledger nodes.
5. Airgap observer verifies outbox drain and ledger consistency.

No connectivity to central infrastructure is required for these steps.

## Server-plane integration boundary

Integration with upstream server architecture is through signed bundle transfer:

1. Signed bundle is transferred with chain-of-custody controls to central systems.
4. Server-side ingest validates:
   - bundle signature
   - bundle integrity hash
   - receipt signatures
   - Merkle consistency and ballot/receipt counts
5. Validated artifacts are anchored into consortium/server infrastructure.

## Why PostgreSQL locally

Polling-place runtime uses PostgreSQL rather than SQLite to support:

- stronger operational controls (roles, backups, tooling)
- stricter transaction handling and visibility
- consistency with server-side data platform practices

## Failure model

- During election hours: machine remains functional without network.
- If export transfer is delayed: polling-place record is preserved locally with signed artifacts.
- Verification can be done locally from receipts and local BB state before central ingest.
