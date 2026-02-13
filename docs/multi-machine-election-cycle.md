# Multi-Machine Session Cycle

This flow runs a mock election with:

- 5 polling-place machine services
- 100 voter sessions per machine (500 total sessions)
- Random spoiled sessions
- Per-session machine reset
- End-of-run integrity verification across airgap + central ingest and ledger nodes

```mermaid
flowchart LR
  A["Mock Data Generator<br/>500 sessions, spoil flags, selections"] --> B["Session Runner"]
  B --> C1["Machine 1 API<br/>100 sessions"]
  B --> C2["Machine 2 API<br/>100 sessions"]
  B --> C3["Machine 3 API<br/>100 sessions"]
  B --> C4["Machine 4 API<br/>100 sessions"]
  B --> C5["Machine 5 API<br/>100 sessions"]

  subgraph SessionFlow["Per Session (on one machine)"]
    S1["Load Election Manifest"] --> S2{"Spoiled?"}
    S2 -- "No" --> S3["Issue Challenge"]
    S3 --> S4["Cast Ballot"]
    S4 --> S5["Verify Receipt"]
    S2 -- "Yes" --> S6["No Cast (Spoiled Session)"]
    S5 --> S7["Close Polls + Export Bundle"]
    S6 --> S7
    S7 --> S8["Ingest Bundle (Airgap)"]
    S8 --> S9["Transfer + Ingest Bundle (Central)"]
    S9 --> S10["Reset Machine Local State"]
  end

  C1 --> S1
  C2 --> S1
  C3 --> S1
  C4 --> S1
  C5 --> S1

  S8 --> AI["Airgap Ingest DB<br/>bundles, receipts, outbox"]
  AI --> AR["Airgap Anchor Relay"]
  AR --> AL1["Airgap Ledger Federal"]
  AR --> AL2["Airgap Ledger State"]
  AR --> AL3["Airgap Ledger Oversight"]

  S9 --> I["Central Ingest DB<br/>bundles, receipts, outbox"]
  I --> R["Central Anchor Relay"]
  R --> L1["Central Ledger Federal"]
  R --> L2["Central Ledger State"]
  R --> L3["Central Ledger Oversight"]

  L1 --> V["Final Verifier"]
  L2 --> V
  L3 --> V
  AL1 --> V
  AL2 --> V
  AL3 --> V
  I --> V
  AI --> V
  V --> O["Result Report<br/>expected vs observed"]
```

### Text fallback

```text
generate sessions -> run per machine -> cast workflow -> export bundle
-> airgap ingest -> central ingest -> relays -> ledgers -> verifier
```

## Verification signals

- `ingest_bundles` count equals total sessions (`500`).
- `ingest_receipts` count equals non-spoiled sessions.
- Airgap and central `anchor_outbox` pending counts are both `0`.
- Airgap and central ledger latest index on all three nodes are each equal and at least bundle count.
- Airgap and central ledger latest hash on all three nodes are each identical.
- Cast/verify success count equals non-spoiled sessions.
