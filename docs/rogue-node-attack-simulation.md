# Rogue Node Attack Simulation

This document shows two ways a rogue-node attempt is detected.

## Run it end-to-end

```bash
./scripts/simulate-rogue-node-attack.sh
```

The script writes report artifacts to:

- `deployments/compose/reports/rogue-node-attack-*.json`
- `deployments/compose/reports/rogue-node-attack-*.md`

## 1) Unauthorized relay role injection (startup block)

Attempt: add `role: "rogue"` to relay config.

Expected result: relay refuses to start during config validation.

Example:

```bash
go run ./cmd/votechain-anchor-relay -config /tmp/relay-rogue.yaml
```

Output:

```text
config error: nodes[3].role must be one of federal|state|oversight
```

## 2) Trusted role spoof with wrong ACK key id (runtime catch)

Attempt: keep allowed roles, but set wrong `ack_key_id` for one role (for example `federal`) and require all 3 ACKs.

Expected result:

1. Relay cannot count spoofed ACK.
2. Outbox event is marked retry with explicit error.
3. Observer shows `outbox_pending > 0` (`overall: degraded`) until a valid relay recovers.

Example DB evidence:

```sql
SELECT id, status, attempts, last_error
FROM anchor_outbox
ORDER BY id DESC
LIMIT 1;
```

Sample `last_error`:

```text
federal:ack key id mismatch: got ed25519:9d8a7d8ed1dcf6e4 want ed25519:0000000000000000
```

## Why this works

- Relay node roles are fixed and validated: `federal|state|oversight`.
- Relay ACKs are verified against pinned public keys and expected key IDs.
- Failed ACK verification is not counted toward quorum.
- Observer/outbox metrics surface failures operationally.
