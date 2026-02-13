# Working Group Demo Playbook

This playbook is for public test-election sessions and architecture working groups.

## Goal

Run a transparent test election with repeatable steps and public artifacts:

- multi-voter cast flow
- poll close + bundle export
- airgap ingest verification + airgap ledger anchoring
- central ingest verification + central ledger anchoring
- observer status/report outputs for discussion

## Run the session

1. Start stack and execute full demo workflow:

```bash
./scripts/demo-working-group.sh --voters 30 --session wg-cityhall
```

2. Open observer endpoints for participants:

- [http://127.0.0.1:8282/v1/observer/status](http://127.0.0.1:8282/v1/observer/status)
- [http://127.0.0.1:8282/v1/observer/report](http://127.0.0.1:8282/v1/observer/report)
- [http://127.0.0.1:8382/v1/observer/status](http://127.0.0.1:8382/v1/observer/status)
- [http://127.0.0.1:8382/v1/observer/report](http://127.0.0.1:8382/v1/observer/report)

3. Review generated session artifacts in:

- `deployments/compose/reports/`

## Discussion checklist

- Was every cast represented by a receipt?
- Did ingest accept exactly one bundle and expected receipt count?
- Did airgap and central outbox pending both drop to zero after relay?
- Did airgap and central blockchain nodes converge at common index/hash?
- What participant questions arose around trust boundaries and chain-of-custody?

## Boundaries

- This workflow is for demos/test elections only.
- It does not constitute election certification evidence.
