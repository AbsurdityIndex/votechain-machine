# Hardening Checklist

This checklist is for production deployment readiness of polling-place and ingest services.

## Platform hardening

- Use dedicated Linux users (`votechain`) with `nologin` shell.
- Enforce full-disk encryption on polling-place devices and ingest hosts.
- Restrict SSH to admin network with hardware-backed admin keys.
- Disable password auth, root login, and unused services.
- Enable automatic security updates and kernel patch cadence.

## Database hardening

- Run PostgreSQL locally on polling-place devices with local socket or loopback only.
- Use separate databases/roles for machine and ingest.
- Apply least-privilege role permissions.
- Enable PITR backups for ingest DB.
- Encrypt backups at rest and in transit.

## Key management

- Generate unique Ed25519 signing keypair per polling-place machine.
- Store private keys under restricted ACLs.
- Rotate keys between election cycles.
- Maintain signed machine registry distribution workflow.
- Validate key ID in manifests and ingest registry.
- Enforce one machine ID per unique key ID (no shared machine signing keys).

## Network hardening

- Polling place: no outbound internet during voting operations.
- Enforce zone segmentation between polling-place airgap services and central services.
- Keep airgap and central database planes isolated.
- Ingest API behind private network or mTLS reverse proxy.
- Keep bearer token secret in vault/secret manager.
- Enable IP allow list for ingest API.
- Add upstream WAF/rate controls if exposed beyond private network.

## Application hardening

- Keep strict JSON decoding enabled.
- Keep request body limits enabled.
- Reject multi-object/trailing-token JSON request bodies.
- Keep idempotency and uniqueness DB constraints enabled.
- Keep cast retry recovery-by-challenge enabled for idempotent replay safety.
- Keep transactional cast flow enabled (challenge + leaf + sth + receipt in one transaction).
- Keep constant-time secret token checks for write/auth tokens.
- Enforce ledger event-id conflict checks (same id cannot map to different payload).
- Keep HTTP server limits set (`ReadHeaderTimeout`, `IdleTimeout`, `MaxHeaderBytes`).
- Keep export directory and bundle files on restricted permissions.
- Monitor failed verification checks and unauthorized attempts.
- Track anchor outbox lag and retry failures.
- Verify relay ACK signatures with pinned ledger node public keys.
- Restrict relay node roles to fixed allow-list (`federal|state|oversight`) and reject duplicate/missing roles.

## Operational controls

- Rotate compose/dev tokens and keys before any external demo (`./scripts/generate-compose-env.sh` at minimum).
- Record chain-of-custody for removable media bundle transfer.
- Require dual-control for ingest approvals in election operations.
- Test restore/recovery path before election day.
- Run pre-election dry runs for end-to-end bundle ingest.
- Run post-election integrity audits on ingest hash chain.
