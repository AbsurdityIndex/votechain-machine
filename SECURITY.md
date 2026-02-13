# Security Policy

## Scope

`votechain-machine` implements hardened runtime and operations code for voting workflows.
It is a research and operational prototype and is not guaranteed to meet any jurisdictional election certification framework.

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | Yes |
| Older commits | No |

## Reporting vulnerabilities

If you discover a security issue, report it privately. **Do not open a public issue.**

1. Email **security@absurdityindex.org** with:
   - A clear description of the issue
   - Steps to reproduce or a PoC
   - Affected component (machine service, relay, ingest, ledger, observer, scripts, docs)
   - Severity estimate and impact

2. We will acknowledge within 72 hours.
3. We will coordinate triage and remediation before public disclosure.

## What we prioritize

- Key management failures (storage, signing, rotation, registry trust)
- Tampering or replay in cast, close, ingest, or relay flows
- Service auth and role/authorization bypasses
- Secret leakage (tokens, DB credentials, chain keys)
- Data integrity failures in audit chains and outbox relays
- Missing or weak threat-model assumptions in consensus-like flows

## What is out of scope

- Issues limited to local non-networked demo environments with no real trust guarantees
- Non-security UX complaints in demo-only scripts
- Dependabot/update noise in CI pipelines unless it changes security posture

## What does not qualify

- Cosmetic issues not affecting integrity or trust boundaries
- Performance tuning in non-production demo loads unless it impacts safety

## Disclosure process

We aim to provide a remediation plan within 90 days.
Where protocol changes are required, we will include rationale in release notes and advisory notes.

## Acknowledgments

Security reporters are credited in release notes and advisories when they opt in.
