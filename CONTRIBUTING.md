# Contributing to votechain-machine

Thank you for your interest in `votechain-machine`.

## Ways to contribute

- **Report bugs** — open an issue describing the failure mode and reproduction commands.
- **Request improvements** — open an issue with concrete acceptance criteria.
- **Submit code** — fork the repo, make the change, and open a pull request.
- **Improve reliability and security** — this repository is especially sensitive to correctness, so reviews in these areas are highly valued.
- **Improve documentation** — docs and operations flow quality are part of protocol quality.

## Development setup

```bash
git clone https://github.com/AbsurdityIndex/votechain-machine.git
cd votechain-machine
git lfs install
go version   # build requires 1.23+ for this module
```

Before running service code, create a local `.env` from `.env.example`:

```bash
cp .env.example .env
```

Use `scripts/generate-compose-env.sh` to produce production-like credentials for demo and local compose flows.

## Pull request workflow

1. Open a focused issue (or draft PR) before large changes.
2. Create a descriptively named branch from `main`.
3. Keep each PR scoped to one change.
4. Include tests or validation and operational checks where practical.
5. Ensure docs are updated if scripts, compose topology, or API behavior changes.
6. Use clear PR summaries and link to related security/architectural rationale.

## Validation checklist

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `go build ./cmd/...`
- [ ] Targeted simulation scripts run from the affected area (for orchestration and verification changes).
- [ ] `docker compose down -v --remove-orphans && docker compose up -d --build` when stack topology changes.

If your PR changes protocol-relevant behavior, include a short threat-model note in the PR description.

## Code style

- Keep code simple and explicit.
- Run `gofmt` on touched Go files.
- Keep scripts readable and avoid hardcoded workstation paths.

## Security and protocol changes

Security/cryptographic changes should include:

- A brief rationale in the PR description.
- Any new assumptions or trust-boundary changes.
- Explicit mention of compatibility implications.
- A request for review by an area owner.

## Reporting security issues

Do **not** open public issues for vulnerabilities.
Use the process in [`SECURITY.md`](./SECURITY.md).

