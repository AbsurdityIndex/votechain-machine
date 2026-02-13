# Releasing votechain-machine

## 1) Local release validation

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
gofmt -l $(find . -name '*.go' -not -path './.git/*') | tee /tmp/gofmt.out && [ ! -s /tmp/gofmt.out ]

./scripts/generate-compose-env.sh .env
./scripts/compose-smoke.sh
```

## 2) Artifact verification

```bash
./scripts/build-pi.sh
./scripts/build-release.sh
```

Validate generated artifacts are versioned and reproducible.

## 3) Release execution

1. Ensure all hardening and simulation scripts pass in a clean workspace.
2. Tag the commit from `main` (`git tag vX.Y.Z`) and push.
3. Publish checksums and release notes derived from `CHANGELOG.md`.
4. Record compose and image version compatibility in a release note.

## 4) Post-release

- Archive demo reports from `deployments/compose/reports`.
- Rotate example compose keys and demo tokens.
- Verify changelog and incident/hardening docs for any migration notes.

## 5) Runtime change checklist

- Smoke endpoints for machine services:
  - `/healthz` on each service
  - `/v1/observer/status`
  - `/v1/ledger/entries/0` on each ledger role

- If deployment or compose topology changed:
  - Verify service restart behavior.
  - Re-run `./scripts/compose-smoke.sh` against a clean compose stack.
