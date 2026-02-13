# Releasing votechain-machine

## 1) Local release validation

```bash
go test ./...
go vet ./...
go build ./cmd/...

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

