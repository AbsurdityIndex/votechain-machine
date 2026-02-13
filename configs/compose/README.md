# Compose Config Notes

These files are for local full-stack orchestration across airgap and central zones.

- Secrets are loaded from environment variables in `.env`.
- Generate local secrets with `./scripts/generate-compose-env.sh`.
- Do not commit real `.env` values or key material.
- Each polling-place machine service uses its own signing keypair in compose.
- Compose runs two isolated bridge networks (`votechain_airgap_net`, `votechain_central_net`).
- Strict operator mode uses `docker-compose.strict.yml` to remove host port publications and set both compose networks `internal: true`.
- Compose build supports host-native `arm64` and `amd64` image builds.
