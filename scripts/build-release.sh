#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
mkdir -p "$OUT_DIR"

pushd "$ROOT_DIR" >/dev/null

export CGO_ENABLED=0

GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-machine-linux-arm64" ./cmd/votechain-machine
GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-machine-linux-armv7" ./cmd/votechain-machine
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-ingest-linux-amd64" ./cmd/votechain-ingest
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-ingest-linux-arm64" ./cmd/votechain-ingest
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-ingest-file-linux-amd64" ./cmd/votechain-ingest-file
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-ledger-node-linux-amd64" ./cmd/votechain-ledger-node
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-anchor-relay-linux-amd64" ./cmd/votechain-anchor-relay
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-observer-linux-amd64" ./cmd/votechain-observer
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-audit-verify-linux-amd64" ./cmd/votechain-audit-verify

echo "Built artifacts:"
ls -lh "$OUT_DIR"/votechain-*

popd >/dev/null
