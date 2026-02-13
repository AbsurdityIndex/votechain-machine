#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
mkdir -p "$OUT_DIR"

pushd "$ROOT_DIR" >/dev/null

export CGO_ENABLED=0

GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-machine-linux-arm64" ./cmd/votechain-machine
GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/votechain-machine-linux-armv7" ./cmd/votechain-machine

echo "Built:"
ls -lh "$OUT_DIR"/votechain-machine-linux-*

popd >/dev/null
