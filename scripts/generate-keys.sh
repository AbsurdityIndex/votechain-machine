#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./keys}"
mkdir -p "$OUT_DIR"

openssl genpkey -algorithm Ed25519 -out "$OUT_DIR/machine-signing-private.pem"
openssl pkey -in "$OUT_DIR/machine-signing-private.pem" -pubout -out "$OUT_DIR/machine-signing-public.pem"

echo "Generated keys:"
ls -l "$OUT_DIR"/machine-signing-*.pem
