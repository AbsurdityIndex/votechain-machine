#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$ROOT_DIR/deployments/compose/keys"

for pub in "$KEY_DIR"/*-public.pem; do
  id=$(openssl pkey -pubin -in "$pub" -outform DER 2>/dev/null | tail -c 32 | openssl dgst -sha256 -binary | xxd -p -c 64 | cut -c1-16)
  echo "$(basename "$pub" .pem): ed25519:$id"
done
