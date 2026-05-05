#!/usr/bin/env bash
# Fails the build if any existing storage slot in BridgeEscrow moves.
# Run as part of CI (before any upgrade) to enforce append-only storage.
#
# `astId` values are non-deterministic — they reflect the AST node id Solidity
# assigned during compilation, which depends on file ordering / cache state /
# compiler version. Two semantically-identical builds produce different
# astIds. We strip them via jq before comparison so the gate enforces the
# meaningful invariant (slot, offset, label, type) and ignores ABI-level noise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SNAPSHOT="$ROOT_DIR/storage-layout.json"
TMP_FRESH="$(mktemp)"
TMP_FRESH_NORM="$(mktemp)"
TMP_SNAP_NORM="$(mktemp)"
trap 'rm -f "$TMP_FRESH" "$TMP_FRESH_NORM" "$TMP_SNAP_NORM"' EXIT

if [[ ! -f "$SNAPSHOT" ]]; then
  echo "error: snapshot missing at $SNAPSHOT — commit one with 'forge inspect BridgeEscrow storageLayout --json > storage-layout.json'" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required for the storage-layout gate (apt install jq)" >&2
  exit 1
fi

cd "$ROOT_DIR"
forge inspect BridgeEscrow storageLayout --json > "$TMP_FRESH"

# Drop astId from every storage entry — only the slot/offset/label/type
# matter for upgrade compatibility. Keep deterministic key ordering with
# `--sort-keys` so the diff stays meaningful.
NORMALIZE='walk(if type == "object" and has("astId") then del(.astId) else . end)'
jq --sort-keys "$NORMALIZE" "$SNAPSHOT" > "$TMP_SNAP_NORM"
jq --sort-keys "$NORMALIZE" "$TMP_FRESH" > "$TMP_FRESH_NORM"

if ! diff -q "$TMP_SNAP_NORM" "$TMP_FRESH_NORM" >/dev/null; then
  echo "error: BridgeEscrow storage layout changed." >&2
  diff -u "$TMP_SNAP_NORM" "$TMP_FRESH_NORM" >&2 || true
  echo >&2
  echo "If this change APPENDS a new field at the bottom (allowed), refresh the snapshot:" >&2
  echo "  forge inspect BridgeEscrow storageLayout --json > storage-layout.json" >&2
  echo "If it MOVES or CHANGES an existing slot, STOP — that breaks upgrade compatibility." >&2
  exit 1
fi

echo "storage-layout OK"
