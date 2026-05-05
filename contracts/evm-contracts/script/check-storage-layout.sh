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
#
# Also strip the trailing astId numbers that Solidity bakes into type names
# (e.g. `t_enum(TokenMode)47694`, `t_struct(Foo)1234_storage`,
# `t_contract(Bar)5678`, `t_userDefinedValueType(Baz)999`). These numbers
# shift between compiles based on AST node ordering and would otherwise
# break the gate even when no slot moved.
NORMALIZE='walk(if type == "object" and has("astId") then del(.astId) else . end)'
STRIP_TYPE_ASTIDS='
  s/(t_enum\([A-Za-z0-9_]+\))[0-9]+/\1/g
  s/(t_struct\([A-Za-z0-9_.]+\))[0-9]+(_storage)/\1\2/g
  s/(t_contract\([A-Za-z0-9_]+\))[0-9]+/\1/g
  s/(t_userDefinedValueType\([A-Za-z0-9_]+\))[0-9]+/\1/g
'
jq --sort-keys "$NORMALIZE" "$SNAPSHOT" | sed -E "$STRIP_TYPE_ASTIDS" > "$TMP_SNAP_NORM"
jq --sort-keys "$NORMALIZE" "$TMP_FRESH"   | sed -E "$STRIP_TYPE_ASTIDS" > "$TMP_FRESH_NORM"

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
