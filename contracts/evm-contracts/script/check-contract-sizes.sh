#!/usr/bin/env bash
#
# EIP-170 size gate — scoped to DEPLOYABLE production contracts.
#
# `forge build --sizes` fails on ANY artifact over the 24,576-byte runtime
# limit, including test-only mocks. `TestableBridgeEscrow` and the upgrade
# mocks inherit the FULL production BridgeEscrow plus extra hooks, so they
# ride right on the optimizer's edge: a one-line change to prod can swing the
# derived mock's bytecode by hundreds of bytes and trip the gate even when the
# real contract shrank. Those mocks are never deployed to a live chain, so
# EIP-170 simply does not apply to them.
#
# This gate enforces the limit only on contracts DECLARED under `src/`
# (the deployable surface — BridgeEscrow, VestingVault, WrappedERC20, the
# deposit-vault/factory, etc.). A genuine production overflow still fails CI.
set -euo pipefail

LIMIT=24576

# Human-readable table for the CI log (don't let its exit code abort us).
forge build --sizes || true

# Machine-readable sizes for the gate. `--sizes` makes forge exit non-zero
# when ANY artifact is over the limit (including the mocks we mean to ignore);
# the JSON is still written to stdout first, and our jq pass below is the real
# authority, so swallow that exit code here.
forge build --sizes --json > sizes.json || true

# Names of every contract DECLARED in src/ (line-anchored so the word
# "contract" inside comments/strings is not matched; interfaces/libraries are
# intentionally excluded — they are not deployable on their own).
src_names="$(grep -rhoE '^[[:space:]]*(abstract[[:space:]]+)?contract[[:space:]]+[A-Za-z0-9_]+' \
  src --include='*.sol' | awk '{print $NF}' | sort -u)"

over="$(jq -r --argjson lim "$LIMIT" \
  'to_entries[] | select(.value.runtime_size > $lim) | .key' sizes.json)"

fail=0
if [ -n "$over" ]; then
  while IFS= read -r c; do
    [ -z "$c" ] && continue
    size="$(jq -r --arg k "$c" '.[$k].runtime_size' sizes.json)"
    if grep -qxF "$c" <<< "$src_names"; then
      echo "::error::production contract ${c} exceeds EIP-170: ${size} B (limit ${LIMIT})"
      fail=1
    else
      echo "note: test/mock contract ${c} is ${size} B (> ${LIMIT}) — ignored (never deployed)"
    fi
  done <<< "$over"
fi

if [ "$fail" -eq 0 ]; then
  echo "EIP-170 OK: all deployable src/ contracts are within ${LIMIT} bytes."
fi
exit "$fail"
