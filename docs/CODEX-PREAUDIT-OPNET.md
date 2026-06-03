# Codex Pre-Audit Review - OPNet Contracts

Scope reviewed in depth:

- `contracts/op-contracts/src/bridge/BridgeDepository.ts`
- `contracts/op-contracts/src/bridge/events.ts`
- `contracts/op-contracts/src/wrapped/WrappedOP20.ts`
- `contracts/op-contracts/src/wrapped/events.ts`
- `contracts/op-contracts/src/authority/BridgeAuthority.ts`
- `contracts/op-contracts/src/authority/events.ts`
- `contracts/op-contracts/src/lib/AmountPolicy.ts`

Trust model context read first: `CLAUDE.md` and `docs/SECURITY.md`.

## Findings

### High - Non-canonical voucher source fields can bypass the source-event replay guard

File: `contracts/op-contracts/src/bridge/BridgeDepository.ts:3636`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:3656`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:1995`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:2015`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:4147`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:4189`

Description:

`claimMintWithVoucher` and `claimReleaseWithVoucher` derive the flow id from canonicalized source fields, but build the replay key from the raw signed source fields. `_flowIdFromVoucher` truncates `sourceChainId` to `u64` and `_evmAddrRightPadToLeftPadU256` copies only the first 20 bytes of the right-padded EVM address fields. By contrast, `buildSourceEventKey` hashes the full 32-byte `sourceChainId`, `sourceBridgeAddr`, and `sourceTokenAddr` values.

This means multiple signed vouchers can name the same flow and the same source tx/log while producing distinct `_usedSourceEvents` keys. Examples:

- `sourceChainId = 1` and `sourceChainId = 2^64 + 1` both map to the same flow id via `.toU64()`, but hash to different replay keys.
- `sourceBridgeAddr` or `sourceTokenAddr` with the same first 20 bytes and non-zero bytes in the right-padding tail maps to the same flow id, but hashes to a different replay key.

The voucher comments require EVM addresses to be bytes20 right-padded with zeros, but the contract does not enforce that canonical encoding before using the raw bytes as replay material.

Exploit / impact scenario:

If the signer service signs a duplicate voucher for the same EVM deposit/burn with a non-canonical chain id or address padding alias, the OPNet contract accepts both vouchers. The `voucherId` can be different, the recomputed `flowId` still matches, and `_usedSourceEvents` does not catch the duplicate because it hashes the aliased raw bytes. This breaks the "each source event can be consumed once" invariant and can double-mint or double-release within the per-flow daily limit and token maxSupply.

Recommended fix:

Reject non-canonical source fields before computing the replay key:

- Require `parsed.sourceChainId` equals the flow's stored chain id as a full `u256`, or at least reject values above `u64::MAX` before calling `.toU64()`.
- Require bytes `[20..32)` of `parsed.sourceBridgeAddr` and `parsed.sourceTokenAddr` to be zero.
- Consider deriving `buildSourceEventKey` from canonicalized values only after these checks.
- Add the same canonicality checks in both `claimMintWithVoucher` and `claimReleaseWithVoucher`.
- Also reject non-160-bit EVM addresses in `addFlow` / `computeFlowId` inputs so governance cannot register ambiguous flow identities.

### Medium - `refundBurn` replay key can collide across wrapped tokens or burners

File: `contracts/op-contracts/src/bridge/BridgeDepository.ts:2805`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:4054`

Description:

OPNet `refundBurn` uses:

```ts
burnId = sha256(burnTxHash || burnNonce)
```

The signed `BurnRefundAuthorization` includes `burner` and `wrappedToken`, but the replay key does not. This diverges from the documented invariant that the burn id binds `wrappedToken` and `burner`, and from the EVM-side shape noted in `CLAUDE.md`, where the replay id includes token and burner because burn nonces are per wrapped token.

Exploit / impact scenario:

If a single OPNet transaction can produce burns from two wrapped-token contracts that currently share the same per-token `burnNonce`, both burns have the same `(burnTxHash, burnNonce)` pair. Refunding the first burn sets `_refundedBurns[sha256(txHash || nonce)]`; refunding the second legitimate burn then reverts as "burn already refunded", even though it is a different token/burn identity. A multicall-style transaction or contract-mediated batch burn is the most plausible collision path.

The failure mode is recovery loss/liveness, not direct extra minting: one legitimate cancelled burn can become impossible to re-mint through the on-chain recovery path.

Recommended fix:

Derive the replay key from the full burn identity:

```ts
burnId = sha256(wrappedToken || burner || burnTxHash || burnNonce)
```

Including `flowId` and/or `burnBlock` as additional domain material is also reasonable, but `wrappedToken` and `burner` are the critical missing fields. Update `isBurnRefunded` to take the same identity tuple, and add tests for two different wrapped tokens with the same `(txHash, burnNonce)`.

### Medium - DRAINING release claims are blocked by an earlier ACTIVE-only gate

File: `contracts/op-contracts/src/bridge/BridgeDepository.ts:1944`, `contracts/op-contracts/src/bridge/BridgeDepository.ts:2041`

Description:

`claimReleaseWithVoucher` has two status gates. The first requires `parsed.flowId` to be exactly `FLOW_STATUS_ACTIVE`. Later, after recomputing and matching the flow id, the function allows `FLOW_STATUS_ACTIVE` or `FLOW_STATUS_DRAINING`.

Because `flowIdRel` must equal `parsed.flowId`, the later ACTIVE-or-DRAINING check is unreachable for DRAINING flows. This contradicts the local `drainFlow` semantics that describe DRAINING as a wind-down mode that blocks new locks while honoring existing release/burn exits.

Exploit / impact scenario:

During an orderly wind-down, governance moves a mode-1/3/4 flow to DRAINING expecting in-flight release vouchers to remain claimable. Users holding already-signed EVM-burn-to-OPNet-release vouchers cannot claim, because the early ACTIVE-only check reverts. Funds remain in OPNet inventory until governance resumes the flow or uses another recovery path, undermining the purpose of DRAINING during incident response.

Recommended fix:

Make the early status gate match the later one for release claims:

```ts
const status = this._flowStatus.get(parsed.flowId).toU32();
if (status != FLOW_STATUS_ACTIVE && status != FLOW_STATUS_DRAINING) revert;
```

Keep `claimMintWithVoucher` and `refundBurn` ACTIVE-only if the intended policy is that DRAINING must not mint new supply.

### Medium - `BridgeAuthority` upgrades brick after normal governor handoff

File: `contracts/op-contracts/src/authority/BridgeAuthority.ts:75`, `contracts/op-contracts/src/authority/BridgeAuthority.ts:87`

Description:

`BridgeAuthority` registers `UpdatablePlugin(1008)`, but its `onUpdate` requires `Blockchain.tx.sender` to equal `_governor`. The local OPNet runtime's `UpdatablePlugin.applyUpdate(address,bytes)` is deployer-only: it rejects unless `Blockchain.tx.sender == Blockchain.contractDeployer`.

After the intended `pushGovernor` handoff to a governance wallet, `_governor` is no longer the deployer. At that point no caller satisfies both conditions:

- deployer is required by the plugin to apply the update;
- governor is required by `BridgeAuthority.onUpdate`.

Exploit / impact scenario:

Once governance is handed off, an authority bug cannot be patched through the registered upgrade plugin. A future critical fix to pause coordination, signer forwarding, or governance cascade logic would be blocked unless governance first rotates back to the deployer or deploys/re-wires a fresh authority. That is a correctness and incident-response risk in the contract that coordinates the rest of the OPNet bridge.

Recommended fix:

Mirror the depository's governance-armed deployer model:

- Keep `applyUpdate` physically deployer-only because the plugin requires it.
- Add a governor/authority-controlled one-shot `proposeUpgrade` flag.
- In `onUpdate`, require `tx.sender == contractDeployer` and require/consume the pending governance authorization once the gate is enabled.

Alternatively, if `BridgeAuthority` is meant to be immutable after deployment, remove the `UpdatablePlugin` registration and document the replacement ceremony instead.

### Low - `setInitialSigner` can inflate `_signerCount` if the hash was already added

File: `contracts/op-contracts/src/bridge/BridgeDepository.ts:923`

Description:

`setInitialSigner` unconditionally writes `_signerKeyHashSet[signerHash] = 1` and increments `_signerCount`. If governance calls `addSignerToSet(signerHash)` before `setInitialSigner(samePubkey)`, the actual set cardinality remains one but `_signerCount` becomes two.

The later `rotateSigner` path already guards against this class by incrementing only if the new hash was absent.

Exploit / impact scenario:

A misordered deployment or signer ceremony can make `_signerCount` exceed the true number of authorized signer keys. Governance could then set `requiredSignatures` to a value that passes `threshold <= signerCount` but is impossible to satisfy with distinct signers, bricking voucher verification until the signer set is repaired.

Recommended fix:

Use the same pattern as `rotateSigner`:

```ts
if (this._signerKeyHashSet.get(signerHash).isZero()) {
    this._signerKeyHashSet.set(signerHash, u256.One);
    this._signerCount.value = SafeMath.add(this._signerCount.value, u256.One);
}
```

## No standalone findings in these scoped files

I did not find standalone exploitable issues in:

- `contracts/op-contracts/src/bridge/events.ts`
- `contracts/op-contracts/src/wrapped/events.ts`
- `contracts/op-contracts/src/authority/events.ts`
- `contracts/op-contracts/src/lib/AmountPolicy.ts`

The `WrappedOP20.ts` review did not surface a direct mint/burn access-control issue: `mintTo` is minter-gated, zero amount and zero recipient are rejected before `_mint`, `burnForRelease` burns before emitting, destination-chain allowlisting is fail-closed, and EVM-recipient upper-byte padding is checked for EVM-family destination chains.

## Items for external auditors to focus on

- Confirm OPNet VM rollback semantics for cross-contract calls after `Revert`. These contracts rely on transaction-level rollback after replay guards and after tip payout calls if a later mint/transfer reverts.
- Cross-check the OPNet voucher source-field canonicality fix against the server voucher builder and EVM flow-id derivation. The on-chain fix should reject aliases even if off-chain code is already canonical.
- Verify whether OPNet supports contract-mediated multi-call transactions that can emit two `BurnedForRelease` events from different wrapped tokens in one tx. The `refundBurn` replay key should still bind token and burner regardless.
- Decide whether `BridgeAuthority` should be upgradeable. If yes, align its upgrade authorization model with `BridgeDepository`; if no, remove or document the plugin-based upgrade surface.
