# Codex Pre-Audit EVM Security Review

Date: 2026-06-02

Scope reviewed:

- `contracts/evm-contracts/src/BridgeEscrow.sol`
- `contracts/evm-contracts/src/VestingVault.sol`
- `contracts/evm-contracts/src/IVestingVault.sol`
- `contracts/evm-contracts/src/WrappedERC20.sol`
- `contracts/evm-contracts/src/DepositVault.sol`
- `contracts/evm-contracts/src/DepositAddressFactory.sol`
- `contracts/evm-contracts/src/AmountPolicy.sol`

Context read first:

- `CLAUDE.md`
- `docs/SECURITY.md`

Verification run:

```bash
cd contracts/evm-contracts
forge test --offline --match-contract 'DepositAddressFactoryTest|RefundLockedDepositTest|BridgeEscrowBurnRefundTest|VestingVaultTest|BridgeEscrowMode4Test|AmountPolicyTest|BridgeEscrowAllModesTest|FlowConsumptionTest'
```

Result: 111 tests passed, 0 failed. A first non-offline `forge test` invocation compiled successfully but Foundry crashed while initializing its signature lookup client on the macOS sandbox; the offline invocation avoided that path and executed the tests.

## Findings

### High - Mint-on-EVM paths do not enforce `flow.cap`, and `WrappedERC20` has no supply cap

Location:

- `contracts/evm-contracts/src/BridgeEscrow.sol:269`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1144`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1664`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1765`
- `contracts/evm-contracts/src/WrappedERC20.sol:83`

Description:

`FlowRecord.cap` is documented in the contract as a mint ceiling for mode 2, but the two EVM mint-authority paths only consume the rolling `dailyLimit`:

- `claimMintWrapped()` checks mode, token binding, status, and `_consumeMintFlowLimits()`, which enforces `minAmount` and `dailyLimit` only.
- `refundBurn()` has the same pattern and then calls `mintFromBridge()`.
- `WrappedERC20.mintFromBridge()` has no `maxSupply` or cap check.

This contradicts the security model statement that every flow is bounded by `cap` and that wrapped tokens have a `maxSupply` ceiling. It also leaves the highest-blast-radius EVM paths bounded only per 24-hour window, not cumulatively.

Exploit / impact scenario:

If the threshold signer set is compromised, or during the documented 1-of-1 launch posture a single signer key is compromised, the attacker can repeatedly submit fresh `MintIntent` values or fresh `BurnRefundAuthorization` tuples with unique replay keys. Each 24-hour window is limited by `dailyLimit`, but the attacker can continue minting across windows without ever hitting `flow.cap` or a token-level supply ceiling. For mode 2 this can inflate wrapped supply beyond the intended route ceiling. For mode 1 it can mint unbacked EVM wrapped tokens if the OPNet-side source event is fabricated by compromised signers.

Recommended fix:

Add a cumulative mint ceiling for mint-on-EVM flows before `mintFromBridge()` is called. The cleanest hard stop is a capped wrapped token, for example `ERC20Capped`, with `totalSupply() + amount <= maxSupply`. If the cap must be per-flow rather than per-token, add explicit per-flow minted/outstanding accounting and update it on mint and burn. Apply the same check to both `claimMintWrapped()` and `refundBurn()`. Existing non-upgradeable `WrappedERC20` deployments would require a fresh capped wrapper deployment and migration.

### Medium - CREATE2 deposit-address locks refund to the self-destructed vault instead of a user-controlled refund address

Location:

- `contracts/evm-contracts/src/DepositVault.sol:31`
- `contracts/evm-contracts/src/DepositVault.sol:36`
- `contracts/evm-contracts/src/DepositVault.sol:40`
- `contracts/evm-contracts/src/BridgeEscrow.sol:823`
- `contracts/evm-contracts/src/BridgeEscrow.sol:932`
- `contracts/evm-contracts/src/DepositAddressFactory.sol:47`

Description:

`DepositVault` forwards its entire balance into `BridgeEscrow.lock()` from the constructor. In `BridgeEscrow.lock()`, the refund destination stored in `LockRecord.user` is `msg.sender`, which is the temporary `DepositVault`, not the human depositor or any user-supplied refund address. The vault then self-destructs in the same constructor.

If this deposit later becomes refundable, `refundLockedDeposit()` transfers the principal to `rec.user`, so the tokens go back to the deterministic vault address. The current vault bytecode has no rescue mode and no refund recipient. Re-sweeping the same deterministic address only deploys the same vault again, which calls `lock()` with the same `opnetRecipient` and `flowId`, then self-destructs again.

Exploit / impact scenario:

A user bridges through a CEX-style deposit address. The source lock succeeds, but the destination voucher is permanently cancelled and the M-of-N signer set marks the deposit refundable. The refund sends USDC/USDT to the now-empty deterministic vault address. Anyone can re-run `sweep()`, but that just locks the funds again to the same OPNet recipient. If the destination path is still cancelled or invalid, the user is trapped in a refund-to-relock loop and cannot recover funds to an EVM wallet.

Recommended fix:

Make the refund recipient explicit for deposit-address flows. Options:

- Add a `lockFor(..., address refundTo)` or equivalent escrow entrypoint and have `DepositVault` pass a user-specified refund address.
- Include `refundTo` in the CREATE2 initcode parameters so the predicted address commits to both `opnetRecipient` and refund destination.
- If retaining a vault-level recovery design, do not self-destruct until refunds are impossible, and add a rescue path that can send refunded tokens to the committed refund recipient instead of re-locking them.

Also add a regression test that sweeps through `DepositAddressFactory`, marks the resulting nonce refundable, calls `refundLockedDeposit()`, and asserts the final balance reaches the intended EVM refund address.

### Medium - Decimal-mismatched release flows are allowed but `claim()` treats source units as destination units

Location:

- `contracts/evm-contracts/src/BridgeEscrow.sol:1174`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1183`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1236`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1242`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1257`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1272`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1978`
- `contracts/evm-contracts/src/AmountPolicy.sol:47`

Description:

`addFlow()` allows `evmDecimals` and `opnetDecimals` to differ, and `AmountPolicy.quote()` correctly supports decimal-aware scaling. However, `BridgeEscrow.claim()` does not use `AmountPolicy` or otherwise scale amounts. It compares `intent.amount <= intent.grossSrcAmount`, applies `minAmount` and `dailyLimit` to `grossSrcAmount`, decrements EVM-side inventory by `grossSrcAmount`, and calculates release-side fees as `grossSrcAmount - amount`.

Those operations are only correct when the OPNet source amount and EVM destination amount share the same decimal basis. The source itself acknowledges this assumption in the comment around the `AmountExceedsGross` guard.

Exploit / impact scenario:

For an OPNet 6-decimal source releasing an EVM 18-decimal token, an honest voucher would have `amount` much larger than `grossSrcAmount` after scaling, so `claim()` reverts with `AmountExceedsGross()`. For an OPNet 18-decimal source releasing an EVM 6-decimal token, `grossSrcAmount` is much larger than the EVM inventory units, so claims can revert with `InsufficientFlowInventory()` or over-decrement accounting if inventory was provisioned at very large values. Either direction makes non-1:1 decimal release flows unusable or misaccounted even though the flow registry accepts them.

Recommended fix:

Until the EVM release path is decimal-aware, reject release-capable flows where `evmDecimals != opnetDecimals`. The stronger fix is to use the stored flow decimals and fee parameters in `claim()`:

- Compute `(grossDst, feeDst, netDst)` from `AmountPolicy.quote(intent.grossSrcAmount, flow.opnetDecimals, flow.evmDecimals, flow.feeBps, flow.minFee, flow.minAmount)`.
- Require the signed destination amount to match the computed net amount.
- Decrement inventory and accrue fees in destination token units, not source units.
- Keep `dailyLimit` semantics explicit: source units if it is intended as source-side volume, destination units if it is intended as inventory pressure.

Add tests for 6-to-18 and 18-to-6 release flows.

### Low - `WrappedERC20.burnForRelease()` burns before validating that `flowId` is registered, active, and bound to the wrapper

Location:

- `contracts/evm-contracts/src/WrappedERC20.sol:26`
- `contracts/evm-contracts/src/WrappedERC20.sol:101`
- `contracts/evm-contracts/src/WrappedERC20.sol:107`
- `contracts/evm-contracts/src/WrappedERC20.sol:111`

Description:

`WrappedERC20.burnForRelease()` accepts any nonzero OPNet recipient and any `flowId`, burns the caller's tokens, increments `burnNonce`, and emits the event. The function does not check the bridge flow registry to confirm that the `flowId` exists, is `ACTIVE`, has a mint/burn-compatible mode, and binds `flow.evmToken` to this wrapper.

This is unlike the claim paths, which reject unregistered, inactive, or token-mismatched flows before value movement.

Exploit / impact scenario:

A malicious or buggy frontend can ask a user to burn wrapped tokens with an unregistered, retired, paused, or wrong-token `flowId`. The burn succeeds on-chain and destroys the user's tokens, but the indexer or signer should be unable to issue a valid destination voucher for that route. The user then needs an operational recovery path, and for fabricated/wrong-flow burns the signer set may correctly refuse `refundBurn()`.

Recommended fix:

Move burn initiation through `BridgeEscrow`, or add a minimal registry check from the wrapper into the bridge before `_burn()`:

- flow exists;
- flow status is `ACTIVE`;
- flow mode is valid for this wrapper's burn direction;
- `flow.evmToken == address(this)`.

Because `WrappedERC20` is non-upgradeable, this requires a fresh wrapper deployment for already-deployed wrappers. At minimum, make the UI/indexer treat arbitrary `flowId` burns as unsafe and add monitoring for burns on unknown or inactive flows.

### Low - Fee-on-transfer or rebasing tokens can still underpay outbound transfers and desynchronize Mode 4 clawback accounting

Location:

- `contracts/evm-contracts/src/BridgeEscrow.sol:1313`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1331`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1513`
- `contracts/evm-contracts/src/BridgeEscrow.sol:1519`
- `contracts/evm-contracts/src/VestingVault.sol:213`
- `contracts/evm-contracts/src/VestingVault.sol:216`
- `contracts/evm-contracts/src/VestingVault.sol:247`

Description:

Inbound paths use balance-delta accounting, but outbound paths assume the requested transfer amount is also the amount delivered. For ordinary USDC/USDT-style tokens this is fine. For fee-on-transfer, rebasing, or otherwise non-canonical ERC-20s, recipients can receive less than the signed or vested amount.

The most concrete accounting issue is Mode 4 clawback. `VestingVault.clawback()` returns `unvested` as the amount it attempted to transfer back to the bridge. `BridgeEscrow.clawbackVestedClaim()` then increments `flow.inventory` by that returned value without measuring the bridge's actual token balance delta. If the vault-to-bridge transfer is taxed or otherwise short, the bridge overcredits inventory.

Exploit / impact scenario:

Governance registers a fee-on-transfer project token for a pooled or vesting flow. Direct `claim()` transfers underpay users relative to `intent.amount`. In Mode 4, a clawback of 1,000 tokens with a 1 percent transfer fee returns only 990 tokens to the bridge, but `flow.inventory` is credited by 1,000. Later claims can pass inventory checks that are not backed by the actual token balance, causing delayed reverts or reserve accounting drift.

Recommended fix:

For the current bridge design, explicitly disallow fee-on-transfer and rebasing tokens for supported flows. If support is required later, add balance-delta checks anywhere tokens move back into bridge custody, especially Mode 4 clawback, and redesign user-facing outbound accounting because an ERC-20 transfer to a user cannot guarantee exact receipt without token-specific handling.

## Reviewed Areas Without Findings

I did not identify exploitable issues in the following scoped areas:

- EIP-712 domain use in `BridgeEscrow`: OZ `EIP712Upgradeable` binds name, version, current `chainId`, and proxy `verifyingContract`.
- Typehash and struct-field inclusion for `ReleaseIntent`, `MintIntent`, `RefundAuthorization`, and `BurnRefundAuthorization` in the scoped Solidity.
- M-of-N ECDSA verification: length-prefixed blob only, OZ `ECDSA.recover`, authorized signer check, duplicate signer rejection, threshold check.
- Replay-flag CEI ordering in `claim()`, `claimMintWrapped()`, `refundBurn()`, and `refundLockedDeposit()`.
- UUPS basics in source: implementation constructor disables initializers, `initialize()` is initializer-gated, `_authorizeUpgrade()` is `onlyOwner`, and no arbitrary delegatecall exists in `BridgeEscrow`.
- Role lattice in `BridgeEscrow`: guardian/pauser can freeze, owner-only unpause, guardian-only paused emergency drain to pinned treasury.
- Mode 4 vault wiring guard: `setFlowVestingVault()` checks `vault.token() == flow.evmToken`; `depositFor()` and `clawback()` are bridge-only in `VestingVault`.

## Items External Auditors Should Focus On

- Verify the actual deployed EVM v1 storage layout against this source out-of-band. The current source and committed snapshot use `uint256[40] __gap` after `pauser` and `refundedBurns`; some project documentation still mentions `uint256[42]`. I verified local source-to-snapshot consistency, not deployed-mainnet append-only safety.
- Re-audit `refundBurn()` on both chains as a mint-authority primitive, especially after adding a cumulative cap or wrapped-token max supply.
- Review the off-chain signer implementation and M-of-N aggregation. The scoped contract enforces M-of-N, but the residual risk depends on keys being operationally independent rather than multiple keys in one process.
- Confirm the intended semantics of `dailyLimit`: source-side volume, destination-side inventory pressure, or minted amount. The current implementation uses different units across paths.
- Decide whether fee-on-transfer/rebasing tokens are in or out of scope. The current contracts are safest if governance treats them as unsupported.
