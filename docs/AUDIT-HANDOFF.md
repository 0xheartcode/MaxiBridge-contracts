# MaxiBridge — Smart Contract Audit Handoff

> **Prepared for:** external third-party audit firm
> **Scope:** **smart contracts only** (EVM Solidity + OPNet AssemblyScript). Off-chain
> components (server, indexer, frontend, admin panel, deploy/ops scripts) are **out of
> scope** for this engagement and are described only where they define a trust boundary
> the contracts rely on.
> **Audit target:** tag `audit-2026-06-02` in the delivered contracts-only repo
> (extracted from monorepo `dev`; that tip **merges the O-1…O-4 fixes** the original
> packet listed as open PRs — see Appendix A for the updated remediation table).
> **Date prepared:** 2026-06-01 · **Updated:** 2026-06-02 (O-1…O-4 remediations merged; E-1/E-2/E-3/O-5 remain open and disclosed in §8)

This is the engagement packet: scope, how to build and test, the architecture and trust
model, the contract inventory, the invariants we most want verified, and the residual
risks we already know about. The standing, evergreen threat model is `docs/SECURITY.md`;
the historical findings log is `docs/REFERENCE.md` §18. Where this doc and `SECURITY.md`
disagree, `SECURITY.md` is the newer truth.

A pre-audit internal self-review (OpenAI Codex, both contract sets) was run at the audit
commit; its findings are summarized in **Appendix A** so you can triage against work we've
already looked at. It is **not** a substitute for your review — treat it as a starting
map, not a clean bill.

---

## 1. What MaxiBridge is

A two-way, **general-purpose cross-chain token bridge** between **Ethereum** (EVM, chainId
1) and **OPNet** (Bitcoin L1 smart-contract platform; AssemblyScript→WASM contracts).
Governance can onboard almost **any token pair** — the five flow modes (§1, below) cover
wrapped mint/burn, pooled lock/release, and pooled lock/vest, and the accounting is
**decimal-aware**, so source and destination decimals can differ (a stablecoin and an
18-decimal asset are both first-class). USDC/USDT are simply the **launch flows**, not a
design constraint. Both directions are **voucher-based**: an off-chain signer set produces a
signature over a fully source-bound preimage, and the **user pays gas on the destination
chain** to redeem it. The server never holds user funds and never submits destination
transactions — it only signs.

```
EVM → OPNet (deposit)                        OPNet → EVM (withdraw)
─────────────────────                        ──────────────────────
1. lock USDC  BridgeEscrow.lock()            1. burn wUSDC WrappedOP20.burnForRelease()
2. indexer waits confirmations + reorg-check 2. indexer waits confirmations + reorg-check
3. signer signs 540-byte ML-DSA voucher      3. signer signs EIP-712 ReleaseIntent
4. user claimMintWithVoucher() → mint wUSDC  4. user BridgeEscrow.claim() → release USDC
```

Five flow **modes** (per-route, chosen by `flowId`, identical machinery on both chains):

| Mode | Name | EVM role | OPNet role |
|---|---|---|---|
| 0 | `WRAPPED` | custody (lock USDC) | mint (wUSDC) |
| 1 | `INVERSE_WRAPPED` | mint (WrappedERC20) | custody (lock OP20) |
| 2 | `NATIVE_BURN_MINT` | mint/burn | mint/burn |
| 3 | `POOLED_LOCK_RELEASE` | custody (pool) | custody (pool) |
| 4 | `POOLED_LOCK_VEST` | custody (pool) → release vests | custody (pool) |

Custody-vs-mint is **per-mode, not per-chain** — see §5 and `docs/ARCHITECTURE.md`
"Token Mode, Custody/Mint Roles & Call Surface" for the full call-surface matrix.

---

## 2. Audit scope

### 2.1 In scope — contracts to review

**EVM (Solidity `0.8.24`, OZ v5.1.0, Foundry):**

| File | LoC | Role |
|---|---|---|
| `contracts/evm-contracts/src/BridgeEscrow.sol` | 2309 | **Core.** UUPS proxy. lock/claim, EIP-712 M-of-N ECDSA verify, refundBurn re-mint, lock-refund (`markDepositRefundable`/`refundLockedDeposit`), flow registry, signer set, role lattice, cancelVoucher, emergencyWithdraw, fees |
| `contracts/evm-contracts/src/VestingVault.sol` | 300 | Mode-4 destination vault; bridge-only `depositFor`/`clawback`, beneficiary `claim`, linear block-based vesting |
| `contracts/evm-contracts/src/IVestingVault.sol` | 41 | Mode-4 interface |
| `contracts/evm-contracts/src/WrappedERC20.sol` | 121 | Wrapped token; `mintFromBridge`, `burnForRelease(flowId,…)` |
| `contracts/evm-contracts/src/DepositVault.sol` | 42 | Per-deposit vault helper |
| `contracts/evm-contracts/src/DepositAddressFactory.sol` | 80 | Deterministic deposit-address derivation |
| `contracts/evm-contracts/src/AmountPolicy.sol` | 89 | Decimal-aware fee/quote math (library) |

**OPNet (AssemblyScript, `@btc-vision/btc-runtime ^1.11.0`, `@btc-vision/assemblyscript ^0.29.3`, `@btc-vision/opnet-transform ^1.2.2`, `@btc-vision/as-bignum ^1.0.0`):**

| File | LoC | Role |
|---|---|---|
| `contracts/op-contracts/src/bridge/BridgeDepository.ts` | 4205 | **Core.** Voucher claims, `_verifyMofN` ML-DSA M-of-N, refundBurn re-mint, lock-refund (`markLockRefundable`/`refundLock`), flow registry, inventory, role lattice, cancelVoucher, confirmBurn, emergencyWithdraw, fees, `UpdatablePlugin(432)` upgrade gating |
| `contracts/op-contracts/src/bridge/events.ts` | 449 | Event definitions + byte layouts |
| `contracts/op-contracts/src/wrapped/WrappedOP20.ts` | 568 | **Non-upgradeable** wrapped token; mint gated to depository, `burnForRelease(flowId,…)`, dest-chain allowlist, `maxSupply` ceiling |
| `contracts/op-contracts/src/wrapped/events.ts` | 112 | Wrapped event layouts |
| `contracts/op-contracts/src/authority/BridgeAuthority.ts` | 400 | Governance-gated upgrade authority (`proposeUpgrade`/`cancelProposedUpgrade`) |
| `contracts/op-contracts/src/authority/events.ts` | 69 | Authority events |
| `contracts/op-contracts/src/lib/AmountPolicy.ts` | 128 | Decimal-aware fee/quote math |

Totals: ~3.0k LoC Solidity, ~5.9k LoC AssemblyScript across both contract sets.

### 2.2 Out of scope (but defines trust boundaries)

- `server/` — indexer, reorg guard, voucher/message signing, admin API, monitoring.
  **The contracts trust the signer set, not the server.** The server's job is to (a) wait
  confirmations + re-check canonical block hash before signing, and (b) refuse to sign
  reorged/duplicate events. A bug there can cause a *failure to sign* or *signing a
  reorged event*, but every signature is still bound on-chain to a specific source event
  and a specific signer epoch — see the invariants in §7.
- `frontend/`, `admin-panel/` — UI only; no privileged on-chain authority.
- `scripts/` — deploy/wire/ops/upgrade tooling. Privileged calls (rotate signer, pause,
  upgrade, refundBurn) originate here but execute under the same on-chain access control
  the contracts enforce.
- `bridge-watchdog/` — independent monitoring service; can call the public pause path, no
  special authority.

### 2.3 Dependencies (trusted, not in scope)

- OpenZeppelin Contracts + Contracts-Upgradeable **v5.1.0** (`Initializable`,
  `UUPSUpgradeable`, `OwnableUpgradeable`, `PausableUpgradeable`,
  `ReentrancyGuardUpgradeable`, `EIP712Upgradeable`, `ECDSA`, `SafeERC20`).
- `@btc-vision/btc-runtime` runtime primitives (`StoredU256`, `StoredAddress`,
  `AddressMemoryMap`, `StoredMapU256`, `ReentrancyGuard`, `UpdatablePlugin`, `sha256`,
  ML-DSA verification host functions).
- Compiler/host correctness for both toolchains is assumed.

---

## 3. Build & test

Each contract set is self-contained (no npm workspaces). Install with
`npm install --legacy-peer-deps`.

### EVM (Foundry)

```bash
cd contracts/evm-contracts
forge build                 # solc 0.8.24, optimizer on (runs=200), via_ir=true, evm=cancun
forge test                  # unit + invariant + fork suites
forge test --match-path test/BridgeEscrow.t.sol -vvv
```

Foundry config of note (`foundry.toml`): `via_ir = true`, `optimizer_runs = 200`,
`evm_version = "cancun"`, `fuzz.runs = 10_000`, `extra_output = ["storageLayout"]`. A
committed `storage-layout.json` is the CI diff gate for UUPS upgrades.

Fork tests (`BridgeEscrow.fork.t.sol`) require `SEPOLIA_RPC_URL` / mainnet RPC env and are
skipped without it.

### OPNet (AssemblyScript)

```bash
cd contracts/op-contracts
npm run build               # compiles wrapped + depository + authority to WASM via asc
npm test                    # @btc-vision/unit-test-framework, runs via tsx
npx tsx __test__/unit/tests/bridge.ts     # individual suite
```

Build targets compile through `@btc-vision/opnet-transform` (the `@method`/`@view`
decorator transform + selector generation). The transform output is what runs on-chain —
selectors are SHA-256 of the Solidity-style signature.

### Existing test coverage (in scope)

EVM Foundry test files (`contracts/evm-contracts/test/`, ~348 test fns):
`BridgeEscrow`, `BridgeEscrowAllModes`, `BridgeEscrowBurnRefund`, `BridgeEscrowMode4`,
`AmountPolicy`, `FeeAccounting`, `FeeSettlement`, `FlowConsumption`, `FlowRegistry`,
`GuardianRole`, `LockInventory`, `LockWithPermit`, `RefundLockedDeposit`, `RelayerTip`,
`TimelockUpgrade`, `VestingVault`, `Create2Deploy`, `DepositAddressFactory`, plus
`BridgeEscrow.fork.t.sol`.

OPNet test files (`contracts/op-contracts/__test__/unit/tests/`):
`bridge`, `wrapped`, `authority`, `burn-refund`, `confirm-burn`, `fee-accounting`,
`flow-consumption`, `flow-registry`, `mode-per-flow-lock`, `relayer-tip-opnet`,
`signer-migration`, `stranded-lock-refund`, `upgrade-authority`.

---

## 4. Architecture (concise)

Full version: `docs/ARCHITECTURE.md`. The load-bearing details:

- **Two signature schemes, by chain.** OPNet verifies a **540-byte ML-DSA** voucher
  (ECDSA is deprecated in the OPNet VM); EVM verifies an **EIP-712 ECDSA** typed struct.
  Both are wrapped as **M-of-N blobs** — the on-chain verifier counts *distinct* valid
  signatures from an on-chain signer set against an on-chain threshold.
- **Source-event binding.** Every signed preimage commits to the full source-event tuple
  `(sourceChainId, sourceBridgeAddr, sourceTokenAddr, sourceTxHash, sourceLogIndex,
  sourceDepositNonce, sourceBlockHash)` — a signature for one deposit cannot be repointed.
- **Domain separation.** Every OPNet preimage is prefixed `networkId ‖ contractSelf ‖
  selector`; every EVM struct binds `chainId`, `verifyingContract`, `expectedOpnetChainId`,
  and a per-method selector/typehash. Cross-chain, cross-contract, cross-method replay all
  fail.
- **Replay guards, single-use, CEI.** `_usedVoucherIds` / `_usedSourceEvents` /
  `_refundedBurns` / `_cancelledVouchers` (OPNet) and `cancelledVouchers` / `usedNonces` /
  `refundedBurns` / `lockedDeposits` (EVM) are all set **before** the external mint/transfer.
- **Epoch-based signer revocation.** Every preimage carries `signerEpoch`; rotating or
  removing a signer bumps the epoch and instantly invalidates every unclaimed
  old-epoch voucher with no deadline clock.
- **Per-flow economic limits.** `cap`, rolling-24h `dailyLimit`, `minAmount`, `tipCapBps`
  (≤ 2%), fee floor, ACTIVE/DRAINING status — all enforced on both the source and claim
  legs (#68 made the claim leg flow-gated too).
- **Upgrade posture.** EVM `BridgeEscrow` = OZ UUPS behind a 3-day `TimelockController`;
  OPNet `BridgeDepository` = `UpdatablePlugin(432 blocks ≈ 3 days)` **plus** a
  governance-armed one-shot `proposeUpgrade` flag (a compromised deployer hot key alone
  cannot push bytecode). **Wrapped tokens (`WrappedOP20`/`WrappedERC20`) are
  intentionally non-upgradeable.**

---

## 5. Trust model & assumptions

What the design assumes, stated plainly so the audit can probe each assumption:

1. **The signer set is the root of trust.** A valid M-of-N signature over a correctly
   bound preimage is sufficient authorization to mint/release on the destination. The
   contracts do **not** independently verify the source-chain event — they trust the
   signer's attestation that it happened, *bound* to immutable source coordinates so the
   attestation can't be reused elsewhere. **The audit question is whether the on-chain
   guards still hold if up to (M−1) signer keys are compromised**, and whether a single
   compromised key can ever exceed its authority through any path (refundBurn, lock-refund,
   confirmBurn, migrateSignerSet).
2. **Launch posture is 1-of-1.** The M-of-N machinery is fully implemented but ships with
   threshold = 1 at launch (see §8/residual risk). Treat single-signer-compromise blast
   radius as a first-class question.
3. **Governor/owner is honest-but-rate-limited.** On mainnet, owner = 3-day timelock
   (EVM) / 432-block plugin + governance arming (OPNet). The audit should confirm there is
   **no privileged path that bypasses the timelock** and **no owner-only path that drains
   user funds without the guardian + paused + treasury-pinned constraints**.
4. **Canonical tokens.** USDC/USDT are non-rebasing, non-fee-on-transfer, but the code
   uses `SafeERC20` + balance-delta accounting (`received = balAfter − balBefore`) to stay
   correct if a non-canonical token is ever added. Confirm the balance-delta guard cannot
   underflow/desync.
5. **Mint-authority paths are the highest blast radius.** `refundBurn` on both chains
   *creates supply*. We flag these for dedicated scrutiny (§8).

---

## 6. Privileged roles & access control

Mirrored symmetrically on both chains (same names, same semantics):

| Role | Powers | Mainnet identity |
|---|---|---|
| **owner / governor** | full authority; upgrades; `addSigner`, `setThreshold`, `addFlow`, `unpause`, role rotation | EVM 3-day `TimelockController`; OPNet governor + `UpdatablePlugin(432)` + arm |
| **guardian** | incident response: `pause`, `cancelVoucher`, `removeSigner`, `migrateSignerSet`, **sole** caller of `emergencyWithdraw` | rotatable EOA on independent device |
| **pauser** | freeze-only; nothing else; zero = disabled | rotatable |
| **treasury** | pinned sink for `withdrawFees` AND `emergencyWithdraw` (fail-closed if unset) | prod Safe |

Key access-control invariants to verify:
- **Freeze-but-never-thaw (H-01):** owner/guardian/pauser may `pause`; **only owner/governor
  may `unpause`**.
- **`emergencyWithdraw`** = guardian-only **+ whenPaused + drains only to `treasury`**.
  Owner cannot drain unilaterally; the pause must be exercised first.
- **Adding a signer does not bump the epoch** (superset; in-flight vouchers stay valid);
  **removing one does** (revocation must be instant). `setThreshold`/`migrateSignerSet`
  bump the epoch.
- **Mode is immutable per `flowId`** — there is no `setFlowMode`; re-moding means a new
  flow + drain the old.

---

## 7. Invariants we most want verified

These are the load-bearing properties; a break in any is likely Critical/High.

1. **No mint/release without a current-epoch, distinct-signer, threshold-meeting signature
   bound to an unconsumed source event.** (Replay guard set before the external call;
   epoch checked; duplicate signers rejected; distinct count ≥ threshold.)
2. **No double-spend / double-mint.** Each voucherId, each source-event tuple, each burnId,
   each lockNonce is consumable exactly once, even across the refund/recovery paths.
3. **`refundBurn` (both chains) cannot re-mint more than the attested burned amount, can
   only target an allowlisted wrapped token in a mint-capable ACTIVE flow, and its
   per-burn replay guard (`burnId`) is set strictly before `mintTo`/`mintFromBridge`.**
   `burnId` must bind enough fields (wrappedToken + burner + txHash + nonce) that two
   wrappeds cannot collide. This is the highest-blast-radius surface.
4. **Preimage byte-exactness.** The 540-byte ML-DSA voucher, 296-byte
   BurnRefundAuthorization, 264-byte RefundAuthorization, 252-byte BurnAttestation, and the
   EVM EIP-712 typehash strings must match the server's encoders bit-for-bit AND admit no
   field aliasing (e.g. a shorter parse that lets two distinct logical vouchers hash equal).
   Layouts are in `CLAUDE.md` §6/§8 and reproduced in **Appendix B**.
5. **ML-DSA M-of-N blob parsing is bounds-safe** — `numSigs` and every `pubLen`/`sigLen`
   are bounds-checked *before* slicing; the blob is variable-length (never assert a fixed
   total). A malformed blob must revert, never read out of bounds or under-count.
6. **EVM ECDSA M-of-N**: low-s enforced (OZ `ECDSA.recover`), zero-address recover rejected,
   distinct signers, threshold counting, no malleability double-count.
7. **CEI / reentrancy** on every value-moving method on both chains, including
   cross-function reentrancy via `VestingVault.claim`/`depositFor`.
8. **Lock-refund returns only the original principal to the original locker**, rebuilt
   in-contract from stored lock state (OPNet) so it can only ever target the exact lock,
   and reverses the inventory credit so `inventory + accruedFees == balance` holds.
9. **VestingVault**: bridge-only `depositFor`/`clawback`; each schedule keyed by
   `opnetNonce` with no top-up confusion; `clawback` returns only the *unvested* portion;
   block-based release rounding cannot over-release; `vault.token() == flow.evmToken`
   wiring guard holds.
10. **Storage layout** is append-only across the upgradeable surfaces — EVM `__gap`
    (`uint256[42]`) accounting is correct vs the committed `storage-layout.json`; OPNet
    `Stored*` field/`nextPointer` order is never reordered/deleted/retyped.
11. **Relayer tip**: `tipCapBps ≤ MAX_TIP_BPS (200)`, cross-multiplied (un-floored) ratio
    check, `tip ≤ amount`, and tip-less vouchers pay the named recipient in full
    (front-run safety).

---

## 8. Known residual risks (we already know these)

Disclosed up front so the audit can confirm or expand, not rediscover:

1. **1-of-1 signer at launch.** M-of-N is built but threshold = 1 initially; single
   signer-key compromise is the top residual risk, mitigated by instant epoch revocation +
   watchdog + pause. Fix = M-of-N ramp + KMS signer (Phase 3; currently a hot wallet).
2. **No independent multi-signer distribution layer yet.** Setting threshold > 1 while
   both keys live in one process gives the *ceremony* of M-of-N without the *security*; the
   ramp is deliberately sequenced after KMS.
3. **`refundBurn` is a mint-authority primitive on both chains** — flagged for dedicated
   re-audit. Trust model == vouchers (same signer set attests the burn is final and the
   destination voucher is cancelled). The OPNet attestation is self-contained (no native
   burn record); the only thing stopping infinite re-mint is the `burnId` replay guard set
   before the mint.
3a. **(E-1, open High) No cumulative mint ceiling on the EVM mint-on-EVM paths.**
   `claimMintWrapped` and `refundBurn` consume only the rolling `dailyLimit`
   (`_consumeMintFlowLimits`); `flow.cap` is NOT enforced on mint (only on inventory
   for modes 0/3/4), and `WrappedERC20.mintFromBridge` has no `maxSupply`. This
   **contradicts SECURITY.md §6/§7** ("every flow bounded by `cap`", "`maxSupply`
   ceiling on wrapped tokens"). Under the 1-of-1 launch posture, a single compromised
   signer can mint across successive 24h windows with no cumulative ceiling. We are
   shipping this OPEN and accepted for the audit-tag scope; the planned fix is a capped
   wrapper (`ERC20Capped`) or per-flow minted/outstanding accounting on both paths
   (fresh non-upgradeable wrapper deploy + migration). **We want the auditor to size the
   real blast radius and pressure-test our compensating controls** (epoch revocation,
   watchdog, pause), not just confirm the gap.
3b. **(E-2/E-3/O-5, open) Other Codex findings shipped open** for the auditor to confirm:
   E-2 CREATE2 deposit refund-to-relock loop, E-3 `claim()` not decimal-aware (latent —
   every live flow is 6/6), O-5 `setInitialSigner` `_signerCount` over-count. See
   Appendix A.
4. **On-chain-v1 → current EVM storage layout** must be diffed out-of-band before the
   mainnet upgrade ceremony; local `dev` is clean append-only but the on-chain delta hasn't
   been verified end-to-end in CI.
5. **`_lockBlock` reorg guard uses block *number*, not block *hash*** on OPNet (A-5),
   pending an OPNet runtime block-hash check.
6. **Ops/recovery scripts are 1-of-1 only** (out of scope, noted for completeness) — they
   refuse to broadcast when `requiredSignatures() > 1` rather than build a doomed blob.

Prior internal reviews (full log: `docs/REFERENCE.md` §18): two pre-launch Codex audits,
full-codebase audits 2026-05-19 and 2026-05-25, and a 2026-05-27 multi-agent
refundBurn/roles/governance review (no Criticals; findings landed across PRs #97–#100).

---

## 9. Specific focus requests

Where we'd most value auditor attention beyond the invariants in §7:

- **`refundBurn` on both chains** — exhaustively, as a mint primitive. Can any sequence of
  (cancel, refund, re-sign, rotate) double-mint or mint to the wrong party?
- **Cross-mode confusion under #68 N:M routing** — one `(evmToken, opnetToken)` pair backing
  several flows of different modes simultaneously. Can a voucher/burn for flow A be claimed
  against flow B? Is `flowId` recomputed-and-asserted on every claim leg (not just trusted
  from the event)?
- **`confirmBurn` (OPNet)** inventory accounting under modes 1 vs 3 — single-count
  invariant (`lockForBridge` produces, `claimReleaseWithVoucher` consumes; `confirmBurn` is
  a pure attestation for mode 1, decrements for mode 3).
- **AmountPolicy decimal-aware quoting** when source/destination decimals differ
  (`grossSrcAmount` vs `grossDstAmount`) — rounding direction, truncation-to-zero, and
  whether fee/net/gross consistency (`gross == fee + net`) holds at every decimal pair.
- **Selector-constant runtime asserts** on OPNet `onDeployment` — confirm a drifted
  hardcoded selector fails loud rather than silently bricking attestations.
- **The two recipient-encoding conventions** (`burnForRelease.ethRecipient` LEFT-pad vs
  preimage `sourceBridgeAddr`/`sourceTokenAddr` RIGHT-pad) — confirm no path conflates them.

---

## 10. Appendix A — pre-audit self-review (Codex) summary

> Generated by an automated OpenAI Codex pass at the audit commit. Full reports:
> `docs/CODEX-PREAUDIT-EVM.md` and `docs/CODEX-PREAUDIT-OPNET.md`. Provided as a triage map;
> NOT a substitute for independent review. These are self-reported and **not independently
> confirmed** — they are listed so the audit team can corroborate or dismiss them rather
> than rediscover them.

### Remediation status (updated 2026-06-02 — verified against the audit-tag code)

The four highest-impact OPNet findings (O-1…O-4) are **fixed and merged** at the audit tag,
each with regression tests. **E-1 (the remaining High), E-2, E-3, and O-5 are knowingly
shipped OPEN** and are disclosed as residual risk in §8 — we want them confirmed/expanded,
not rediscovered. E-4/E-5 are accepted as policy (see notes).

| Finding | Status at audit tag | Where to verify |
|---|---|---|
| O-1 (High) — source-event replay-key bypass | ✅ **Fixed** | `buildSourceEventKey` canonicalizes chainId→u64 + EVM addr low-20 (`BridgeDepository.ts`); tests in `bridge.ts`, `flow-consumption.ts` |
| O-2 (Med) — `refundBurn` burnId omits token+burner | ✅ **Fixed** | `_burnRefundId(wrappedToken,burner,txHash,nonce)`; `isBurnRefunded` widened; tests in `burn-refund.ts` |
| O-3 (Med) — DRAINING release claims unreachable | ✅ **Fixed** | early gate accepts ACTIVE\|DRAINING on the release path |
| O-4 (Med) — `BridgeAuthority` upgrade brick | ✅ **Fixed** | Option C: governance-armed deployer (`proposeUpgrade`/`cancelProposedUpgrade`, 2-of-2); tests in `authority-upgrade-authority.ts` |
| O-5 (Low) — `setInitialSigner` count inflation | ⚠️ **OPEN** (disclosed §8) | `setInitialSigner` still increments `_signerCount` unconditionally |
| E-1 (**High**) — no EVM mint cap / `maxSupply` | ⚠️ **OPEN** (disclosed §8) | mint-on-EVM paths bound by `dailyLimit` only; `WrappedERC20` uncapped |
| E-2 (Med) — CREATE2 deposit refund strand | ⚠️ **OPEN** (disclosed §8) | `DepositVault` refund-to-relock loop |
| E-3 (Med) — decimal-mismatch flows mis-account | ⚠️ **OPEN** (disclosed §8; latent — all live flows are 6/6) | `claim()` not decimal-aware |
| E-4 (Low) — `burnForRelease` no flow validation | Accepted (off-chain mitigation; indexer monitors unknown-flow burns) | `WrappedERC20.burnForRelease` |
| E-5 (Low) — FoT/rebasing token desync | Accepted (policy: such tokens are not whitelisted) | — |

> **Additional hardening landed at the audit tag (not in the original Codex list):**
> LOW-2 (OPNet `WrappedOP20` EVM-family is now a per-chain governance flag, not a hardcoded
> chainId list) and LOW-3 (EVM `BridgeEscrow` rejects sig blobs where `numSigs > signerCount`).

Auditors should re-confirm O-1/O-2/O-3/O-4 resolve cleanly without regressions, and treat
**E-1/E-2/E-3/O-5 as still-live** — they are intentionally in scope for this engagement.

### OPNet (`docs/CODEX-PREAUDIT-OPNET.md`) — 1 High, 3 Medium, 1 Low

| # | Sev | Title | Location |
|---|---|---|---|
| O-1 | **High** | Non-canonical voucher source fields bypass the source-event replay guard. `_flowIdFromVoucher` truncates `sourceChainId` to `u64` and reads only the first 20B of the right-padded EVM address fields, but `buildSourceEventKey` hashes the full 32B — so two signed vouchers naming the same flow + same source tx/log can produce distinct `_usedSourceEvents` keys (e.g. `chainId=1` vs `2^64+1`, or non-zero address right-pad tail). Could double-mint/double-release within daily-limit/maxSupply **if** the signer ever produces such an alias. Fix: reject non-canonical source fields (chainId ≤ u64, address bytes `[20..32)` zero) before computing the replay key. | `BridgeDepository.ts:3636,3656,1995,2015,4147,4189` |
| O-2 | Medium | `refundBurn` replay key `sha256(burnTxHash‖burnNonce)` omits `wrappedToken` + `burner` — **contradicts the documented invariant** (`CLAUDE.md` §16 / SECURITY.md) that `burnId` binds both. Two wrappeds sharing a `(txHash, nonce)` pair → second legit cancelled burn becomes un-refundable (recovery liveness loss, not extra mint). Fix: `burnId = sha256(wrappedToken‖burner‖burnTxHash‖burnNonce)`; update `isBurnRefunded`. | `BridgeDepository.ts:2805,4054` |
| O-3 | Medium | DRAINING release claims unreachable. `claimReleaseWithVoucher`'s early gate requires status `== ACTIVE`; the later `ACTIVE \|\| DRAINING` check is dead code, so in-flight release vouchers can't be claimed during an orderly wind-down. Fix: make the early gate `ACTIVE \|\| DRAINING` for release claims (keep mint/refundBurn ACTIVE-only if intended). | `BridgeDepository.ts:1944,2041` |
| O-4 | Medium | `BridgeAuthority` upgrades brick after governor handoff — `UpdatablePlugin.applyUpdate` is deployer-only but `onUpdate` requires `tx.sender == _governor`; after `pushGovernor` no caller satisfies both. Fix: mirror the depository's governance-armed deployer model, or drop the plugin if authority is meant to be immutable. | `BridgeAuthority.ts:75,87` |
| O-5 | Low | `setInitialSigner` unconditionally increments `_signerCount` even if the hash was already added via `addSignerToSet`, inflating the count → a satisfiable-looking threshold becomes impossible, bricking verification. Fix: only increment when the hash was absent (as `rotateSigner` already does). | `BridgeDepository.ts:923` |

Codex reported **no standalone findings** in `events.ts` (all three), `AmountPolicy.ts`, or
`WrappedOP20.ts` (mint minter-gated, zero amount/recipient rejected, burn-before-emit,
fail-closed dest-chain allowlist, EVM-recipient padding checked).

OPNet items flagged for the external team: confirm OPNet VM tx-level rollback semantics
after `Revert` (the replay-guard-then-external-call ordering relies on it); corroborate the
O-1 canonicality fix against the server voucher builder; confirm whether OPNet supports
contract-mediated multicall that could emit two `BurnedForRelease` from different wrappeds
in one tx (the O-2 collision path); decide whether `BridgeAuthority` should be upgradeable.

### EVM (`docs/CODEX-PREAUDIT-EVM.md`) — 1 High, 2 Medium, 2 Low

Codex compiled and ran the scoped EVM suite (`forge test --offline` over 8 contracts):
**111 tests passed, 0 failed**.

| # | Sev | Title | Location |
|---|---|---|---|
| E-1 | **High** | Mint-on-EVM paths don't enforce `flow.cap`, and `WrappedERC20` has **no supply cap** — `claimMintWrapped` / `refundBurn` consume only the rolling `dailyLimit` (via `_consumeMintFlowLimits`); `mintFromBridge` has no `maxSupply` check. **Contradicts `SECURITY.md` §6/§7** ("every flow bounded by `cap`", "`maxSupply` ceiling on wrapped tokens"). A compromised signer set can mint across successive 24h windows without ever hitting a cumulative ceiling. Fix: cumulative mint ceiling (capped wrapper, e.g. `ERC20Capped`, or per-flow minted/outstanding accounting) on both paths. (Non-upgradeable wrapper ⇒ fresh deploy + migration.) | `BridgeEscrow.sol:269,1144,1664,1765`; `WrappedERC20.sol:83` |
| E-2 | Medium | CREATE2 deposit-address refund loop — `DepositVault` forwards its balance into `lock()` from its constructor (so `LockRecord.user = msg.sender =` the temporary vault) then self-destructs. `refundLockedDeposit` sends principal back to the now-empty deterministic vault address; re-sweeping just re-locks with the same params → user trapped in a refund-to-relock loop, can't recover to an EVM wallet. Fix: commit an explicit `refundTo` into the CREATE2 initcode / `lockFor(...)` entrypoint, or don't self-destruct until refunds are impossible + add a rescue path. | `DepositVault.sol:31,36,40`; `BridgeEscrow.sol:823,932`; `DepositAddressFactory.sol:47` |
| E-3 | Medium | Decimal-mismatched release flows accepted but `claim()` isn't decimal-aware — `addFlow` allows `evmDecimals != opnetDecimals` and `AmountPolicy.quote` scales correctly, but `claim()` never calls it: it compares/decrements/fees in **source units**. 6→18 release reverts `AmountExceedsGross()`; 18→6 reverts `InsufficientFlowInventory()` or mis-accounts. Fix: either reject release flows where decimals differ, or make `claim()` use `AmountPolicy.quote` + stored flow decimals and require the signed dst amount to match. | `BridgeEscrow.sol:1174,1183,1236,1242,1257,1272,1978`; `AmountPolicy.sol:47` |
| E-4 | Low | `WrappedERC20.burnForRelease()` burns **before** validating `flowId` (existence/ACTIVE/mode/`evmToken` binding) — unlike claim paths. A bad/retired/wrong-token `flowId` burns user tokens with no valid destination voucher path. Fix: registry check before `_burn()` (or route burns through `BridgeEscrow`). (Non-upgradeable ⇒ fresh deploy; min. add indexer monitoring for unknown-flow burns.) | `WrappedERC20.sol:26,101,107,111` |
| E-5 | Low | Fee-on-transfer/rebasing tokens underpay outbound transfers and desync Mode-4 clawback — inbound uses balance-delta but outbound assumes requested == delivered; `clawbackVestedClaim` credits `flow.inventory` by the *returned* amount without measuring the actual delta → overcredit on taxed transfers. Fix: disallow FoT/rebasing tokens for flows, or balance-delta every inbound-to-custody move (esp. clawback). | `BridgeEscrow.sol:1313,1331,1513,1519`; `VestingVault.sol:213,216,247` |

Codex reported **no findings** in: EIP-712 domain/typehash/struct-field inclusion
(`ReleaseIntent`/`MintIntent`/`RefundAuthorization`/`BurnRefundAuthorization`), M-of-N ECDSA
verification (length-prefixed blob, OZ `ECDSA.recover`, authorized-signer + duplicate +
threshold checks), replay-flag CEI ordering, UUPS basics (`_disableInitializers`,
initializer-gated `initialize`, `onlyOwner _authorizeUpgrade`, no arbitrary delegatecall),
the role lattice (freeze/owner-only-unpause/guardian-paused-treasury-pinned drain), and the
Mode-4 vault wiring guard (`vault.token() == flow.evmToken`, bridge-only `depositFor`/`clawback`).

> **⚠️ Doc/code drift flagged by Codex (not a contract bug, but fix before handing the firm the docs):** the source + committed `storage-layout.json` use **`uint256[40] __gap`** after `pauser` + `refundedBurns`, but `CLAUDE.md` §10 (EVM) still says `uint256[42]`. Codex verified local source↔snapshot consistency but **not** deployed-mainnet append-only safety — that out-of-band v1-layout diff remains a pre-mainnet gate (residual risk §8.4).

EVM items flagged for the external team: out-of-band diff of the actual deployed v1 storage
layout vs this source; re-audit `refundBurn` on both chains as a mint primitive (esp. after
adding a cap); review off-chain signer/M-of-N aggregation for genuine key independence;
nail down `dailyLimit` units (source volume vs dst inventory vs minted) — currently
inconsistent across paths; decide whether FoT/rebasing tokens are in scope.

### Cross-cutting themes (both passes)

- **`refundBurn` is the recurring concern on both chains** — O-2 (replay-key doesn't bind
  token+burner) and E-1 (no cumulative cap). Aligns with our own §8.3 residual-risk flag;
  the firm should treat it as the top priority.
- **Three findings contradict the written security model** — O-2 vs the documented `burnId`
  binding, E-1 vs the documented `cap`/`maxSupply` ceilings, and the `__gap` 40-vs-42 doc
  drift. We should reconcile `CLAUDE.md`/`SECURITY.md` with the code (or the code with the
  docs) **before** the firm starts, so they audit against an accurate model.
- **Decimal-aware accounting is half-wired** on both sides (O-1 truncation in flow-id
  derivation; E-3 `claim()` not using `AmountPolicy`) — non-1:1 flows are the soft spot.

---

## 11. Appendix B — message formats (auditor quick reference)

The authoritative, annotated layouts live in `CLAUDE.md` §6 (voucher preimages), §7 (ML-DSA
M-of-N blob), and §8 (selectors + event layouts + the two recipient-padding conventions).
The server-side encoders (`server/src/voucher/`) are the bit-for-bit off-chain counterparty
but are **out of scope and not included** in this contracts-only delivery (the off-chain
signer/server is a separate engagement). To let you check the contract's encode/decode
against a known-good signed message **without the server**, this delivery ships the committed
cross-validation reference vectors at `scripts/src/integration/fixtures/voucher-fixture.{json,bin,sig}`
(and the `-tipped` variant). Treat these bytes as the canonical reference: the contract's
parser must agree with them, and the authoritative field-by-field layout is in `CLAUDE.md` §6
and Appendix B below.

Key layouts (sizes in bytes, all multi-byte fields big-endian):

- **EVM→OPNet ML-DSA voucher — 540B.** `networkId(32) ‖ contractSelf(32) ‖ selector(4) ‖
  recipient(32) ‖ sourceChainId(32) ‖ sourceBridgeAddr(32, RIGHT-pad) ‖ sourceTokenAddr(32,
  RIGHT-pad) ‖ sourceTxHash(32) ‖ sourceLogIndex(4) ‖ sourceDepositNonce(32) ‖
  sourceBlockHash(32) ‖ wrappedToken(32) ‖ grossSrcAmount(32) ‖ grossDstAmount(32) ‖
  feeDstAmount(32) ‖ netDstAmount(32) ‖ relayerTip(16) ‖ signerEpoch(4) ‖ voucherId(32) ‖
  flowId(32)`.
- **ML-DSA M-of-N blob** (the `mldsaSig` arg, variable length): `[u32 numSigs]` then per
  signer `[u32 pubLen][pubKey][u32 sigLen][rawSig]`. LEVEL2: pubKey 1312B, sig 2420B → a
  1-of-1 blob = 3744B.
- **OPNet→EVM EIP-712 `ReleaseIntent`**: `(address token, address to, uint256 amount,
  uint256 srcChainId, bytes32 opnetTxHash, uint32 opnetEventIndex, uint256 burnNonce, uint32
  signerEpoch, bytes32 opnetNonce, uint256 grossSrcAmount, uint128 relayerTip, bytes32
  flowId)`. Domain `{name:"BridgeEscrow", version:"1", chainId, verifyingContract}`.
- **OPNet BurnRefundAuthorization — 296B**, **RefundAuthorization — 264B**, **BurnAttestation
  (confirmBurn) — 252B** — full field lists in `CLAUDE.md` §8.

---

*This packet, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, and `docs/REFERENCE.md` §17–§19
all ship in the delivered contracts-only repo at tag `audit-2026-06-02`. Questions about
intended behavior should be resolved against `docs/SECURITY.md` first.*
