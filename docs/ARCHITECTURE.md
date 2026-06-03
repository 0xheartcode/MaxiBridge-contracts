# Bridge Architecture — One-Page Overview

For load-bearing rules (storage layout, signer model, selectors, non-negotiables) see `CLAUDE.md`.

---

## What It Does

A **general-purpose token bridge** between Ethereum mainnet and OPNet (Bitcoin L1). Governance can onboard almost **any token pair** through five flow modes (wrapped mint/burn, pooled lock/release, pooled lock/vest) with decimal-aware accounting — **USDC/USDT are the launch flows, not a limit**. Depending on the flow's mode, each side does lock-and-release, mint-and-burn, or pooled custody. Both directions use a **voucher model**: the user pays gas on the destination chain, not the server.

```
EVM → OPNet (DEPOSIT)
  User locks USDC in BridgeEscrow.lock()
    → Locked event emitted
  Indexer waits EVM_CONFIRMATIONS blocks
  Server re-checks canonical block hash (reorg guard)
  Server signs ML-DSA voucher bound to source event
  User calls BridgeDepository.claimMintWithVoucher(voucher, sig)
    → wUSDC minted to user

OPNet → EVM (WITHDRAW)
  User burns wUSDC via WrappedOP20.burnForRelease(flowId, ...)
    → BurnedForRelease event emitted (carries flowId — #68)
  Indexer waits OPNET_CONFIRMATIONS blocks
  Server signs EIP-712 ReleaseIntent bound to burn event
  User calls BridgeEscrow.claim(intent, sig)
    → USDC released to user
```

---

## Message Formats

### ML-DSA Voucher (EVM → OPNet, 540 bytes)

Used by `BridgeDepository.claimMintWithVoucher`. The contract hashes the preimage with SHA-256, then verifies the ML-DSA signature against the registered signer pubkey for the current epoch.

| Field | Size | Purpose |
|-------|------|---------|
| `networkId` | 32B | Domain separation — 1=mainnet, 2=testnet |
| `contractSelf` | 32B | Prevents replay on a different BridgeDepository |
| `selector` | 4B | SHA-256(`claimMintWithVoucher(bytes,bytes)`) |
| `recipient` | 32B | OPNet identity key — only this address can claim |
| `sourceChainId` | 32B | 1 = Ethereum mainnet |
| `sourceBridgeAddr` | 32B | EVM BridgeEscrow address (20B right-padded) |
| `sourceTokenAddr` | 32B | EVM USDC or USDT (20B right-padded) |
| `sourceTxHash` | 32B | EVM tx hash of the Locked event |
| `sourceLogIndex` | 4B | Log ordinal — binds to one specific Locked event |
| `sourceDepositNonce` | 32B | Locked.depositNonce from the EVM contract |
| `sourceBlockHash` | 32B | Canonical block hash at sign time (reorg binding) |
| `wrappedToken` | 32B | OPNet wUSDC or wUSDT address |
| `grossSrcAmount` | 32B | Source-side gross (balance-delta on EVM) |
| `grossDstAmount` | 32B | Destination-side gross (= grossSrcAmount until decimal-aware AmountPolicy lands) |
| `feeDstAmount` | 32B | 0.5% fee on destination side |
| `netDstAmount` | 32B | Amount minted to recipient |
| `relayerTip` | 16B | Permissionless tip — PAID OUT on claim (mint-split on OPNet, transfer-carve on EVM; both emit `RelayerTipPaid`; capped per-flow by `tipCapBps`) |
| `signerEpoch` | 4B | Must equal current on-chain epoch |
| `voucherId` | 32B | Unpredictable server nonce — per-voucher replay guard |
| `flowId` | 32B | Flow binding (#68) — appended last; the depository routes the claim by `_flowMode[flowId]`, not by `_tokenMode` |

> **Per-flow routing (#68).** Both chains now resolve the bridge mode from the **flow**, not the token. EVM → OPNet claims route by the voucher's trailing `flowId` (→ `_flowMode[flowId]`); OPNet → EVM burns carry a `flowId` first arg into `burnForRelease`, and the depository likewise routes by `_flowMode[flowId]`. `_tokenMode` is no longer routing-authoritative — one (evmToken, opnetToken) pair can back multiple flows/modes.

**Why ML-DSA?** OPNet's contract VM has deprecated ECDSA in favour of the quantum-resistant ML-DSA scheme. The server holds an ML-DSA keypair (WIF + hex in `.env` for v1; HashiCorp Vault or AWS KMS custom service for production).

### EIP-712 ReleaseIntent (OPNet → EVM)

Used by `BridgeEscrow.claim`. Standard Ethereum typed-data signing. The signer is an ECDSA key (EVM-native).

```solidity
struct ReleaseIntent {
    address token;          // USDC or USDT
    address to;             // recipient — signed, front-run safe
    uint256 amount;         // net amount (fee deducted)
    uint256 srcChainId;     // 1 = OPNet mainnet network id
    bytes32 opnetTxHash;    // source burn tx
    uint32  opnetEventIndex;
    uint256 burnNonce;      // monotonic nonce from WrappedOP20
    uint32  signerEpoch;    // must match current EVM contract epoch
    bytes32 opnetNonce;     // unique server id — EVM replay guard
    uint256 grossSrcAmount; // PR β.2.format — source-side gross
    uint128 relayerTip;     // PR β.2 — permissionless tip (paid to msg.sender)
    bytes32 flowId;         // PR β.2.payout-evm — flow binding + tipCap lookup
}
```

`ECDSA.recover` (via OpenZeppelin) enforces low-s, preventing signature malleability.

---

## Indexer Loop with Reorg Guard

Both scanners (EVM and OPNet) follow the same pattern:

```
1. Load cursor: (last_block, last_block_hash) from indexer_cursors table
2. For each new block:
   a. Fetch block N → extract relevant events
   b. Verify block.hash == expected (reorg check)
   c. If mismatch: walk back to find common ancestor; mark affected rows `reorged`; rewind cursor
   d. If match: upsert events into deposits/withdrawals with UNIQUE constraint (tx_hash, log_index)
   e. Advance cursor: write (N, block.hash) atomically
3. When a row reaches CONFIRMATIONS threshold:
   a. Pre-sign re-check: re-fetch source block by hash; verify tx still in block at log_index; verify N confs met
   b. If checks pass: sign voucher/message; set row status = voucher_ready / signature_ready
   c. If checks fail: mark row `reorged`; do not sign
```

The `UNIQUE(chain_id, evm_tx_hash, evm_log_index)` constraint on the deposits table and `UNIQUE(opnet_tx_hash, opnet_event_index)` on withdrawals prevent double-crediting even if the indexer re-processes a block range.

---

## Signer Rotation — Epoch Model

Neither direction uses deadline-based voucher expiry. Instead, validity is scoped to a **signer epoch**:

- Both contracts store `currentEpoch` (u32).
- Every voucher/message embeds the `signerEpoch` at sign time.
- The contract rejects any claim where `intent.signerEpoch != currentEpoch`.
- Calling `rotateSigner(newKey)` increments `currentEpoch` and stores the new signer identity.
- All old-epoch vouchers/messages immediately stop verifying — no waiting.
- The server detects the new epoch at startup and re-signs all `voucher_ready` / `signature_ready` DB rows with the new key, transparent to the user.

This design means compromising the signing key and rotating it takes all outstanding vouchers to zero-cost invalidation in one transaction, with no expiry clock to race against.

See `RUNBOOK.md` for the step-by-step rotation procedure.

---

## Reserve Monitoring

The `/api/reserves` endpoint computes, per token pair:

- **EVM locked:** balance of `BridgeEscrow` for USDC and USDT
- **OPNet supply:** `totalSupply()` of wUSDC and wUSDT
- **In-flight adjustments:** deposits in `pending_confirmation` or `voucher_ready` (not yet minted) are excluded from the OPNet side; withdrawals in `signature_ready` (burned but not released) are excluded from the EVM side

Thresholds (alert triggers):

| Severity | Absolute mismatch | Relative mismatch |
|----------|-------------------|-------------------|
| Warning  | > $100            | > 0.02%           |
| Critical | > $1,000          | > 0.10%           |

Accrued fees (the 0.5% retained on the source side) are tracked separately and are intentionally excluded from the mismatch calc — they represent protocol revenue, not a reserve gap.

---

## Soft Config Layer

Operators can toggle bridge behaviour at runtime without a server redeploy via a **three-tier config authority**:

```
Tier 1 — env vars (startup defaults, secret-safe)
  ↓ overridden by
Tier 2 — bridge_config DB table (live, operator-editable via admin panel)
  ↓ overridden by
Tier 3 — on-chain governance (immutable until next upgrade ceremony)
```

The `bridge_config` SQLite table holds namespaced string keys:

| Namespace | Example keys | Purpose |
|-----------|-------------|---------|
| `global.*` | `global.maintenance_mode`, `global.maintenance_banner`, `global.announcement` | Site-wide toggles and banners |
| `evm.<chainId>.*` | `evm.1.deposit_enabled`, `evm.1.withdraw_enabled` | Per-EVM-chain deposit/withdraw gates |
| `opnet.<networkId>.*` | `opnet.1.deposit_enabled`, `opnet.1.withdraw_enabled` | Per-OPNet-network deposit/withdraw gates |

**Public endpoint:** `GET /api/config` returns the subset of keys that the dApp is allowed to read (maintenance mode, chain toggles, announcement text). No auth required.

**Admin endpoint:** `GET/POST /api/admin/server-config` allows operators to view all keys and upsert values from the **Server Config** page in the admin panel. Every write is audit-logged to `admin_audit`.

**Frontend hook:** `useServerConfig()` fetches `/api/config` once per page load (module-level cache, deduped promise), then exposes typed helpers: `isMaintenanceMode`, `maintenanceBanner`, `announcement`, `isDepositEnabled(chainId)`, `isOpnetWithdrawEnabled(networkId)`, etc. When `isMaintenanceMode` is true, the Landing page replaces the bridge UI with a maintenance overlay — no redeploy needed.

---

## Token Mode, Custody/Mint Roles & Call Surface

The bridge supports **five flow modes (0–4)**, chosen **per-flow by `flowId`** — the
route's mode is read from `_flowMode[flowId]` on BOTH chains (#68 N:M), *not* from a
per-token stamp. Every mode is **bidirectional**, and one `(evmToken, opnetToken)`
pair can back several modes at once.

### Why exactly five

The modes are not arbitrary — they enumerate every legal combination of **what kind
of asset lives on each chain**, plus one payout variant. For any side, the bridge
either **custodies** the real asset (lock/release moves it in and out of escrow) or
holds **mint** authority over a wrapped representation (mint/burn creates/destroys
supply). Two chains × two roles = four combinations, and mode 4 layers a payout shape
on top of mode 3:

```
Asset NATIVE to one chain (bridge can't mint it — e.g. canonical USDC, MOTO)?
├── native to EVM   → mode 0  WRAPPED            (EVM custody / OPNet mint)
└── native to OPNet → mode 1  INVERSE_WRAPPED     (OPNet custody / EVM mint)

Asset is dual-chain native (bridge holds mint authority on BOTH)?
└── supply MOVES between chains, burn-here = mint-there → mode 2  NATIVE_BURN_MINT

Fixed supply, pre-funded reserves on each side, NO minting?
├── pay destination all-at-once → mode 3  POOLED_LOCK_RELEASE
└── destination drips over time → mode 4  POOLED_LOCK_VEST  (= mode 3 + VestingVault)
```

You don't "pick mode 2" for an existing token — it requires deploying a token whose
mint authority is handed to the bridge on both chains. Custody modes (0/1) are forced
by *where the issuance authority already lives* (you can't mint canonical USDC). Pooled
modes (3/4) are for projects that want one fixed supply shared across chains. Mode 4 is
the only "payout shape" distinction rather than a custody distinction — it exists as a
separate mode (not a flag on 3) because its `claim` leg calls `VestingVault.depositFor`
instead of a plain transfer: different external interface, different clawback semantics.

### Custody vs mint is PER-MODE, not per-chain

"Which chain holds the real asset (lock / pool = **custody**) vs which issues a
wrapped representation (**mint**)" **flips by mode** — it is NOT a fixed property of
EVM vs OPNet:

| Mode | EVM role | OPNet role |
|------|----------|------------|
| 0 `WRAPPED` | **custody** — locks USDC/USDT | **mint** — wUSDC/wUSDT |
| 1 `INVERSE_WRAPPED` | **mint** — WrappedERC20 | **custody** — locks canonical OP20 |
| 2 `NATIVE_BURN_MINT` | mint/burn (no lock) | mint/burn (no lock) |
| 3 `POOLED_LOCK_RELEASE` | **custody** — pre-funded pool | **custody** — pre-funded pool |
| 4 `POOLED_LOCK_VEST` | **custody** — pool; release vests | **custody** — pre-funded pool |

Mode 0 (USDC↔wUSDC, the launch flow) is the *only* one where EVM is purely custody
and OPNet purely mint. Because it dominates today it's tempting to over-generalize
"EVM = custody, OPNet = mint" — but architecturally either chain can be either role.
This is precisely **why OPNet carries the same `treasury` / `guardian` /
`emergencyWithdraw` lattice as EVM**: it genuinely custodies real OP20 in modes 1/3/4,
so those balances need the same pinned-recovery protection EVM gives its locked reserves.

### Call surface per mode (both directions)

Source side **locks or burns**; destination side **mints or releases**. The mode
(via `flowId`) decides which:

| Mode | Direction | Source call | Destination call |
|------|-----------|-------------|------------------|
| 0 | EVM→OPNet (deposit) | EVM `lock` | OPNet `claimMintWithVoucher` (mint) |
| 0 | OPNet→EVM (withdraw) | OPNet `burnForRelease` | EVM `claim` (release USDC) |
| 1 | OPNet→EVM (deposit) | OPNet `lockForBridge` | EVM `claimMintWrapped` (mint) |
| 1 | EVM→OPNet (withdraw) | EVM `burnForRelease` | OPNet `claimReleaseWithVoucher` (release) |
| 2 | EVM→OPNet | EVM `burnForRelease` | OPNet `claimMintWithVoucher` (mint) |
| 2 | OPNet→EVM | OPNet `burnForRelease` | EVM `claimMintWrapped` (mint) |
| 3 | EVM→OPNet | EVM `lock` | OPNet `claimReleaseWithVoucher` (release from pool) |
| 3 | OPNet→EVM | OPNet `lockForBridge` | EVM `claim` (release from pool) |
| 4 | EVM→OPNet | EVM `lock` | OPNet `claimReleaseWithVoucher` (release from pool) |
| 4 | OPNet→EVM | OPNet `lockForBridge` | EVM `claim` → `VestingVault.depositFor` (linear drip) |

Mode 4 is identical to mode 3 on every leg except the **EVM-release** leg, where the
released amount lands in a per-flow `VestingVault` that drips linearly to the
beneficiary over a fixed block window. See `CLAUDE.md` §5 for the two-step setup and
reorg/clawback procedure.

### Cross-chain symmetry of the entry points

The per-chain call surface pairs **1:1** — each chain has BOTH a mint-claim and a
release-claim:

| Role | EVM `BridgeEscrow` | OPNet `BridgeDepository` |
|------|--------------------|--------------------------|
| source lock | `lock` | `lockForBridge` |
| claim → **MINT** wrapped | `claimMintWrapped` | `claimMintWithVoucher` |
| claim → **RELEASE** (escrow/pool/vault) | `claim` | `claimReleaseWithVoucher` |
| burn wrapped | `WrappedERC20.burnForRelease` | `WrappedOP20.burnForRelease` |
| provision pool | `provisionInventory` | `provisionInventoryOpNet` |
| drain pool | `drainFlow` | `drainInventoryOpNet` |
| lock-refund (stranded lock → return principal) | `markDepositRefundable` + `refundLockedDeposit` | `markLockRefundable` + `refundLock` |
| burn-refund (re-mint after dest cancelled) | `refundBurn` | `refundBurn` |
| roles | `setTreasury` / `setGuardian` / `setPauser` / `emergencyWithdraw` / `withdrawFees` | `setTreasury` / `setGuardian` / `setPauser` / `emergencyWithdraw` / `withdrawFees` |

**The transfer AND recovery surfaces are now symmetric, and every mode is bidirectional.**
The lock-refund pair and the `refundBurn` re-mint exist on BOTH chains; the role lattice
(rotatable treasury/guardian, freeze-only pauser, treasury-pinned emergency drain) is
mirrored. `refundBurn` is a mint-authority primitive on both sides → **dedicated re-audit
before mainnet.** Two deliberate asymmetries remain, each with a reason:

- **Signature scheme** — EVM verifies EIP-712 **ECDSA**; OPNet verifies a 540-byte
  **ML-DSA** voucher. Intrinsic to the two L1s. A side effect: the OPNet function name
  is *consensus-bound* (the voucher preimage embeds `sha256('claimMintWithVoucher(bytes,bytes)')`),
  so OPNet names are verbose (`…WithVoucher`/`…ForBridge`) and can't be renamed freely;
  EVM's EIP-712 binds the struct not the function name, so EVM names are terser
  (`claim`, `lock`). Cosmetic divergence, real cause.
- **`confirmBurn`** — OPNet's positive burn attestation for inverse/pooled inventory
  accounting (#44) has no EVM twin; EVM's inventory accounting is local to `claim`. This
  is an accounting-shape difference, not a recovery gap (the recovery primitives above
  are fully mirrored).

### Mode selection & routing — who decides, and how

The mode is a property of the **flow** (a route), not the token, and it's chosen at
flow-registration time:

- **Governance decides which flows exist.** Only the governor can call `addFlow`
  (`BridgeEscrow.addFlow(FlowAddParams{ mode, … })` on EVM,
  `BridgeDepository.addFlow({ mode, … })` on OPNet), which returns
  `flowId = keccak256(identity tuple)`. The two sides must agree on the mode or the
  route's `claim` reverts. **Mode is immutable for a given `flowId`** — there is no
  `setFlowMode`. To "change a token's mode" you register a new flow and drain the old
  one (`drainFlow` → DRAINING, no new locks/mints), or leave both live.
- **The user picks the flow, from a curated menu.** Each transfer carries a `flowId`;
  the user (really, the dApp) selects from the flows governance already registered for
  that exact token pair. This is *not* a free choice — an unregistered `flowId`, a
  token-binding mismatch, an inactive/paused/draining flow, or an over-cap/over-limit
  transfer all revert. The `flowId` is also baked into the **signed voucher preimage**
  and recomputed + asserted on claim (FINDING-003), so a user can't repoint a
  server-signed voucher at a different flow. Think "pick a lane at a toll booth someone
  else built and approved," not "decide the rules."
- **N:M routing.** Because the mode lives on the flow, one `(evmToken, opnetToken)`
  pair can back *several* flows of different modes simultaneously (e.g. MOTO with both
  a pooled mode-3 route and a vesting mode-4 route); the user picks per transfer. In the
  common case a pair has exactly one flow and the dApp fills the `flowId` in silently —
  no mode picker is shown.
- **Operator responsibility.** Because users select from whatever is registered and
  `ACTIVE`, a misconfigured flow is a *live* flow the moment it's added. That's why
  `addFlow` is governor-only, why mode-4 flows defensively reject claims until
  `setFlowVestingVault` is wired, and why each custody-side flow must be separately
  funded via `provisionInventory*` (a mode-3 flow with zero inventory rejects every
  claim even if a sibling flow on the same pair is healthy).

When the indexer processes a deposit or withdrawal event it resolves the flow's mode (via the flowId on the source event, falling back to the on-chain mode view) and stores `token_mode`, `source_event_type`, and `dest_method` on the DB row. The dApp reads `dest_method` from the status API and calls the correct claim function — `ClaimButton` never hard-codes a function name.

---

## Smart Contracts

| Contract | Chain | Purpose |
|----------|-------|---------|
| `BridgeEscrow` | EVM (UUPS proxy) | Holds locked USDC/USDT; verifies EIP-712 on claim; epoch-gated signer |
| `WrappedOP20` | OPNet | wUSDC / wUSDT — mint gated to BridgeDepository; `burnForRelease` emits BurnedForRelease |
| `BridgeDepository` | OPNet | Verifies ML-DSA voucher; dual replay guards (voucherId + sourceTxHash+logIndex); mints via WrappedOP20 |

Both OPNet contracts implement the upgrade commandments from `CLAUDE.md`: append-only storage, version-gated `onUpdate()` migrations, `@final` class decorator, no manual `execute()` dispatch.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| User pays destination gas | Eliminates server wallet funding, removes griefing surface (server can't be DoS'd into paying gas for attackers) |
| No voucher deadlines | Epoch-based invalidation is cleaner than clocks; avoids race conditions where user's voucher expires during a network congestion spike |
| No MIN_BRIDGE floor, no daily cap | Chosen by operator; security comes from signer rotation + KMS (Phase 3), not rate limits |
| `SafeERC20` + balance-delta on EVM | USDT does not return `bool`; balance-delta prevents over-reporting by fee-on-transfer tokens that might be accidentally whitelisted |
| Composite dedup `(tx_hash, log_index)` | Two different events in the same tx (different log indices) must be treated as separate deposits; a simple tx_hash unique constraint would drop the second |
| Separate read `JSONRpcProvider` on frontend | OPWallet extension provider must not be used for reads — it may route through the wallet's own RPC and silently fail on complex queries |

---

*For implementation specifics: contracts in `contracts/op-contracts/` and `contracts/evm-contracts/`; server in `server/`; frontend in `frontend/`. For ops procedures: `docs/RUNBOOK.md`.*
