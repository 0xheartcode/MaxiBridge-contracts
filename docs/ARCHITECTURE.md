# Bridge Architecture — One-Page Overview

For full design rationale and locked decisions see the master plan at `/Users/dippy/.claude/plans/zesty-sleeping-thacker.md`.

---

## What It Does

Moves USDC/USDT between Ethereum mainnet and OPNet (Bitcoin L1). Lock-and-release on EVM, mint-and-burn on OPNet. Both directions use a **voucher model**: the user pays gas on the destination chain, not the server.

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
  User burns wUSDC via WrappedOP20.burnForRelease()
    → BurnedForRelease event emitted
  Indexer waits OPNET_CONFIRMATIONS blocks
  Server signs EIP-712 ReleaseIntent bound to burn event
  User calls BridgeEscrow.claim(intent, sig)
    → USDC released to user
```

---

## Message Formats

### ML-DSA Voucher (EVM → OPNet, 508 bytes)

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
| `relayerTip` | 16B | Permissionless tip (signed over; payout in a future PR) |
| `signerEpoch` | 4B | Must equal current on-chain epoch |
| `voucherId` | 32B | Unpredictable server nonce — per-voucher replay guard |

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

## Token Mode & Dest-Method Tagging

The bridge supports four token flow modes (on-chain enum on `BridgeEscrow`):

| Mode | Name | EVM → OPNet | OPNet → EVM |
|------|------|-------------|-------------|
| 0 | `WRAPPED` | lock → `claimMintWithVoucher` | burn → `claim` |
| 1 | `INVERSE_WRAPPED` | lock → `claimMintWithVoucher` | burn → `claimReleaseWithVoucher` |
| 2 | `NATIVE_BURN_MINT` | burn → `claimMintWithVoucher` | burn → `claim` |
| 3 | `POOLED_LOCK_RELEASE` | lock → `claimMintWrapped` | burn → `claim` |

When the indexer processes a deposit or withdrawal event it resolves the token's mode via `GET /api/tokens/:address/mode` (which proxies the on-chain `tokenMode` view) and stores `token_mode`, `source_event_type`, and `dest_method` on the DB row. The dApp reads `dest_method` from the status API and calls the correct claim function — `ClaimButton` never hard-codes a function name.

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
