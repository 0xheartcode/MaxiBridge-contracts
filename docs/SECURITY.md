# MaxiBridge — Security Model & Threat Defenses

This is the **durable, evergreen** description of how the bridge defends itself. It is
the model that point-in-time audits check *against*. When an audit closes a finding, the
corresponding guardrail here should already describe the intended behavior; when this doc
and an audit disagree, the audit is the newer truth and this doc should be reconciled.

- **System overview / how it works**: `docs/ARCHITECTURE.md`
- **Audits**: external audit pending; prior internal review records are in git history.
- **Incident procedures**: `docs/RUNBOOK.md`

The bridge is **defense-in-depth** — almost every exploit has to defeat several
independent layers, not one. The core invariant the whole design protects:

> You cannot forge a signature, and if a signer key is compromised you kill it in one
> epoch bump while the watchdog screams and the bridge can be frozen.

---

## 1. The trust core — voucher / signature integrity

Every cross-chain transfer is authorized by an off-chain signature the destination
contract verifies on-chain.

- **M-of-N signer set, not 1-of-1 trust.** OPNet verifies an M-of-N ML-DSA blob
  (`_verifyMofN`); EVM verifies an M-of-N ECDSA blob (`_verifySignatures`). With
  threshold > 1, a single compromised signer key cannot forge a transfer. (See §11
  for the current 1-of-1 launch posture and the ramp.)
- **Distinct-signer enforcement.** The same key counted twice does not satisfy a
  2-of-3 — duplicates are rejected before the threshold check.
- **Epoch-based instant revocation.** `rotateSigner` / `setRequiredSignatures` /
  `removeSignerFromSet` bump `signerEpoch`; every unclaimed voucher from the old epoch
  stops verifying immediately on-chain. No deadline needed; the server re-signs honest
  pending rows under the new epoch.
- **ML-DSA (quantum-resistant) on OPNet.** ECDSA is deprecated in the OPNet contract VM;
  in-contract verification is ML-DSA Level 2.
- **Full source-event binding.** Each voucher commits to `(sourceChainId,
  sourceBridgeAddr, sourceTokenAddr, sourceTxHash, sourceLogIndex)` — a signature for
  one deposit can't be repointed at a different deposit, token, or chain.

## 2. Domain separation — no cross-context replay

Every signed preimage is prefixed with `networkId ‖ contractSelf ‖ selector`:

- **`networkId`** (1=mainnet, 2=testnet) — a testnet voucher can't replay on mainnet.
- **`contractSelf`** — a voucher for one depository can't replay against another.
- **`selector`** — a `refundBurn` attestation can't be replayed as a `confirmBurn`, etc.
- **`expectedOpnetChainId`** enforced on every EVM claim; **`networkId`** enforced on
  every OPNet voucher.

## 3. Replay guards — every consumable is single-use

| Guard | Protects |
|---|---|
| `_usedVoucherIds` | each voucher consumed once |
| `_usedSourceEvents` (composite key) | each source deposit/burn drained once |
| `refundedBurns` / `_refundedBurns` (burnId) | each burn re-minted once — the ONLY thing stopping infinite re-mint |
| `cancelledVouchers` / `_cancelledVouchers` | Tier-3 cancelled vouchers permanently dead |
| DB `UNIQUE(chain_id, tx_hash, log_index)` | server-side dedup before signing |

All set **before** the external call (CEI).

## 4. Reentrancy & value-movement safety

- **`ReentrancyGuard` / `nonReentrant`** on every state-mutating method, both contracts.
- **CEI ordering** — mark-used / set-replay-flag happens *before* mint or transfer.
- **`SafeERC20`** on EVM (USDT doesn't return a bool; raw `transfer` would silently
  "succeed").
- **Balance-delta accounting** — `received = balanceAfter - balanceBefore`, so
  fee-on-transfer / non-canonical tokens can't desync the ledger.

## 5. The role lattice — privileged-action containment

Mirrored symmetrically on both chains (`CLAUDE.md` §14):

- **owner / governor** — full authority, but on mainnet it's a **3-day
  TimelockController** (EVM) / **`UpdatablePlugin(432 blocks)`** (OPNet). Every
  privileged change gets a 3-day public window for users to exit.
- **guardian** — incident response only: may freeze, cancel vouchers, remove signers,
  and is the **sole** caller of `emergencyWithdraw`.
- **pauser** — freeze-only, nothing else; rotatable, zero = disabled.
- **Freeze-but-never-thaw (H-01)** — owner/guardian/pauser can pause; **only
  owner/governor can unpause**. A compromised pauser/guardian can't keep the bridge
  open after the owner halts it.
- **`emergencyWithdraw`** — guardian-only **+ whenPaused + treasury-pinned**. Three
  conditions; drains only to the pre-set `treasury`, never an arbitrary address. Owner
  can't drain unilaterally.
- **Role-rotation audit trail** — `TreasurySet` / `GuardianSet` emit `(old, new)` so a
  forgotten or accidental rotation is reconstructable from logs.

## 6. Mint-authority hardening (highest blast radius)

The re-mint paths (`refundBurn`) create supply — the scariest surface. Guardrails:

- **Per-flow `dailyLimit`** consumed by `refundBurn` on both chains — a compromised
  signer set can't mint unbounded amounts across fabricated burn tuples.
- **Mode allowlist** — `refundBurn` only mints where the bridge legitimately holds mint
  authority (modes 0/2 OPNet, 1/2 EVM).
- **`maxSupply` ceiling — OPNet `WrappedOP20` only.** Its OP20 base enforces a fixed
  `maxSupply` (set ~`1e24` at deploy = nominal/non-binding, and permanent since the token
  is non-upgradeable). **EVM `WrappedERC20` is intentionally uncapped** (no `maxSupply` /
  `ERC20Capped`) — its mint path is bounded by per-flow `dailyLimit` + the reserve/TVL
  divergence monitor + guardian pause, not a hard ceiling (E-1).
- **`whenNotPaused` / `requireNotPaused`** — pause halts mint authority system-wide.
- **ACTIVE-only** — a DRAINING (winding-down) flow can't be minted into.
- **`burnId` binds `wrappedToken` + `burner`** — per-token burn nonces can't collide and
  block a legitimate recovery.
- **Wrapped tokens are non-upgradeable** — the largest user-facing surface ships as
  immutable code; a flaw means a fresh deploy + migration, never an in-place change.

## 7. Economic rate-limiting (per flow)

Even with valid signatures, every flow is bounded: `cap`, rolling 24h `dailyLimit`,
`minAmount`, `tipCapBps` (relayer-tip cap, max 2%), fee floors. A flow can be `paused` /
`drained` independently. This bounds blast radius per route — a compromised flow can't
drain the whole bridge.

## 8. Reorg defense

- **Confirmations wait** (`EVM_CONFIRMATIONS` / `OPNET_CONFIRMATIONS`) before signing.
- **Pre-sign ancestor re-check** — the indexer re-fetches the block by hash and verifies
  the tx is still at the expected log index before signing.
- **`sourceBlockHash`** baked into the voucher preimage.
- **C-01 invalidation** — a burn reorged out after its voucher was signed is pulled from
  the claimable surface; operator runs `cancelVoucher`.
- **Stranded-lock recovery** — `markDepositRefundable` → `refundLockedDeposit` (EVM) /
  `markLockRefundable` → `refundLock` (OPNet) returns principal when a destination
  voucher is permanently cancelled. The OPNet preimage is **rebuilt from stored lock
  state**, so a refund can only ever target the exact original lock.

## 9. Upgrade safety

- **Append-only storage** (Five Upgrade Commandments) — never reorder/delete/retype a
  field; new fields append at the bottom only.
- **Storage-layout CI diff gate** — `check-storage-layout.sh` fails the build on drift.
- **Governance-gated upgrades** — beyond the timelock, OPNet `applyUpdate` requires a
  one-shot `proposeUpgrade` flag, so a compromised deployer hot key alone can't push
  malicious bytecode (#16b / #43).
- **3-day timelock** on upgrades, both chains — symmetric exit window.
- **Selector-constant runtime asserts** — `onDeployment` verifies each hardcoded
  selector matches `encodeSelector(...)`, so constant drift fails loud at the ceremony
  instead of silently bricking every attestation.

## 10. Operational / monitoring

- **Independent watchdog** (`bridge-watchdog/`) — separate service polling EVM-locked vs
  OPNet-supply; alerts and can auto-pause on critical TVL divergence. Hard-clamps its
  detection threshold so a hostile config can't disable it.
- **Reserve monitoring** every 60s (WARN > $100 / 0.02%, CRITICAL > $1000 / 0.10%).
- **Indexer-lag / signer-health / queue-age monitors.**
- **Two-key model** — the deployer/governor key (signs Bitcoin txs, is `msg.sender`) is
  distinct from the voucher-signer key (signs preimages, stored as a pubkey hash).
  Mixing them is the #1 operational footgun (`CLAUDE.md` §6b).
- **Typed-confirmation gates on ops scripts** — mint-authority and governance-transfer
  scripts refuse to broadcast without an env var re-typing the exact target, so a CLI
  typo can't drain or brick anything (see `docs/RUNBOOK.md` for the `CONFIRM_*` vars).
- **API boundary** — admin routes behind `x-admin-secret` / session auth; identity-hex
  validated; parameterized SQL; CORS allowlist; rate limits.

---

## The M-of-N model in detail

### What it means

- **N** = number of authorized signer keys in the set.
- **M** = threshold — the minimum number of *distinct* valid signatures to authorize a
  transfer.

"2-of-3" = three keys authorized, any two must sign. No single key can authorize alone,
and the bridge survives the loss of N−M keys. The point is to remove the single point of
failure: one stolen signer key shouldn't be able to drain the bridge.

### How verification works

The signer set lives in contract storage and is consulted on every claim:

**OPNet `BridgeDepository`:**
- `_signerKeyHashSet` — map of `sha256(pubkey) → 1` for each authorized signer (the set of N).
- `_signerCount` — N.
- `_requiredSignatures` — M.
- `_signerEpoch` — bumped on any change; instantly invalidates old-epoch vouchers.

The claimer submits a concatenated blob (`CLAUDE.md` §7):

```
[u32 numSigs]
repeat numSigs times:
  [u32 pubLen][signerPubKey][u32 sigLen][rawSig]
```

`_verifyMofN` walks each entry: computes `sha256(pubKey)`, checks it's in
`_signerKeyHashSet` **at the voucher's epoch**, verifies the ML-DSA sig over
`sha256(voucher)`, rejects duplicate signers, and finally asserts
`distinct_valid_count >= _requiredSignatures`.

EVM is the same shape with ECDSA: `mapping(address => bool) isSigner`, `signerCount`,
`signerThreshold`, blob `[uint8 numSigs][sig_0(65)]…`, each `ECDSA.recover`'d, distinct,
counted against threshold.

Key property: **M and N live on-chain; the signatures are gathered off-chain.** The
contract doesn't care *who* coordinates the signers — it counts distinct valid sigs.

### Admin surface

**OPNet** (`onlyGovernorOrAuthority`):

| Method | Effect | Epoch bump? |
|---|---|---|
| `addSignerToSet(pubKeyHash)` | N += 1 | **No** — superset, in-flight vouchers stay valid |
| `removeSignerFromSet(pubKeyHash)` | N −= 1, rejects if N would drop < M | **Yes** — removed key dead immediately |
| `setRequiredSignatures(m)` | M = m, rejects `m == 0` or `m > signerCount` | **Yes** |
| `migrateSignerSet(...)` | atomic add[] / remove[] / set-threshold | **Yes** |

**EVM**: `addSigner(address)` (onlyOwner), `removeSigner(address)`
(onlyOwnerOrGuardian), `setThreshold(uint256)` (onlyOwner),
`migrateSignerSet(address[],address[],uint256)` (atomic).

Asymmetry by design: **adding** a signer doesn't bump the epoch (the old signer's sigs
remain valid in the new superset, so in-flight vouchers don't break); **removing** one
does (a removed/compromised key must die immediately).

The operational ceremony for going multi-signer is in `docs/RUNBOOK.md`.

---

## Current residual risks (be honest)

The design philosophy (`CLAUDE.md` §5) is deliberately "no hard protocol caps; security
from signer integrity + epoch invalidation + strong binding." Per-flow limits were
layered on later as defense-in-depth, not as the primary control. Known gaps:

1. **1-of-1 signer at launch.** The M-of-N machinery is fully built but the threshold is
   1 for launch — a single signer-key compromise is the highest residual risk today.
   Mitigated by instant epoch revocation + the watchdog + pause, but the real fix is the
   M-of-N ramp (#38) and the **KMS signer** (Phase 3 — currently a hot wallet).
2. **No server-side signature distribution layer.** The contracts and the server packer
   (`packOpnetMofN`) are M-of-N-ready, but there is no coordinator that fans a preimage
   out to N *independent* signing services and collects partials. Setting threshold > 1
   while both keys sit in one process gives the *ceremony* of M-of-N without the
   *security* — the win only materializes when the M keys are genuinely independent
   (separate hosts / KMS). This is why the ramp is sequenced after the KMS work.
3. **Ops/recovery scripts are 1-of-1 only (A-3).** `refund-burn-opnet.ts` and
   `mark-lock-refundable-opnet.ts` assemble a single-signer blob; they now refuse loudly
   when `requiredSignatures() > 1` rather than broadcast a doomed blob. A multi-signer
   gather for these flows is an open design decision (CLI args / file drop / interactive).
4. **On-chain v1 storage layout** for the deployed EVM impl must be diffed against the
   current `BridgeEscrow.sol` out-of-band before the mainnet upgrade ceremony — local
   `dev` is clean-append-only but the on-chain-v1 → today delta hasn't been verified
   end-to-end in CI.
