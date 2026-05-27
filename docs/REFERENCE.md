# Bridge — Extended Reference

Extracted from bridge/CLAUDE.md to keep main context small. Read on-demand for ops, history, and detailed procedures.

## 14. Emergency withdraw (`BridgeEscrow.emergencyWithdraw`)

Phase 1.4 hardened this function — it is no longer a single-key escape hatch.

### Phase 1 interface (current)

```solidity
function emergencyWithdraw(
    address token,     // USDC, USDT, or any ERC-20 the escrow holds
    uint256 amount     // in token base units (6 dec for USDC/USDT)
) external nonReentrant whenPaused;
//        ^ onlyGuardian (msg.sender check, not modifier)
```

Funds always go to the `treasury` slot; the destination is never caller-controlled. Emits `EmergencyWithdraw(token indexed, treasury indexed, amount, by indexed)`.

Three independent guards now apply:
1. `whenPaused` — the contract MUST be paused via the owner pipeline first; the guardian alone cannot drain a live bridge.
2. `msg.sender == guardian` — the guardian role is set via `setGuardian(address)` (**owner-rotatable**, not set-once).
3. `treasury != address(0)` — the destination is set via `setTreasury(address)` (**owner-rotatable**). Drain attempts before treasury is set revert with `TreasuryNotSet()`.

Useful for:
- Migrating escrowed funds before a contract upgrade
- Pulling funds during an incident while forensics run

NOT useful for:
- Reclaiming individual test deposits without a full round-trip — the user's three-tier refund path (`cancelVoucher` + `refund` server endpoint) is the right tool now.

### Pre-flight (one-time, after every fresh deploy)

```bash
# Set the guardian (owner-rotatable — pick an EOA on an independent device, paged)
cast send $EVM_BRIDGE_ESCROW \
  "setGuardian(address)" $GUARDIAN_ADDR \
  --private-key $OWNER_KEY --rpc-url $EVM_RPC_URL

# Set the treasury (owner-rotatable — pick the prod Safe address)
cast send $EVM_BRIDGE_ESCROW \
  "setTreasury(address)" $TREASURY_ADDR \
  --private-key $OWNER_KEY --rpc-url $EVM_RPC_URL
```

### Usage via `cast` (incident response)

```bash
# 1. Owner pauses the bridge (REQUIRED — emergencyWithdraw is whenPaused)
cast send $EVM_BRIDGE_ESCROW "pause()" \
  --private-key $OWNER_KEY --rpc-url $EVM_RPC_URL

# 2. Guardian drains balances to the pre-set treasury
BAL=$(cast call $EVM_USDC "balanceOf(address)(uint256)" $EVM_BRIDGE_ESCROW --rpc-url $EVM_RPC_URL)
cast send $EVM_BRIDGE_ESCROW \
  "emergencyWithdraw(address,uint256)" \
  $EVM_USDC $BAL \
  --private-key $GUARDIAN_KEY --rpc-url $EVM_RPC_URL
```

### Risk model
- A compromised **owner** alone can pause but CANNOT drain — guardian role is required.
- A compromised **guardian** alone CANNOT drain — owner-controlled pause is required first.
- A compromised **owner + guardian** drain to `treasury` only — the Safe address is the recovery sink, not an attacker EOA.
- For mainnet: `owner` should be a Safe + `TimelockController` (Phase 2.2 — 3-day delay). `guardian` should be on an independent device, paged via PagerDuty. `treasury` should be a separate Safe (or the same Safe with policy review).

---

## 15. Deploy procedure (fresh / from scratch)

Exact order matters — OPNet contracts reference each other.

```bash
# 1. Make sure `.env` has deployer keys funded on both chains
#    EVM: ETH for gas, EVM_USDC/EVM_USDT whitelisted, EXPECTED_OPNET_CHAIN_ID set
#    OPNet: BTC for funding + reveal + indexing-wait tx fees, OPNET_NETWORK_ID=2
#    Server: MLDSA_SIGNER_WIF + MLDSA_SIGNER_KEY are the voucher signer; they'll
#            be registered via setInitialSigner during wire

# 2. Build everything first so WASMs + artifacts exist
cd bridge
npm run build:contracts         # contracts/op-contracts/build/*.wasm
npm run build:evm               # contracts/evm-contracts/out/

# 3. Deploy
cd scripts
npm run deploy:evm              # prints proxy + impl addresses
                                # writes addresses.json

npm run deploy:opnet            # serial wUSDC → wUSDT → BridgeDepository
                                # BridgeDepository.onDeployment gets 32B u256 networkId from
                                #   OPNET_NETWORK_ID env
                                # Use OPNET_SKIP_INDEX_WAIT=1 if you prefer to verify
                                #   indexing yourself via explorer and don't want 30-min polls

# 4. Wait for the 3 OPNet contracts to be indexed by the RPC
#    (watch mempool.space / opscan, or run `npm run verify` until all are green)

# 5. Wire contracts — setBridgeDepository on both wrapped, addWrappedToken
#    on depository, setInitialSigner on depository
npm run deploy:wire

# 6. Verify all cross-references green
npm run verify                  # PASS/FAIL per field; aim for all PASS

# 7. Append addresses to .env (deploy scripts write addresses.json; mirror
#    key ones to .env so server + frontend pick them up)
#    The addresses currently-deployed are at the bottom of `.env` under
#    "─── Deployed Contract Addresses ───"

# 8. Boot services
cd ..
npm run dev                     # server :8080 + frontend :5173 + admin :5174
```

### `OPNET_SKIP_INDEX_WAIT=1` — what and when

Set this env var to bypass `waitForCodeIndexed` polling inside the deploy script. Use when:
- The OPNet testnet RPC is slow to serve `getCode` for freshly-deployed contracts (known quirk — view methods work, `getCode` lags for several blocks).
- You're watching mempool.space / opscan yourself and don't need the script to block.

Without it, the script polls every 30s for up to 30 min per contract. That's ~1h worst-case for a fresh 3-contract deploy.

---

## 16. Upgrade procedure

### EVM (UUPS proxy)

```bash
# 1. Modify BridgeEscrow.sol (NEVER reorder/delete/retype existing storage;
#    new storage goes BEFORE __gap and __gap shrinks by same amount).

# 2. Rebuild + test
cd contracts/evm-contracts
forge build && forge test

# 3. Refresh committed storage-layout snapshot (ONLY if your changes touch
#    storage; function/event/error additions don't change layout)
python3 -c "
import json
d = json.load(open('out/BridgeEscrow.sol/BridgeEscrow.json'))
s = d.get('storageLayout', {})
open('storage-layout.json','w').write(json.dumps(
    {'storage': s.get('storage', []), 'types': s.get('types', {})},
    indent=2
))
"

# 4. Run upgrade — pass impl name as CLI arg (default: BridgeEscrowV2 test mock)
cd ../scripts
npm run upgrade:evm -- BridgeEscrow

# Script:
# - Loads COMMITTED storage-layout.json
# - Builds new impl, extracts ITS layout
# - Diffs — aborts on any slot move / retype / label change / slot removal (new
#   slots at the end are fine)
# - Deploys new impl
# - Calls proxy.upgradeToAndCall(newImpl, '0x') from owner wallet
# - Updates addresses.json

# 5. Refresh committed snapshot to match new state for future upgrades:
cd ../contracts/evm-contracts
python3 -c "..."   # same block as step 3
```

### OPNet (redeploy as update)

```bash
# 1. Modify contract source (follow Five Upgrade Commandments — append-only
#    storage, @deprecated comments for retired fields, new migration branch
#    in onUpdate gated by _storageVersion check)

# 2. Build
npm run build:contracts

# 3. Run upgrade
cd scripts
npm run upgrade:opnet            # defaults to BridgeDepository; pass CLI arg for
                                 # wUSDC / wUSDT
```

`scripts/src/upgrade/opnet-upgrade.ts` uses `TransactionFactory.signDeployment` with `existingContractAddress` set to the already-deployed bech32 — OPNet treats that as an update. The contract's `onUpdate()` runs once; version-gated migrations execute based on `_storageVersion` value.

---

## 17. Known quirks & gotchas (hit during initial deploy)

### `provider.call()` does NOT work for OPNet writes
The `CallResult` returned from `provider.call()` simulates correctly but `.sendTransaction()` fails with "Contract address not set" (target contract isn't attached to the result). Only `getContract()` produces a CallResult wired for sending. scripts-dev originally wrote `bareSimulateAndSend` using `provider.call` — we rewrote wire-contracts.ts to use `getContract()` with typed ABIs. Anti-pattern documented in workspace CLAUDE.md.

### OPNet `getCode()` indexer lag
After a deploy, the target contract's view methods work immediately (you can call `governor()`, `paused()`, etc.) but `provider.getCode(address)` returns "bytecode not found" for several more blocks. Verify scripts that rely on `getCode` will show FAIL while everything else shows PASS. The script `verify-deployment.ts` reports this explicitly so you can disambiguate.

### `padEnd` vs `padStart` for `ethRecipient`
Frontend `evmAddressToBytes32` MUST use `padStart(64, '0')` — puts address in the LOW 20 bytes. `padEnd` puts it in the HIGH 20 bytes which the contract rejects (`"WrappedOP20: EVM recipient upper 12 bytes must be zero"`). scripts-dev's consistency audit caught this as a BLOCKER — every EVM-destined burn would have reverted.

### Preimage fields use RIGHT-pad; `ethRecipient` uses LEFT-pad
Read §8 (Recipient encoding — WATCH OUT). Two OPPOSITE conventions in the same voucher system. Both are intentional; documented to prevent future confusion.

### `waitForCodeIndexed` can block for 30 min
Indexer delays on OPNet testnet are real. Set `OPNET_SKIP_INDEX_WAIT=1` when you can verify deploys yourself.

### OPNet contract deploys are NOT idempotent by default
Re-running `deploy:opnet` would deploy fresh duplicate contracts. The script now reads `addresses.json` first and skips any already-deployed entry. If you need a fresh re-deploy, manually blank the relevant entries in `addresses.json`.

### OPNet Address comparisons — use `.equals()` / `.isZero()`, NEVER `===`
JS reference equality doesn't work for `Address` objects with identical bytes — they compare unequal. Audit-fix #1 replaced 14 occurrences; regression test guards against future drift.

### Backgrounded OPNet broadcasts create duplicates
Workspace rule: NEVER run OPNet broadcast scripts in the background. Accidentally starting a second instance while the first is polling creates duplicate on-chain state. The Bash tool's `run_in_background=true` or auto-backgrounding on long-running jobs should be avoided. Deploy scripts log their progress — trust them.

### `storage-layout.json` needs `extra_output = ["storageLayout"]` in foundry.toml
Without it, `forge inspect` returns "Could not get storage layout" and the layout in build artifacts is empty. We set this.

### `@btc-vision/transaction` vs `opnet` package — DIFFERENT USE CASES
- `@btc-vision/transaction` = ONLY for `TransactionFactory` (deployments, BTC transfers, signatures)
- `opnet` = for contract interactions (`getContract → simulate → sendTransaction`)
- Mixing them silently produces plain BTC transfers instead of contract calls. This is the #1 OPNet workspace bug.

### Cross-package `opnet` type narrowing
When ABIs are generated under `contracts/op-contracts/abis/` (with the contracts' version of `opnet` types) and imported into `scripts/` (with its own version of `opnet`), TS enum members don't line up. Cast to `any` at the import boundary (per workspace CLAUDE.md "Cross-package type mismatch" guidance).

### Server's `multipart.fieldSize` silently truncates at 4KB
ML-DSA sigs are ~4840 chars. Default `multipart` silently truncates to 4KB, corrupts the blob, sig verification fails downstream. Set `fieldSize: 64 * 1024` on every multipart body handler.

---

## 18. Audit findings status

Two Codex audits run:
1. **Plan-level** (before code): 25 findings (6 CRITICAL, 8 HIGH, 7 MEDIUM, 4 LOW). Full output at `/tmp/bridge-audit-output.txt`.
2. **Shipped-code** (post-implementation): 1 HIGH, 3 MEDIUM, 4 LOW. Full output at `/tmp/bridge-shipped-audit-output.txt`.

Plus scripts-dev's cross-codebase consistency audit which caught **2 BLOCKERs + 3 HIGH + 2 MEDIUM** that would have only surfaced in production.

### Status (as of April 18 2026)

**Closed** — all plan-level CRITICALs and HIGHs; both consistency audit BLOCKERs; several shipped-code findings:
- ✅ SafeERC20 + balance-delta on EVM lock
- ✅ Strict EIP-712 + low-s ECDSA
- ✅ Recipient `to` bound in signed struct (front-run safe)
- ✅ UUPS hardening full checklist
- ✅ Source-tx identity in every voucher (txHash + logIndex + bridgeAddr + tokenAddr + chainId)
- ✅ ReentrancyGuard + CEI on both sides
- ✅ Composite `(tx_hash, log_index)` replay guards on both chains
- ✅ Fee rounding `max(minFee, amount*bps/10000)` in server (on-chain only enforces `gross == fee + net`)
- ✅ `_storageVersion` first + append-only OPNet storage discipline
- ✅ Register endpoint pre-validates tx before creating DB row
- ✅ Session-only admin auth in prod
- ✅ ML-DSA voucher preimage binding (540 bytes incl. trailing flowId — #68; full field list)
- ✅ `@method`/`@view` decorators only; no manual `execute` dispatch
- ✅ Signer epoch invalidation (no deadlines)
- ✅ Address equality `.equals()/.isZero()` (14 locations fixed)
- ✅ `VOUCHER_NETWORK_ID` deploy-time initialized via `_networkId` StoredU256
- ✅ `UpdatablePlugin(144)` registered on both OPNet contracts
- ✅ ML-DSA blob canonical length checks (`sig.length == 3736`, `pubLen == 1312`)
- ✅ Widened source-event replay key (chainId + bridgeAddr + tokenAddr + txHash + logIndex)
- ✅ `WrappedOP20.burnForRelease` pauseable (`_paused` + `setPaused` + `paused()`)
- ✅ Signer epoch u32 bound check in `rotateSigner`
- ✅ EVM `srcChainId` enforced in `claim` (via `expectedOpnetChainId`)
- ✅ Padding bug (frontend `padEnd` → `padStart`) — consistency audit BLOCKER #1
- ✅ `MintedFromVoucher` parser offsets (server read wrong fields) — consistency audit BLOCKER #2

**Deferred (pre-mainnet-with-real-volume, not blocking current test):**
- 🟨 **HIGH** Pin `@btc-vision/btc-runtime` package version + commit a full storage layout snapshot including base-class slots (analogous to `contracts/evm-contracts/storage-layout.json`) — mitigates drift when the runtime bumps.
- 🟨 **MEDIUM** Replace `unchecked { amountReceived_ = balAfter - balBefore; }` with a `require(balAfter > balBefore)` check. Canonical USDC/USDT are safe; only matters if `setSupportedToken` ever enables a rebasing/receiver-fee token later.
- 🟨 **MEDIUM** Runbook note: always call `setInitialSigner` immediately after depo deploy (already done this run).
- 🟨 **LOW** `setSupportedToken(disabled)` blocks in-flight signed claims for that token — emergency kill switch, intentional; document.
- 🟨 **LOW** Future multi-EVM chain IDs need their own zero-upper-byte allowlist in `WrappedOP20` (currently hardcoded to 1 + 11155111).

**Operational (not contract-level, not blocking):**
- Postgres migration from SQLite (scale)
- AWS KMS / Vault for signer keys
- TimelockController as UUPS upgrade authority
- Safe multisig as `owner`
- External audit (Trail of Bits / OZ)
- Bug bounty (Immunefi)
- Flashbots/Protect RPC for EVM claim submission
- Public proof-of-reserves page

Full Mainnet Pre-Launch Checklist lives at the bottom of the plan file.

---

## 19. Test matrix

| Suite | Count | Command | Harness |
|-------|-------|---------|---------|
| EVM Foundry unit + fork | 46 | `forge test` | forge-std |
| OPNet contracts | 41 | `npm test` in `contracts/op-contracts/` | `@btc-vision/unit-test-framework` |
| Server (core) | 30 | `npm test` in `server/` | `node --test` |
| Server (monitoring) | 15 | same suite | same |
| Frontend smoke | 6 | `npm test` in `frontend/` | vitest |
| **Total** | **138** | `npm run test:all` | |

CI workflows in `.github/workflows/` run per-subdir on path filters.

---

## 20. Deploy history

### 2026-04-17 → 2026-04-18

- **EVM BridgeEscrow** deployed to Ethereum mainnet (chainId 1)
  - Impl v1: `0x4ab61d5F9c1324A9f279bF216e162abb7940DB52` (initial deploy, no emergencyWithdraw)
  - Impl v2: `0x5c8194FbeF33f499B92d8199d1C62cFA5cD4a9Bc` (post-upgrade, adds emergencyWithdraw)
  - Proxy: `0xc63BF445E59607Ae30AB377fAe10260BA626bF68` (unchanged across upgrade)
  - Upgrade tx: `0x7086658f4cc27ebfb1cb62ccf5e1b3ff342d9d511c03c0497b7309984924b7a5` (block 24903764)
  - Whitelisted: canonical mainnet USDC + USDT
  - Owner / signer / deployer: `0x5DB730b89351F286fE1825B02d68d09C1bA6Efc6` (conflated for v1 test)
  - `expectedOpnetChainId`: `2` (OPNet testnet)

- **OPNet side** deployed to OPNet testnet (networkId 2)
  - `wUSDC`: `opt1sqrf3csku5dgwzkuvdpax45lcm4936mzznchnf3hv`
    - Funding tx: `f71e53b52d11ed383763a63bcbb497e9c8a24df66e6d02f91bf711a72ac04cd9`
    - Reveal tx: `4af1a25e6b946d67040c3a9892160dc1ad41f2817247ec22e227f369dd8fb477`
  - `wUSDT`: `opt1sqzs6xa5jn8jdgs65j4j6le0f2m8s6jewxy6k00fy`
    - Funding tx: `b7e93ce6b549155a508bce6a2d3cb039f70d94e999b2f3cfccbdd9bcc362d5e5`
    - Reveal tx: `ef197fa69c0b30752730a52d877d01c48554e0b8168dcbe68f8df0754363ff0d`
  - `BridgeDepository`: `opt1sqr2gjw4s4l5dcjr4w0y9h97x6vdl5q77ncxqxr70`
    - Funding tx: `25c76b516a765cc5370044c4f0afd73f5e5e7a29a90bd5f10a4ef73bab28529a`
    - Reveal tx: `eaae0d2a50500a92e51d3a62d9a90c11c6ecc4b1535ee63b8995d40f66318d99`

- **Wiring** (5 txs, all on OPNet testnet)
  - `wUSDC.setBridgeDepository(depo)`: `b7f3f90f0e17fdc38bccea4dd55d282f010c9f0a1a10b9393e8038a0b99b22cc`
  - `wUSDT.setBridgeDepository(depo)`: `41ccf4a2dce8a0a322151ec5b0f102f7b4c3eb06060bfb97e092d5d285fbd4da`
  - `depo.addWrappedToken(wUSDC)`: `dc187abd66c06c8b5a8fc0d33bc900f6c475c1356fe53d18ad8e5db551035b20`
  - `depo.addWrappedToken(wUSDT)`: `f4872cfd7c5eecd2601ea0787871c175446dd127b9a37f86e102cdd5a9b1ba30`
  - `depo.setInitialSigner(1312B pubkey)`: `b1cb4d786c056ed4072839795bb7f543a2ef798887f4b799770c314e6596a595`

- **`verify-deployment.ts` result:** 16/19 PASS + 3 cosmetic FAILs (getCode indexer lag while view methods already work).

---

## 21. References

### Workspace-level
- `/Users/dippy/Documents/code/opnet/CLAUDE.md` — OPNet-wide rules, Five Upgrade Commandments, Selector System, Two-Key Problem, Gas & Fees, Anti-Patterns
- `/Users/dippy/.claude/plans/zesty-sleeping-thacker.md` — master plan, audit responses, locked decisions

### Copied / inspired patterns
- Voucher preimage + ML-DSA signing: `/Users/dippy/Documents/code/opnet/slohmV2/server/src/voucher.ts`
- Voucher contract pattern: `/Users/dippy/Documents/code/opnet/slohmV2/contracts/src/bonds/BondDepository.ts` lines 829–921
- OPNet indexer: `/Users/dippy/Documents/code/opnet/utxobot/src/indexer/{scanner,state,provider}.ts`
- OPWallet connect + two-key: `/Users/dippy/Documents/code/opnet/slohmV2/frontend/src/hooks/{useWallet,useMLDSAIdentity}.ts`
- Admin auth (session + bcrypt): `/Users/dippy/Documents/code/opnet/slohmV2/server/src/routes/auth.ts`
- OP20 base template: `/Users/dippy/Documents/code/opnet/tokens/contracts/src/dippy/DippyToken.ts`
- ECDSA claim pattern (EVM inspiration, NOT code to copy): `/Users/dippy/Documents/code/barkbridgeback/`

### Project docs
- `docs/ARCHITECTURE.md` — technical overview
- `docs/RUNBOOK.md` — incident response (pause, signer compromise, reorg, stuck deposit)
- `docs/TERMS.md` — DRAFT frontend T&C

### Audit artifacts
- `/tmp/bridge-audit-output.txt` — initial Codex plan audit (25 findings)
- `/tmp/bridge-shipped-audit-output.txt` — post-implementation Codex audit
- scripts-dev's consistency audit — in conversation history, key findings in this file §17

---

## 22. Never / anti-patterns

- Raw PSBT (`new Psbt()`, `Psbt.fromBase64()`) — FORBIDDEN in all OPNet code
- `@btc-vision/transaction` for contract CALLS (it's for `TransactionFactory` only — deployments, BTC transfers)
- `bitcoinjs-lib`, `ecpair`, `tiny-secp256k1`, `express`/`fastify`/`koa`
- `networks.testnet` (that's Testnet4) or `networks.regtest` — use `networks.opnetTestnet`
- Committing `.env` or any secret
- `provider.call()` for OPNet writes (silent BTC-transfer trap) — use `getContract()`
- Manual `execute()` dispatch in OPNet contracts (SDK incompatibility)
- Setting `CallResult.calldata` manually — wallet extension ignores
- Running OPNet broadcast scripts in the background (duplicate on-chain state)
- `Number(bigint)` for token amounts (precision dies above 2^53)
- Fee-on-transfer or rebasing tokens in the EVM whitelist (only canonical USDC + USDT)
- `padEnd` for `ethRecipient` bytes32 encoding (puts address in HIGH bytes — reverts)
- `padStart` for preimage `sourceBridgeAddr`/`sourceTokenAddr` (breaks bit-for-bit agreement with contract)
- JS `===` / `!==` on OPNet `Address` objects (use `.equals()` / `.isZero()`)
- `provider.sendTransaction(sim, ...)` — it's `sim.sendTransaction({...})` on the CallResult itself
- Daily caps / per-wallet velocity / MIN_BRIDGE_USD floor (user decision: no limits for v1)
- Voucher deadlines (user decision: use `signerEpoch` instead)
- `x-admin-secret` as prod admin auth (session-only in prod; dev fallback only)
- Hardcoding `VOUCHER_NETWORK_ID` — deploy-time initialized via `_networkId` storage slot
- `0x` prefix on addresses in `JSONRpcProvider.call()` — expects raw bytes; but string prefix needed for `provider.call` hex form (check call site)
- Skipping `super.onDeployment(calldata)` / `super.onUpdate(calldata)` as first line of overrides — plugin storage won't initialize
- ML-DSA blob as raw sig (must be `[pubLen][pubkey][rawSig]` = 3736 bytes for L2)
- Committing Ralph artefacts (`progress.txt`, `prd.json`, `pdr.txt`, `AGENTS.md`, `PLAN.md`)
- `Co-Authored-By: Claude` lines in commit messages
