# Bridge — Project Reference

Authoritative project reference for the EVM ↔ OPNet bridge. Read this first before any coding, deploy, or ops work. Supplements (never contradicts) the workspace-wide rules at `/Users/dippy/Documents/code/opnet/CLAUDE.md`.

Master plan: `/Users/dippy/.claude/plans/zesty-sleeping-thacker.md`.

---

## 1. What this is

A cross-chain bridge for **USDC/USDT** between **Ethereum mainnet** (chainId 1) and **OPNet testnet** (network id 2). Two directions, both voucher-based (user pays destination-side gas):

```
EVM → OPNet (deposit)                    OPNet → EVM (withdraw)
─────────────────────                    ──────────────────────
1. User locks USDC/USDT via              1. User burns wUSDC/wUSDT via
   BridgeEscrow.lock(...)                   WrappedOP20.burnForRelease(...)
   → Locked event                           → BurnedForRelease event
2. Indexer waits EVM_CONFIRMATIONS       2. Indexer waits OPNET_CONFIRMATIONS
3. Server signs 460-byte ML-DSA          3. Server signs EIP-712 ReleaseIntent
   voucher (free, off-chain)                (free, off-chain)
4. dApp shows "Claim wUSDC"              4. dApp shows "Claim USDC"
5. User signs claimMintWithVoucher       5. User signs BridgeEscrow.claim(sig)
   (pays OPNet gas)                         (pays ETH gas)
6. Contract verifies ML-DSA + nonce      6. Contract verifies EIP-712 + nonce
   → mints wUSDC/wUSDT                      → releases USDC/USDT
```

**Fee:** 0.5% (50 bps), deducted on the source side of each direction.

---

## 2. Current deployment state

**EVM — Ethereum mainnet (chainId 1):**

| | Address |
|---|---|
| `BridgeEscrow` proxy | `0xc63BF445E59607Ae30AB377fAe10260BA626bF68` |
| `BridgeEscrow` implementation (v2, post-emergencyWithdraw) | `0x5c8194FbeF33f499B92d8199d1C62cFA5cD4a9Bc` |
| Canonical USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| Canonical USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` |
| Owner / deployer | `0x5DB730b89351F286fE1825B02d68d09C1bA6Efc6` |
| EIP-712 signer | `0x5DB730b89351F286fE1825B02d68d09C1bA6Efc6` (same as owner for v1 test) |
| Current signer epoch | `1` |
| `expectedOpnetChainId` | `2` (OPNet testnet) |

**OPNet — testnet:**

| | bech32 |
|---|---|
| `wUSDC` | `opt1sqrf3csku5dgwzkuvdpax45lcm4936mzznchnf3hv` |
| `wUSDT` | `opt1sqzs6xa5jn8jdgs65j4j6le0f2m8s6jewxy6k00fy` |
| `BridgeDepository` | `opt1sqr2gjw4s4l5dcjr4w0y9h97x6vdl5q77ncxqxr70` |
| Deployer / governor | `opt1pzd2404nxv4w7ms93a46hyx2jggmlakjh8wf8dt82j57nazm5maxs0egawz` |
| `networkId` | `2` (testnet) |
| Current signer epoch | `1` |
| ML-DSA signer pubkey hash @ epoch 1 | derived from `MLDSA_SIGNER_WIF`/`MLDSA_SIGNER_KEY` in `.env` |

**Source of truth:** `scripts/src/addresses.json` (updated by deploy / wire / upgrade scripts). Root `.env` mirrors these for server + frontend runtime use.

---

## 3. Directory structure

```
/Users/dippy/Documents/code/opnet/bridge/
├── .env                      # SECRETS + ADDRESSES — gitignored, do not edit fields other than append
├── .env.example              # shape + Sepolia commented alt
├── CLAUDE.md                 # THIS FILE
├── README.md
├── dev-all.sh                # concurrent runner (server + frontend + admin panel)
├── package.json              # root scripts — npm run dev / build:* / test:*
├── Dockerfile                # multi-stage: builds all three + single runtime container
├── railway.toml              # BitBrace workspace volume mount
│
├── evm-contracts/            # Solidity + Foundry (UUPS BridgeEscrow)
│   ├── src/BridgeEscrow.sol
│   ├── test/                 # 46/46 passing (+ fork tests behind SEPOLIA_RPC_URL)
│   ├── script/Deploy.s.sol
│   ├── script/check-storage-layout.sh
│   ├── storage-layout.json   # COMMITTED snapshot — CI diff gate for upgrades
│   └── foundry.toml          # extra_output = ["storageLayout"]
│
├── contracts/                # OPNet AssemblyScript
│   ├── src/
│   │   ├── wrapped/WrappedOP20.ts
│   │   ├── wrapped/events.ts
│   │   ├── bridge/BridgeDepository.ts
│   │   └── bridge/events.ts
│   ├── __test__/unit/        # 41/41 passing
│   ├── abis/                 # Auto-generated ABIs (BridgeDepository.*, WrappedOP20.*, OP20.*)
│   ├── asconfig.json
│   ├── tsconfig.json
│   └── package.json          # Sacred versions — see §8
│
├── server/                   # hyper-express + better-sqlite3 + ethers v6 + opnet
│   ├── src/
│   │   ├── index.ts          # CORS + /health + routes + indexers + monitoring + static serve
│   │   ├── config.ts         # Zod-validated env
│   │   ├── db/               # schema.sql + migration runner
│   │   ├── routes/           # auth.ts, bridge.ts, admin.ts
│   │   ├── indexer/          # evm-scanner.ts, opnet-scanner.ts, cursor.ts, reorg-guard.ts
│   │   ├── voucher/          # opnet-voucher.ts (ML-DSA) + evm-message.ts (EIP-712)
│   │   ├── signers/          # EcdsaSigner / MldsaSigner interfaces — hot-wallet v1; KMS swap-in later
│   │   └── monitoring/       # TVL, indexer lag, signer health, queue age, reorg counters
│   └── package.json          # 30/30 tests + 15 monitoring = 45 passing
│
├── frontend/                 # React 19 + Vite 6 + Tailwind v4 (public dApp)
│   ├── vite.config.ts        # envDir: '../', node polyfills, stream-browserify alias
│   ├── src/
│   │   ├── abi/              # bridgeEscrow.ts, bridgeDepository.ts, wrappedOP20.ts
│   │   ├── hooks/            # useEvmWallet (wagmi), useOpnetWallet (OPWallet two-key)
│   │   ├── store/            # Zustand — bridgeStore, walletStore
│   │   ├── pages/            # Bridge.tsx, History.tsx, Claim.tsx
│   │   ├── components/       # TermsModal, AddressConfirm, BridgeForm, ClaimButton, ...
│   │   └── lib/              # utils.ts — evmAddressToBytes32 uses padStart!
│   └── package.json          # 6/6 smoke tests passing
│
├── admin-panel/              # React 19 + Vite (separate ops UI on port 5174)
│   ├── vite.config.ts        # base: '/admin/', envDir: '../'
│   └── src/                  # Login, Dashboard, DepositsQueue, WithdrawalsQueue,
│                             # Tokens, SignerRotation, Reserves, Pause, AuditLog
│
├── scripts/                  # Deploy + upgrade + ops (TypeScript + tsx)
│   ├── src/
│   │   ├── addresses.json    # CANONICAL deployed address registry
│   │   ├── lib/              # env, addresses, evm-client, opnet-client, opnet-bare,
│   │   │                     #   opnet-deploy, abi-loaders, timeouts
│   │   ├── deploy/           # evm-deploy.ts, opnet-deploy.ts, wire-contracts.ts
│   │   ├── upgrade/          # evm-upgrade.ts (storage-layout diff gate), opnet-upgrade.ts
│   │   ├── ops/              # rotate-signer-{evm,opnet}, pause-{evm,opnet},
│   │   │                     #   unpause-*, add-supported-token-evm, set-fee-bps,
│   │   │                     #   verify-deployment, balances, generate-signer
│   │   └── integration/      # round-trip.ts, security-drills.ts, verify-contracts.ts,
│   │                         #   generate-fixture.ts, verify-fixture.ts
│   └── package.json
│
├── docs/
│   ├── ARCHITECTURE.md       # one-page technical overview
│   ├── RUNBOOK.md            # signer compromise, pause, reorg, stuck-deposit recovery
│   └── TERMS.md              # DRAFT T&C for frontend modal (legal review required)
│
└── .github/workflows/        # CI matrix — per-subdir paths filter
    ├── evm-ci.yml            # forge build + test + storage-layout diff
    ├── opnet-contracts-ci.yml
    ├── server-ci.yml
    ├── frontend-ci.yml
    ├── admin-ci.yml
    └── scripts-ci.yml
```

---

## 4. Quick-start commands

All run from `bridge/` root unless noted. Every subdir has its own `package.json` — this is OPNet convention (no npm workspaces).

```bash
# Boot everything locally (server :8080, frontend :5173, admin :5174)
npm run dev

# Build everything
npm run build:contracts       # OPNet WASMs (both)
npm run build:evm             # Foundry
npm run build:server          # tsc + schema copy
npm run build:frontend        # vite build
npm run build:admin           # vite build (base=/admin/)

# Run entire test suite
npm run test:all              # 46 EVM + 41 OPNet + 45 server + 6 frontend = 138 passing

# Individual test suites
npm run test:evm              # forge test
npm run test:contracts        # @btc-vision/unit-test-framework
npm run test:server           # node --test
npm run test:frontend         # vitest

# Deploy (from scripts/)
cd scripts
npm run deploy:evm            # BridgeEscrow proxy + impl + initialize
npm run deploy:opnet          # wUSDC → wUSDT → BridgeDepository (serial)
                              #   set OPNET_SKIP_INDEX_WAIT=1 to skip getCode polling
npm run deploy:wire           # setBridgeDepository + addWrappedToken + setInitialSigner
npm run verify                # PASS/FAIL table across both chains

# Upgrade (from scripts/)
npm run upgrade:evm -- BridgeEscrow      # defaults to BridgeEscrowV2 test mock
npm run upgrade:opnet                    # redeploy a contract's WASM as update

# Ops (from scripts/)
npm run pause:evm / unpause:evm
npm run pause:opnet / unpause:opnet
npm run rotate:evm <new_address>
npm run rotate:opnet <new_pubkey_hex>
npm run balances             # escrow vs wrapped totalSupply — reserve check
npm run generate-signer      # prints new wallet keys (doesn't write .env)

# Integration (from scripts/)
npm run integration:dry-run            # compile + plan, zero network
npm run integration:verify             # on-chain coherence PASS/FAIL
npm run integration:fixture            # rebuild voucher cross-validation fixture
npm run integration:fixture:verify     # re-check committed fixture
npm run integration                    # live round trip (INTEGRATION_LIVE=1 gated)
npm run integration:drills             # security drills (replay, rotation, reorg)
```

---

## 5. Architecture (locked)

1. **Chains v1:** Ethereum mainnet + OPNet testnet. Hybrid: real USDC/USDT locked on-chain, wrapped tokens on OPNet testnet for safety during initial testing.
2. **Wrapped tokens:** unified — one `wUSDC`, one `wUSDT` on OPNet, 1:1 backed, 6 decimals (matches USDC/USDT). Future multi-chain expansion means same wUSDC is backed by all chains' USDC combined (fungibility risk to re-audit when adding BSC/Arb/Base).
3. **Both sides upgradeable:**
   - **EVM:** OZ UUPS proxy with full hardening (`_disableInitializers` in impl ctor, `initializer` gated init, `_authorizeUpgrade` onlyOwner, no `selfdestruct`, no arbitrary `delegatecall`, `uint256[49] __gap`, storage-layout CI diff gate).
   - **OPNet:** `UpdatablePlugin(144 blocks)` registered in every contract ctor; `onUpdate()` runs migrations gated by `_storageVersion: StoredU256`; storage APPEND-ONLY per workspace "Five Upgrade Commandments".
4. **Single root `.env`** at `/Users/dippy/Documents/code/opnet/bridge/.env` shared by server / scripts / contracts. Frontend + admin-panel read it via Vite `envDir: '../'`.
5. **No protocol limits.** No floor, no daily caps, no per-wallet velocity. Security comes from:
   - AWS KMS signer (Phase 3; hot wallet for v1 dev)
   - Epoch-based signer invalidation (instantaneous rotation)
   - Strong source-event binding in every voucher/sig (chainId + bridgeAddr + tokenAddr + txHash + logIndex)
6. **No voucher deadlines.** A voucher is valid as long as its `signerEpoch` is the current epoch. Rotating the signer invalidates all unclaimed vouchers from the old epoch instantly; server re-signs honest pending rows with the new epoch.
7. **Fee:** 0.5% (50 bps), deducted on the source side of each direction. `fee = max(minFee, amount * feeBps / 10_000)`; reject if `fee == 0n` OR `amount <= fee`.
8. **`emergencyWithdraw` exists on `BridgeEscrow`** (added post-deploy via upgrade #1). `onlyOwner + nonReentrant`; drains any ERC-20 held by the escrow to an arbitrary recipient. For v1 test only; long-term the `owner` role moves to a Safe multisig + timelock.

---

## 6. Voucher preimages (CRITICAL — both sides)

### EVM → OPNet (ML-DSA, 460 bytes)

```
Offset  Size  Field
  0     32    networkId           (u256 BE) — 1=mainnet, 2=testnet; domain separation
 32     32    contractSelf        (Address) — BridgeDepository's own identity
 64      4    selector            (u32 BE)  — SHA-256('claimMintWithVoucher(bytes,bytes)')
 68     32    recipient           (Address) — tx.sender binding (theft-proof)
100     32    sourceChainId       (u256 BE) — 1 = Ethereum mainnet
132     32    sourceBridgeAddr    (bytes20 RIGHT-PAD: addr in [0..20), zeros in [20..32))
164     32    sourceTokenAddr     (bytes20 RIGHT-PAD: addr in [0..20), zeros in [20..32))
196     32    sourceTxHash        (bytes32)
228      4    sourceLogIndex      (u32 BE)
232     32    sourceDepositNonce  (u256 BE) — from Locked event
264     32    sourceBlockHash     (bytes32) — canonical hash at sign time (reorg guard)
296     32    wrappedToken        (Address) — OPNet wUSDC or wUSDT
328     32    grossAmount         (u256 BE)
360     32    feeAmount           (u256 BE)
392     32    netAmount           (u256 BE)
424      4    signerEpoch         (u32 BE)  — MUST equal _signerEpoch at verify time
428     32    voucherId           (u256 BE) — per-voucher replay guard
460          = total → SHA-256 → 32B hash → ML-DSA verify
```

14 × 32B + 3 × 4B = 460B. Server + contract + test fixture must agree **bit-for-bit** — a single-byte drift fails ML-DSA verify on-chain.

Cross-validation fixture: `scripts/src/integration/fixtures/voucher-fixture.{json,bin,sig}`. Run `npm run integration:fixture:verify` to diff against committed bytes (catches drift with first-divergent-byte reporting).

### OPNet → EVM (EIP-712 typed struct)

```solidity
struct ReleaseIntent {
    address token;
    address to;
    uint256 amount;
    uint256 srcChainId;
    bytes32 opnetTxHash;
    uint32  opnetEventIndex;
    uint256 burnNonce;
    uint32  signerEpoch;
    bytes32 opnetNonce;
}
```

Domain: `{ name: "BridgeEscrow", version: "1", chainId: <EVM_CHAIN_ID>, verifyingContract: <proxy addr> }`.

Typehash string (MUST match `BridgeEscrow.sol` byte-for-byte):
```
ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)
```

---

## 7. ML-DSA signature blob format (CRITICAL)

The `mldsaSig` arg passed to `claimMintWithVoucher(voucher, mldsaSig)` is **NOT** a raw ML-DSA signature. It is a prefix-packed blob so the contract can recover which signer pubkey produced the sig and verify the pubkey is the currently-allowed signer for the voucher's epoch:

```
[pubLen : u32 big-endian (4B)] [signerPubKey : bytes] [raw ML-DSA sig : bytes]
```

For ML-DSA LEVEL2: pubKey = 1312 bytes, sig = 2420 bytes, pubLen prefix = 4 bytes → **total blob = 3736 bytes**.

Contract verification flow:
1. Assert `sig.length == 3736`
2. Read `pubLen` from first 4 bytes; assert `pubLen == 1312`
3. Extract `signerPubKey = blob[4 : 4+pubLen]`
4. Compute `pubKeyHash = sha256(signerPubKey)`
5. Look up `_bridgeSigners[voucher.signerEpoch]` and verify == `pubKeyHash` (else reject)
6. Extract `rawSig = blob[4+pubLen : end]`
7. Verify `Blockchain.verifyMLDSASignature(LEVEL2, signerPubKey, rawSig, sha256(voucher))`

Server MUST pack in exactly this order. Frontend passes the blob through unchanged. Reference: `bridge/contracts/__test__/unit/tests/bridge.ts:packSigBlob`.

---

## 8. Contract method selectors (LOCKED — do not change without coordinated rebuild)

| Method | Signature | Selector |
|--------|-----------|----------|
| `claimMintWithVoucher` | `claimMintWithVoucher(bytes,bytes)` | `0x59893fe6` |
| `burnForRelease` | `burnForRelease(bytes32,uint256,uint32)` | `0x1d40b843` |
| `mintTo` | `mintTo(address,uint256)` | `0xedb20b7e` |
| `setBridgeDepository` | `setBridgeDepository(address)` | `0xad2a4138` |
| `rotateSigner` | `rotateSigner(bytes)` | `0x932e12d6` |
| `setInitialSigner` | `setInitialSigner(bytes)` | `0x10c503a3` |
| `setPaused` | `setPaused(bool)` | `0x1da7d6ff` |
| `addWrappedToken` | `addWrappedToken(address)` | `0xf9d97ede` |
| `networkId` (view) | `networkId()` | `0x63d10908` |
| `paused` (view) | `paused()` | `0x5c0ff0ee` |

Both `BridgeDepository` and `WrappedOP20` register `UpdatablePlugin(144)` which adds standard upgrade selectors: `submitUpdate(address)`, `applyUpdate(address,bytes)`, `cancelUpdate()`, `pendingUpdate()`, `updateDelay()`. Governor-only.

**`BridgeDepository.onDeployment` calldata:** pass exactly 32 bytes representing a u256 big-endian `networkId` (`1`=mainnet, `2`=testnet). Stored in `_networkId`; enforced on every voucher. `WrappedOP20.onDeployment` calldata: unchanged from OP20 template `(name, symbol, decimals, maxSupply)`.

### Recipient encoding — WATCH OUT, TWO CONVENTIONS

**`burnForRelease.ethRecipient` uses LEFT-PAD (LOW 20 bytes).** `ethRecipient` is a fixed 32-byte `bytes32`. For EVM destinations (chainId 1 / 11155111), the contract enforces upper 12 bytes are zero + lower 20 = ETH address. Callers left-pad: `padStart(64, '0')`. **Never `padEnd`** — puts the address in bytes 0..19 and reverts.

**Voucher preimage `sourceBridgeAddr` / `sourceTokenAddr` use RIGHT-PAD (HIGH 20 bytes).** Inside the 460-byte preimage, EVM bridge + token addresses are encoded as `ethAddr20 ++ zeroPad12` (address in bytes 0..19, zeros in bytes 20..31). OPPOSITE convention from `ethRecipient` — intentional because these are opaque binding fields the contract never needs to recover the 20-byte EVM address from. To extract an EVM address from a preimage field, slice `[0..20]`, NOT `[12..32]`.

### `BurnedForRelease` event data layout (132 bytes total)

```
Offset  Size  Field
  0      32   user              (Address)
 32      32   amount            (u256 BE)
 64      32   ethRecipient      (bytes32 — for EVM dest, last 20B = address)
 96       4   destChainId       (u32 BE)
100      32   burnNonce         (u256 BE)
132          = end
```

Server indexer: for EVM destinations, extract `ethRecipient[12:32]` (last 20 bytes) as `address to` in the EIP-712 ReleaseIntent.

### `MintedFromVoucher` event data layout (264 bytes total)

```
Offset  Size  Field
  0     32    recipient         (Address)
 32     32    wrappedToken      (Address)
 64     32    sourceChainId     (u256 BE)
 96     32    sourceTxHash      (bytes32)
128      4    sourceLogIndex    (u32 BE)
132     32    grossAmount       (u256 BE)
164     32    feeAmount         (u256 BE)
196     32    netAmount         (u256 BE)
228     32    voucherId         (u256 BE)
260      4    signerEpoch       (u32 BE)
264          = end
```

Server scanner parses `netAmount` at offset 196, `voucherId` at offset 228. **Off-by-one traps here have happened** — the server initially parsed with a 96B layout (recipient + netAmount + voucherId), mis-read `netAmount = wrappedToken` and `voucherId = sourceChainId`, and every claim stayed stuck in `voucher_ready` forever. Fixed; covered by a regression test.

---

## 9. Package versions (SACRED — never guess)

### OPNet contracts (`contracts/package.json`)
- `@btc-vision/btc-runtime` `^1.11.0`
- `@btc-vision/as-bignum` `^1.0.0`
- `@btc-vision/assemblyscript` `^0.29.3`
- `@btc-vision/opnet-transform` `^1.2.2`

### Scripts / server / frontend
- `opnet` `^1.8.6`
- `@btc-vision/transaction` `^1.8.2`
- `@btc-vision/bitcoin` `^7.0.0`
- `@btc-vision/walletconnect` `^1.10.5` (frontend)
- `@btc-vision/bip32` `latest`
- `@btc-vision/ecpair` `latest`
- `ethers` `^6` (scripts, server)
- `wagmi` + `viem` (frontend EVM)

### EVM contracts
- Solidity `0.8.24`
- OZ Contracts `^5` (regular + Upgradeable)
- Foundry latest stable

### Backend deps (`server/package.json`)
- `hyper-express` `^6.17.3` (NEVER express/fastify/koa)
- `better-sqlite3` `^12` (WAL mode required)
- `bcrypt` `^6`, `zod` `^3`, `dotenv` `^17`
- `@noble/curves` `^2` (NEVER `tiny-secp256k1`)

### Substitutions (mandatory)
- `bitcoinjs-lib` → `@btc-vision/bitcoin`
- `ecpair` → `@btc-vision/ecpair`
- `tiny-secp256k1` → `@noble/curves`
- `express/fastify/koa` → `hyper-express`

---

## 10. Non-negotiables

### OPNet contracts
- `@method`/`@view` decorators ONLY — NEVER manual `execute()` dispatch
- `@final` on contract class
- SafeMath on ALL u256 arithmetic
- `StoredU256` subPointer = `EMPTY_POINTER` (never `u256.Zero`)
- Unique `Blockchain.nextPointer` — no hand-picked slots
- **Append-only storage** across upgrades — never reorder, delete, or retype fields. Deprecate in place (keep `nextPointer` slot; stop reading/writing).
- `onUpdate()` mandatory; migrations gated by `_storageVersion: StoredU256`.
- `super.onDeployment(calldata)` and `super.onUpdate(calldata)` as FIRST line of every override.
- `ReentrancyGuard` extended on `BridgeDepository` + `WrappedOP20`; `@nonReentrant` on every state-mutating @method
- CEI: verify → mark used → mint (never the other order)
- No `while` loops, no map-key iteration
- **Never import** `@method`/`@view`/`ABIDataTypes` — compile-time globals
- Address comparisons: `.equals()` / `.isZero()` NEVER `===` / `!==` / `=== Address.zero()` — JS reference equality does not work for Address objects
- ML-DSA blob length check BEFORE slicing: `if (sig.length != 3736) revert`, `if (pubLen != 1312) revert`

### EVM contracts
- `SafeERC20` for every token call (USDT doesn't return `bool`)
- Balance-delta amount check: `received = balanceAfter - balanceBefore`; emit/sign `received`, not `amount`. Use a `balAfter <= balBefore` guard (not `unchecked`) if you ever enable a non-canonical token later.
- OZ `EIP712Upgradeable` + `ECDSA.recover` (enforces low-s via OZ)
- UUPS hardening (all applied to `BridgeEscrow`):
  - `_disableInitializers()` in impl constructor
  - `initialize` gated by `initializer` modifier
  - `_authorizeUpgrade` onlyOwner
  - No `selfdestruct`, no arbitrary `delegatecall`
  - `uint256[49] private __gap` trailing the storage layout (was 50; shrunk 1 when `expectedOpnetChainId` was appended)
  - Storage-layout CI gate via `evm-contracts/storage-layout.json`
  - Foundry `extra_output = ["storageLayout"]`
- Recipient `to` in signed struct — anyone may submit, only `to` receives (front-run safe)
- `ReentrancyGuardUpgradeable` + CEI on `lock`/`claim`/`emergencyWithdraw`
- `PausableUpgradeable` with separate pause role (not upgrade authority)
- `expectedOpnetChainId` enforced on every claim (audit-fix, reverts `InvalidSrcChainId()` on mismatch)

### Server
- `hyper-express` only (NEVER express/fastify/koa)
- `better-sqlite3` WAL mode + parameterized prepared statements only (never string-interpolate SQL)
- TypeScript strict, `node:22-slim` for Docker (NEVER alpine — hyper-express needs glibc)
- CORS allowlist from `FRONTEND_URL` env (never `*`)
- `/health` endpoint required
- `multipart` `fieldSize: 64 * 1024` (ML-DSA sigs are ~4840 chars; default 4KB truncates silently)
- Pre-validate tx on `/register` endpoints — fetch receipt + logs, verify event targets our bridge, whitelisted token, sender matches request. No DB row for unknown txs.
- Admin auth: session-only in `NODE_ENV === 'production'`. `x-admin-secret` only in dev.
- Indexer: pre-sign ancestor re-check (fetch block by hash, verify tx still at expected log index, verify confirmations met) before signing any voucher/message.
- Composite dedup: `UNIQUE(chain_id, tx_hash, log_index)` on deposits; `UNIQUE(opnet_tx_hash, opnet_event_index)` on withdrawals.
- BigInt for all fee math. `fee = Math.max(minFee, amount * feeBps / 10000n)`; reject if `fee === 0n` OR `amount <= fee`.
- Signer rotation re-signs all pending DB rows transactionally.

### Frontend
- Vite `envDir: '../'` — reads root `.env`
- `signer: null, mldsaSigner: null` for OPNet contract calls (OPWallet extension signs)
- Separate `JSONRpcProvider` for reads (never wallet provider for reads)
- Always `simulate` before `sendTransaction`
- UTXO queries: `optimize: false` always
- `increaseAllowance` (never `approve`) for OP20
- `getContract()` for all writes — 5 params (addr, abi, provider, network, sender). 4 for reads (no sender).
- **Never `provider.call()` for writes** — its `CallResult` fails `sendTransaction` with "Contract address not set" / silently doesn't embed calldata in the Bitcoin tx. Only `getContract()` produces properly-wired `CallResult`s.
- Address arguments to contract methods must be `Address` objects — use `toAddress(bech32)`. Never raw bech32 strings.
- BigInt for all financial math. NEVER `Number(bigint)` for token amounts (precision dies above 2^53).
- `vite-plugin-node-polyfills` + `resolve.alias: { stream: 'stream-browserify' }`
- T&C modal: 3 checkboxes, cannot skip; `AddressConfirm` step with typed-last-4-chars gate.
- `evmAddressToBytes32` MUST use `padStart(64, '0')`, NEVER `padEnd`. Unit test at `frontend/src/__tests__/smoke.test.tsx` asserts the correct hex.

### Admin panel
- `base: '/admin/'` in `vite.config.ts` (asset paths resolve under `/admin/` when served from single container)
- Session auth only; no on-chain writes directly from the panel — all privileged ops go through server admin endpoints
- Type-to-confirm UX on every destructive action

---

## 11. Signer key model

| Key | Purpose | v1 dev | Production (Phase 3) |
|-----|---------|--------|---------------------|
| EVM ECDSA signer | Signs EIP-712 `ReleaseIntent` for `BridgeEscrow.claim` | Hot wallet from `cast wallet new` (or deployer), private key in root `.env` | AWS KMS, revocable in seconds |
| OPNet ML-DSA signer | Signs 460-byte voucher preimage for `claimMintWithVoucher` | `Wallet.fromWif + MLDSA`, keys in root `.env` | Vault transit / custom KMS sign service |

Signer modules behind interfaces (`EcdsaSigner.sign(digest)`, `MldsaSigner.sign(preimage)`) — drop-in swap for KMS in Phase 3.

### Rotation procedure (epoch-based, no deadline)

1. Governor generates new signer keys off-chain (use `npm run generate-signer` in `scripts/` — prints keys to stdout; NEVER writes `.env` automatically).
2. Governor calls `rotateSigner` on BOTH contracts:
   - EVM: `BridgeEscrow.rotateSigner(newAddr)` via `npm run rotate:evm <addr>`
   - OPNet: `BridgeDepository.rotateSigner(newPubkeyHex)` via `npm run rotate:opnet <hex>`
3. Both contracts' `signerEpoch` increments; old-epoch sigs immediately stop verifying on-chain.
4. Server switches to new signer keys (update `.env`, restart) + re-signs all `voucher_ready` / `signature_ready` DB rows with new epoch in a single DB transaction. Admin endpoint: `POST /api/admin/signers/rotate`.
5. Audit log row written to `admin_audit`.

**Compromise response:** same but pause both contracts first (`npm run pause:evm` + `npm run pause:opnet` + pause both wrapped OP20s — see RUNBOOK), unpause after DB re-sign completes.

---

## 12. Gas

### EVM
Default reasonable. No per-op tuning needed. Owner upgrades: ~500k gas; `claim`: ~150k; `lock`: ~100k; `emergencyWithdraw`: ~60k.

### OPNet `minGas` (per workspace CLAUDE.md rule: `minGas` is NOT refundable — size per op)

| Operation | Gas used | Safe `minGas` |
|-----------|---------|---------------|
| `claimMintWithVoucher` | ~5-7B (ML-DSA ~500M + mint + events) | `2_000n` starting; benchmark on live testnet |
| `burnForRelease` | ~1B | `1_000n` |
| Admin writes (setBridgeDepository, addWrappedToken, setInitialSigner, rotateSigner) | ~237M-1B | `1_000n` – `2_000n` |
| `setPaused` | ~237M | `1_000n` |
| Deployments | ~5B | set via script `gasSatFee: 10_000n` |

Testnet `minGas: 10_000n` is fine for ops work. **On mainnet, size per op** — `10_000n` for a simple admin call wastes ~$6 per tx.

### Fee rate
`feeRate: 2` is default in deploy/wire. For mainnet, match Bitcoin mempool min (often `1`). Workspace CLAUDE.md has full table.

---

## 13. Reserve monitoring

Run by `server/src/monitoring/tvl-monitor.ts` every 60s. Compares EVM-locked USDC/USDT to OPNet `totalSupply()` of wUSDC/wUSDT, accounting for in-flight deposits + pending burns + accrued fees.

| Level | Threshold | Action |
|-------|-----------|--------|
| **WARN** | >$100 absolute OR >0.02% relative | Alert Telegram + Slack |
| **CRITICAL** | >$1,000 absolute OR >0.10% relative | Alert + optional auto-pause (if `AUTO_PAUSE_ON_DIVERGENCE=true`) |

Other continuous monitors: indexer lag (`ALERT_INDEXER_LAG_THRESHOLD_BLOCKS=100`), signer health (3+ failures AND >20% failure rate in rolling 60s window), pending queue age (`ALERT_QUEUE_AGE_THRESHOLD_SEC=3600`), reorg counter (any reorg rewinds alert).

All env-configurable. Default auto-pause is `false` — opt-in only.

---

## 14. Emergency withdraw (`BridgeEscrow.emergencyWithdraw`)

Added post-deploy via upgrade #1. Owner-only escape hatch that bypasses the voucher/claim flow. Useful for:
- Reclaiming test deposits without a full round-trip
- Migrating escrowed funds before a contract upgrade
- Pulling funds during an incident while forensics run

### Interface

```solidity
function emergencyWithdraw(
    address token,     // USDC, USDT, or any ERC-20 the escrow holds
    address to,        // recipient
    uint256 amount     // in token base units (6 dec for USDC/USDT)
) external onlyOwner nonReentrant;
```

Emits `EmergencyWithdraw(token indexed, to indexed, amount, by indexed)`.

### Usage via `cast`

```bash
# 1. Withdraw 100 USDC back to yourself
cast send $EVM_BRIDGE_ESCROW \
  "emergencyWithdraw(address,address,uint256)" \
  $EVM_USDC $BRIDGE_OWNER 100000000 \
  --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $EVM_RPC_URL

# 2. Drain ALL USDC the escrow holds
BAL=$(cast call $EVM_USDC "balanceOf(address)(uint256)" $EVM_BRIDGE_ESCROW --rpc-url $EVM_RPC_URL)
cast send $EVM_BRIDGE_ESCROW \
  "emergencyWithdraw(address,address,uint256)" \
  $EVM_USDC $BRIDGE_OWNER $BAL \
  --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $EVM_RPC_URL
```

### Risk model
Single owner key controls this function. If compromised → attacker drains the escrow. Mitigations:
- For v1 mainnet-EVM / testnet-OPNet test: acceptable with the current deployer key.
- Before any real production volume: transfer `owner` to a Safe multisig + 48h `TimelockController`.

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
npm run build:contracts         # contracts/build/*.wasm
npm run build:evm               # evm-contracts/out/

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
cd evm-contracts
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
cd ../evm-contracts
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
When ABIs are generated under `contracts/abis/` (with the contracts' version of `opnet` types) and imported into `scripts/` (with its own version of `opnet`), TS enum members don't line up. Cast to `any` at the import boundary (per workspace CLAUDE.md "Cross-package type mismatch" guidance).

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
- ✅ ML-DSA voucher preimage binding (460 bytes, full field list)
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
- 🟨 **HIGH** Pin `@btc-vision/btc-runtime` package version + commit a full storage layout snapshot including base-class slots (analogous to `evm-contracts/storage-layout.json`) — mitigates drift when the runtime bumps.
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
| OPNet contracts | 41 | `npm test` in `contracts/` | `@btc-vision/unit-test-framework` |
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
- OP20 base template: `/Users/dippy/Documents/code/opnet/tokens/contracts/contracts/src/dippy/DippyToken.ts`
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
