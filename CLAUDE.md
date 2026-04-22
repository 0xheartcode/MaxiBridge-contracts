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

## 6b. Two-wallet key model — NEVER MIX (CRITICAL)

The bridge operates with **two distinct OPNet wallets**, and confusing them
on-chain bricks every voucher:

| Role | Env vars | What it signs | Authority |
|------|---------|---------------|-----------|
| **Deployer / Governor** | `OPNET_DEPLOYER_WIF` / `OPNET_DEPLOYER_MLDSA` | The Bitcoin tx that carries OPNet calldata (deploy, wire, rotateSigner, pause/unpause). Its identity is `msg.sender` inside the contract, which `onlyGovernor` methods check against. | `BridgeDepository._governor` |
| **Voucher signer** | `MLDSA_SIGNER_WIF` / `MLDSA_SIGNER_KEY` | 460-byte ML-DSA voucher preimages (off-chain). Its **pubkey hash** is stored at `BridgeDepository._bridgeSigners[epoch]`. The contract verifies every claim's ML-DSA blob against this hash. | Registered at epoch via `setInitialSigner` / `rotateSigner` |

### The failure mode we already hit on mainnet

A one-off script called `setInitialSigner(wallet.mldsaKeypair.publicKey)`
where `wallet` was built from the DEPLOYER env vars. On-chain hash became
`sha256(DEPLOYER_pubkey)`. The server signs vouchers with the SIGNER wallet
(correctly — it reads `MLDSA_SIGNER_*`), so every voucher carried a pubkey
blob whose hash didn't match the stored slot. Contract reverted with
`rogue signer pubkey`. Fix required a `rotateSigner` tx (epoch bump).

### Rules

- **The pubkey passed to `setInitialSigner` / `rotateSigner` MUST be the
  `MLDSA_SIGNER_*` wallet's pubkey, never the DEPLOYER's.** `wire-contracts.ts`
  gets this right by explicitly constructing a second `Wallet.fromWif` from
  `MLDSA_SIGNER_WIF` + `MLDSA_SIGNER_KEY` just for the pubkey — do not refactor
  it to reuse `createOpnetContext().wallet`.
- **The Bitcoin tx carrying that call IS signed by the DEPLOYER keypair**
  (it's the governor). That's correct — do not swap it.
- Any one-off / ops script that touches the signer slot MUST use the same
  two-wallet pattern. If you need a quick `tmp-*.mts`, build both wallets
  explicitly; don't shortcut through `createOpnetContext()` defaults.
- Pre-flight check before rotating: compute `sha256(SIGNER.pubkey)` locally
  and compare to what the server reports at `/api/stats/public →
  opnetSignerHash`. If they differ, you're about to brick the chain. Abort.

### Quick pubkey-derivation snippet (put in ops scripts, never in tmp files)

```typescript
import { Wallet } from '@btc-vision/transaction';
import { requireEnv } from '../lib/env.js';
import { getOpnetNetwork } from '../lib/opnet-client.js';

const signerWallet = Wallet.fromWif(
    requireEnv('MLDSA_SIGNER_WIF'),
    requireEnv('MLDSA_SIGNER_KEY'),
    getOpnetNetwork(),
);
const signerPubKey = signerWallet.mldsaKeypair.publicKey; // 1312 B
```

### Upgrading SIGNER keys

Rotating the signer off a compromised or lost key:
1. `MLDSA_SIGNER_*` → new mainnet WIF + MLDSA hex in `.env` **and** Railway.
2. `npm run rotate:opnet -- 0x<new_signer_pubkey_hex>` from the deployer
   session (pubkey hex derived from the SNIPPET above).
3. Server re-signs every `voucher_ready` row with the new epoch — do it in
   a single DB transaction from the admin endpoint, per §6.
4. Verify `signerHashAtEpoch(newEpoch) == sha256(newPubkey)` matches
   `/api/stats/public → opnetSignerHash` before touching anything else.

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

## 14+. Extended reference (on-demand)

Operational details, gotchas, audit status, and deploy history moved to `docs/REFERENCE.md` to keep this file small. Read it when you need:

- §14 Emergency withdraw interface + `cast` usage
- §15 Fresh deploy procedure (EVM + OPNet + wire)
- §16 Upgrade procedure (UUPS + OPNet redeploy)
- §17 Known quirks (padEnd/padStart, getCode lag, provider.call trap, multipart truncation, etc.)
- §18 Audit findings status (closed + deferred)
- §19 Test matrix (138 tests across 5 suites)
- §20 Deploy history (addresses, tx hashes)
- §21 References (inspired patterns, audit artifacts)
- §22 Never / anti-patterns (duplicates workspace CLAUDE.md — extracted there)
