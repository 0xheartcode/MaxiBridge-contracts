# MaxiBridge — Smart Contracts (Audit Delivery)

Contracts-only export of the MaxiBridge cross-chain bridge (Ethereum ↔ OPNet) for
third-party security audit. The off-chain components (server/indexer, frontend, admin
panel, deploy/ops scripts) are **not** part of this delivery — they are a separate
engagement and define only the trust boundaries described in the handoff.

## Start here

**`docs/AUDIT-HANDOFF.md`** — the engagement packet: scope, build & test, architecture,
trust model, privileged roles, the invariants we most want verified, known residual risks
(including findings we are knowingly shipping open), and the message-format reference.

Resolve any question about intended behavior against **`docs/SECURITY.md`** first.

## In scope

| Path | Contracts |
|---|---|
| `contracts/evm-contracts/` | Solidity 0.8.24 / Foundry — `BridgeEscrow` (UUPS), `VestingVault`, `WrappedERC20`, `DepositVault`, `DepositAddressFactory`, `AmountPolicy` |
| `contracts/op-contracts/` | AssemblyScript / `@btc-vision/btc-runtime` — `BridgeDepository`, `WrappedOP20`, `BridgeAuthority` |

## Documents

- `docs/AUDIT-HANDOFF.md` — engagement packet (read first)
- `docs/SECURITY.md` — evergreen threat model (source of truth)
- `docs/ARCHITECTURE.md` — technical overview (flow modes, voucher format, roles)
- `docs/REFERENCE.md` — extended reference (deploy/upgrade procedures, §17–§19 quirks/audit-status/test-matrix)
- `docs/CODEX-PREAUDIT-OPNET.md` / `docs/CODEX-PREAUDIT-EVM.md` — automated self-review (triage map, not a clean bill)
- `docs/WHITEPAPER.tex` — protocol whitepaper
- `CLAUDE.md` — authoritative byte-level message/selector reference (§6 voucher preimages, §7 ML-DSA M-of-N blob, §8 selectors + event layouts)
- `scripts/src/integration/fixtures/voucher-fixture.{json,bin,sig}` — canonical cross-validation reference vectors

## Build & test

Full instructions in `docs/AUDIT-HANDOFF.md` §3. In brief:

```bash
# EVM (forge deps vendored under lib/ — no network needed)
cd contracts/evm-contracts && forge build && forge test

# OPNet
cd contracts/op-contracts && npm install --legacy-peer-deps && npm run build && npm test
```

Audit tag: **`audit-2026-06-02`**.
