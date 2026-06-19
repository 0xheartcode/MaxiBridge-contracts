# PeckShield PVE-0619 — Response & Disposition

Response to the June 19, 2026 PeckShield findings deck (`MaxiBridge Audit Findings`).
Companion to the PVE-0616 round (PR #1). Code-only changes land on branch
`peckshield-pve-0619-fixes`.

These findings are the **net-new** items in the 0619 deck (PVE006–PVE010, N1-5,
N3, N3-2, N3-3, N4, N5, N5-2, N5-3); the PVE001–PVE005-x and N1-x/N2-x items
were already addressed in PR #1.

> **Deploy posture:** none of these add or reorder storage. They layer on top of
> the N2 storage removal from PR #1, which already made this a **fresh-deploy**
> (not in-place upgrade) cycle. EVM `storage-layout.json` must still be
> regenerated for the N2 change, unchanged by this PR. OPNet ABIs were
> regenerated (`BridgeDepository.*`, `BridgeAuthority.d.ts`) for the new
> `SignerAdded`/`SignerRemoved` events and the `@emit` annotation.

## Disposition

| ID | Title | Disposition |
|----|-------|-------------|
| PVE006 | EVM `addFlow` chainId/evmBridge validation | **Fixed** — bind `evmChainId == block.chainid` + `evmBridge == address(this)` |
| PVE006-2 | OPNet `addFlow` opnetBridge validation | **Fixed** — bind `opnetBridge == self` |
| PVE007 | OPNet `drainInventoryOpNet` mode gate | **Fixed** — mode ∈ {1,3,4} |
| PVE007-2 | EVM `drainInventory` mode gate | **Fixed** — mode ∈ {0,3,4} |
| PVE008 | VestingVault duration overflow | **Fixed** — `vestingBlocks_ < 2^63` |
| PVE008-2 | EVM `provisionInventory` sum bound | **Fixed (defensive)** — already safe; see note |
| PVE009 | WrappedOP20 `mintTo` | **Fixed** — token-level pause guard added to `mintTo` (mirrors `burnForRelease` + EVM `mintFromBridge`); zero-checks retained |
| PVE010 | Trust on admin keys (EOA) | **Answered (no code)** — owner = Timelock/Safe on mainnet |
| N1-5 | Stale `claimMintWrapped` NatSpec | **Fixed** — references corrected to `claim` |
| N3 | WrappedOP20 ↔ flowId association | **Declined** — full association impossible; `flowId != 0` also rejected (0 is a valid "unbound" sentinel) |
| N3-2 | AmountPolicy `scale` overflow guards | **Fixed** — guards on both chains |
| N3-3 | OPNet tip pre-check `gt` → `ge` | **Fixed** — applied OPNet + EVM for parity |
| N4 | `lockWithPermit` simplification | **Fixed** — calls `lockFor(..., msg.sender)` |
| N5 | EVM `migrateSignerSet` events | **Fixed** — per-item SignerRemoved/SignerAdded/ThresholdSet |
| N5-2 | OPNet `addSignerToSet`/`removeSignerFromSet` events | **Fixed** — new SignerAdded/SignerRemoved events |
| N5-3 | BridgeAuthority `@emit` decorator | **Fixed** — annotation added |

---

## Notes on the non-obvious dispositions

### PVE006 / PVE006-2 — why binding to self is correct (and multi-chain-safe)
`flowId` is hashed from `(mode, evmChainId, evmBridge, evmToken, opnetBridge,
opnetToken)` and **both chains must derive the identical flowId** or the route
is dead (funds lock against a flow that can never be claimed cross-chain).

- The EVM escrow *is* the EVM-source bridge → its `evmChainId`/`evmBridge` are
  always this chain and this address. Bind them.
- The OPNet depository *is* the OPNet bridge → its `opnetBridge` is always this
  contract's own identity (the same `contractSelf` every voucher binds to).
  Bind it.

Each side binds only **its own** bridge address; the **foreign** side's address
stays a parameter (EVM keeps `opnetBridge` as a param; OPNet keeps
`evmBridge`/`evmChainId` as params). This holds under the multi-chain roadmap
(#33): each EVM chain runs its own escrow and binds its own self/chainid; there
is a single OPNet depository that binds its own self. No deployment ever needs
to register a flow on behalf of a different same-side bridge.

### PVE008-2 — already safe; fix is defense-in-depth
The deck states the code "only bounds `received`, not the sum." This is
imprecise: the existing `newInventory > flow.cap` check, combined with `cap`
being a `uint128`, already guarantees `newInventory ≤ cap ≤ uint128.max`, so the
`uint128(newInventory)` cast was provably safe. We added the explicit
`newInventory > type(uint128).max` guard anyway so the cast's safety is *local*
(no longer depends on reasoning about `cap`'s storage type). No behavioural
change for any reachable state.

### PVE009 — pause guard FIXED (revised from an earlier decline)
- **Pause guard — fixed.** `mintTo` now reverts when `_paused` is set, mirroring
  `burnForRelease` on the same contract and the EVM sibling
  `WrappedERC20.mintFromBridge` (which already carries `whenNotPaused`). `_paused`
  is therefore a full freeze: mint **and** burn.
- **Why the earlier decline was wrong.** The decline rested on "`mintTo` is
  `onlyMinter` (only `BridgeDepository`), whose claim path already gates on
  `requireNotPaused`, so the only mint path is already freezable by pausing the
  depository." But `onlyMinter` also admits **any address granted via
  `grantMinter`** (governor *or* BridgeAuthority), and the contract explicitly
  anticipates "any future depository the BridgeAuthority hands a minter role to."
  A granted minter that is not the (paused) depository — or that does not itself
  check the depository pause — could mint with **no circuit breaker**, and
  `WrappedOP20` is non-upgradeable, so the gap would be permanent. The token-level
  guard is the defense-in-depth PVE009 asked for, and it brings OPNet into parity
  with the EVM mint path rather than diverging from it. The `wrapped.ts` test that
  asserted "mintTo still works while paused" was flipped to assert it reverts.
- **"Redundant" zero-checks — declined (kept).** The `to.isZero()` /
  `amount.isZero()` checks give precise boundary errors and do not rely on
  `_mint`'s internal behaviour; removing them is a gas micro-opt with a
  behaviour-change risk we decline at a public entrypoint.

### N3 — fully declined (both the association AND a `flowId != 0` check)
Validating the full WrappedOP20 ↔ flowId association inside `burnForRelease` is
declined by design: the wrapped token is **non-upgradeable** and holds no flow
registry, so it cannot know which flowIds are valid for it without a circular
call into the depository — and that binding is already enforced at claim time on
the depository. The auditor concurs ("seems impossible").

A narrower `flowId != 0` check was **also rejected**: `flowId == 0` is a
**supported sentinel**, not an invalid input. `burnForRelease` records flowId
without validating it (#68 Tier C, "recorded, not validated here"); a burn with
flowId 0 emits `BurnedForRelease` with flowId 0, and the off-chain signer falls
back to the `(evmToken, opnetToken)` pair resolver (the same path a pre-#68
132-byte-event wrapper takes). Rejecting zero would break that legitimate
unbound/legacy burn path, so flowId stays recorded-not-validated by design.

### N3-3 — behaviour-neutral, applied for intent + parity
Changing the tip pre-check from `gt` to `ge` only differs at `tip == net`, which
the cross-multiply cap check (`tip ≤ tipCapBps ≤ MAX_TIP_BPS = 2%`) already
rejects for every valid config. Applied on **both** chains so the direct bound
matches intent and stays symmetric.

### PVE010 — centralization (no code)
Acknowledged and by design. The mainnet owner is **not** an EOA:
- EVM: `TimelockController(259200s / 3 days)` owns `BridgeEscrow`; the governance
  Safe is proposer.
- OPNet: governor is the governance Safe; upgrades go through
  `UpdatablePlugin(432 blocks / ~3 days)` plus the governance-gated upgrade
  authority.

The deploy ceremony (`docs/runbooks/mainnet-deploy.md`) transfers ownership off
the deployer EOA, which is dev/testnet only.

---

## Test posture
- **EVM (`forge test`):** runs locally; suite green (see PR body for counts).
- **OPNet build (`npm run build`):** clean, exit 0; ABIs regenerated.
- **OPNet unit suite (`npm run test`):** requires the `op-vm` native addon, which
  is prebuilt against **GLIBC_2.39**. Local dev hosts on Ubuntu 22.04 (GLIBC
  2.35) cannot run it; execute in a glibc-2.39 container / CI runner
  (e.g. `node:22-bookworm`). Same environment gap noted in the PVE-0616 round.
