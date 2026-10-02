# What's missing

*As of 2026-10-02.* An inventory of gaps between the Deposits spec, cl-deposits and deposits-rust
(branch `signed-header-v2`), found while running the devnet and the red team. What exists is
recorded in docs/REDTEAM.md and docs/TRUST-MODEL.md; this lists only what does not.

## Fraud proofs and punishment

- ~~**Unauthorised vault spend (DEP-06 type 7).**~~ **Done (2026-10-02), both implementations.**
  `UnauthorizedVaultSpend`, wire type 10 (DEP-06 now carries the wire table). Each node scans every
  new block for spends of the vault outpoints it replicates, judges them 3 blocks deep, and proves
  each witness signer on every ledger the signer operates. Proven live on mixed quorums (a Rust
  node detected a theft, and Rust and cl receivers disputed). **Limits:** a confiscation is
  excused only by a verifier that knows it (one that disputed in it or signed it), so a member
  without a fork accuses honest confiscation signers (`attack-vault-missed-confiscation.sh`). A
  rotation recorded later than the 3-block grace is taken for a theft (`vault-rotate-late`). The
  Rust record of confiscations it signed is in memory and lost on restart. The verifier checks that
  the spend's block exists, not that the transaction is in it.
- **Consolidated `NonConforming` proof (DEP-19 §5).** Neither implementation has it as specified.
  Cross-ledger contagion runs through `NonConformingCosignature` evidence instead, which now
  accepts the fault's operator as the accused.
- ~~**Duty to act on proofs (DEP-19 §6).**~~ **Done (2026-10-02):** both implementations verify,
  produce and act on `DisputeDereliction`. cl c7976a5 (verifier + `report-derelict-members` +
  act); deposits-rust ec7457b (producer; it already verified/acted). A cl-built proof verifies on
  the reference with a matching proof hash. Found and fixed two latent wire mismatches: the proof is
  now self-evident (no embedding) on both sides, and `original_fraud_block_hash` serialises as hex.
  Exercised end to end on the devnet (2026-10-02, `redteam/attack-dereliction.sh`, short
  `dispute_response_blocks`): proof produced, derelict's ledger disputed, acting member untouched.
- **Lottery recovery after a withheld reveal.** When an armer withholds its preimage, cl's honest
  armers loop on "missing a reveal" and never take the recovery path; recovery needs 3 signatures
  and gets 1. Shown live 2026-10-02: the lottery output unspent 187 blocks after confiscation (past
  CSV-144). Neither the claim nor the recovery leaf moves the funds.
- ~~**Invalid armer collateral vetoes a confiscation.**~~ **Done (2026-10-02):** DEP-03 makes the
  participant set an eligibility cut (pledge confirmed by, unspent through, and worth its
  declaration at the snapshot E); a failing armer is excluded, not a veto. One eligible armer
  takes custody without a draw; none reopens arming (four arms per armer), then the post-expiry
  tiers. Both implementations agree on a shared vector and live (`attack-veto-pledge.sh`, all
  three modes: cl and the reference excluded the same armer at the same snapshot).
- **Credits beyond collateral: the implementations disagree.** The reference rejects (and disputes)
  an update whose obligations exceed the collateral while the quorum is active; cl allows it; the
  spec requires only reserves ≥ obligations. A mixed quorum disputes an honest zero-collateral ledger.
- **Censorship proofs (DEP-11, DEP-12).** Not acted on in either implementation. cl has
  `verify-censorship` with no caller. The reference has DeliveryEmbed, but the wallet-to-member
  escalation channel is unwired.
- **Co-sign refusal proofs (DEP-19 §9).** Signed proposals (Kind 9108) and
  `cosign_response_blocks` exist in neither implementation.
- **Stale-proof handling in a yielded reference member.** A member that yielded never applies
  the winner's DisputeAcquire, so a replayed proof against the former operator passes its
  current-operator check. Each replay then re-announces its dispute (no state change).

## Rulesets and rotation

- ~~**Absolute-height recovery tiers.**~~ **Removed (2026-10-02):** the `legacy` and
  `cltv-offset-literal` rulesets are gone from both implementations and the spec; the Tier-1
  minority is ceil(n/2)-1. The devnet was reset to fresh ledgers to drop vaults built under them
  (old state in `pre-reset-20261002/`).
- ~~**cl members ignore the reference's `rotation_sign`.**~~ **Done (2026-10-02):** a reference
  operator rotates its vault itself; cl members now rebuild and sign that rotation. Soak ledger B
  (ref2) rotated with four cl cosigners.

## Devnet infrastructure

- **The signet cannot mine fast any more.** Fast red-team mining made a 2016-block window take 1.3
  days, so difficulty rose 4× at 14112; blocks now take ~25 s and grinding sometimes fails. Scenarios
  that mine hundreds of blocks (vault-recovery-tier, withhold-reveal) cannot run. Needs a regtest
  devnet, or a signet reset and a mining budget per window.

## Ledger operations

- **`ExitRequest`, `ExitCancel`, splice-in (DEP-20 §3–4).** Absent from both implementations.
  The rotation splice-out, one of the two censorship-protected obligations, has nothing to act
  on.
- ~~**Operator stand-down after confiscation.**~~ **Done (2026-10-01):** a cl operator stands down
  once custody moves or a majority of its quorum disputes it (cl 9b1a6d4), and cl members refuse
  to extend a deposed operator's chain (3e1ad0f), as the reference's members already did.

## Quorum composition (DEP-19 §10)

- **Member vault ratio (§10.1), declared anchors (§10.2), anchor intersection (§10.3).** Not
  checked by either implementation at QuorumAddMember or QuorumBegin.
- **`signer_block_height` on cosignatures (§10.5).** Not on the wire.
- **Implementation diversity.** With two implementations, one always holds a majority of a
  seven-member quorum; no third implementation exists.

## Wallet side

- **Trust signals.** Nothing computes the exposure signals the trust model names: operator
  collateral summed across its ledgers, member coverage (own collateral against collateral
  guarded), cosign latency, rotation history. Nothing presents them per ledger.
- **Watcher.** No wallet runs its own replica for detection; detection relies on members.

## Spec text

- **DEP-05 §Cosignature Threshold** claims an honest majority prevents equivocation. Both
  implementations re-sign a sequence that has not committed (needed for liveness), so equivocation
  is detected and punished, not prevented.
- **DEP-19 §5** makes a member who co-signed two updates at one sequence a `NonConforming` fault.
  Honest retries do exactly that.
- **DEP-19 §10.1** says the signers of a theft of V "hold at least 1.5 V". Confiscation costs a
  signer only its collateral, so the bite is smaller by the collateral fraction.
- **DEP-11 / DEP-12** do not state that censorship proofs cover only same-ledger transfers and
  rotation exits, nor that the request must still be servable at the deadline.
- **`UncreditedLightningPayment`** (DEP-03's table) and DEP-11's Lightning credit obligation remain,
  although Lightning is no longer an obligation under DEP-20.
- **Lottery N** (docs/LOTTERY-N.md): committed under Q, claimed under k. Mitigated in cl, not
  resolved in the spec.
- **Accountable signing rounds:** undecided (docs/REDTEAM.md, attack #2).

## Analysis

- **Contagion simulation** (analysis/contagion_sim.py): no operators with several ledgers, no
  operator contagion, no per-key dilution, no strategic quorum joining, no unequal vaults, no
  detection or punishment failure.
- **Contagion taints a key for good.** Once a key is accused, every new ledger it runs or cosigns
  is disputed on sight, including after a false accusation (a late rotation, or a missed
  confiscation). Nothing clears an accusation. On the devnet this means a scenario must use keys
  that no earlier run accused (fresh-key nodes cld7+, picked by `redteam/_lib.sh`).
- **Not measured on the devnet:**
  - ~~the rollback depth when every honest replica is offline~~ measured 2026-10-02: caught on return,
    rolled back to the last honest seq (REDTEAM.md);
  - off-ledger extraction through a courier leg;
  - a colluding majority against an honest minority before `quorum_expiry + 720`.

## Concerns: what might happen

Risks we are worried about, given what exists and what doesn't.

**Loss of funds**
- A colluding majority of a quorum spends an honest operator's vault at Tier 0. Today nothing
  notices, the colluders keep their own vaults, and the victim ledger's depositors lose their funds.
- Even when theft is punished by contagion, the victims are not made whole: confiscated colluder
  vaults go to the lottery winners on the colluders' own ledgers, not to the depositors robbed.
- An operator equivocates using honest retries alone (no colluder needed) and extracts value off the
  ledger before detection: a courier leg paid against a lock that later rolls back, or a swap
  counterparty paid out. The rollback does not reach effects outside the ledger.
- One implementation bug shared by a quorum majority is a network-wide failure. Findings 11–14 were
  each an honest node verifying too little. With two implementations, one always holds a majority
  of a seven-member quorum.

**Detection failing**
- Every honest replica of a ledger is offline when the fraud happens. The fraud stands until one
  returns, and honest activity after it is rolled back with it.
- A colluding majority is detected at once but cannot be punished on the attacked ledger until
  `quorum_expiry + 720` (minority confiscation). Meanwhile it can already spend the vault.
- Quorum capture is likelier than the simulation assumes: a coalition seats its keys on each other's
  quorums (DEP-19 §10's residual), rather than being drawn at random.
- A member guarding many quorums with a small vault offers little bite per ledger. Security
  concentrates in the largest operators (the "pyramid").

**Held funds**
- An operator ignores a depositor's transfer or exit request with no consequence, until its quorum
  expires. The "cannot hold deposits hostage" guarantee is unenforced.
- An operator's own fee collection pushes a balance below an escalated request, so the request is no
  longer servable at the deadline.
- The custody lottery goes unclaimed: the committed N differs from the armed count (lottery N), or
  a last revealer withholds. Custody then waits for recovery leaves while no one operates the ledger.
  Confirmed live for the withheld reveal (2026-10-02): past CSV-144 the recovery does not happen either.

**Honest parties punished**
- DEP-19 §5 implemented as written would slash honest members for re-signing a round that did not
  commit.
- A censorship proof built on an unservable request (a depositor's double spend, or a bad request
  embedded by a member) frames an honest operator. The servability rule exists in cl only, and
  nothing acts on censorship proofs yet.
- A replayed or stale proof re-announces disputes; bogus proofs naming unknown ledgers each cost a
  relay query.

**Operations**
- The relay is a single point: a relay that censors, delays or drops ephemeral events stalls
  cosigning, reveals and confiscation signing.
- A confiscated operator keeps operating its old ledger. Wallets that don't notice may keep sending
  it requests, or fund its old reserves address.
- A reorg near the tip changes the block hash an update signed. Cosigners that check it refuse, and
  signing can stall until heights settle.
- A slow implementation drags every quorum where it holds the deciding votes. At Q = 7 cl's
  per-cosign cost set the pace for half the ledgers until it was fixed.
