# What's missing

*As of 2026-09-30.* An inventory of gaps between the Deposits spec, cl-deposits and deposits-rust
(branch `signed-header-v2`), found while running the devnet and the red team. What exists is
recorded in docs/REDTEAM.md and docs/TRUST-MODEL.md; this lists only what does not.

## Fraud proofs and punishment

- **Unauthorised vault spend (DEP-06 type 7).** Specified, but no implementation has it: no watch
  on a ledger's vault outpoint, no proof type, no verifier, no contagion on the witness signers.
  So a spend of a vault outside a recorded rotation or a dispute-backed confiscation goes
  unnoticed by both implementations. The theft the contagion simulation models (a colluding
  majority spending an honest vault at Tier 0) is not caught by either.
- **Consolidated `NonConforming` proof (DEP-19 §5).** Neither implementation has it as specified.
  Cross-ledger contagion runs through `NonConformingCosignature` evidence instead, which now
  accepts the fault's operator as the accused.
- **Duty to act on proofs (DEP-19 §6).** No dereliction tracking: a member that ignores a
  valid proof within `dispute_response_blocks` is not provable in either implementation.
  `DisputeDereliction` evidence exists in both as a type, but no node produces it.
- **Censorship proofs (DEP-11, DEP-12).** Not acted on in either implementation. cl has
  `verify-censorship` with no caller. The reference has DeliveryEmbed, but the wallet-to-member
  escalation channel is unwired.
- **Co-sign refusal proofs (DEP-19 §9).** Signed proposals (Kind 9108) and
  `cosign_response_blocks` exist in neither implementation.
- **Stale-proof handling in a yielded reference member.** A member that yielded never applies
  the winner's DisputeAcquire, so a replayed proof against the former operator passes its
  current-operator check. Each replay then re-announces its dispute (no state change).

## Ledger operations

- **`ExitRequest`, `ExitCancel`, splice-in (DEP-20 §3–4).** Absent from both implementations.
  The rotation splice-out, one of the two censorship-protected obligations, has nothing to act
  on.
- **Operator stand-down after confiscation.** A cl operator whose vault was confiscated keeps
  operating the old ledger. Its members refuse every cosign ("in dispute state").

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
- **Not measured on the devnet:**
  - the rollback depth when every honest replica is offline at the fraud;
  - off-ledger extraction through a courier leg;
  - a colluding majority against an honest minority before `quorum_expiry + 720`.
