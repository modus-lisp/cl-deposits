# Provisional rulings awaiting review

Rules adopted or proposed to see whether they work, and to be reviewed together later.
Each entry gives where it lives, why, the alternatives, and the evidence gathered so far.

Status: **provisional** = written into the spec draft and/or code, not final; **held** =
proposed, not adopted; **open** = a question with no rule yet.

## 1. strict-lottery-v8: freeze status (provisional)

- **What:** `strict-lottery-v8` = `grounded-arms-v7` plus a strict lottery. A confiscation whose
  lottery includes the operator or any key in Accused(grounds) is not authorised; it is challenged
  and, unanswered, proven against its witness signers. Earlier rulesets accept either reading.
- **Where:** spec `a7da7f7` (DEP-03/06/18, marked Draft, not frozen). cl branch `v8` (`c9461ab`,
  `11b485a`, `943bfe7`, `8f6c7ed`, `3122561`, `768e316`); Rust branch `v8` (`a4b6e68`, `ae9f993`).
  Not merged to master/main, not deployed to the soak.
- **Why:** under the lenient reading a guilty majority could confiscate into a lottery of its
  own colluders.
- **Evidence:** regtest 8/8 on v8 builds (confiscation-answer, confiscation-bump,
  invalid-credit-collude, collude-q7, vault-spend, ruleset-prior, ruleset-undeclared). Shared
  vectors `lottery_accused.txt` (22 cases) and `ruleset_naming.txt` (48) pass in both
  implementations. No live colluder self-lottery has run under v8 yet (`:lottery-include-accused`
  exists; the scenario is not wired).
- **Before freezing:** review entries 2, 4 and 5. Entry 2 changes the lottery output's script, so it
  is part of v8.

## 2. Recovery voters exclude the accused (provisional)

- **What:** under `strict-lottery-v8` the lottery's recovery voters are the governing quorum's members
  minus the operator minus Accused(grounds). Every threshold (subset attestation and the recovery
  tiers) is sized over what remains by the existing rule: T = ⌊r/2⌋ + 1, tiers T / T−1 / T−2 / 1.
  With no voter left (the whole quorum accused) the lottery has only its full-set leaf: the
  all-revealed claim works, anything else strands, and that is accepted.
- **Where:** spec DEP-06 §Lottery, `730c7cf`. cl `lot:strict-voters` and node `lottery-voters`
  (`40622cb`); Rust `types::strict_voters`, `armers::lottery_voters_with` and
  `Node::lottery_voters` at every lottery site (`5be6517`).
- **Why:** accused voters could otherwise meet the recovery thresholds and take the output (30ea46ac:
  3 of 5 voters accused; the CSV-8064 leaf needs only 1).
- **Alternatives dropped:** shrinking the voter set to a minimum (it breaks subset-claim
  attestation); thresholds of at least |Accused| + 1 over the full quorum (the user: "asking losers
  to help winners"); proper-subset claims without attestation (entry 6, dropped).
- **Evidence:** the shared vector `lottery_voters_accused.txt` (0, 1, 3 and 5 of 5 accused: voters,
  thresholds, tiers, leaf count, address, leaves) passes in both implementations. cl's vectors gate
  also spends each lottery under consensus: a subset claim attested by the remaining voters
  verifies, attestations by accused keys don't count, and the all-accused lottery has only its
  full-set claim.

## 3. Raised thresholds (dropped)

Proposed (every threshold at least |Accused| + 1 over the full quorum) and dropped in favour of
entry 2.

## 4. A lottery unclaimed despite revealers also re-arms (provisional)

- **What:** if the lottery output is still unspent when its CSV-144 recovery leaf opens, a re-arm
  round starts even though some participants revealed.
- **Why:** otherwise a winner that never claims, or yields by mistake, strands the ledger.
  Soak, 2026-11-04: ledger 30ea46ac's sole participant ref6 yielded its own custody (a Rust bug,
  fixed in deposits-rust `b230c92`) and the output stayed unspent.
- **Where:** spec DEP-06 Phase 4, `d5aa6e0` (draft).
- **Alternative:** re-arm only when nobody revealed (the earlier text); strands on any unclaimed
  lottery with revealers.

## 5. The re-arm round's recovery spend (provisional)

- **What:** version 2, nLockTime 0, one input through the recovery leaf of tier t with nSequence
  that tier's CSV (144/1008/4032/8064, the proposer names the lowest elapsed tier), one output to
  the next round's lottery, fee = reference feerate × ⌈(4·94 + W)/4⌉ with W the witness as the
  tier's threshold signs it.
- **Where:** spec DEP-06 Phase 4 `88afbef` (fixes the draft's nSequence 144, which could not spend
  the later tiers). cl `lot:rearm-spend` (`768e316`), Rust `LotteryOutput::rearm_spend`
  (`ae9f993`). Shared vector `rearm_spend.txt`, 9 cases, byte-identical in both; cl also checks each
  claimed vsize against a fully witnessed spend.
- **Status (Nov 7):** cl orchestrates the round (deadline, the round's arms, proposing and signing
  the spend, following it, reveal and claim). Regtest passes `rearm` (everyone withholds) and
  `rearm-yield` (everyone reveals, and the drawn winner yields its own custody, as ref6 did on soak
  30ea46ac). Both runs had only cl voters: deposits-rust builds the spend byte-identically (vector)
  but doesn't run a round, so a mixed quorum's re-arm needs a cl voter to propose, and a Rust voter
  won't sign.

## 6. Proper-subset claims without voter attestation (dropped)

Considered and dropped: holdouts are already handled by the subset leaves. The assessment, in short:
without attestation every revealer can claim through a favourable subset (the singleton leaf at
least), so claims become a race. It would be sound only with chain-dated reveals (signed heights
can be back-dated to frame an honest claimant) and a `target_reserves` that honest keys can
re-confiscate.

## 7. Re-arming a lottery whose window has already closed (ruled 2026-11-07: option (c), recurring windows)

- **What:** DEP-06 Phase 4 dates round r+1's arm window only from h_L: (h_L + 72, h_L + 72 + w] when
  nobody revealed, (h_L + 144, h_L + 144 + w] otherwise, reopening once. A lottery that stranded
  before re-arm was deployed, or while every voter was down, is past both windows and can never
  re-arm.
- **Seen:** regtest 4a6487ee (round-1 output at 649, still unspent at 1750, reveals held). The soak's
  stranded lotteries, 30ea46ac and f5274842, are the same case, so re-arm can't rescue them as the
  spec stands.
- **Options:** (a) leave them stranded, the residual risk the spec already names; (b) a late round:
  the window opens at the first block, at or after h_L + 144, in which a voter sees the output
  unspent and no window open, which every voter must agree on from public state (hard: "first seen"
  isn't public); (c) windows recur every k blocks after h_L + 144 while the output is unspent,
  bounded by the four-arm limit. (c) is deterministic from h_L alone, so every voter rebuilds the
  same round, and it's my recommendation (provisional, under strict-lottery-v8).
- **Ruling (the user, 2026-11-07):** "permanent stranding isn't going to work, so let's go with 3",
  i.e. option (c). Specified in DEP-06 Phase 4 step 3 (spec, under strict-lottery-v8). Window 0 is
  (o, o+w] and window 1 its reopening; windows j >= 2 are (o+(j-1)k, o+(j-1)k+w], with
  k = 144·⌈(2w+1)/144⌉ (144 for w <= 71). The round takes the first window whose cut is non-empty,
  and the four-arm bound spans every window. Why this k: the first recurring window opens at
  o + k >= h_L + 216, after the reveal deadline and the CSV-144 claim time for revealers, so no
  window runs while a reveal or claim is pending. k > 2w keeps the windows disjoint. Built in cl
  (`lot:rearm-round-window` and friends, `nd::rearm-round-window-of`) and Rust (`rearm_round_window`
  et al.). Vector `rearm_windows.json`; regtest `check-rearm-late.sh`.
- **Pre-v8 lotteries (ruled by the user, 2026-11-07: "they're devnet - don't worry too much"):**
  re-arm stays v8-only. The soak's pre-v8 stranded lotteries (30ea46ac, f5274842) stay stranded as
  devnet casualties. Extending re-arm to them would mean running a frozen ruleset's lottery with new
  behaviour, and would give 30ea46ac's colluders recovery votes.


## 8. A rotation by the non-disputing subset dissolves a standing dispute (ruled 2026-11-10: "no")

- **Seen:** signet soak, ledger J. Members disputed J's expired quorum (QUORUM-EXPIRED); ref6, who
  had not disputed, then cosigned the operator's re-establishing rotation `27d16c7a`, and J
  unfroze. Evidence: `/mnt/lisp/signet/archive/cascade-20261107/` (forks snapshot, ref6/cld logs).
- **As the spec stands:** DEP-05 ends an expiry dispute on any later QuorumBegin, and a QuorumBegin
  needs only the threshold, so a subset that never disputed can lift the freeze. That's
  rule-consistent for an expiry ground, which a fresh quorum answers.
- **Question:** should the same hold for a fraud ground (equivocation, a non-conforming update)?
  A colluding subset could otherwise rotate an accused operator out of a dispute it should lose.
- **Options:** (a) keep it as is for every ground; (b) a QuorumBegin ends only expiry disputes,
  and a fraud dispute stands until its lottery resolves (recommended); (c) require the disputers'
  consent to any rotation while a dispute stands.

- **Ruling (2026-11-10, the user: "no"):** option (b). Under `strict-lottery-v8` a QuorumBegin
  ends only expiry disputes; a dispute on any other ground freezes co-signing whatever its
  `last_valid_sequence` (DEP-05 §Deposed operator, spec 72ee902). Both implementations
  (`cosign-refusal` / `cosign_refusal`, ruleset-gated), vector `cosign_refusal.json` (v8 cases),
  regtest `fraud-rotation`. Still open: a colluding threshold can rotate the vault *away from* the
  disputants (not re-seating them); the dispute then stands on a vault already spent by a
  rotation the rules call authorised. That needs its own ruling (a rotation cosigned while a
  fraud dispute stands as non-conforming, or the dispute following the vault).

## 9. A DisputeAcquire whose claim never landed (ruled 2026-11-10: "yes")

- **Seen:** signet soak, ledger 751e6951. cld7's fork carries a DisputeAcquire at seq 11 for a
  claim that never reached the chain (a restart before claims had to be accepted first). cl now
  lets such a node keep re-arming (`drive-rearm`: an acquire counts only once the lottery output is
  literally spent), but the acquire stays on its fork, and other nodes read it as the dispute's end.
- **Options:** (a) an acquire is final as published; the node simply lost its turn; (b) an acquire
  binds only once its claim confirms, and implementations ignore unconfirmed ones (recommended:
  it matches the "literal = confirmed" rule elsewhere); (c) a later DisputeRetract op voids it.

- **Ruling (2026-11-10, the user: "yes"):** option (b). Under `strict-lottery-v8` a
  `DisputeAcquire` binds only once its `claim_txid` is confirmed (DEP-06 §Phase 4, spec 72ee902).
  cl reads confirmations through `getrawtransaction` (`tx-confs-fn`, cached once confirmed); Rust
  learns them in the vault watch (`note_confirmed_claims`) so the co-sign path only reads a cache.
  Vector `cosign_refusal.json`; regtest `acquire-unconfirmed` (red-team op `:phantom-acquire`).
  Still open: Rust's branch choice (`main_loop`, "chains with DisputeAcquire > longest") and its
  operator-side custody check still read an acquire as published.
- **Follow-up (2026-11-12): the re-arm path.** The ledger fold is pure: a published acquire left the
  acquirer's fork at `normal`, and a round-2 arm needed a dispute, so 751e6951's round 2 never armed.
  Under v8 a later round's arm is now valid on such a fork. The reasoning: a confirmed claim spends the
  lottery output, so if a later round exists, the acquire never bound (DEP-06 spec 129b983, cl
  d637db8, vector `dispute_rearm.json`). This applies an existing ruling, so it needs no new one.
  Rust now folds re-arm rounds too (TLV 366 `rearm_round` on DisputeArmed; a later round from Disputed,
  Armed or Tombstoned, or from Normal on an armed acquire-on-confirm fork; a lower round refused), so
  `dispute_rearm.json` (13 cases) and the TLV vector `dispute_armed_round.json` run in both, not cl-only.
  Lead, unruled: spec step 2 takes "each armer's latest [arm] there" (in the window); both
  implementations take the round's latest counted arm and then filter by window.

## 10. soak-rotate keeps a stuck member in the plan (ruled 2026-11-10: "permissionless means letting people gfy")

- **Seen:** the Nov 7 cascade began with every rotation of A failing on cld2's silent consent for
  five hours until A's quorum expired. The consent wait is now 180 s, but a member that never
  answers still blocks the operator's rotation.
- **Options:** (a) leave it to the operator; (b) near expiry, rotate without a member whose consent
  failed N times (recommended for the soak harness; DEP-18 operator policy allows it).
- **Ruling (2026-11-10, the user: "permissionless means letting people gfy"):** beyond the harness,
  a spec rule (DEP-11 §Rotating without a silent member, every ruleset, it judges nothing): from
  `drop_margin` blocks before expiry the operator seats the consenting members, cut to the largest
  valid size (current members first, then newcomers, each in consent order), and validators never
  refuse a QuorumBegin for leaving a member out. cl `lg:seat-consenting` + `:trim-staged`, Rust
  `rotation_seat::seat_consenting` + the auto-refresh drop path, vector `rotation_seat.json`,
  `soak-rotate` drops a silent member within `SOAK_DROP_MARGIN`, regtest `rotation-drop`.

## 11. A rotation past expiry (ruled 2026-11-14: "i think we can allow it, but we can't require members to sign")

- **Asked:** may a quorum rotate after its expiry? Under REVIEW 8 a rotation ends an expiry
  dispute, and the soak fork reported that cl never cosigns a post-expiry QuorumBegin, so a lapsed
  ledger could never be saved that way.
- **What the code actually did:** both implementations already cosigned establishment ops
  (QuorumAddMember, QuorumRemoveMember, QuorumBegin) past expiry, at the tier's threshold (DEP-05
  §Lifecycle, DEP-06 §Race). The "not cosignable at this height" refusals on the soak were
  transfer-locks (op 70), which are rightly refused past expiry. On the live soak H, J and L
  re-established past expiry (expiries 5855/5881/5874 became 7151/7177/7170, and the rotation
  rungs confirmed). B, D and F had already been confiscated.
- **Ruling (2026-11-14):** allowed, never owed, under every ruleset (it judges nothing):
  - A post-expiry QuorumBegin is valid at its tier's threshold until a confiscation of the vault
    confirms. Confirmed spends decide the race; mempool spends do not.
  - No member is obliged to take part. A refusal is never a fault, never grounds for a proof,
    dispute or arm, and never counts as silence against the member. Its only consequence is DEP-11's:
    the member is not seated.
  - When the re-establishment confirms first, every expiry dispute on the ledger ends: each
    disputant yields, armed or not, and every pledge lapses with no lottery and no loss.
  - A member never cosigns a QuorumBegin over a vault whose confiscation confirmed.
  - Implementation policy: cosign by default, with an opt-out (cl `CLD_REFUSE_POST_EXPIRY_ROTATION`
    or the control port's `(:policy :post-expiry-rotation nil)`; Rust
    `DEPOSITS_REFUSE_POST_EXPIRY_ROTATION`).
- **Gap found:** Rust yielded only an armed expiry dispute. An un-armed one stayed open for good
  (ref2, ref3 and ref7 on J). Rust now yields it too.
- **Where:** spec DEP-05 §A rotation past expiry is allowed, never owed, and §When a
  `quorum_expired` dispute ends; DEP-06 §Race, "Confirmed decides; pledges lapse with the loser".
  Vector `post_expiry_rotation.json`; regtest `rotation-post-expiry` (`rescue`, `confiscated`).
- **Closed (2026-11-15): an opted-out member no longer signs the rungs.** The policy first gated
  only the cosign of the establishment ops and the consent to a seat. If the rotation was recorded
  anyway (the other members a majority), an opted-out member of the spent vault still answered
  `rotation_sign`, because its replica then showed the new quorum's expiry. That couldn't harm the
  member:
  - it signs only rungs of a final, recorded `QuorumBegin`, so no type-7 proof can stand against it;
  - a rung and a confiscation of one vault are not equivocation;
  - none of its own funds move.
  But its signature could still carry a rotation it declined over the tier's threshold. An opt-out
  that can do that isn't one (coordinator, 2026-11-15). Rung signing now applies the same policy,
  at the `QuorumBegin`'s block height, against the spent vault's expiry (the replica before the
  `QuorumBegin`). In cl that's `rung-sign-policy-allows-p` in `handle-rotation-sign`; in Rust,
  `rung_sign_policy_allows` in `process_rotation_sign_request`. Vector `post_expiry_rotation.json`,
  cases `rung_sign`.

- **Amendment (2026-11-15): under v8 only a confirmed re-establishment ends the expiry dispute.**
  Regtest `rotation-post-expiry` (rescue, default arm window) produced a real race:
  - 17:58:30: the operator's post-expiry QuorumBegin was recorded.
  - 17:58:32: ref6 (d40db88) broadcast its confiscation.
  - 17:59:09: ref6 yielded its armed expiry dispute ("quorum re-established") while its own
    confiscation was still in the mempool.
  - 17:59:31: the confiscation confirmed, and the rotation's rungs could never be signed.
  ref6 gave up its lottery stake in the spend that won. cl's member did not yield. The spec was
  inconsistent: DEP-05 ended the dispute once the chain *held* a later QuorumBegin, while DEP-06
  §Race (this item) said the rotation's spend must *confirm*. The coordinator ruled this an
  application of the standing reading that only confirmed spends decide (acquire-on-confirm,
  REVIEW 9), so no new user ruling was needed.
  - Under strict-lottery-v8 (`:expiry-ends-on-spend`, judged at the dispute's fork point), the
    dispute ends only once some QuorumBegin after its fork point has a rung in a block. A recorded
    but unspent one leaves the dispute standing: no yield, still armed on, still confiscated.
  - Earlier rulesets keep the old reading.
  - This also closes DEP-06's "liveness of a recorded rotation" stall for v8 ledgers.
  - Where: spec 4efadff (DEP-05, DEP-06 §Race and Limits, DEP-18); cl `expiry-dispute-ended-p` /
    `arm-on-expiry-dispute-p` (`:on-spend`), `reestablishment-confirmed-p` in `drive-dispute` and
    `fork-live-p`; Rust `expiry_dispute_ended_under` / `arm_on_expiry_dispute_under`,
    `ruleset_expiry_ends_on_spend`, `expiry_watch`. Vector `expiry_dispute_ends.json`: 4 `ended`
    and 2 `arm` ruleset cases.
  - Still open: Rust's arm decision on another member's expiry DisputeEnter
    (`validate_dispute_enter_quorum_expired` in `inbound.rs`) still compares the anchor with the
    ledger's *current* expiry. A recorded but unspent QuorumBegin therefore still stops a reference
    member arming on a v8 expiry dispute.

## 12. Backdated arms (ruled 2026-11-15: "A for now, but let's write down the scenario in the repo")

- **Asked:** a fork's `DisputeArmed` is self-signed, so an armer can date an arm inside a window
  that has closed (round 1: at or below the confiscation block) and publish it after the spend.
  Every rebuild through "each armer's latest arm" then changes. The options were:
  - (A) judge a spend by the arm set its signers used;
  - (B) make arm timestamps provable, by cosigning or anchoring arms;
  - (C) leave it.
- **Ruling (2026-11-15):** A for now; B recorded as the open future fix.
  - Under `strict-lottery-v8` signers publish arm manifests, and judges are existential over
    valid manifests.
  - Omission of an armer is signing policy, not a provable fault. That is the accepted cost.
  - The next round's lottery is the confirmed output's.
- **Where:** docs/ADVERSARIAL.md §Backdated arms (the scenario, its evidence, what A accepts, B's
  costs); spec DEP-03 §Arm manifests, DEP-06 §Authorised confiscation, §Spend challenge and Phase 4
  step 5. Vector `arm_manifest.json`; regtest `backdated-arm`.


## 13. A rotation recorded below its rungs' answer floor (found 2026-11-19; fixed cl f28a49f, rust answer-floor, spec 0373ba0)

**Decision taken, for review: it is a duty on every ruleset, not a v8 rule.**  Nothing in it changes
what a validator accepts: the `QuorumBegin` C recorded was valid under DEP-05, and the judge's answer
rule (DEP-06 §Spend challenge 1) was already the rule.  What was missing was the obligation that
keeps the two consistent: an operator records a rotating `QuorumBegin` only with cosignatures by the
rungs' tier reaching that tier's threshold, and a member signs rungs only for such a one.  Gating it
on v8 would have left every older vault able to repeat C.  If you want it ruleset-gated anyway, the
only change is where the cl/Rust checks read their switch.

**What happened.**  Signet ledger C (8b19a178): a post-expiry rescue was planned at vault tier 0
(5 of 8, the operator among them) just before tier 1 opened at 8285, and its `QuorumBegin` (seq
361569) recorded at 8287 with the 3 cosignatures the lifecycle then asks.  The rung (2653505d) spent
tier 0, where an answer needs 4.  The operator's own vault watch challenged its rotation and answered
itself with a `QuorumBegin` no judge could accept; the window lapsed and, once its relay read
worked again, it proved all five rung signers (six false oracle ALARMs, none acted on).

**Also decided here:** a node never presents a proof against its own key (DEP-06): a judgement that
calls our own signature theft is our judge's fault.  Both implementations log it loudly instead.

**Still open:** the answer path (Kind 9112) publishes a `QuorumBegin` without asking whether it meets
the floor, so an operator can "answer" with something every judge rejects.  Harmless once the floor
is enforced at recording, and left as it is; an answerer could warn.
