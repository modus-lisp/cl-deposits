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


## 8. A rotation by the non-disputing subset dissolves a standing dispute (open)

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

## 9. A DisputeAcquire whose claim never landed (open)

- **Seen:** signet soak, ledger 751e6951. cld7's fork carries a DisputeAcquire at seq 11 for a
  claim that never reached the chain (a restart before claims had to be accepted first). cl now
  lets such a node keep re-arming (`drive-rearm`: an acquire counts only once the lottery output is
  literally spent), but the acquire stays on its fork, and other nodes read it as the dispute's end.
- **Options:** (a) an acquire is final as published; the node simply lost its turn; (b) an acquire
  binds only once its claim confirms, and implementations ignore unconfirmed ones (recommended:
  it matches the "literal = confirmed" rule elsewhere); (c) a later DisputeRetract op voids it.

## 10. soak-rotate keeps a stuck member in the plan (harness, open)

- **Seen:** the Nov 7 cascade began with every rotation of A failing on cld2's silent consent for
  five hours until A's quorum expired. The consent wait is now 180 s, but a member that never
  answers still blocks the operator's rotation.
- **Options:** (a) leave it to the operator; (b) near expiry, rotate without a member whose consent
  failed N times (recommended for the soak harness; DEP-18 operator policy allows it).
