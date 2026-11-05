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
- **Before freezing:** decide entries 2–5, since several would change the lottery output's script
  and so belong in v8 or a v9.

## 2. Recovery voters are not shrunk (provisional)

- **What:** the lottery's recovery voters stay the full governing quorum minus the operator, even
  when some voters are accused.
- **Why not shrink:** recovery voters also attest which participants revealed (DEP-06 Phase 4,
  `lottery_subset_attest`). A proper-subset claim needs a threshold of voter signatures, so a voter
  set shrunk below the leaves' thresholds leaves honest winners unable to claim.
- **Known gap:** accused voters remain voters. The CSV-8064 timeout leaf has threshold 1, so a single
  accused voter can spend the lottery output after 8064 blocks; at CSV 144 the accused can meet T
  when they are a majority of voters (30ea46ac: 3 of 5).
- **Where:** DEP-06 §Lottery (recovery voters); no code change.

## 3. Raised recovery and attestation thresholds (held, not adopted)

- **Proposal:** every recovery tier and subset-attestation threshold becomes at least
  |Accused(grounds) ∩ voters| + 1, so the accused can never spend or attest alone (the output
  strands rather than being stolen).
- **Objection (user, 2026-11-05):** "seems like you're asking losers to help winners though." Subset
  claims already depend on recovery voters, mostly losers, attesting R; raising the thresholds makes
  winners need more help from parties with no stake in helping them.
- **Status:** not implemented. Entry 6 is the direction under consideration instead.

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
- **Not done:** the round's orchestration (detecting the deadline, collecting the round's arms,
  proposing and signing the spend, reveal and claim against the new output) in either
  implementation, and the all-yield regtest scenario. Recovery voters must still sign the spend, so
  entry 6's objection applies here too.

## 6. Proper-subset claims without voter attestation (open, design under consideration)

**Proposal.** After the reveal deadline a participant may claim through a subset leaf with no voter
signatures. The subset S must equal the reveals R published before the deadline; a claim through
any other subset is a provable fault, slashed from the claimant's replacement collateral.

**Assessment: sound only with three changes; it trades prevention for punishment.**

1. *Without attestation every revealer can win.* The singleton leaf {self} pays its only member, and
   with |R| ≥ 2 most revealers find some S ⊆ R that they win. Claims become a race among all
   revealers through leaves that open at the same height; the draw no longer decides the outcome
   unless deterrence does. When everyone revealed, the honest full-set winner can claim at once (no
   CSV), ahead of every subset leaf; this only matters when someone withholds.
2. *R must be dated by the chain, not by signed updates.* Signed `block_height` is only
   non-decreasing on its signer's own chain and is never checked against Bitcoin. A withholder could
   publish a back-dated "reveal" after seeing an honest claim through S = R, making S ⊊ R'
   retroactively: a framing attack on the honest winner. Dating each reveal by its spend of the
   armer-share reveal-claim leaf, which already publishes the preimage on chain, makes R the set of
   reveal spends confirmed by the deadline. Every verifier with the chain computes the same R.
3. *The proofs.* S ⊊ R (the claimant left out a revealer to pick a favourable subset) is literal: the
   claim witness plus the omitted member's on-chain reveal at height ≤ deadline. S ⊄ R (S includes a
   member with no timely reveal, so its preimage was shared privately) is judged from the chain,
   which deterministically shows that the member's share was not spent through its reveal leaf by
   the deadline. Neither needs a relay, a challenge window or any voter.

**The race and which spend wins.** All claims spend the same lottery outpoint and the first to
confirm wins; nothing in script prefers the honest R-claim. The claim's shape is fixed (DEP-03: one
output to the claimant's own `target_reserves`, with its declared replacement collateral as input
1), so a misclaimant cannot redirect value elsewhere. It becomes the custodian, holding the lottery
value plus its own collateral in its declared vault, with a provable fault on record.

**What slashing can recover.** The faulty claim makes the misclaimant's new custody disputable on
literal grounds, so the ledger goes to another confiscation and lottery and the honest participants
can arm again. This recovers everything, the lottery value and the misclaimant's collateral, only if
the misclaimant's `target_reserves` vault is confiscatable by honest keys. Today `target_reserves` is
an address the armer declares freely. If it is a key the misclaimant alone controls, nothing is
recoverable: slashing "from the replacement collateral" reaches nothing, because that collateral sits
in the same output. So the scheme also needs:

- `target_reserves` constrained to a reserves vault whose tiers include the dispute's honest recovery
  voters (or the next governing quorum), checked when the arm is made; and
- the expected gain of misclaiming (the lottery output) to be outweighed by the loss (the collateral,
  plus losing custody again). Since the lottery output can far exceed the collateral, deterrence
  rests on re-confiscation succeeding, not on the collateral alone.

**A simpler alternative, with no subset leaves at all.** Keep only the full-set leaf. If anyone
withholds, nobody can claim, and after the deadline the output goes to the re-arm round (entry 5)
over the revealers only, the withholders having forfeited their shares and an arm. The draw is then
always over everyone who revealed, there is nothing to attest and nothing to race, and a withholder
gains nothing and loses its share. The cost is an extra round whenever someone withholds, and the
re-arm spend still needs recovery voters to sign it. That is liveness help (moving the output to the
next round's lottery), not choosing a winner.

**Recommendation for review:** prefer the full-set-only alternative. If proper-subset claims stay,
they need chain-dated reveals and a constrained `target_reserves` before attestation can be dropped.
