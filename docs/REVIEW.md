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
- **Not done:** the round's orchestration (detecting the deadline, collecting the round's arms,
  proposing and signing the spend, reveal and claim against the new output) in either
  implementation, and the all-yield regtest scenario.

## 6. Proper-subset claims without voter attestation (dropped)

Considered and dropped: holdouts are already handled by the subset leaves. The assessment, in short:
without attestation every revealer can claim through a favourable subset (the singleton leaf at
least), so claims become a race. It would be sound only with chain-dated reveals (signed heights
can be back-dated to frame an honest claimant) and a `target_reserves` that honest keys can
re-confiscate.
