# The custody lottery's N is decided after it is committed to

*Red-team finding, 2026-09-27. Status: documented; both implementations left as the spec and
reference have them. See docs/REDTEAM.md.*

## Summary

DEP-03's custody lottery has each disputant commit to a preimage whose **length** carries its
contribution: `17 ≤ LEN ≤ 16+N`, `contribution = LEN − 16 ∈ 1..N`, winner `= Σ contributions mod N`,
with the claim leaf enforcing the bounds with `OP_SIZE`. N is "the number of disputants". The
commitment is made at **arm time**, but the number of disputants is known only when the **arm
window closes**. The two implementations resolve this the same way, and inconsistently:

| step | N used | where |
|---|---|---|
| commit (arm) | **Q**: the latest QuorumBegin's members minus the operator | reference `dispute.rs` `arm_n` = `dispute_lottery_n_from_history`; cl `dispute-lottery-n` |
| claim leaf, winner | **k**: the members that actually armed | reference `LotteryScriptBuilder::new(participants, …)` → `participants.len()`; cl `build-lottery` |

When every member arms (k = Q) nothing is wrong. When fewer do (k < Q), each armer's preimage was
drawn from `17..16+Q` but the claim leaf only accepts `17..16+k`. The claim succeeds only if
every committed contribution happens to be ≤ k:

    P(claim possible) = (k/Q)^k        Q=3, k=2: 4/9 — five in nine such lotteries cannot be claimed

A lottery that cannot be claimed is not lost. The lottery output's recovery leaves let the
recovery quorum sweep it after CSV 144 (a majority), then 1008, 4032 and 8064 blocks with
lower thresholds. But no one takes custody, and nobody wins.

## What happened on the devnet

Ledger F (74bde8be…, operated by ref3, Q = 3: cld1, cld4, ref2) expired at 6719. The cl
members' expiry watch disputed it, and both cl members armed. ref2 did not arm: the reference
recovery CLI can't read a ledger longer than 500 updates, and its daemon auto-arms only at
expiry + 720. So k = 2.

- Confiscation ab2202beedfcc53460d1c871288cea0c4c68ee0f40f062018d938efbd8ac48c7, confirmed at
  height 7666: respectful, Tier 1, lottery output 478,907 sats.
- Reveals: cld1 18 bytes (contribution 2), cld4 **19 bytes (contribution 3)**. The claim leaf
  for k = 2 accepts at most 18.
- Both members' drivers report `waiting to claim: preimage length 19 out of 17..18`. The output
  can be recovered through the CSV-144 recovery leaf from height 7810.

## A second defect of the same shape, already in the spec: partial-reveal leaves

For N ≥ 3 the spec adds one partial-reveal leaf per possibly-missing disputant: a sub-lottery over
the other k = N−1, with the **parent** N's bounds ("each surviving participant's commitment was
chosen under the parent-N contract"). Contributions are then in `1..N`, so the sum reaches `k·N`,
but the dispatch was sized for bounds of k:

- **Linear** (k ≤ 5 or ≥ 11): k conditional subtractions of k reduce sums below `k(k+1)`. The top
  sum, `k·N = k(k+1)` (every contribution at its maximum), leaves index k, which has no branch.
  The claim fails, with probability `(1/N)^k`.
- **CombinedTable** (6 ≤ k ≤ 10, i.e. N = 7): arms cover sums `k..k²` only. Sums in
  `(k², k(k+1)]` have no arm.

Both implementations build these leaves the same way, so they agree on the addresses and share
the defect. It is rarer than the main finding, but it is the same mismatch between the bounds a
contribution was committed under and the modulus the script reduces by.

## Options

**Keep the spec (current).** Every member must arm for the lottery to be claimable with
certainty. When some don't, the recovery quorum sweeps the output after the CSV and custody
stays unresolved.

**(a) Bounds from Q, modulus from k.** The claim leaf accepts `17..16+Q` and reduces the sum
mod k (as the spec already does for partial reveals, with the dispatch fixed to cover `k..k·Q`:
Q subtractions, or arms up to `k·Q`). Always claimable. **Biased** whenever k ∤ Q: a contribution
uniform on `1..Q` is not uniform mod k. Q = 3, k = 2: contributions fall mod 2 as {1, 0, 1}, and
with two armers the lower-keyed one wins with probability 5/9, not 1/2. The bias is fixed and
public, not exploitable adaptively (commit-reveal), but it is unfair.

**(a+) Unbiased: contributions in `1..L`, L = lcm(2..Q).** Quorum sizes are restricted to
{3, 5, 7}, so L ∈ {6, 60, 420} and the longest preimage is 16 + 420 = 436 bytes, under
Tapscript's 520-byte push limit. L is divisible by every possible k ≤ Q, so `Σ mod k` is exactly
uniform however many members arm. Reduce the sum (≤ k·L ≤ 2940) by conditional subtraction of
`k·2^j` for decreasing j (about 12 steps), which replaces both dispatch regimes and fixes the
partial-reveal leaves with the same code. Cost: a new preimage-length rule, claim script and
winner calculation in DEP-03 and in both implementations, incompatible with lotteries built
before it.

**(b) Require all Q to arm.** Otherwise confiscate without a lottery (e.g. straight to the
recovery quorum). This is simple, but a single absent member blocks custody.

## Recommendation

(a+) if the lottery is meant to settle custody fairly with a partial quorum. That is the case
this soak produced within a day: one member's tooling couldn't arm. Until then, the drivers
(ours, the reference's) should treat a lottery that cannot be claimed as recoverable, not
pending: sweep through the recovery leaf once its CSV passes, rather than waiting on a claim that
can never verify.
