# Trust model: honesty requirements, capital efficiency, trust heuristics

*Working analysis, 2026-09-30.* This grounds the spec's security claims (DEP-05 §Security Model,
§Cosignature Threshold, §Lifecycle; DEP-06; DEP-19) in what the devnet has measured and what the red
team found (docs/REDTEAM.md). Q is the number of cosigners and n the operator's ledgers.

## 1. What each guarantee needs

| guarantee | what it needs | measured / found |
|---|---|---|
| **Validity:** no committed update breaks the rules | an honest **majority** of cosigners at the update's tier, each validating in full (state, conformance, witnesses) | Finding 11: cl cosigners skipped depositor authorization, so a cl-majority quorum signed a witness-less spend; one reference member refused. **Honesty is not enough: honest members must also be correct.** |
| **Detection** of a bad committed update | **one** honest, online replica of the ledger (member or watcher) | forged lock on A: flagged within 1 s, forked within 2 s (19:55:29 → :31) |
| **Punishment:** confiscation at Tier 0 | a **majority** of recovery voters sign the confiscation | A: fraud at height 9518, confiscation confirmed at 9521, custody at 9522 (all three online) |
| **Punishment** when the majority colluded | not available at Tier 0; minority confiscation opens at `quorum_expiry + 720`, solo at `+ 4032` | not run. A colluding majority can already spend the vault through Tier 0 (DEP-05: "a quorum majority custodies the operator's entire vault"). |
| **No equivocation** | *spec claim:* an honest majority prevents it (DEP-05 §Cosignature Threshold). *Actually:* nothing prevents it; it is **detected** by one honest online replica and **punished** by a majority | Both implementations re-sign a sequence that has not committed (retries are needed for liveness), so an operator can collect majorities on two branches from honest members alone. DEP-05's argument assumes "signed = applied". |
| **Liveness:** updates keep flowing | a majority online and willing to cosign | soak: ~60 updates per ledger per minute with Q = 3 and mixed implementations |
| **Custody moves** when the operator vanishes | majority at expiry; minority at +720; one member at +4032; operator alone at +8064 | respectful expiry path ran end to end (soak 1, claim #4) |
| **Censorship resistance** | an honest member embeds the request, plus a proof the network acts on | **not enforced** in either implementation (REDTEAM claims #3, #5) |

**Conclusions:**
- Safety of funds needs an honest, *correct* majority. Detection needs only one honest online replica.
  Punishment needs a majority again, or waiting out expiry.
- The gap between "detected" and "punished" is exactly where a colluding majority operates. It can't
  hide the fraud, but it can outrun the punishment.
- "Correct" is doing real work: every red-team finding so far (11–14) was an honest node verifying
  too little. The honesty requirement is really **honest + independently implemented**.

## 2. Capital efficiency

The operator's vault is `U = reserves + collateral`, with obligations ≤ reserves. So the capacity per
sat locked is `R = reserves / U`, and the rest is idle bond.

**With an honest majority**, on-ledger fraud gains nothing: the ledger rolls back to the last valid
update, deposits continue on the winner's fork, and the collateral goes to the lottery (punitive).
What an operator *can* extract is **value settled off the ledger against a state that is later rolled
back**, within the window between the fraud and the freeze:
- a courier leg on another ledger paid against a lock that rolls back (DEP-13);
- a swap counterparty paid out on-chain or over Lightning against a rolled-back transfer;
- (not measured) an equivocation branch shown to one party while the other branch is shown to another.

Measured window with an online honest member: **same block** (1–2 s). So the collateral needed against
an honest-majority quorum is small: what counterparties will settle off-ledger within seconds, plus
enough to make the lottery worth running (the winner's reward).

**With a colluding majority**, DEP-05's arithmetic applies: gain ≈ `U × R / n` per ledger taken, cost ≈
`U × C / n` per ledger where an honest majority can confiscate (contagion, DEP-19 §5–6). The simulated
"max safe sybil %" (DEP-05) tops out at 49% for C ≥ 60%. **Collateral mainly buys protection against
collusion, not against a lone operator.**

**Finality for counterparties.** A fraud at sequence N that is detected at N + k rolls back k updates,
honest ones included. With an online honest member k ≈ 0 (A froze on the next update). If every honest
replica is offline, k grows until one returns. So an update is final once an honest replica has seen it
and a detection cycle has passed. A counterparty that settles off-ledger (courier, swap) should wait
for that, not merely for the cosignatures.

## 3. Trust heuristics for a wallet choosing a ledger

Observable from public data (relay + chain), roughly in order of what the findings say matters:

1. **Implementation diversity in the quorum:** no single implementation holds a majority of
   cosigners. Findings 11–14 were each one implementation verifying too little. A mixed quorum turned
   Finding 11 from theft into a refused update. *Observable:* members' software is not on the wire today;
   it could be advertised in member terms (self-reported), or inferred from behaviour.
2. **Honest-majority plausibility:** members are independent operators, each with their own ledger,
   `min_member_collateral` at stake (DEP-05), and a history of being online (cosign latency and refusal
   rate are visible on the relay).
3. **At least one reliably online replica** (member or independent watcher): this is what makes
   detection immediate. Wallets can run their own watcher for ledgers they hold.
4. **Collateral ratio and the operator's total collateral across ledgers** (contagion), against the
   wallet's exposure and the off-ledger settlement it plans (§2).
5. **Lifecycle position:** distance to `quorum_expiry`, and a history of rotating on time. Past expiry
   the quorum's authority degrades by tier.
6. **Terms:** `service_response_blocks`, fee schedule and limits, timeout heights. These bound how long
   funds can be held and what they cost.

## 4. Open questions, with how to answer each

- **Colluding-majority fraud against an honest minority, end to end:** what the minority can do before
  `quorum_expiry + 720`, and whether contagion (DEP-19 §5–6) is implemented anywhere. *Devnet run plus
  code reading.*
- **Detection with members offline:** the rollback depth k as a function of honest-replica uptime.
  *Devnet: stop the honest members, commit a fault, restart them, measure k.*
- **Off-ledger extraction:** a courier leg across two ledgers whose source lock rolls back. Who loses,
  and how much should a courier wait? *node-test plus devnet.*
- **Re-run the sybil simulation** (DEP-05 table) under the current rules: Q ∈ {3, 5, 7}, tiers,
  contagion, and implementation diversity as a second axis.
- **DEP-05 §Cosignature Threshold** needs rewording: it claims an honest majority prevents equivocation;
  retries mean it is detected and punished instead. A spec decision (see REDTEAM, attack #2).
