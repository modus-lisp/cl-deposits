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

### 2a. Does contagion deter collusion? (simulation)

`analysis/contagion_sim.py` (output in `analysis/contagion_sim.out`): N = 100 operators, one vault each,
reserves R fully used, collateral C = 1 − R, quorums of Q drawn at random. A coalition of a fraction p
spends every vault whose quorum it holds a majority of (Tier 0). It takes the whole vault from honest
operators and the deposits from its own. With contagion (DEP-19 §5–6), each coalition key that signs
loses its collateral once, if its own quorum has an honest majority. The attacker picks targets and
signers greedily for maximum net. The table gives the largest p at which the attack is unprofitable
in 95% of 200 trials:

| contagion | Q | R = 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 |
|---|---|---|---|---|---|---|---|---|
| off | 3 | 0.01 | 0.01 | 0.01 | 0.02 | 0.01 | 0.02 | 0.01 |
| off | 5 | 0.05 | 0.04 | 0.04 | 0.05 | 0.04 | 0.04 | 0.04 |
| off | 7 | 0.07 | 0.08 | 0.07 | 0.08 | 0.07 | 0.08 | 0.07 |
| on | 3 | 0.08 | 0.09 | 0.07 | 0.08 | 0.01 | 0.02 | 0.01 |
| on | 5 | 0.22 | 0.21 | 0.20 | 0.19 | 0.13 | 0.04 | 0.05 |
| on | 7 | 0.28 | 0.30 | 0.29 | 0.30 | 0.24 | 0.17 | 0.08 |

**Readings:**
- **Without contagion the network is safe only while no quorum anywhere is captured:** 1–8% of
  operators. Signing a theft is free.
- **Contagion is the security model.** With it, Q = 7 tolerates ~30% colluding operators, Q = 5
  ~20% and Q = 3 ~8%, at R ≤ 0.5. It deters collusion; it does not prevent it.
- **Capital-efficiency ceiling, per theft:** a theft of one vault needs `floor(Q/2) + 1` signers,
  each losing C, so it pays whenever `C < 1 / (floor(Q/2) + 1)`. That's R above 0.5 at Q = 3, above
  0.67 at Q = 5, above 0.75 at Q = 7. Above the ceiling, contagion stops mattering.
- **Below the ceiling the limit is key reuse:** a key that signs many thefts is slashed once (DEP-19
  §10.1 says so), and coalition keys whose own quorum the coalition holds are unslashable. That's why
  safety plateaus below the ceiling instead of reaching it.
- **So honest operation at Q = 7 locks ~2 sats per sat of deposits (R = 0.5) for ~30% collusion
  tolerance.** Going to R = 0.4 buys nothing; going past R = 0.6 loses it fast. DEP-05's table (49% at
  C ≥ 60%) assumed wallets deposit only on honest operators, and did not let a majority spend an
  honest vault. This model does both, so it is the harsher bound.

**Two spec problems this exposes:**
- **DEP-19 §10.1 overstates bite.** "Three signers of a theft of V then hold at least 1.5 V between
  them on ledgers that can slash them": holding is not losing. Confiscation costs a signer only its
  collateral; the reserves are owed to its depositors and continue on the winner's fork. Real bite is
  `need × C × (member vault)`, a factor C of what §10.1 implies.
- **DEP-19 §5 makes honest retries slashable.** It drops `Equivocation` because two canonical updates
  at one sequence "imply a member who co-signed both, which is a `NonConforming` fault of that member".
  But re-signing a sequence that has not committed is required for liveness (REDTEAM attack #2), so
  honest members would be slashed. The fault is the operator's; a cosigner who signed two rounds cannot
  be told apart from a colluder.

**Not modelled yet:** strategic quorum joining (the coalition choosing which ledgers to serve on, the
DEP-19 §10 residual), unequal vaults (the "pyramid"), several ledgers per operator, detection or
punishment failing (members offline, contagion not implemented: today, only the reference's
cosigner-side `fault_ledger_id` evidence exists), and deposits concentrating on honest ledgers.

### 2b. Q = 7 on the devnet (2026-09-30)

The devnet runs §2a's sweet spot: 12 nodes (6 cl, 6 reference), 12 ledgers, Q = 7, R = 0.5, each
quorum split 4–3 by implementation with the operator's implementation in the minority
(`soak_plan`). All twelve formed first time with 144 deposits.

- **The cost of Q = 7 is cosign fan-out, not consensus.** The first run showed reference-operated
  ledgers at a fifth of the others' rate. The cause: every cl cosign forked `bitcoin-cli` from a
  multi-gigabyte heap, ~175 ms each, two or three times per request, which capped a cl node at 2–3
  cosigns a second against ~6 asked by its seven quorums. Reference-operated quorums are
  cl-majority, so they waited on the slowest cl answer. Caching the chain height and block hashes
  (cl 08b86af) cut cl answers from a 6–20 s median to **21 ms** (p90 40–80 ms). Reference members
  answer in ~10 ms.
- **Throughput after the fix:** 227–290 updates per ledger per 5 minutes, evenly across operators
  and implementations (the bots' request rate is now the limit), with zero refusals and no
  non-conforming flags.
- **Operational load per node:** each serves 7 quorums. At ~50 updates a minute per ledger that is
  ~6 cosign requests a second per node, which is comfortable once a cosign costs milliseconds.

### 2c. Contagion on the devnet (2026-09-30)

Implemented cosigner contagion (DEP-19 §5): cl d4614e7 (produce and act) and deposits-rust efe4143
(produce; it already acted). `redteam/attack-collude-q7.sh`:
- **Three of seven collude** on A (cld2–cld4 cosign blind, cld1 forges a lock): 3 of the 4 cosignatures
  needed; every reference member refused (`InvalidWitness`); nothing committed.
- **Four of seven collude** on test ledger M (cld1 operates; cld2–cld5 cosign blind): the forged lock
  commits. Then:
  - M is disputed by its honest members within seconds; C, E, G and I (the colluders' own ledgers,
    each Q = 7 with an honest majority) within ~36 s, by members acting on cl-built proofs. The
    reference acted on them unchanged.
  - **All five vaults were confiscated punitively on chain** (M, C, E, G, I: 0.499996 BTC each,
    15–16 confirmations). M's lottery went to cld6; C, E, G and I to honest reference members.
  - The coalition's tally: nothing gained (the lock rolled back with M); collateral lost on five vaults
    (1.25 BTC at R = 0.5).
- **Operator contagion (added: cl 62b69bb, deposits-rust 56efa41).** The first run left cld1, the forging
  operator, with its other ledger A untouched. The same NonConformingCosignature evidence now accepts the
  fault's operator as the accused, and is presented against every other ledger it operates. **Re-run on a
  fresh ledger M2:** M2 was disputed within 9 s, and **A, cld1's other ledger, by all four of its honest
  members (ref2–ref5) within 26 s.** The ledgers confiscated from the colluders in the first run now have
  new custodians and were not disputed again; the reference found its existing forks. Loose end: a
  confiscated cl operator keeps operating its old ledger, and its members refuse every cosign ("in dispute
  state"). That's noise, not harm; it should stand down.
- **So running more ledgers, and serving on more quorums, is more exposure, and exposure is the signal.**
  An operator's every vault is at stake for fraud on any of its ledgers, slashable by each ledger's own
  quorum. A member's own vault is at stake for every quorum it serves, but slashed once (DEP-19 §10.1), so
  its bite per ledger guarded is its collateral divided by the number it guards. §3's heuristics should
  score both: operator collateral summed across its ledgers, and member coverage (own collateral against
  the collateral it guards).
- **Not yet tested: the theft §2a models.** A colluding majority spending an honest operator's vault
  at Tier 0 is on-chain, not a ledger update. It needs DEP-06 type 7 (unauthorised vault spend) and
  contagion on its witness signers.

### 2d. Operator contagion quantified: more ledgers, more deterrent (simulation)

`analysis/coverage_sim.py` extends §2a to L ledgers per operator. An on-chain theft (DEP-06 type 7)
names every signer, so each exposed key loses collateral on **every** ledger it operates with an
honest majority — one accusation, every vault it runs at risk (the §2c live run). Largest safe
coalition fraction p (unprofitable in ≥95% of trials, N=60):

| mode | Q=7, R=0.5 | Q=7, R=0.7 | Q=5, R=0.5 | Q=3, R=0.5 |
|---|---|---|---|---|
| no contagion | 0.09 | 0.09 | 0.06 | 0.02 |
| contagion, L=1 | 0.32 | 0.19 | 0.23 | 0.10 |
| contagion, L=3 | 0.49 | 0.42 | 0.42 | 0.31 |
| contagion, L=5 | 0.55 | 0.49 | 0.50 | 0.42 |

**Readings:**
- **L=1 matches §2a** (Q=7,R≤0.5 ≈ 0.30): the model is consistent with the one-ledger sim.
- **More ledgers, more deterrent.** At Q=7, R=0.5, going 1→5 ledgers lifts tolerance 32%→55%. A
  key operating L ledgers has L vaults of collateral, all slashable on a single accusation, so each
  exposed signer costs the coalition ~L×C and theft stops paying at much higher p.
- **It rescues capital efficiency.** The L=1 cliff above R=0.5 (0.19 at R=0.7) is softened by scale:
  L=5 holds 0.49 at R=0.7. An operator that runs several ledgers can safely run leaner vaults.
- **So "runs several ledgers" is a strong, checkable signal** (DEP-04 ads + QuorumBegins): it is
  exposure, and exposure is the bond. The pyramid DEP-19 §10 describes is the healthy shape — large
  operators, each with much at stake, anchoring the network.
- **Caveat (unchanged):** this assumes random quorums and that a key's vaults are real and
  independent. A coalition that seats its keys on each other's quorums, or fronts thin vaults behind
  many ledgers, is the §10 residual the heuristics must still price. Full output: analysis/coverage_sim.out.

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
- **Extend the simulation (§2a):** strategic quorum joining, unequal vaults, several ledgers per
  operator, and implementation diversity as a second axis.
- **DEP-05 §Cosignature Threshold** needs rewording: it claims an honest majority prevents equivocation;
  retries mean it is detected and punished instead. A spec decision (see REDTEAM, attack #2).
