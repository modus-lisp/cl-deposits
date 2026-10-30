# Adversarial: participants who mean harm

The backlog of deliberate attacks to run, from one-off red-team scenarios up to
live attackers inside the soak. Ideas go in as soon as anyone has them, even
half-formed, since they are easy to lose. Environmental faults with no malice
are in [CHAOS.md](CHAOS.md). The concern-to-facility map is
`redteam/CONCERNS.md`, and run results go in `docs/REDTEAM.md`.

Status: **have** = a scenario or switch exists; **next** = agreed and queued;
**idea** = written down, not yet built.

## Oracle

Prerequisite for running anything below inside the soak. The soak must know
which ledgers and keys are adversarial:

- a dispute, proof or confiscation against an attacker is a **pass** when it
  arrives in time, and a **failure** when it doesn't;
- any dispute, proof, challenge or refusal-to-cosign against an honest
  party is an **alarm**.

False accusations have been the most damaging class of bug so far (Oct 21:
an honest rotation proven as theft, then spread to four ledgers by slashing).
Without the oracle, a busy adversarial soak is noise.

Status: next.

## Live attackers in the soak

| Attacker | Status | Notes |
|---|---|---|
| Attacker ledgers: two or three ledgers whose operators periodically run an attack from the catalogue below | next | Expected result asserted by the oracle each time |
| Byzantine member seated in honest quorums: randomly withholds or delays cosignatures, omits balance commitments, withholds ruleset declarations | next | Switches exist: `:omit-commitments`, `:withhold-rulesets` |
| Hostile depositor bot: malformed descriptors, replays, duplicate deliveries, reused nonces, dust exits, fee-griefing | next | |
| Lagging or blind judge, kept permanently behind | idea | `:lag-replica` exists; the challenge path should absorb it |

## Operator attacks

| Attack | Status | Notes |
|---|---|---|
| Invalid credit; forged lock (honest and colluding arms) | have | `attack1-invalid-credit.sh`, `attack-forge-lock.sh` |
| Equivocation; rollback depth | have | `member-equivocate.lisp`, `attack-rollback-depth.sh` |
| Censorship / held funds | have | `attack-censor-hold.sh` |
| Unanchored vault spend; forged anchor | have | `attack-vault-spend.sh`, `attack-vault-anchored.sh` |
| Recovery-tier spend outside any rotation or dispute | have | `attack-vault-recovery-tier.sh` |
| Stale signed heights: stamping old heights to dodge windows | idea | Heights are non-decreasing, but how stale can they be? |
| Nonsense `block_hash` values | idea | Never judged against the chain by design; confirm nothing breaks |
| Rotating with members' stale commitments (born expired) | have (as a rule) | DEP-05 born expired; no live scenario |
| Fee extraction just under the DEP-07 cap | idea | |
| Withholding a rotation tx after recording its QuorumBegin | idea | |
| Racing a challenge answer: publishing the answer late, just inside the window | idea | |
| Spam QuorumChallenges against honest spends | idea | Cost of answering at scale |

## Member and quorum attacks

| Attack | Status | Notes |
|---|---|---|
| Colluding majority (Q7) and contagion | have | `attack-collude-q7.sh` |
| Withholding a reveal | have | `attack-withhold-reveal.sh` |
| Dereliction (a member that won't confirm a disclosed fraud) | have | `attack-dereliction.sh` |
| Veto via pledge spend | have (never valid) | `attack-veto-pledge.sh`: its precondition hasn't arisen in any run |
| A member that stops cosigning entirely | idea | Not provable today (known limit) |
| Strategic seating to capture quorums | have (sim) | `analysis/seating_sim.py` |
| A receiver whose whole quorum is attacker keys (L4) | idea | Seating / trust-model limit |
| Lottery griefing: arming without ever claiming | idea | |

## Depositor and wallet attacks

| Attack | Status | Notes |
|---|---|---|
| Malformed and oversized descriptors | have (vector) | `descriptor_validity.json`; refusal-only rule |
| Replayed / duplicated requests, nonce reuse | have (vector) | `nonce_delivery.json` |
| Dust exits and policy exits designed to cost the operator fees | idea | DEP-20 / DEP-21: exits pay their own fees |
| Mass dormancy or migration storms | idea | |

## Infrastructure attacks

| Attack | Status | Notes |
|---|---|---|
| Malformed proofs | have | `fuzz-proofs.lisp` |
| Relabelled updates | have | `attack-relabel.sh` |
| An equivocating relay: different views to different nodes | idea | Needs per-node event policy in beacon |
| A relay withholding challenge answers or DEP-14 revocations | idea | Data-availability limit; check that the windows absorb outages |
| Relay spam / DoS (flood of valid-looking events) | idea | |
| Eclipsing one node's bitcoind (feed it a stale or forked chain) | idea | |
| Differential fuzzing of encodings between cl and Rust (TLVs, descriptors, commitments) | idea | Every cross-impl divergence so far was found by hand or by a soak |

## Trust-model attacks (DEP-21 and beyond)

| Attack | Status | Notes |
|---|---|---|
| TEE class break: a platform's attested seats signing theft | have (sim) | `analysis/zeroday_sim.py`, `attest_sim.py` |
| Stolen verifier or trust-root key | idea | DEP-14 revocations, DEP-21 endorsements |
| Identity fork after an enclave handoff | idea | DEP-21 §8 |
| Endorsing one codebase under two source names to dodge `max_per_source` | idea | DEP-21 open question 6 |
