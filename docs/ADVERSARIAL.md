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

Status: **have**: `devnet/soak-oracle.py`, started by `soak.sh start` (summary in `soak.sh status`,
verdicts in `soak/log/oracle.log`). It judges what nodes publish on the relay, the same for both
implementations: fraud proofs (9101), spend challenges (9111) and answers (9112). Adversaries are
listed in `soak/adversaries.tsv`, scheduled attacks in `soak/attacks.tsv`. Replaying the Nov 3 archive
(`--replay`) gives ALARM 11: the Oct 30 NonConformingUpdate and its four contagion proofs, and the
Nov 2 lapsed-challenge vault-spend proofs.

## Live attackers in the soak

| Attacker | Status | Notes |
|---|---|---|
| Attacker ledgers: two or three ledgers whose operators periodically run an attack from the catalogue below | **have** | `soak-attackers.sh`, one scenario every 4 h in rotation: check-obligations (uncredited payment + unhonoured obligation, depositors paid from the confiscation), `attack-soak-fault.sh` forge-lock / invalid-credit (blind colluding majority) / equivocate (end to end: proof, confiscation, lottery claim), vault-spend, vault-anchored. Attacker roles only from minted nodes outside the soak (`soak/soak-nodes`), stopped once burned; the honest member and ref6 are soak nodes. End-to-end verdicts in `soak/attack-outcomes.tsv`, per attack in the oracle summary |
| Byzantine member seated in honest quorums: randomly withholds or delays cosignatures, omits balance commitments, withholds ruleset declarations | **have** | `soak-byzantine.sh` (member: `:lag-replica`, `:withhold-rulesets`); the commitment faults are an operator's, so they run as attacks: `attack-soak-fault.sh omit-commitments` and `falsify-commitments` (new switch, a balance 1 msat off). Expected: refused, nothing commits, nobody disputed. Nov 4 09:00: omit refused (0 of 3 cosignatures), PASS |
| Hostile depositor bot: malformed descriptors, replays, duplicate deliveries, reused nonces, dust exits, fee-griefing | **have** | `soak-hostile.sh` + `devnet/hostile-wallet.lisp`, every 20 min from a funded fresh key: bad-descriptor, overdraw, dust-exit, nonce-reuse, and replay (an exit request twice, then a different one under its nonce, while the relay duplicates every request to the operator for 3 min). Nov 4 manual replay on E (cl) and B (Rust): the duplicate got the original result and the different request was refused on both |
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
| Arm on another member's grounds by copying its carried proof into one's own DisputeEnter (allowed by grounded-arms-v7; motive is never examined) | idea | Check the copy counts exactly like the original |
| Carry a proof that verifies but accuses someone else, or an old one from an earlier vault period | have (vector) | grounded_arms.txt: wrong accused is ungrounded; an old valid proof still grounds a new dispute (by design?) |
| A groundless DisputeEnter entered first, then the real proof arrives: one DisputeEnter per live fork keeps the groundless one | idea | Race in redteam scenarios that enter disputes by hand; a member could lose its grounds |
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

## Proofs from replayed state (DEP-22 draft)

| Attack | Status | Notes |
|---|---|---|
| A judge with corrupted state (double apply, gap, wrong baseline) publishing a proof that looks real | have (incidents) | Oct 30 23:33Z on F, Oct 31 fee baseline. Inject with a switch that perturbs one replica's state; expect refusals, never proofs |
| An operator whose item pointer skips an update (to hide a debit) | idea | DEP-22 item fork proof |
| An operator committing a wrong snapshot root when moving to v7 | idea | The last replay-judged conviction under DEP-22 |
| An operator pointing an item at an update on another branch | idea | Should surface as Equivocation |

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
