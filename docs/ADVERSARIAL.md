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
| Byzantine member seated in honest quorums: randomly withholds or delays cosignatures, omits balance commitments, withholds ruleset declarations | **have** | `soak-byzantine.sh` (member: `:lag-replica`, `:withhold-rulesets`); the commitment faults are an operator's, so they run as attacks: `attack-soak-fault.sh omit-commitments` and `falsify-commitments` (new switch, a balance 1 msat off). Expected: refused, nothing commits, nobody disputed. Nov 4 09:00: omit refused (0 of 3 cosignatures), PASS; 10:22: falsify refused (0 of 3), PASS |
| Hostile depositor bot: malformed descriptors, replays, duplicate deliveries, reused nonces, dust exits, fee-griefing | **have** | `soak-hostile.sh` + `devnet/hostile-wallet.lisp`, every 20 min from a funded fresh key: bad-descriptor, overdraw, dust-exit, nonce-reuse, and replay (an exit request twice, then a different one under its nonce, while the relay duplicates every request to the operator for 3 min). Nov 4 manual replay on E (cl) and B (Rust): the duplicate got the original result and the different request was refused on both |
| Lagging or blind judge, kept permanently behind | have (regtest) | `redteam/check-confiscation-answer.sh` (`:blind-relay`): the judge challenges and accepts the answer; a judge that cannot read where answers go reaches no verdict on a lapse (DEP-06, Nov 5) |

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
| Every participant withholds its reveal, so the lottery can't be claimed | have | `check-rearm.sh` (`:withhold-reveal`): the re-arm round recovers it (DEP-06 Phase 4, provisional) |
| The drawn winner yields its own custody (every fork yields, nobody claims) | have | `check-rearm-yield.sh` (`:yield-win`, round 1 only; the soak 30ea46ac shape): the re-arm round recovers it |
| Every voter is down (or runs a build without re-arm) through a round's scheduled windows | have | `check-rearm-late.sh` (`:hold-rearm-until`): the first recurring window re-arms the stranded lottery (DEP-06 Phase 4 step 3, ruled Nov 7) |
| An armer arms between windows, or in every recurring window with a failing pledge, to burn the four-arm bound | idea | A between-window arm counts against the bound but belongs to no window; once every armer has run out, the output stays unspent until the vault's post-expiry tiers. Untested |
| A recovery voter refuses to sign or follow the re-arm spend, below the tier's threshold | idea | Should fall through to the later tiers (1008/4032/8064); untested |
| A participant withholds in every round, burning the four-arm bound to strand the output for good | idea | The spec's named residual risk; check that honest armers' rounds still claim through the subset leaves |
| Dereliction (a member that won't confirm a disclosed fraud) | have | `attack-dereliction.sh` |
| Veto via pledge spend | have (never valid) | `attack-veto-pledge.sh`: its precondition hasn't arisen in any run |
| A member that stops cosigning entirely | idea | Not provable today (known limit) |
| Strategic seating to capture quorums | have (sim) | `analysis/seating_sim.py` |
| A receiver whose whole quorum is attacker keys (L4) | idea | Seating / trust-model limit |
| Lottery griefing: arming without ever claiming | idea | |
| A guilty majority confiscates into a lottery of its own colluders (`:lottery-include-accused`) | next | Authorised under v7, a theft under strict-lottery-v8; scenario not yet wired |

| **Grind the lottery cut against early reveals.** cl published each preimage as soon as its own confiscation proposal reached the mempool. When two proposers raced over different cuts of the arms, the losing proposal's participants had already revealed, and a proposer seeing those preimages could pick the subset (DEP-06 admits any subset of the arms counted at the confiscation's block) that makes itself win. Seen on the signet soak Nov 8–9: B `4c37ee24`, C `2e746831`, H `34ee321e`, L `900c3874` were logged "on chain; revealed" and never confirmed (the competing `90c29326`, `c58f3a19`, `a1da468e`, `477414c9` did). Evidence: `/mnt/lisp/signet/archive/cascade-20261107/` | fixed | (cl rungfix): reveal only at 3 confirmations, as deposits-rust; save a lottery only once confirmed. Scenario idea: two proposers, one grinding, assert no reveal precedes depth 3 |
| **A false theft proof by a judge that cannot rebuild a bumped vault's confiscation.** Any node that (re)starts after a vault is confiscated, or never looked while it was unspent, rebuilt the confiscation from rung 0's amounts when the rotation had confirmed at a higher rung, challenged the authorised spend, and its lapse convicted the signers (cl only; DEP-03 already said to read the rung from the spending input). Soak Nov 8: G `1707005c`, spend `df9cac8c`, Δ 6076 sats; cld4 challenged, cld2/cld3/cld4 then disputed honest A, I, K by contagion (ALARMs 2026-11-08T20:43). An attacker can cause this on purpose: bump a rotation (anyone may broadcast a higher rung) and wait for a restarted judge | fixed | (cl rungfix; spec DEP-03 clarified; vector + `redteam/check-confiscation-vault-rung.sh`) |
| **Strand a lottery by being its only Rust participant.** deposits-rust looked for the lottery over every arm it holds now; a confiscation over a valid subset (a proposer that saw fewer arms) was never recognised, so its sole participant neither claimed nor yielded and nobody else can. 751e6951 round 1 (output `343e8375`, block 4259, participant ref6 only) stranded from Nov 6. A cl proposer can do this to a Rust member deliberately by proposing over a subset | fixed | (deposits-rust: subset search in the claim) |
| **Withhold Rust's voters from a re-arm.** deposits-rust answers `lottery_rearm_sign` with "Unknown action", so a mixed quorum's tier-0 re-arm (threshold T) never gathers T. cl only ever asked tier 0: E `d5880288` round-1 lottery `543cfc26` sat at "3 of 4 re-arm signatures" for ~3000 blocks | fixed | (cl: fall through open tiers, per DEP-06 "or a later tier if fewer sign"); Rust still runs no re-arm round (**next**) |
| **A phantom DisputeAcquire outlives the fix that stops new ones.** cld7's fork of 751e6951 ends in a DisputeAcquire (seq 11) committed by the pre-69c3225 restart bug; its fork is "normal" for good, so it can never arm a re-arm round ("DISPUTE-ARMED-REARM ... state normal", 108 times). Under "no retraction" cld7 is out of that quorum; recovery depends on the remaining voters and the lower tiers | idea | should a node refuse its own fork's DisputeAcquire on load when no on-chain claim backs it? (ruling) |

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
