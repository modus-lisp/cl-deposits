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
| An operator disputes its own ledger: on a proof against itself it opens a fork and signs a `DisputeEnter` at the fork point's next sequence, then keeps signing its chain | have (found live; a rule since DEP-06 §Enter "The accused never disputes itself") | Not an attack on anyone else: it hands every member an Equivocation proof against itself, signed by its own key at one sequence, whenever a member holds both updates. A republished fork is enough: Rust ref4 on 5effb9e8 (signet Nov 19–20, CHAOS.md), proved by four members the morning after. Gates: `self_dispute.json` (both), Rust `self_dispute_vector` / `no_permitted_dispute_makes_us_equivocate` / `fork_fate_vector`, cl nodes "respectful dispute on quorum expiry" (the operator opens no fork and signs nothing). A live arm would point a member's QuorumExpired proof at an attacker operator with a pre-fix binary and check the oracle scores the Equivocation as a PASS |
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
| **Deliver the proof before the updates.** Hand a member a valid proof whose fault sits past its replica's tip (or let it arrive while the member lags), so it refuses the proof as "follows an update that is not in this ledger's history" and never judges it again: the member loses its standing in the dispute (no fork, no arm, no vote) | have (vector + gates) | Regtest 1120-075609, 2026-11-20T08:02:51Z: ref7, 3 s behind 7341c3d1 at seq 4, refused four seq-9 NonConformingUpdate proofs for good. Mitigation (DEP-06 §Verification, "missing history is not invalidity"): a proof that fails while a history need (`fr:proof-history-needs` / `history_needs`) is unmet is PARKED, never refused; the ledger is caught up off the handler (`kick-proof-catch-up`; the Rust run loop's gap-fill) and the proof is judged again when its needs are met or the replica advances. Vector `proof_history_needs.json` (judge / park / refuse); node gate "a proof we cannot judge YET is parked, not refused" |
| **Flood the parked set.** Publish many proofs (valid-looking, distinct hashes) whose needs reach far past every replica, to grow members' memory or push out the one real parked proof | have (gates) | Bounded per accused ledger: 32 held, one per proof hash; when full a proof displaces the one reaching FURTHEST past the replica, or is dropped if it reaches further itself, so far-ahead junk cannot evict a proof about to become judgeable; each is held at most an hour; a progress re-judge is at most once a minute (Rust) / once a watch pass (cl). Residual: 32 x (ledgers a member cosigns) proofs of memory, and a flood can still fill a ledger's set ahead of a real proof that reaches further than the junk |
| Grief a lottery with dust: pay the lottery's address (anyone can derive it from the public arms) so "a UTXO at the lottery's script" is the attacker's coin, not the confiscation's output | have (unit) | **Fixed (Rust, branch lottery-outpoint; cl never searched by script, its UTXO scan covers only its own target address):** the lottery is claimed, re-armed and judged at its outpoint (the confiscation's output 0, or the latest re-arm spend's), never by searching for a UTXO paying its script. Rust's `claim_lottery` had taken the first UTXO at the script (`find_utxo_for_script`); `chain_backend::outpoint_tests` holds a dust coin and the real output at one script and requires the named outpoint. A redteam scenario (`:lottery-dust`, pay the address before the confiscation confirms) is not yet wired |
| Name any confirmed transaction in a `DisputeAcquire`: an armer appends an acquire whose `claim_txid` is some confirmed transaction (its own payment, another dispute's claim), and under v8's confirm-only rule members read custody as moved to it | have (vector) | **Fixed (branch lottery-outpoint, cl and Rust; DEP-06 "An acquire binds once its claim confirms", now MUST):** an acquire binds only if its claim is confirmed AND its input 0 spends the dispute's current lottery outpoint, walked back from the claim through re-arm spends to a transaction that spends the vault. Seen without malice in regtest rearm-rust 1120-090836 (CHAOS.md §Chain). Vector `acquire_binding.json` (the unrelated-payment, other-output and older-round cases); nodes gate "v8: the same confirmed claim does not bind when its lottery is another vault's". A scenario (`:phantom-acquire` with a real confirmed txid instead of a random one) is not yet wired |
| Reuse of cl's preimage across disputes of one ledger: cl derived the lottery seed from the node key and the ledger id (plus the round), so its second dispute of a ledger committed the preimage it revealed in the first. Anyone could compute cl's contribution before the second draw's arms closed and arm (or withhold) to steer it | have (gate) | **Fixed (branch lottery-outpoint, cl; DEP-06 Phase 2 "fresh per dispute and per round", now MUST):** the seed (`lottery-seed`, v2) binds the fork's `last_valid_sequence` and the chain hash at its fork point (both from our own DisputeEnter, so a restart re-derives it before the base is loaded) and the round. A fork armed by an older build is still recovered through the v1 seed. Restart gate "a dispute of the same ledger at another fork point draws a fresh seed". Rust already bound `last_valid_sequence` |

| **Grind the lottery cut against early reveals.** cl published each preimage as soon as its own confiscation proposal reached the mempool. When two proposers raced over different cuts of the arms, the losing proposal's participants had already revealed, and a proposer seeing those preimages could pick the subset (DEP-06 admits any subset of the arms counted at the confiscation's block) that makes itself win. Seen on the signet soak Nov 8–9: B `4c37ee24`, C `2e746831`, H `34ee321e`, L `900c3874` were logged "on chain; revealed" and never confirmed (the competing `90c29326`, `c58f3a19`, `a1da468e`, `477414c9` did). Evidence: `/mnt/lisp/signet/archive/cascade-20261107/` | fixed | (cl rungfix): reveal only at 3 confirmations, as deposits-rust; save a lottery only once confirmed. Scenario idea: two proposers, one grinding, assert no reveal precedes depth 3 |
| **A false theft proof by a judge that cannot rebuild a bumped vault's confiscation.** Any node that (re)starts after a vault is confiscated, or never looked while it was unspent, rebuilt the confiscation from rung 0's amounts when the rotation had confirmed at a higher rung, challenged the authorised spend, and its lapse convicted the signers (cl only; DEP-03 already said to read the rung from the spending input). Soak Nov 8: G `1707005c`, spend `df9cac8c`, Δ 6076 sats; cld4 challenged, cld2/cld3/cld4 then disputed honest A, I, K by contagion (ALARMs 2026-11-08T20:43). An attacker can cause this on purpose: bump a rotation (anyone may broadcast a higher rung) and wait for a restarted judge | fixed | (cl rungfix; spec DEP-03 clarified; vector + `redteam/check-confiscation-vault-rung.sh`) |
| **Strand a lottery by being its only Rust participant.** deposits-rust looked for the lottery over every arm it holds now; a confiscation over a valid subset (a proposer that saw fewer arms) was never recognised, so its sole participant neither claimed nor yielded and nobody else can. 751e6951 round 1 (output `343e8375`, block 4259, participant ref6 only) stranded from Nov 6. A cl proposer can do this to a Rust member deliberately by proposing over a subset | fixed | (deposits-rust: subset search in the claim) |
| **Withhold Rust's voters from a re-arm.** deposits-rust answers `lottery_rearm_sign` with "Unknown action", so a mixed quorum's tier-0 re-arm (threshold T) never gathers T. cl only ever asked tier 0: E `d5880288` round-1 lottery `543cfc26` sat at "3 of 4 re-arm signatures" for ~3000 blocks | fixed | (cl: fall through open tiers, per DEP-06 "or a later tier if fewer sign"); Rust (2026-11-14) folds round-tagged arms and, as a recovery voter, answers `lottery_rearm_sign` only for the spend it rebuilds byte for byte through an open tier; regtest `rearm-mixed` needs ref7's signature for tier 0 (threshold 2 of 2) and passes. Still open: Rust proposing and assembling a re-arm spend, arming a later round, and claiming in one. Related, fixed in cl d637db8: **slow voters.** A voter whose answer comes after the proposer's 30 s wait was dropped on every pass (d5880288, a2d44d7a: "only 1 of 3"). Late answers are now kept by sighash; regtest `rearm-slow` slows both voters past the wait |
| **A phantom DisputeAcquire outlives the fix that stops new ones.** cld7's fork of 751e6951 ends in a DisputeAcquire (seq 11) committed by the pre-69c3225 restart bug; its fork is "normal" for good, so it can never arm a re-arm round ("DISPUTE-ARMED-REARM ... state normal", 108 times). Under "no retraction" cld7 is out of that quorum; recovery depends on the remaining voters and the lower tiers | have | ruled 2026-11-10 (REVIEW 9, "yes"): under strict-lottery-v8 an acquire binds only once its claim confirms, so a phantom one deposes no one and the lottery stays live (DEP-06 §Phase 4). cl `acquire-binds-p`, Rust `claim_confirmed`; regtest `acquire-unconfirmed` (red-team `:phantom-acquire`) |
| **Rotate a fraud dispute away.** A threshold of members that never disputed cosigns the accused operator's QuorumBegin; before the 2026-11-10 ruling the freeze rule scoped every non-expiry dispute to the latest QuorumBegin, so the disputants' freeze lifted and they cosigned the accused's chain again (J unfroze this way on an expiry ground, which is correct) | have | ruled (REVIEW 8, "no"): under strict-lottery-v8 a fraud dispute freezes whatever its last_valid_sequence (DEP-05). Regtest `fraud-rotation`. **Still open:** the colluders can rotate *without re-seating* the disputants, so the dispute stands on a vault the rotation already spent (needs a ruling) |
| **Hold a quorum hostage by staying silent.** A member that never answers consent requests blocked every rotation of its operator until the quorum expired (soak A, Nov 7, cld2), handing every member a respectful-confiscation path | have | ruled (REVIEW 10, "permissionless means letting people gfy"): DEP-11 §Rotating without a silent member; the operator seats the consenting members from `drop_margin` before expiry. Regtest `rotation-drop`. Idea: a silent *majority* (fewer than three consent): only the expiry cascade remains, by design |
| **Game the seating order.** The seated set is the current members first, then newcomers, each in consent order (`seat_consenting`); a newcomer cannot displace a current member, but among current members the earliest consents are kept. A member could race its consent to stay seated over a slower honest one | idea | operator policy, not judged; watch for it if seats become valuable |

## Rule inverters

A **rule inverter** deliberately computes the opposite of a rule that every node must compute
identically (user, 2026-11-15). Most such rules sit behind two guards: a spend or claim that honest
voters sign only if it is byte for byte the one they rebuild, and a voter threshold. Against
both, an inverter only builds something nobody else signs, and the honest result lands without it
(**self-defeating**). An inverse that wins anyway is a finding. The inverters in the harness:
cl `ADVERSARY :invert-arm-selection` (a voter and proposer on the replaced arm rule) and
`:late-rearm` (an armer that re-arms after its window closed); regtest `rearm-invert` runs both.

| Rule (DEP-03/06) | Inverse | Guard | Self-defeating? |
|---|---|---|---|
| Re-arm arm selection (DEP-06 Phase 4 step 2): each armer's latest arm inside the window, of its first four | latest counted arm, then window-filtered (both implementations until 2026-11-15) | byte-identical spend | Yes for a proposer or voter now (`rearm-invert`: refused, the honest spend lands). **It was not for an armer** under the replaced rule: a later same-round arm signed past the close withdrew it from a closed window or emptied the cut. Fixed in both (cl `pick-round-arms`, Rust `pick_round_arms`; vector `rearm_window_arms.json`) |
| **Arm `block_height` inside a closed window** (the dating every window rule reads) | sign a same-round arm with a `block_height` inside an already-closed window and publish it late (after some voters signed, or after the spend confirmed) | none: fork updates are not cosigned, so DEP-02's 6-block bound never applies; only "non-decreasing along the armer's own fork" does | **NOT self-defeating: ruled 2026-11-15 (option A, arm manifests); see §Backdated arms below.** The arm is valid and in-window, so voters who rebuild before and after it arrives build different spends, and once the spend has confirmed every node that rebuilds the round afterwards derives a different next lottery and stops following it (a liveness grief; a newcomer can backdate a first arm into the cut the same way). Raised to the coordinator |
| Accused exclusion (DEP-03 §Lottery): Accused(grounds) are neither participants nor recovery voters (v8) | include the accused as participants or voters | under v8 a confiscation whose lottery includes the accused is not authorised (REVIEW 1); the re-arm spend is byte-identical | Yes under strict-lottery-v8. **No under earlier rulesets**, which accept either reading: a guilty signing majority can confiscate into its own lottery (known; the reason for v8) |
| Re-arm window j (step 3): the first closed window with a non-empty cut | a later non-empty window | byte-identical spend | Yes |
| Four-arm bound: an armer's first four arms by sequence count | the last four | byte-identical spend (round 1: the confiscation rebuild) | Yes |
| Recovery voters: the QuorumBegin governing the fork point, minus the operator (and the accused under v8) | a QuorumBegin past the fork point (e.g. one the operator rotated in afterwards) | byte-identical spend and confiscation | Yes |
| Recovery tier: the spend's nSequence is the tier's CSV | an earlier tier | consensus (CSV) | Yes |
| Re-arm fee: `reference_feerate` × the tier's exact vsize | another fee | byte-identical spend | Yes |
| Eligibility split at the window's close (`split_at`, confiscated_at = close) | at the tip | byte-identical spend | Yes |
| Grounded arms (v7+): only grounded DisputeEnters' arms count | count ungrounded arms | byte-identical spend and confiscation | Yes |
| Winner draw: sum of (len − 16) mod n over the revealed set | another winner | full-set leaf: consensus; subset leaf: voters attest only that subset's winner | Yes |
| Reveal deadline (72 blocks) before a subset claim | attest a subset early | voters attest only past it | Yes |
| Recovery destination: only the next round's lottery output | anywhere | the voter threshold only (the script does not bind it) | **No if the inverters hold the threshold**: honest voters must not sign, and v8 removes the accused, but colluders the grounds do not accuse still count (CHAOS Nov 5 lead). The trust assumption, not a new finding |

Every "Yes" assumes the honest voters hold the threshold. Any rule can be inverted by voters who
hold it.

## Backdated arms (ruled 2026-11-15: option A, arm manifests)

**What is possible, and why.** A `DisputeArmed` is an update on the armer's own fork. Its author
signs it and nobody cosigns it. DEP-02's bound on a header's height (within six blocks of the
cosigner's tip) is a cosigner check, so it never applies to these updates. The fold asks only that
heights do not decrease along the fork. A same-round re-arm must repeat the commitment and declare
collateral, but its target and pledge may change. So any armer can sign an arm dated at or below a
block that has already passed:

- at or below the confiscation block C, for round 1;
- inside a re-arm window that has already closed, for a later round.

It can then publish that arm after the spend is signed, or after it confirms. Every rule that
reads "each armer's latest arm" up to a height then gives a later reader a different answer than
the spend's signers had. Three ways this hurts:

1. **Round 1, the judge (the serious one).**
   - Judges rebuild a confirmed confiscation from each armer's latest arm at or below C (cl
     `rebuild-matches-p` over `armers-of :until C`; Rust `rebuild_matching` over
     `collect_armers_until`). They try every subset, and each subset's E (the highest signed height
     of its arms) fixes its pledge cut and obligations.
   - Say a participant publishes, after C, a re-arm dated C that pledges a coin created after E.
     Every subset containing that armer now excludes it at its own E, and every subset without it
     builds a different lottery. No subset rebuilds the confirmed bytes.
   - A judge without a cached verdict then challenges the honest confiscation, and proves against
     its signers when the challenge lapses: the Nov 4 false-proof chain, started after the fact by
     one armer. The cached verdict is cl's `*rebuilt-confiscations*`, held in memory only: a
     restart loses it, and a new or wiped node never had it. Rust re-judges in the same way.
   - **Reproduced on regtest, 2026-11-15** (`redteam/check-backdated-arm.sh` on `0ee6c1f` plus the
     testing-only `:backdated-rearm` knob). The scenario is ledger aa5bdc01: OP cld391, C2..C5
     cosign blind (cld390, cld389, cld388, cld387), H cld386 disputes, and X cld368 and J cld364
     are honest.
     - The confiscation c57e78a0 confirmed at 12107, and J first judged it "answered by its
       anchor".
     - X then published a round-1 re-arm signed at 12107, pledging a coin created at 12111.
     - J restarted without its vault-watch state, then logged: "armer 02ad368d excluded … pledge
       confirmed at 12111, after the snapshot 12107"; "VAULT SPEND CHALLENGED … nothing we hold
       answers it; challenging (5 signers)"; and after the window "vault spend: 3d42a6c1 signed it;
       lapsed-challenge proof against its ledger c0573b85" and "4cd8690d signed it; lapsed-challenge
       proof".
     - Both are proofs against signers of an honest confiscation. 3d42a6c1 is J itself: it proved
       against its own ledger.
2. **Round 1, the landed set, past eight armers.**
   - Claimers recover the confirmed lottery's participants by trying subsets of the current arms
     (cl `lottery-paid-by`, Rust `match_landed_set`). The output script binds only keys and
     commitments, so a changed target or pledge still matches, and so does a backdated newcomer.
   - Above eight candidates the search does not run, so seven backdated newcomers on a two-armer
     dispute lose the set. Rust re-derives it on every claim pass; cl keeps the lottery it signed
     or saw, but a node that never saw it re-derives it too.
   - Rust unit test `a_backdated_round_1_arm_loses_the_landed_set_only_past_8_armers` (`32bd467`)
     asserts that behaviour.
3. **Re-arm rounds, the split.**
   - The next round's lottery was re-derived from the window's cut (each armer's latest in-window
     arm). An arm backdated into a closed window, published after some voters signed, leaves
     voters that rebuilt before it and voters that rebuilt after it with different spends.
   - Published after the spend confirmed, it leaves every later reader with a different next
     lottery, so they stop following the round: a liveness grief.

**The ruling (A).** Arms stay self-signed. A spend is judged by the arm set its signers used, not
by "latest" (DEP-03 §Arm manifests, `strict-lottery-v8` only; frozen rulesets unchanged):

- Signers publish a **manifest**: (armer, sequence) per participant, carried in a Challenge
  Answer, Kind 9112, as `round` and `arms`.
- A spend is honest iff some valid manifest rebuilds it byte for byte. Valid means each named arm
  exists, no armer is named twice, each arm is within its armer's four-arm bound and of the round,
  and each is signed in the window.
- A judge without a manifest never proves on a failed rebuild. It challenges, and only a lapse
  proves. A manifest that does not rebuild the spend is no answer.
- The set after confirmation, including the next round's lottery, is the manifest's whose lottery
  pays the confirmed output.
- A backdated arm can at most delay a spend before it confirms, while voters' views converge.

**What we accept under A.**
- Before A, leaving out an armer was provable: the judge's rebuild from every arm would not match.
  Under A it is signing policy. A spend over any valid subset of the arms is honest, so a recovery
  threshold could quietly exclude an armer it dislikes, and the excluded armer has no proof to
  publish.
- Honest signers include every armer they saw by the close, and both implementations do. The guard
  is the threshold, as for the recovery destination in the table above.
- An excluded armer loses only its chance at custody. Its pledge is never taken.

**The open future fix (B): make arm timestamps provable.** Two ways:
- *Cosign arms*, so DEP-02's six-block bound applies. This costs a cosigning round per arm, and
  the cosigners are the recovery quorum, the parties a dispute already distrusts. A quorum that
  withholds cosignatures could then keep an armer out, the veto the self-signed arm was meant to
  avoid.
- *Anchor arms* on chain or in a timestamping service, so an arm counts only from its anchor's
  block. This costs a transaction (or an external dependency) per arm, and adds latency inside a
  six-block window.

Either way, "each armer's latest arm" becomes safe to re-derive, and omission becomes provable
again. Not scheduled.

**After A, the same regtest** (`backdated-arm`, flipped to expect no challenge and no proof;
ledger 4ae05a84):
- The confiscation e05b97a4 confirmed at 12247.
- X published a round-1 re-arm signed at 12247, pledging a coin created at 12251.
- The restarted judge J logged "4ae05a84's spend e05b97a4d603a127 rebuilds from its arm manifest
  (2 arms)" and "answered by its anchor". It raised no challenge and made no proof.

Unit evidence:
- cl `inspect/node-test.lisp`: the latest-arms rebuild fails after the backdated arm, and the
  manifest rebuilds it. A manifest missing a participant, or naming the backdated arm, does not.
  A manifest published by a node that signed nothing answers for the spend (permissionless).
- Shared vectors: `arm_manifest.json` (11 cases of arm-set validity, including the newcomer and
  the nine-armer case) and `confiscation_manifest.txt` (the rebuild), both run by cl and Rust.

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
