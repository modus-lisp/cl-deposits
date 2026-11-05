# Chaos: an honest network in a hostile environment

The backlog of environmental faults to run against the devnets: everything goes
wrong except that no participant means harm. Ideas go in as soon as anyone has
them, even half-formed, since they are easy to lose. The deliberately malicious
counterpart is [ADVERSARIAL.md](ADVERSARIAL.md).

Status: **have** = running in the soak or the scenario suite; **next** = agreed
and queued; **idea** = written down, not yet built.

Every run of these needs the oracle described in ADVERSARIAL.md §Oracle. Under
chaos alone, the expected number of disputes, proofs and challenges against
anyone is zero. Each one is a finding.

## Processes and versions

| Fault | Status | Notes |
|---|---|---|
| Random node restarts (chaos loop) | **have** | `devnet/soak-chaos.sh`; nodes are started with `setsid -f`, so no wrapper shell survives a restart |
| Stochastic deploys: each node switches build at a random time inside a window and converges by a fixed point | **have** | `devnet/soak-deploy.sh`; first used Oct 30 for balance-anchor-v6 |
| Continuous version churn: repeated stochastic deploys, so mixed versions are normal, with occasional rollbacks | idea | `soak-deploy.sh --rollback` exists but has not been run |
| Freeze a node (SIGSTOP 5–20 min), then resume it far behind | **have** | `soak-chaos.sh`, 20% of turns (CHAOS_FREEZE_PCT). Exercises gap-fill, the replica lane and stale cosigns |
| kill -9 mid-write | **have** | `soak-chaos.sh`, 20% of turns (CHAOS_KILL9_PCT). Crash consistency of append-only ledger persistence and fork files |
| Disk full on one node | idea | What does a failed persist do? It must never sign past what it saved |
| Slow disk or I/O stalls | idea | |
| Memory pressure / heap exhaustion on a cl node | idea | |
| Clock skew on a node | idea | Nothing should read wall time for a rule; check that's true |

## Network and relay

| Fault | Status | Notes |
|---|---|---|
| Drop, delay, duplicate and reorder relay events per node | **have** | `soak-netchaos.sh` (every 30 min, one node, 5–20 min): delay, jitter (reorder), dup, lossy. Rules in `devnet/beacon-relay.lisp`; dup is beacon's `(:DUP s)` verdict (beacon 3413ba6). Faults apply to what the node publishes: beacon cannot tell which connection is which node |
| Cut one node off the relay for minutes | **have** | `soak-netchaos.sh` `cut`: everything it publishes and every request addressed to it is refused. It still reads; a full cut would need per-connection identity in beacon |
| Partition: two groups of nodes see different relays | idea | Needs a second beacon instance |
| Relay restart / store loss | idea | Does everyone recover history, or does a ledger strand? |
| Relay serving truncated history (page caps, `until` edges) | idea | The Rust reimport walk once relied on page size |
| Full inbox / backpressure | idea | Rust once dropped updates silently when an actor inbox was full (fixed Oct 24); keep a regression |
| Slow relay (high latency on every query) | idea | Challenge windows and cosign timeouts must hold |

## Chain

| Fault | Status | Notes |
|---|---|---|
| Short reorgs (invalidate 1–3 blocks, mine a competing branch) | **have** | `soak-chainchaos.sh` (every 2 h, reorg or fee spike). First depth-1 reorg by hand at height 810, Nov 4 |
| Deep reorg past the 3-block rule | idea | What does each implementation do when a "judged" spend vanishes? |
| Fee spikes: raise the mempool's feerate for a while | **have** | `soak-chainchaos.sh`: for 20–45 min every mempool tx below 12 sat/vB is held out of blocks (prioritisetransaction), so low rungs stall |
| Mempool eviction of a rung | idea | |
| Stalled mining (no block for a long stretch), then a burst | idea | Windows are in blocks; check nothing assumes block rate |
| bitcoind restart or RPC outage on one node | idea | |
| One node's bitcoind lagging behind the others | idea | Judging needs to tolerate a different tip |
| Two writers on one checkout: a docs commit made with `-a` in a checkout whose submodules were stale rolled four dependency pins back (55a567f, fixed in a4f871b) | idea (process) | A gate or pre-commit check that refuses a commit moving a submodule pin backwards |
| Signet difficulty climb | have (by accident) | Mining one block a minute raises difficulty 4x every 2016 blocks; reset when it hurts |

## Scale and time

| Fault | Status | Notes |
|---|---|---|
| Long-running ledgers (100k+ updates) | have | The Oct 24–28 soaks found Rust and cl full scans at about 140–190k updates |
| Many dispute forks on one ledger | idea | cl once held 56 forks on one node |
| Many ledgers per node | idea | |
| Bot load spikes | idea | |

## Leads: unexplained observations to chase

| Observation | Seen | Notes |
|---|---|---|
| **cl judges a lapsed proof valid that Rust rejects: 6056fb38's confiscation rung 1.** cl members accept the lapsed-challenge proof against ref6 as grounds on ledger J and sign its confiscation; Rust members refuse. ref6 answered the challenge (Kind 9112, 116 updates) at 15:29Z, so under DEP-06 an answer exists. cl's `rebuilt-confiscation-p` still misses that rung: the cl-side half of the Nov 4 false chain (cld13 challenged the same rung) | Nov 5 16:08Z | **Fixed in cl 4d8cb1d (Nov 5).** cl's `dispute-view` replayed the operator's whole linear chain, which on 6056fb38 carried on past the fork point with the colluding majority's invalid credit. The replay refused it (OVER-OBLIGATION), the rebuild failed silently, and every cl judge took the honest rung 1 for unanswered. The base now ends at the last fork point (DEP-06 §Authorised confiscation, spec 87ad391, every ruleset); Rust already did. Vector `confiscation_past_fault.txt` from the real 6056fb38 data; both implementations pass, and it fails without the fix. After the deploy (11:53 local), cl judges excluded every arm on J ("its proof does not verify: the spend is answered") and signed nothing more. |
| A docstring with bare double quotes became code: the soak's cl raised "variable A is unbound" in the vault-spend verifier, so cl judged no vault-spend proof (failing closed as "not judged yet") | Nov 5 10:30–11:07 | **Fixed in cl 354cc9e,** with a new `compile` gate in inspect/run-all.sh that fails on any undefined-variable warning (it fails on 04d687a) |
| A judge blind to the relay lets a confiscation challenge lapse ~3 min before it can rebuild the confiscation from the published answer, and proves an honest lottery participant (regtest confiscation-answer, c782e0db: answer at 18:47:58, lapsed proof against e7a388b7 at 18:58:50, accepted at 19:01:50) | Nov 4 | **Fixed Nov 5 (cl 04d687a + 354cc9e, Rust 8d832c2, spec 07340c0).** Cause: the answer carries only the dispute's updates, and a judge whose relay lacked the ledger rebuilt from them with no LedgerOpen. Both now rebuild from the judge's own base chain plus the answer; on regtest the answer was accepted 60 s after the challenge. Separately, DEP-06 "a lapse is judged where answers are read": no lapsed proof is published, entered or accepted unless the relays and own store were re-read and found no answer; unreadable means no verdict |
| Ledger J (honest, ref6) confiscation at 4/5 signatures on a false lapsed-challenge proof; cl members kept proposing, 806 sats each | Nov 4 11:25–16:57Z | **Never confiscated.** Since cl 4d8cb1d no member signs it, and no arm on J has grounds, so it can never reach 5/5. J itself stays frozen at seq 49174: the members that disputed it on the false proof keep refusing to cosign, which is the intended outcome (no retraction; a node that acted on a false proof leaves that quorum). J recovers only by re-seating its quorum, or through its expiry path. ref6's other ledgers 1badeb9d and f3297395: no new proposal or signature since the fix. The oracle's three ref6 ALARMs are marked resolved in `soak/alarms-resolved.tsv`. |
| **False accusation chain against an honest soak operator (ref6).** cld13 challenged rung 1 (23f29403) of the invalid-credit attacker ledger 6056fb38's confiscation, a rung it had itself signed; nobody answered within the 72-block window (check-obligations had just mined about 120 blocks), and lapsed-challenge proofs went out against the rung's signers ref6 and 82bf1db5, then by contagion onto ref6's ledgers J (soak), 1badeb9d and f3297395. cl soak nodes armed on J; its confiscation was at 4 of 5 signatures at 09:51 | Nov 4 09:29–09:51 | Three causes: (1) cl's watch judged a rung it signed only by a fresh relay rebuild, which missed: fixed in cl 702d6e0, deployed by 10:21; (2) Rust answers only rotation challenges (`answer_spend_challenges` in vault_watch.rs looks only for a QuorumBegin), never confiscation ones as DEP-06 requires: NOT fixed, a cross-impl divergence; (3) Rust's early rung bump (above) put a rung > 0 on chain at all. Harness: the fast-mining scenario is out of the signet default, burned members stay up (6aa6954) |
| A cosigner of the fault can win the confiscation's lottery: on the invalid-credit attack ledger 6056fb38, colluder cld26 (which cosigned the over-obligation credit and was itself proven, NonConformingCosignature) armed with valid grounds and won custody | Nov 4 09:28 | DEP-03/06 exclude only the accused operator. The fault update's cosignature set is literal evidence, so the cut could exclude its signers; a ruleset question for the user |
| Rust bumps a confiscation to rung 1 33 s after rung 0 (ledger 1badeb9d: 09:24:07 rung 0, 09:24:40 rung 1, no block in between) | Nov 4 09:24 | `h_c` comes from `wallet.get_block_height()`, the BDK sync height, which lags bitcoind under load; a stale low h_c makes the schedule run early. Costs fee only |
| cl logs "confiscation <rung 0> on chain; revealed" for a rung that a higher rung then replaced (1badeb9d: rung 1 4a2e8a66 confirmed, its lottery output claimed by ref6) | Nov 4 09:24 | The claim used the confirmed rung, so likely wording only; check what cl keys its reveals on |
| A cl operator whose update the relay refused never sent it again: members stood at the seq before it and refused every later update ("expected seq N"). Ledger I (cld5) wedged at seq 37009 from 06:29, its inbox passed 75,000, and C and E could not rotate without cld5's consent | Nov 4 06:29 (netchaos lossy rule on cld5) | **Fixed** in cl: `republish-missed` resends our updates N.. when a member expects N. The reference already heals by diffing the relay against its history |
| An UncreditedLightningPayment proof has nothing that dates the payment: it shows the preimage and an accused update at proof_sequence with no credit, but proof_sequence could precede the payment. Its embedding is checked only for presence and causal chain, never against proof_sequence | Nov 4 (reading, dispute-entry fork) | cl has no lightning verifier and declines these; Rust accepts them with an embedding. Needs a settle-time anchor (e.g. the invoice's expiry, or an accused update acknowledging the HTLC) |
| regtest `down` returns while bitcoind still holds its datadir lock, so the next `up` aborts and no cl node starts | Nov 3 | devnet/regtest-net.sh should wait for bitcoind to exit |
| cl's builder and cosigner take a confiscation's shape from their *own* fork's reason; DEP-06 and the watch take it from every DisputeEnter | Nov 3 (code reading, grounded-arms-v7 work) | Under grounded-arms-v7 both use the grounded DisputeEnters; under earlier rulesets a dispute with mixed reasons can still split builder and watch |
| Grounds after a custody change: Rust reads the ruleset and governing quorum_expiry from the original operator's chain, cl from its base record's state | Nov 3 (code reading) | A dispute of a new custodian (DEP-06 proof 11) may judge an expiry ground differently; no vector covers it |
| A stale DisputeEnter (a dispute on a vault since rotated away) moved the watch's fork point below the builders'; its challenge of F's real confiscation lapsed into false contagion against cld4, cld5, cld6, and G, I and K then expired and were confiscated | Nov 2 06:38Z | Fixed: DEP-03 §The dispute, cl 02bbc86, Rust af425fa. Grounded arms (v7) pending. Scenario idea: a disputant with a stale DisputeEnter on a rotated vault joins a new dispute, and every watch must excuse the confiscation |
| cl wallets time out on transfer_lock / transfer_complete against Rust-operated ledgers (B D F H J L), Oct 30 20:00 – Oct 31 02:00 EDT | Oct 31 | **Explained.** Rust replicas left a deposit's open block and fee baseline at 0 (set only on the operator's commit path), so Rust operators proposed FeeCollects from height 2016; cl members refused until 2317 (open 301 + 2016), and each refused round held the operator's cosign pipeline. Fixed: deposits-rust c088582 / 136ac8f, DEP-07 4edaf08, vector `deposit_baseline.txt`. Existing soak deposits keep `opened_at_block` 0 in Rust's state snapshots (affects `fee_change_after_blocks` and `blocks_since_open_below` only) |
| cld1's dispute on F, entered on its own false NonConformingUpdate (fixed in cl b0747f7), stays standing with an 8M-sat pledge | Oct 30 23:33Z | Goes dormant once F's vault is spent by a rotation, but cld1 keeps refusing to cosign F ("we disputed it") forever. Design question: a node whose own proof no longer verifies has no way to stand down |
| Does Rust verify its own proofs against a replay before publishing (DEP-06 "Verify before publishing")? | Oct 31 | **Done** in deposits-rust c088582: every proof goes through `publish_fraud_proof`, and a non-conforming verdict from replica state is re-verified from the history before arming |
| cl nodes rejected 6 fork updates as "HeightDecreases" during restarts | Oct 28 05:32–05:41 | Not investigated |
| Whether a Rust operator stands down after losing custody to a lottery winner | Oct 28 | The reset removed the state that showed it |
| A cl bot's empty reply before any other fault | Oct 20 21:00:56 | Unexplained |
| A cl bot's balance view drifting (InsufficientDepositBalance) | Oct 24 | |
| cl memo tables are process-global: `*pledge-verdicts*`, `*obligations-memo*`, `*rebuilt-confiscations*`, `*rebuild-misses*`, keyed by ledger rather than by node | Oct 30 (code reading) | Gates and chaos tests run several nodes in one image, so one node's cached verdict could leak into another's |
