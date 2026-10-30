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
| Freeze a node (SIGSTOP 5–20 min), then resume it far behind | next | Exercises gap-fill, the replica lane and stale cosigns |
| kill -9 mid-write | next | Crash consistency of append-only ledger persistence and fork files |
| Disk full on one node | idea | What does a failed persist do? It must never sign past what it saved |
| Slow disk or I/O stalls | idea | |
| Memory pressure / heap exhaustion on a cl node | idea | |
| Clock skew on a node | idea | Nothing should read wall time for a rule; check that's true |

## Network and relay

| Fault | Status | Notes |
|---|---|---|
| Drop, delay, duplicate and reorder relay events per node | next | Through beacon's event-policy hook. Duplicate delivery is DEP-17; reordering is the lagging-replica case (Oct 21) |
| Cut one node off the relay for minutes | next | |
| Partition: two groups of nodes see different relays | idea | Needs a second beacon instance |
| Relay restart / store loss | idea | Does everyone recover history, or does a ledger strand? |
| Relay serving truncated history (page caps, `until` edges) | idea | The Rust reimport walk once relied on page size |
| Full inbox / backpressure | idea | Rust once dropped updates silently when an actor inbox was full (fixed Oct 24); keep a regression |
| Slow relay (high latency on every query) | idea | Challenge windows and cosign timeouts must hold |

## Chain

| Fault | Status | Notes |
|---|---|---|
| Short reorgs (invalidate 1–3 blocks, mine a competing branch) | next | The 3-deep spend rule, proof dating by signed height, spends that reorg out |
| Deep reorg past the 3-block rule | idea | What does each implementation do when a "judged" spend vanishes? |
| Fee spikes: raise the mempool's feerate for a while | next | Rotations and confiscations should actually climb their fee ladders |
| Mempool eviction of a rung | idea | |
| Stalled mining (no block for a long stretch), then a burst | idea | Windows are in blocks; check nothing assumes block rate |
| bitcoind restart or RPC outage on one node | idea | |
| One node's bitcoind lagging behind the others | idea | Judging needs to tolerate a different tip |
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
| cl nodes rejected 6 fork updates as "HeightDecreases" during restarts | Oct 28 05:32–05:41 | Not investigated |
| Whether a Rust operator stands down after losing custody to a lottery winner | Oct 28 | The reset removed the state that showed it |
| A cl bot's empty reply before any other fault | Oct 20 21:00:56 | Unexplained |
| A cl bot's balance view drifting (InsufficientDepositBalance) | Oct 24 | |
