# Red team: the claims the spec makes, and the attacks that test them

Devnet: `devnet/soak.sh` (six mixed ledgers) is the substrate; attacks run
against a live quorum with both implementations present.  cl nodes play the
attackers (an adversary mode on the control socket); the reference nodes are
victims and detectors, then roles are swapped where our code has the detection.
Every attack states its pass condition as what the HONEST side must do.

| # | claim (where) | attack | status |
|---|---|---|---|
| 1 | strict-majority cosign, independent validation (DEP-05 §63, whitepaper) | operator + colluding majority sign an invalid update; honest minority must refuse and dispute | |
| 2 | equivocation caught and punished (DEP-06) | equivocate with a colluding cosigner on both branches; double-spend across forks; colluder's slashing share excluded | operator caught; double cosignatures are not attributable (honest retries), collateral is the backstop (analysis) |
| 3 | censorship provable (DEP-11, DEP-12) | operator ignores a signed request; DeliveryEmbed; clock; censorship proof; dispute | not enforced in either implementation (open) |
| 4 | inactivity moves custody (DEP-19 §1–3) | operator silent past inactivity_blocks; majority attestation; respectful custody | |
| 5 | co-sign refusal provable; withholding majority is the stated limit (DEP-19 §9) | cosigner answers all but the clock-satisfying update | not implemented in either (open) |
| 6 | fraud proofs cannot be forged or replayed (DEP-06 §Verification) | malformed / stale / wrong-ledger / replayed proofs; cross-implementation acceptance rules | wrong-ledger: relabelling (closed, v2); self-accusing member: Finding 12 (fixed); malformed, stale open |
| 7 | lottery fair and spendable (DEP-03 §Custody Lottery) | out-of-range preimage; withheld reveal (partial leaf); commit≠reveal | N mismatch: organic #6 (mitigated); commit≠reveal: Finding 14 (cl fixed); withheld reveal: priced by the armer share (analysis) |
| 8 | transport outside the trust model | censoring / delaying relay; replayed ephemeral requests vs nonce+expiry | replay led to Finding 11 (fixed); relay censorship open |
| 9 | stated limitation: majority can spend an honest vault at Tier 0 (DEP-05 §120) | measure cost and footprint, not disprove | |

### 2026-09-30 — scenario: rollback depth, and why a blind window needs a self-sufficient majority

`redteam/attack-rollback-depth.sh` aims to measure how deep a rollback reaches when every honest
replica was offline at the fraud. Building it surfaced the key insight before it even ran: at Q = 7
a committed update needs 4 cosignatures, so to commit fraud with *no honest witness online* the
colluders must themselves be a majority (4), and only the remaining 3 honest members can be stopped.
The first draft stopped 4 and colluded with 3 — the fraud could not commit (tip stayed at seq 8).
Fixed to 4 colluders (cld2–cld5) and 3 stopped (cld6, ref6, ref7).

**This composes the concerns:** a blind window (no honest witness) is only reachable by a colluding
majority — exactly the case contagion punishes (§2c: all four colluders' own ledgers confiscated).
An honest member online means detection is immediate (forge-lock on A: 1 s). So "every honest
replica offline" is not an independent risk; it is a mode of the majority-collusion risk, and the
rollback it buys costs the colluders their vaults. (Run blocked on flaky ledger formation under soak
load; the design analysis stands.)

### 2026-09-30 — scenario: censorship hold (DEP-11/12), run

`redteam/attack-censor-hold.sh` on A (cld1 operates). **Honest arm:** cld1 answers, the transfer
commits. **Censor arm:** cld1 drops every wallet request (`:ignore-requests`); the transfer times
out; the wallet escalates through member cld6, whose DeliveryEmbed lands on its own ledger
(`:REQUEST-HASH` returned). Then **nothing acts on it**: no live dispute on A within 60 s (the
tombstoned forks there are from the earlier forge-lock run, not this), cld6 logs no embed-driven
action, and the victim's funds stay locked. Confirms docs/MISSING.md: censorship proofs are
unwired. Side observation: a victim's LOCKED balance climbs run to run as never-completed
transfers accumulate locks; these self-heal at each lock's timeout_height
(fail-expired-transfers, ~144 blocks here), so it is latency, not a stuck-funds bug.

### 2026-10-02 — dereliction (DEP-19 §6) end to end, live

`redteam/attack-dereliction.sh` and a manual drive on the devnet.  cld1 forged a witness-less
lock on a fresh ledger DL with a colluding majority (cld3 cld4 cld5 cosign blind); cld6, a member,
was set :ignore-fraud — it refused the update but took no dispute action.  The honest member cld2
self-detected, disputed DL, and armed a dereliction watch.  Once cld6 kept operating its own ledger
K past dispute_response_blocks (5), cld2 and cld3 produced DisputeDereliction proofs:
"02d2d197 kept operating ee96a0e4 5 blocks past the fraud without disputing 7667ca05".  cld6's K
went to :ARMED for confiscation; cld2's and cld3's own ledgers stayed clean (acting members are not
punished).  So a member that stays online and ignores a fraud proof is itself slashed — the duty the
trust-model cascade (§2e/§2g) assumes is now real on the wire, both implementations.

Two wiring bugs the live run surfaced and fixed: the dereliction watch was armed only on the
received-proof path, not on self-detection (report-non-conforming); and :ignore-fraud gated only
received proofs, so a derelict member still self-disputed.  A deterministic node-test gate now drives
the whole self-detect -> watch -> drive-dereliction -> dedup chain.

## Capital efficiency vs security: the axis every attack is measured on

The protocol's security is bought with idle capital: the collateral fraction
of every operator's vault, the reserves that cap obligations, the collateral
each quorum member must keep on its own ledger, and the funds a wallet has
parked behind a lock or a clock.  Every attack above has a COST to the
attacker (collateral at risk, quorum seats to hold, blocks to wait) and an
EXPOSURE (reserves, deposits, or a hold on someone's funds for N blocks), and
both scale with the parameters the spec leaves to operators:

| knob | where | efficiency side | security side |
|---|---|---|---|
| collateral / reserves ratio | QuorumBegin | idle sats per sat of deposit capacity | slashable loss per byte of fraud |
| quorum size Q ∈ {3,5,7} | QuorumBegin | seats to fund and cosign latency | seats a coalition must buy |
| quorum_expiry / membership | member terms | rotation frequency (on-chain fees) | how long a stale quorum can hold |
| timeout_height on locks | wallet | capital parked per failed transfer (the soak found 450k of 640k sats parked) | window a counterparty can stall |
| service_response_blocks, inactivity_blocks | member terms | how long a wallet's funds can be held hostage | how soon censorship / silence is provable |

Each harness is parameterised by these and reports attacker cost, exposure,
and time-to-detection as numbers, so the output is a curve per claim rather
than a pass/fail.  The question to answer for growth is: at which settings
does the cheapest attack cost more than it can take, and how much capital
sits idle to get there.

Findings go below, dated, with the harness that reproduces them.

## Findings

### 2026-09-25 — organic #1: the reference member forked ledger A on an unnamed rule and the dispute went nowhere

Found while diagnosing why ledger A was stuck (see devnet/README.md).  At
15:28:50Z ref2 (a cosigner of A) received seq 81027 — an ordinary
`TransferLock` of 11 536 319 msat, fee 23 074, carrying 2 cosignatures from
the cl members — and logged `NON-CONFORMING COSIGNED update … quorum
cosigned an update that fails conformance — arming dispute`, created a
dispute fork at 81026, "Published DisputeEnter on fork", added ref3 to the
fork's quorum, and from then on treated every further update on A as a gap.

What the honest side should have done per DEP-06: publish DisputeEnter,
arm (DisputeArmed with collateral), and drive confiscation.  What happened:

- the rule is not named in its log, and our validator (and our replica of
  its own state) accepted the update; the two implementations disagree on
  conformance of a plain transfer lock, and the reference does not say why
  (its violation kinds: InsufficientReserves, InvalidWitness, ZeroAmount,
  EmptyDestination, UnparseableDescriptor, ExceedsCollateral,
  FeeWindowNotElapsed);
- **no DisputeEnter for A exists on the relay** (no update with the
  dispute-enter discriminant under A's tag from any key), so the cl members
  never learned a member had forked, and `(:forks)` on every cl node is NIL;
- ref2 never armed (no DisputeArmed, no collateral scan in its log), so the
  fork was a private opinion with no on-chain consequence;
- A's remaining cosigners were the two cl nodes, so the ledger kept going with
  exactly the threshold and no slack, until one cl node fell behind and A froze.

Attack #1's harness (`redteam/attack1-invalid-credit.sh`) reproduces this
shape deliberately — a cl majority cosigns a credit over reserves — with the
reference as the honest minority; its pass condition is precisely the three
things that did not happen here.  Its file is quarantined at
`/mnt/lisp/signet/deposits/ref2/quarantine/`.

Lead on the unnamed rule: `LedgerState::check_speculative` first APPLIES the
operation to a copy and reports a refusal as `StateMachineRejected`; a plain
TransferLock can only be refused for insufficient available balance.  So the
reference's replica most likely held a different balance for the source
deposit than ours at 81026 — a **fold divergence between the two
implementations**, i.e. a consensus bug, not a policy disagreement.  Next:
replay A's history through both folds (`deposits-node nostr validate` /
`ledger validate` vs `cl-deposits.ledger:replay`) and diff every deposit's
balance and locked_balance at 81026.  Candidates from UPSTREAM-NOTES #6:
TransferComplete fee accounting, FeeCollect vs locked balance.


### 2026-09-26 — organic #2: consent could not cross between implementations, so reference ledgers could not rotate

A, then F, froze past (or at) their rotation window overnight.  Three causes, peeled in order:

1. **devnet relay saturated** (`devnet/relay.py`, ours, not the protocol): every REQ without `#d`
   scanned all 670k stored events; the reference bots issue one per transfer.  94% CPU, delivery
   p90 11–13 s, max 52 s; a cl cosign round gives up at 16 s, so rotations (a cosigned
   QuorumAddMember) failed.  Fixed with kind/author/tag indexes sorted by created_at: same results
   on 11 filter shapes, 0.5–1.5 s → 1–57 ms, delivery p90 0.9 s.  `kill -USR1` toggles a REQ trace.
2. **reference consent_request carried the whole ledger history** (`coordination.rs`
   `request_consent`): ~102 MB for B's 108k updates, built under the global `ledgers` mutex.  The
   relay dropped the connection on it (4 MB cap) every cycle, taking ref2's subscriptions with it.
   Even a relay that carried it would not help: nostr-sdk drops received events over 70 kB
   (`RelayLimits` MAX_EVENT_SIZE), so no reference member could ever see a consent for a ledger
   longer than ~70 updates.  The in-memory history is also truncated, so history[0] was not the
   LedgerOpen and ref↔ref consent was refused outright.  Fixed in deposits-rust: a 40-update
   LedgerOpen-rooted prefix (from disk when memory is truncated) plus `ledger_sequence`, as cl sends.
3. **reference consent timeout 10 s** — shorter than the member's own QuorumJoin cosign round;
   a busy member's grant arrived at 16 s, after the operator gave up.  Raised to 60 s (cl's value).

Claim this bears on: DEP-11 rotation / DEP-19 — a quorum that cannot re-consent expires, and at
Tier 0 post-expiry value stops.  A spec-level bound on consent size is missing.

### 2026-09-26 — organic #3: a cl ledger under traffic could not rotate before expiry

`begin-quorum` required the tip not to have moved since `prepare-quorum`, but funding the reserves
needs confirmations, and transfers chain meanwhile.  Every cl rotation so far succeeded only after
expiry, when value-moving operations were refused and nothing competed.  The QuorumBegin
`ledger_hash` is a state anchor committed in the reserves script, not a chain link (the reference
says so explicitly), so it now anchors the prepared hash; what is checked instead is that the
staged members still match the prepared reserves.  Gate: inspect/node-test.lisp "rotation: a
ledger that moves between prepare and begin still rotates".  D rotated under traffic 13:06.

### 2026-09-26 — organic #4: a frozen reference ledger (F), a lost publish, and a pager that could not see past its own heal

F froze at 03:39Z not because of expiry but because its tip was never published.  ref3
committed seq 141513 at 03:39:36; `persist_ledger_to_disk` had just spent 21 s rewriting the
2.1 GB ledger log on the runtime, the relay's pings went unanswered, and the connection dropped
at 03:39:36.537 — with the update's publish.  Nothing republishes a failed publish, so the cl
members sat at 141512 refusing every later cosign ("expected seq 141513").

The net for that is heal, and heal could not see it: its backward created_at pager ended at the
first second holding a full page (a previous heal batch), so it saw 22,891 of 141,514 updates
and re-published the "missing" 118k oldest-first, 500 a pass — building the next wall — with the
real gap 118k entries down the queue.  The same truncated view is behind ref2's "cannot determine
lottery N" when arming a dispute on F.  Fixed in deposits-rust (step past a no-new-events second);
the next pass saw 141,513 of 141,514, re-published the tip, and F moved within seconds.

Also fixed on the way: consent took its 40-update prefix by parsing the whole 2.1 GB log (20 s
per attempt, synchronously); it now streams the head.  ref3 wedged once for 33 min (0% CPU,
every thread parked) right after such an attempt — suspected, not proven (no ptrace here).

### 2026-09-26 — organic #5: a rotation broadcast but never committed strands the reserves

B's rotation tx (c17b93e7…) spent its vault at 16:30:53Z; ref2 was restarted during the
confirmation wait.  The refresh path persisted the new vault only after the QuorumBegin
committed, so the restart lost the only record of it, and every retry rebuilt a rotation from
the spent vault (`bad-txns-inputs-missingorspent`) until B expired at 6674.  The funds are safe
in tb1p6q0j… (spendable by the staged quorum); no QuorumBegin points at it.  Fixed in
deposits-rust: persist at broadcast; on an Active ledger a recorded vault that is not the
committed `reserves_key` is resumed, not rebuilt.  Not yet exercised on the devnet (no reference
ledger has been inside its refresh window since the deploy).  B itself is left expired, as a
live test of claim #4.

### 2026-09-27 — claim #4, first observation: nobody disputes B's expiry

Hours past B's quorum_expiry: no fork on either cl member (cld2, cld3), and nothing from the
reference member (ref3) — though the references do auto-dispute other expired ledgers.  On our
side `check-expired-quorums` exists only as a control command; no poller runs it, so a cl member
never notices an expired quorum by itself.  B keeps committing post-expiry-allowed updates,
which may be why the reference does not treat it as dead.  Next: a periodic expiry check in the
cl node, and why the reference skips B.

### 2026-09-27 — claim #4, second observation: the cl members now dispute; nobody arms

Why the reference member did not dispute B: it waits `quorum_expiry + 720` before auto-disputing
(`DEFAULT_GRACE_BLOCKS`, "give the operator a window to re-establish").  DEP-05 §Lifecycle row 3
gives cosigners majority confiscation *at* quorum_expiry ("cosigners get majority confiscation
immediately at expiry because they were trusted to keep the quorum healthy"), with operator
re-establishment racing it — so the 720-block hold-off is reference policy, stricter than the
spec.  The cl expiry watch (5ec1801) uses a 3-block grace and catches each replica up from the
relay before judging it (cld2's replica of B was 5,600 updates behind on restart).

Rolled out 23:40–23:56: cld2 and cld3 disputed B at 7207/7210, cld1 and cld4 disputed F, and the
cl members disputed ~15 of ref2's small ledgers that expired after the same failed rotations.
Every fork stops at DisputeEnter: on our side arming (DisputeArmed with replacement collateral)
and confiscation are control-socket commands only, so custody does not move.  Next for claim #4:
automatic arming and majority QuorumExpired confiscation in the cl member, then watch the
reference members join at +720 (B: 7394; F: 7439).

### 2026-09-27 — claim #4 holds on chain: a cl member confiscated an expired reference ledger by itself

F (ref3's, expired 6719) was disputed by the cl expiry watch, armed by hand to learn the path,
then driven by the dispute driver (21be4ed): cld1 proposed the respectful confiscation
ab2202be… at Tier 1 (legacy ruleset: minority after block 1008) with one signature, and it is on
chain — 478,907 sats to the lottery (the obligations), 49,519,093 back to the operator.  Both cl
armers revealed.  What it took, in order:

- **Tier by height (082a602).**  Confiscation always signed Tier 0 (3 of F's 4 voters); the
  reference member refused ("Not armed"), so 2 of 3 was a dead end.  DEP-06 opens a minority leaf
  at expiry + 720; cl now signs the tier open at the height and sends the reference's
  `tier_index`.
- **A collateral wallet (440ba29).**  A cl node had no view of its own coins.  It now finds UTXOs
  at its key-path address (scantxoutset), pledges one covering the stricter of our floor and the
  reference's (ceil(obligations × collateral/reserves) + 5,000 sats), whole and at full value
  (the claim signs that input for exactly the declared amount), never twice, and consolidates when
  no single coin fits.
- **The dispute driver (21be4ed):** arm with a pledge, propose when the arm window closes,
  reveal once the confiscation is on chain, claim or yield.

Found on the way:
- **The reference's recovery CLI cannot handle a ledger past 500 updates**: 15 single-page
  `.limit(500)` fetches in node_cli/recovery.rs, so `recovery dispute` on F failed "No LedgerOpen
  found (seq 0)".  Its daemon path (auto-arm at expiry + 720) uses the fixed pager.
- **The reference neither sets nor enforces `dispute_arm_blocks`** (always None); cl uses 6.
- **DEP-06 §Phase 2's "recovery quorum (quorum members minus the disputants — the disputed
  operator + non-arming members)" reads either way**; both implementations take it as the armers.
- **A cl member falsely disputed D** (cl-operated, rotated to 8256): cld1's replica, just
  restarted, was behind the rotation; the watch's catch-up raced the replica lane and stopped, and
  the stale replica was judged.  Fixed (7913002): judge only a replica at the relay's tip, never
  catch up from the watch, and yield a quorum_expired dispute whose quorum has returned.
- **Our fraud path wrote "quorum-expired"**, the reference writes and matches "quorum_expired";
  an expiry dispute of ours was unrecognisable to it, and to our own driver (which would have
  confiscated without respect).  Fixed in the same commit.

### 2026-09-27 — organic #6: the custody lottery's N is decided after it is committed to

Details and options in **docs/LOTTERY-N.md**.  Both implementations commit preimages under
N = Q (quorum members) but build the claim leaf with N = k (members who armed).  With k < Q the
claim is possible only with probability (k/Q)^k — F (Q = 3, k = 2) drew a 19-byte preimage
against an 18-byte bound and its lottery output (478,907 sats, confiscation ab2202be…) cannot
be claimed; it is recoverable through the CSV-144 recovery leaf from height 7810.  The spec's
partial-reveal leaves carry the same bounds-vs-modulus mismatch (sums above k² / k(k+1) have no
dispatch arm).  Decision (2026-09-27): keep the spec for now; an unbiased fix (contributions in
1..lcm(2..Q)) is written up there.

### 2026-09-27 — attack #1 run, and organic #7: a reference member that disputed stays blind

**Attack #1** (`redteam/attack1-invalid-credit.sh`, ledger C: cld2 operates; cld3, cld4, ref3
cosign), a credit of twice the reserves:

- **Honest arm: pass for the cl cosigners.** Both refused on the merits: `OVER-OBLIGATION (credit
  40000000000 would take obligations 480000000 over reserves 20000000000)`.  Nothing committed.
  ref3 never evaluated it: it dropped every request as `stale_cosign` (age 2–11 s; its loop is
  seconds behind).
- **Collude arm.**  The first run tested nothing: the operator's own commit refused its
  invalid update, so nothing was published.  After 22bf055 the colluding operator publishes it
  (seq 101369, cosigned by cld3 and cld4).  **ref3, the honest minority, did not detect it within
  600 s.**

**Why (organic #7):** ref3's replica of C has been frozen at seq 67,860 since 2026-09-26 07:45.
It forked C at 67,859 when C had expired during the relay outage; cld2 re-established the quorum
at 07:41 and C has run for a day since, but ref3 never followed the canonical chain again.  Every
update is a "gap", its reimport fetches 35k updates and applies none, and it re-fires
`Auto-dispute: ledger 2b01cc1a is past quorum_expiry` every minute from the stale replica: a
false accusation, the reference-side twin of cl's D bug (fixed on our side in 7913002 by judging
only a current replica and standing down when the quorum returns).

**Claim #1 on the devnet as it stands:** a strict-majority cosign protects the ledger only while
the honest minority is following it.  After one expiry dispute, the reference member was not.
Next: rerun on a ledger whose reference member is current (checked first), and in deposits-rust,
stand down from an expiry dispute once the quorum is re-established and resume following.

### 2026-09-27 — organic #8: the reference loses updates from its own ledger files

Root-caused while fixing #7 (deposits-rust 713dd7e):

- **ref3's saved copy of C is missing seqs 53,330 (TransferLock) and 60,353 (TransferComplete).**
  The relay has both.  Replaying the file gives exactly the 497 `Insufficient deposit balance`
  errors ref3 logs at every restart since 09-25, and rejects C's valid 67,860 with the logged
  numbers.  With the two updates restored, 0 failures and 67,860 onward apply.  So ref3's
  "NON-CONFORMING COSIGNED update … seq 67860" and its fork (reason `auto_dispute`) were a
  **false accusation from a corrupt replica**, not an expiry dispute.  #7's blindness follows
  from it.
- **ref2's saved copy of A is missing seq 97,173** (0–100,130 held, A is at 132k).  A second
  damaged file on a second node: the loss is systematic.  It is later than organic #1's fork at
  81,027, so it does not prove #1 was the same cause, but #1 ("forked A on an unnamed rule";
  the replica "held a different balance") has exactly this shape.
- **Sweep of every reference ledger file over 100 kB:** every large ledger a reference node
  *replicates* has holes, and neither ledger they *operate* has any — ref2: F 1,002 missing (seq
  100,033 and a contiguous run from 121,035), D 3, A 1, B (operated) 0; ref3: B 6, E 4, C 2,
  F (operated) 0.  The loss is on the replica path.
- **Mechanism, confirmed and fixed (deposits-rust 4cdf348):** the persisted cursor was an index
  into the in-memory history, reset by compaction, which ran while replica updates were applied
  from three places (ledger actor, relay reimport, event-store catch-up).  Two losses, each
  reproduced by a test that failed before the fix: compaction between an apply and its save
  (single holes; a whole reimport batch if unsaved), and compaction *during* a save, whose stale
  length then skipped ~1,000 updates — ref2's log shows `compact_ledger: RAM 51001→50000` then
  `persist_ledger_to_disk: 51001 entries (+1)` for F, which lost 121,035–122,035.  The cursor is now
  a sequence, only advanced; trims drop only persisted updates; saves per ledger are serialised;
  files with holes are detected at load, repaired from the relay when the fill chains exactly,
  and otherwise kept out of dispute judgments.
- **Earlier guess:** `compact_ledger` resets the persisted count to the trimmed
  in-memory length, so an update added to memory but not yet written is counted as persisted and
  never written.  Both of ref3's holes coincide with compaction events (`RAM 51008→50000`).  It can
  hit any node holding more than ~50k updates of a ledger.
- Also fixed in 713dd7e: the relay catch-up's early stop fired on any sequence at or below our
  tip, which a heal burst of old updates triggers, so every catch-up began past the gap and
  applied nothing; the expiry watch now judges only a current replica and stands down from a
  quorum_expired dispute whose quorum returned.

### 2026-09-28 — attack #1 on the fresh soak: claim #1 holds in both implementations

After the mulligan (every replica current, ledger C at seq ~17.8k: cld2 operates; cld3, cld4,
ref3 cosign):

- **Honest arm — pass, all three on the merits.**  cld3/cld4: `OVER-OBLIGATION (credit
  40000000000 would take obligations 480000000 over reserves 20000000000)`; ref3: `Cosign refused:
  conformance violations [InsufficientReserves { reserves: 20000000000, obligations: 40480000000 },
  ExceedsCollateral …]`.  0 of 2 cosignatures; nothing published.
- **Collude arm — pass.**  The colluding operator published seq 17,840 with cld3's and cld4's
  blind cosignatures.  **ref3 detected it in 7 s** (`NON-CONFORMING COSIGNED update … seq 17840`)
  and forked at 17,839; cld3 and cld4, whose validation stays honest, rejected it on apply and
  disputed too (35b3354); cld3 published a NonConformingUpdate proof.

The dispute that follows exposes the next layer:

- **9a — the reference sizes replacement collateral from the fraudulent obligations.**  ref3:
  `Auto-arm: operator-key P2WPKH UTXO has only 1000000 sats, required ≥ 61445000 — declaring
  None`.  DEP-06 sizes it from obligations at `last_valid_sequence` (480M msat → ~725k sats, what
  cl computed and pledged); 61.4M sats is the credit's 40.48B msat.  The fraud inflates the bond an
  honest member needs to dispute it, and ref3 armed without collateral.
- **9b — ref3's fork never reached the relay.**  cld3/cld4 list only their own two forks and
  count "2 of 3 armed"; ref3 logged `Published DisputeArmed on fork`.  The reference publishes a
  fork by re-broadcasting the whole chain from genesis in one burst (17,840 kind-9100 events under
  its Nostr key 0472774f…); the relay received exactly the first 9,978 (seq 0–9,977, within one
  second) and nothing after — so the fork's own DisputeEnter and DisputeArmed, at the tail, were
  lost.  Nothing on the relay side dropped them and ref3 logged no error: a silent client-side
  loss.  The prefix need not be re-sent at all (it is on the relay under the operator's events).
  Not a cl bug; queued for deposits-rust.
- **9c — the reference rejects cl's fraud proofs:** `Fraud proof rejected: proof_hash … not
  embedded at seq 0 on ledger …`.  cl sent a placeholder embedding (seq 0, "inline"); the
  reference's `verify_fraud_broadcast` required an embedding and, off the accused ledger, a causal
  link for *every* proof type.  **Decision (2026-09-28):** embedding is for censorship and
  off-ledger fraud, where there is no signed on-ledger evidence; a proof that is itself
  cryptographic evidence of non-conformity (non-conforming update, equivocation, stale or
  non-conforming co-signature, winner collateral deviation, unauthorised vault spend, expired
  quorum) needs neither, and verifiers must not require them.  For a member reporting its own
  operator after the fraud they are unsatisfiable anyway (no honest member co-signs past the
  fraud, so no causal link forms).  DEP-06 clarified on branch `dep06-embedding-scope` (774b9c7).
  **Closed (2026-09-28):** deposits-rust 982de7a (embedding required only for off-ledger types;
  optional on the wire) and a76a049 (NonConformingUpdate proved by replaying the linked history
  and applying the fault — the old verifier proved only chain breaks, so C's fault, which chains,
  was "conforming"); cl f41b87b omits the embedding for self-evident proofs.  Live: a cl-built
  proof of C's seq 17,840, no embedding, `Fraud proof VERIFIED … (self-evident, no embedding)` on
  ref2 and ref3.
  Follow-ups found on the way (deposits-rust, not fixed): NonConformingCosignature's verifier
  runs conformance with `DenyAll`, so an honest cosigned withdrawal would "prove" fraud; a
  chain-break proof could be relabelled across ledgers if an operator reused a key (an update's
  `ledger_id` is not covered by its hash); and the reference disputes from its *replica's* tip
  (`last_valid_seq=20181` for a fault at 17,840) because its base keeps applying flagged updates.
- **cl retries catch-up into a known-invalid update forever** (`catch-up on eff80500 stopped at
  seq 17840: OVER-OBLIGATION`, every pass): noisy, and should stop once the fork is open.
- With ref3 short of collateral and not visible to cl, the cl drivers wait (to 9191) for the third
  armer, and C's Tier-0 confiscation needs ref3's signature: likely to stall.

### 2026-09-29 — claims #3 and #5 are not enforced in either implementation

Censorship (#3, DEP-11/12) and cosign refusal (#5, DEP-19 §9) are specified, but nothing acts on them.
cl has the DEP-12 escalation (a member anchors a DeliveryEmbed) and `verify-censorship`, but no caller
outside its test. The reference has the DeliveryEmbed operation and CLI, but the wallet-to-member
channel is "not yet plumbed" (DEP-12) and censorship or refusal appear only in test models and
wishlists. DEP-19's signed proposals (Kind 9108) exist in neither. So **an operator can ignore a
depositor's request with no consequence** short of letting its quorum expire: the "cannot hold
deposits hostage" guarantee (DEP-11 §Transfer and Exit-Request Processing) holds on paper only.
Nothing to attack live.

Reviewing cl's verifier for when it is wired in:
- **Fixed (cl, this commit):** it credited the operator only for answers after the member's
  causal-link cosignature, so a request served promptly still read as censored.
- **Servability (decided 2026-09-29):** censorship proofs are to cover only inter-ledger
  transfers, which are always satisfiable when valid, and the censored request must still be valid
  at the deadline. So a depositor who double-spends before the deadline, or a member who escalates an
  unservable request, proves nothing. **Implemented in cl:** the request's operation, replayed onto
  the operator's chain up to the breach update, must conform and apply there. Tested with a real
  signed TransferLock, a double spend before the deadline, and a request with no operation. Open: the
  inter-ledger restriction in the spec text; the fee-collection interaction (an operator's fee could
  push a balance below the request, within the fee-cadence bounds); and wiring any of this into
  disputes, in both implementations.

### 2026-09-29 — analysis: equivocation needs no colluder, and double cosignatures prove nothing

Attack #2 (equivocation with a colluding cosigner), analysed rather than run. First reading: the spec
has no penalty for a cosigner who signs both branches, so a colluder arms and shares the payout. But
**re-signing a sequence is required for liveness.** When a round fails to reach a majority (members
slow, offline, or the chain has moved on; under v2 a later height changes the signed bytes), the
operator must be able to ask again at the same sequence. Both implementations allow it: a cosigner
signs any update at its next sequence that chains onto its tip, and refuses a different update only at
a sequence it has already committed.

So the operator needs **no** colluder. At Q = 3: B and C cosign X in round 1; the operator keeps X,
claims a timeout, and B and C cosign Y in round 2. Two fully cosigned branches, from honest retries.
The honest and colluding cases produce identical evidence, so no rule can penalise "cosigned both"
without punishing honest members. The first-reading options (excluding the double-signer, or a new
punitive type for it) are withdrawn.

What the protocol relies on is detection (both branches get published; any member holding both proves
equivocation, and the ledger rolls back to the last valid update) plus punitive confiscation of the
operator. Open questions (for the user):
- **What survives the rollback:** effects outside the ledger (an on-chain withdrawal, a Lightning
  payment) made on one branch before detection. The real bound is that operator collateral must
  exceed what can be extracted within the detection window, a capital-efficiency parameter.
- **Accountable rounds:** a round-2 request could carry the operator's signed abandonment of round 1.
  That gives honest cosigners cover and doubles the proof against the operator, but a colluder can get
  one too, so it adds accountability, not exclusion. Any such rule must keep a stuck round
  recoverable.

### 2026-09-29 — analysis: the withheld reveal is priced, not prevented

Attack #7 (withheld reveal). Commit-reveal lets the last revealer see every other contribution first.
DEP-06 gives the missing disputant's index a partial-reveal leaf (a sub-lottery of the others, CSV 72)
and makes withholding cost the withholder its armer share, which falls to the sweep and is paid pro
rata to revealers (§"abort option"). So it is priced, not prevented. At Q = 3, a colluding pair
wins custody with probability 2/3 if both reveal. If the last revealer withholds whenever the honest
member would win (1/3), the sub-lottery gives the other colluder 1/2: **5/6** in all, at one armer
share per use. Whether that price is enough depends on the share against the value of custody (the
ledger's fees, and its reserves as collateral for future fraud). That is a protocol-economics
question for the capital-efficiency table above, not an implementation bug. Not run on the devnet.

### 2026-09-29 — Finding 14: a member could reveal another's preimage as its own (cl)

Attack #7 (commit ≠ reveal). cl's Kind 9106 handler checked that a reveal was signed by the member it
names and that the preimage opened *some* armer's commitment, but not that member's. A member could
wait for the others' reveals and publish, as its own, whichever copy made the off-chain winner
calculation name it. Only one reveal is kept per member, so its genuine reveal was then ignored. It
could not claim on chain (the script checks each preimage against its owner's commitment), but the
honest winner, believing it had lost, yielded, and the lottery went unclaimed.

**Fixed (cl 557722e):** a signed reveal must open the signer's own commitment. node-test: D
publishes B's preimage signed by D; no member counts it, and the lottery still gives exactly one
script-selected winner. **The reference was never exposed:** it attributes every revealed preimage
by `HASH160(preimage) == commitment`, whoever published it (`a_preimage_matches_only_its_own_commitment`).

### 2026-09-29 — Finding 13: the reference cannot verify a proof of a forged witness

Replaying A's stored NonConformingUpdate proof (cld1's witness-less lock at seq 6969, Finding 11)
from a throwaway key, to test stale-proof replay after custody moved to cld3:
- **cl:** did nothing. A proof only enters a dispute on the base record, for a base member
  without a fork of its own, and every base member already has one.
- **ref2 and ref3 rejected it:** "fault update at seq 6969 chains onto its predecessor and
  applies cleanly with no conformance violations". Yet at 19:55:30 ref2's own replica had flagged the
  same update `InvalidWitness`.

The reference's proof verifiers run conformance with `AllowAll`. `deposits-protocol` has no
descriptor evaluator, and `DenyAll` would condemn honest withdrawals, so a fault whose only defect
is its witness is unprovable. A reference member that did not watch the update land (offline,
joined late, catching up from the relay) would reject a valid proof of a forged spend. The same
code excludes ExpiryPassed and NonceReplay as proof because `block_height` "is signed by no one".
DEP-02 v2 made that false.

**Fixed (deposits-rust ab15a4f, 06088e9, 3167885):**
- Every node-side proof verifier gets the real dep16 authorizer. `AllowAll` is left only in
  deposits-protocol's own tests.
- ExpiryPassed, NonceReplay and the two fee-cadence violations count as proof again: their
  heights are signed under v2.
- The Finding 12 operator rule is explicit: the accused must be the operator at the fault's
  sequence, and that follows DisputeAcquire, so a successor's own faults are provable too.
- A verified proof disputes only if it accuses the replica's current operator.

**Re-run live:** the replayed proof now **verifies** on ref2 and ref3 (`Fraud proof VERIFIED …
NonConformingUpdate`). ref3 is not a member and skips it. ref2 logs "INITIATING DISPUTE", finds its
existing fork, DisputeEnter and DisputeArmed, changes no state, and re-publishes its old dispute
announcement. The stale rule did not fire: a member that yielded never applies the winner's
DisputeAcquire, so its replica still names cld1. So there's no harm, but each replay makes a yielded
reference member re-announce its dispute (open, noise).

### 2026-09-29 — malformed fraud proofs: both implementations hold

`redteam/fuzz-proofs.lisp` sent 15 Kind 9101 events under D's tag from a throwaway key: not JSON,
`{}`, `null`, wrong types, an unknown proof type, update hex that isn't hex, a 1 MB hex field, a
negative sequence, 2^80, a string sequence, a short ledger id, a non-hex accused key, arrays nested
10,000 deep, and a 50,000-entry `causal_chain`. Every node stayed up and answered in milliseconds;
nobody disputed D; every proof was rejected with a reason (cl: TLV and operator errors; ref2:
TLV decode errors, unknown ledger). One lever: a proof naming a ledger ref2 does not hold made it
try a relay gap-fill for it, so each bogus proof costs a relay query (open, minor).

### 2026-09-29 — Finding 12: a quorum member could freeze an honest ledger by accusing itself

Attack #6 (forged proofs). cl's `verify-equivocation` checked that two same-sequence updates shared a
signer, that the signer was the accused, and that both bound to the ledger's chain. It never checked
that the accused **operates** the ledger, and `verify-non-conforming-update` didn't either. A quorum
member holds a key too. It could sign two different updates at the next sequence (or one that breaks
the rules), chained onto the tip under the ledger's id, and broadcast a proof accusing itself. Every
honest cl member verified it and disputed an honest operator's ledger. That's any ledger frozen by
any one of its members, at no cost.

**Fixed (cl a2bbe3b):** the accused must be the ledger's operator at that sequence. That comes from
the fold of the history before it, so custody changing hands is followed. The node-test gate shows
both proofs failing and nobody disputing, while the operator's real equivocation still verifies.

**Live, `redteam/member-equivocate.lisp`** on D (cld3 operates; cld1, cld4 and ref2 are members),
cld1 as the attacker:
- **Equivocation proof:** cld1 and cld4 reject it ("the accused does not operate the ledger at
  that sequence").
- **Non-conforming-update proof:** the same.
- **ref2 rejects both**, as "does not follow an update of this ledger" / "follows an update that is
  not in this ledger's history". Its binding indexes only the accused's updates in the history, and
  a member has none on another operator's chain. The reference was safe by construction; the rule is
  now explicit (deposits-rust 06088e9).

### 2026-09-29 — Finding 11: cl cosigners and replicas did not check the depositor's authorization

Found while looking for replayed wallet requests (attack #8). cl checked a depositor's witness,
the operation's expiry and the nonce window only in the operator's request handlers. The fold
recorded nonces but never refused one, and cosigners and replicas ran none of the three rules.
A cl operator could lock a deposit with **no witness at all**, or replay a depositor's signed lock
(the completion preimage is public after the first), and its cl members cosigned it. On the
devnet two of every cl ledger's three cosigners are cl nodes, so only the reference member stood
in the way. That is a depositor's funds at the mercy of the operator: the property the quorum
exists to remove.

**Fixed (cl b85f7f6).** `src/conformance.lisp` states the rules as the reference's
`check_conformance` does: ExpiryPassed, NonceReplay (a seen nonce whose expiry is still at or
above the height) and Unauthorized (the witness does not satisfy the descriptor), for the
operations a depositor signs. The cosigner applies them at the height it signs; a replica
applies them before the fold and disputes a violation like any non-conforming update; and a
NonConformingUpdate proof verifies on them. The node-test red-team gate builds each attack
through `append-operation`, as a malicious operator would. Before the fix, the witness-less
lock was cosigned and committed.

**Live, `redteam/attack-forge-lock.sh`** on A (cld1 operates; cld2, cld3 and ref2 cosign), a
5,000,000 msat lock from a cl wallet's deposit with an empty witness:
- **honest:** every cosigner refused (cld2 and cld3 `Unauthorized`, ref2 `InvalidWitness`), 0 of 2
  cosignatures, nothing committed, and the balance was untouched.
- **collude** (cld2 and cld3 cosign blind): seq 6969 committed at 19:55:29. ref2 flagged it
  `NON-CONFORMING COSIGNED … InvalidWitness` at 19:55:30 and forked at 6968 at 19:55:31. The
  colluders' own replicas disputed it too: every member of A is armed. A is frozen and in the
  dispute drivers' hands (confiscation, lottery), as in attack #1.

**No false positives:** over the first minutes after the deploy, each cl node cosigned 650–750
updates from both implementations' wallets, refusing only on ordinary sequence races.

### 2026-09-29 — the v2 devnet: first observations

The devnet was brought up fresh on DEP-02 v2 signing. All six mixed ledgers formed and moved
~600 updates each in the first ten minutes, with replicas agreeing to within one update.

- **Block hash byte order (cl, fixed in 926b129).** Every cl cosigner refused ref2's first
  QuorumBegin on B ("block_hash is not our chain's"). cl read `getblockhash`'s display order,
  while the reference, and cl's own `height-of-block`, use internal order. cl operators never
  stamp a block hash, so the cl-only regtest smoke could not see it. DEP-02 now names the
  order.
- **Relabel attack rerun:** the relabelled copies no longer verify (`SIGNATURE-VERIFIES NIL`),
  and cld2 and cld3 reject each as a bad operator signature. ref2's `LedgerActor` still logs
  "equivocation at seq N" for them: it compares content at a sequence before any signature is
  checked. It refuses to apply them and raises no proof, but the log is misleading. **Closed**
  (deposits-rust f3508c9): only an update whose operator signature verifies is called one. The rerun
  logs none.
- **Not a fold disagreement:** ref2 refused A's seq 63 (a TransferLock) as
  `InsufficientDepositBalance { available: 2038365, required: 36828898 }`. The deposit's balance is
  38,867,263 in both implementations, and the gap is exactly this lock's amount plus fee. After a
  6.5 s stall, ref2 answered the request against a state that already held the same lock.
  cld2 and cld3 made the majority. **Closed** (deposits-rust f3508c9): the gate already allowed an
  idempotent re-sign of a committed update, but it was then re-validated against the state it had
  produced. That step is now skipped for it.

### 2026-09-28 — attack: relabelled updates (ledger_id is signed by no one)

An update's `ledger_id` is covered by neither its content hash nor its operator signature
(DEP-02 §Signing), and an operator signs all its ledgers with one key. On the devnet every cl node
signs the ledger it operates and its own member ledger with its node key. So anyone can
republish an operator's honest update from one ledger tagged with another's id, and the signature
still verifies. The reference closed this in its verifiers (deposits-rust bedabe0, f581dba).
cl had the same exposure in five places:

| where | what the relabelled update did |
|---|---|
| `verify-equivocation` | two same-seq updates, signed, different: verified, although one was another ledger's |
| `verify-non-conforming-update` | "does not chain onto the canonical tip" counted as proof |
| live detector in `accept-update` | a member broadcast an equivocation proof, and every member forked the honest operator's ledger |
| `follow-ledger` (a follower, or a member rebuilding a lost replica) | a relabelled genesis became the genesis: the rebuild became the other ledger, or aborted |
| `catch-up` | a relabelled update at the next seq failed the chain check, was taken for a rule break, and the replica never caught up again |

**Fixed (a24ec2c, ae2dbd5).** An update is bound to a ledger when it is a seq-0 LedgerOpen that
derives the ledger id, or when its `previous_hash` names one of that ledger's updates. Both
equivocating updates and a non-conforming fault must be bound. A fault following an update other
than its predecessor (rewind or skip) is still proof; one following nothing here is not. Rebuild
and catch-up take only updates that continue the chain. The node-test checks fail on the old code.

**Live, `redteam/attack-relabel.sh`:** cld1's own ledger 09b1dc41 (seq 0–5) republished from a
throwaway key as A (cld1's, seq 80k). cld2, cld3 and cld4 each logged all six as ignored: no
equivocation, no proof, no fork. ref2 and ref3 logged nothing either. Before the fix, each member
would have seen six equivocations and forked A. The six events stay on the relay under A's tag.

**Found on the way (72600ae).** After the deploy, cld4 broadcast four bogus EQUIVOCATION proofs
on C at 17840 and failed to rebuild C. None of the three causes was new:

- The node subscribes to the relay before loading its data dir. A cosign request in that
  window found no record for C, took it for a lost replica, and rebuilt 80k updates from the relay,
  racing the load. The worker lanes now wait for the load.
- The rebuild took dispute forks' updates, which share the ledger's tag, into the base. It now
  builds only the operator's chain.
- The live detector did not check the two updates had one signer. It took a fork member's
  DisputeEnter for the operator equivocating. Other nodes refused the proofs ("operators differ").

**Closed in the protocol (2026-09-28): DEP-02 v2 signing.** `ledger_id`, `block_height` and
`block_hash` are now part of `cosign_data`, so the operator signature, every cosignature and the
hash chain cover them (spec branch `dep02-signed-header` a23cf09, deposits-rust `signed-header-v2`,
cl b1f6106). A relabelled or re-dated update no longer verifies at all. `block_height` was the
sharper half: it decides the lifecycle tier, and anyone could move an honest update past
`quorum_expiry`. The chain-binding checks above stay as a second line. It was a clean break: the v1
digests and single-cosignature tags are retired, and the devnet was archived
(`deposits-soak2-2026-09-28.tar.gz`) and brought up fresh. `vectors/dep02-signing-v2.json` is
produced independently by both implementations and matches byte for byte.

**Open:** the reference's gap repair already follows the chain through duplicates (ledger_repair.rs
`fill_gap`). Its paginated catch-up and the recovery CLI have not been checked against the relabelled
updates now on the relay. `quorum-names-us-p` (cl) reads the newest QuorumBegin by tag with limit 1,
so a relabelled QuorumBegin can make a member skip rebuilding a lost replica for six hours.

### 2026-09-28 — fraud to custody, end to end (and an unbonded custodian)

After deposits-rust ed1e469 (the winner read reveals only from ephemeral kind-20101 requests,
which relays do not store; it now reads the durable Kind 9106 reveals too, publishes its own as
9106, and fetches 7 events instead of paging the ledger), ref3 claimed at 06:52:13 —
`We won the lottery … Claim TX broadcast: 755480b8… DisputeAcquire published! We are now the
operator.`  **Claim #1 end to end:** an invalid majority-cosigned update, detected by the honest
minority and by the colluders' own replicas, disputed, armed by all three, confiscated punitively
(C's 49,999,600 sats), drawn fairly (k = Q), and claimed by the winner who took custody.

**Finding 10 — cl signs a confiscation for an armer that declared no replacement collateral.**
The claim has one input: ref3's arm predates the 9a fix and declared none, so the new custodian
is unbonded.  DEP-06: "legacy events without it cause strict cosigners to refuse confiscation";
the reference is strict (it refused cld3's proposal for exactly that), cl's `check-armer-collateral`
checks only armers that did declare, so cl's two signatures carried ref3's confiscation.

### 2026-09-28 — the first fraud-to-confiscation run (as it stood before the claim)

With 9a/9b fixed (deposits-rust e3b266e, 1cc610f) and cl's stale-proposal fix (724551b):
ref3 published its fork's 4 own updates, saw all 3 participants armed, and proposed the
confiscation of C.  It confirmed at Tier 0, **punitive**: d042411c…, one output of 49,999,600 sats
(C's reserves + collateral) to the lottery tb1pmvek2z….  All three revealed (cld3 18 B, cld4 17 B,
ref3 18 B → sum 5 mod 3 = 2): **ref3 won**; cld3 and cld4 yielded.  Every preimage is in bounds
(k = Q = 3), so the claim is valid — but ref3 has not attempted it (no claim line in 30+ minutes;
its `auto_confiscate` / `auto_collect_fees` tasks time out at 10 s).  Queued for deposits-rust.

Along the way (cl, 724551b): a signer keeps every proposal it signs, and cld3's driver took its
cached, never-broadcast proposal for a spent lottery; a cached transaction neither pending nor swept
is now dropped and the chain asked again, and a member that revealed but finds the lottery gone
concludes that the winner claimed it.  The fixed reference also re-published ref3's *old* arm
(declared no collateral), so ref3 refused cld3's competing proposal over its own arm; its own
proposal went through.

### Open (2026-09-27)

- **F's lottery** could not be claimed (organic #6); mitigated (c3cd4cd) and swept to the
  operator by cld1 + cld4 in 174bea4f….  The reference does neither mitigation.  The organic #5
  rotation fix still has not been exercised on the devnet.
- **B**: reserves spent by the stranded rotation, so nothing to confiscate; the driver says so
  and does not arm.  The funds sit in tb1p6q0j… until someone recovers that vault.
- **catch-up stopped on INSUFFICIENT-BALANCE replaying D** (cl operator, cl replica) — a fold
  or ordering disagreement between two cl nodes; not chased yet.
- all four cl nodes now run e5d7f63 (anchor) and 5ec1801 (expiry watch); C rotated at 23:07
  only after cld2 was restarted onto the anchor fix.

### 2026-09-30 — claim #9, demonstrated: a colluding majority spends an honest vault at Tier 0, and nothing reacts

`redteam/attack-vault-spend.sh` on the live soak.  Ledger V (5-of-8: cld1
operator, cld2–cld6 + ref6 + ref7 members, 0.5 BTC reserves).  The thieves:
cld1 + cld2 + cld3 + cld4 + cld5 — exactly the threshold, no more.  The
facility: `(:vault-spend :ledger V :address DEST)` on the daemon builds the
tier-0 spend of the reserves outpoint from public state (the same shape a
confiscation uses, but to the colluders' address), signs it, and collects the
other four signatures over the relay with a `theft_sign` request that only
answers on nodes armed with `(:adversary :set :theft-sign t)`.

Result (tx a21854c7…, 5 signatures, 0.49999822 BTC to cld2's address):

- the spend assembled, verified, and broadcast; the output is live on chain;
- 120 s of watching the honest minority (cld6, ref6, ref7): zero log lines,
  zero disputes, zero forks on V.  No watch on the reserves outpoint exists
  in either implementation — the honest side cannot even see the theft, let
  alone prove it.  This is DEP-05 §120's stated limitation, now measured:
  the attack costs a threshold of colluding seats and takes one relay round
  (~20 s under soak load); the exposure is the entire vault.

The same run with the relay's new fault injection armed
(`relay.jsonl.faults.json`: drop kind 20101, author cld1, action theft_sign)
collects 1 of 5 signatures and fails — the relay can now censor any request
by kind/author/action/to, which is the transport attack of claim #8 made
controllable.  (Fixing that found a bug: the relay's action matcher read
`content["action"]`, but requests carry the action as a tag — corrected.)

### 2026-09-30 — the red-team facilities, and what is still unrun

Built today (all in `redteam/`, all against the live soak):

- `attack-vault-spend.sh` — above; **run, PASS** (the gap is the finding).
- `attack-censor-hold.sh` — DEP-12: operator ignores a wallet transfer
  (`:ignore-requests`), wallet escalates through a member (`escalate` action
  on the wallet CLI → `delivery_embed`); honest arm = the transfer lands,
  censor arm = the embed lands but nothing acts on it.  **Written, not yet
  run.**
- `attack-withhold-reveal.sh` — the last revealer holds the lottery hostage
  (`:withhold-reveal`): confiscation lands, the preimage never does, custody
  waits.  **Written, not yet run.**
- `attack-rollback-depth.sh` — every honest replica offline during the fraud;
  measures how long it stands and how deep the rollback reaches when they
  return.  **Written, not yet run.**
- relay fault injection (`devnet/relay.py`): drop/delay rules by
  kind/author/action/to, re-read from `relay.jsonl.faults.json` on every
  EVENT.  **Run** (the drop above); delay untested on the devnet relay.

The adversary switches (`:ignore-requests`, `:withhold-reveal`,
`:theft-sign`, `:vault-spend`) are all disarmed after each run; the soak
continues underneath.

### 2026-10-02 — unauthorised vault spend (DEP-06 type 7) detected, live

The 2026-09-30 run (`attack-vault-spend.sh`, claim #9) showed the gap: a colluding majority spent
a vault at Tier 0 and no node reacted.  cl now closes it.  Each node scans every new block (once,
node-wide, `getblock` verbosity 3) for inputs spending any vault outpoint it replicates; a spend
that is not a txid a recorded QuorumBegin creates, nor the node's known confiscation, and whose
tier witness verifies to threshold under the QuorumBegin's reserves, is an `UnauthorizedVaultSpend`
(discriminant 10) against each signer, published on every ledger the signer operates.  A node that
cosigns such a ledger verifies it against its own replica of the spent ledger and disputes.

Live (6 cl nodes, cl-only 6-voter quorum, theft by cld1 + cld2 cld3 cld4): cld6 logged `VAULT SPEND`
for the theft, identified 4 signers, and published proofs against the 20 ledgers cld1 operates plus
the other signers'; the receivers verified and disputed (`contagion: ... signed an unauthorised
spend of ...'s vault; disputing its ledger ...`).  Found live: `getblock` verbosity 2 has no
`prevout` (need 3), and a per-ledger scan was minutes per pass, so the scan is node-wide.
Harness: `redteam/attack-vault-spend.sh` now PASSes on detection (`REFS=""` forms a cl-only quorum;
the reference members' add-member stalled under this run).

### 2026-10-02 — the scenario suite on beacon: what holds, what was fixed, what blocks

**Infrastructure.** The devnet relay is now beacon (pure CL, `devnet/beacon-relay.lisp`; cl 74e505a,
beacon 35c98ef/3fab92d), with the old relay's fault injection carried over (drop/delay by kind,
author, action, recipient). Rust bot failures fell from 38% to 18% on it. The scenario suite is
`redteam/run-all.sh` (17 scenarios, each on fresh ledgers, switches disarmed after each run,
PASS/FAIL table; cl 02228ca, c74d390). A watchdog restarts a reference node that falls silent.

**Bugs found by running it, all fixed:**

| bug | where | fix |
|---|---|---|
| vault watch accused the signers of the node's own confiscation (it looked on the base record; the confiscation lives on the fork) | cl | 02228ca |
| only the member that *built* a confiscation knew it, so its cosigners accused its signers | Rust | 091afc7 |
| deposed operators kept operating ledgers whose custody had moved; members kept retrying | cl | 9b1a6d4 (stand down), 3e1ad0f (cl members refuse a deposed operator, as Rust did) |
| every stale update from a deposed operator re-imported its ledger (~6k updates) and stalled consent | Rust | f09a300 (rate limit) |
| non-members fully verified every fraud proof, re-importing each named ledger (~4 h of main loop on ref6) | Rust | b0068c9 |
| QuorumBegin recorded the default ruleset, not the prepared one, so a tier-1 theft did not match | cl | 848485d |
| a theft's proof storm (one per signer × parity × operated ledger) made each cl node re-fetch the spent ledger per copy; two workers fell 7k events behind and consent timed out | cl | f3d7685 (verdict cache) |
| soak bots sent fee 0; bot wallets and dispute collateral drained | harness | 8de35cf, 5117518 |

**Results** (contagion = honest members dispute the colluders' other ledgers too):

| scenario | attack succeeds? | caught? |
|---|---|---|
| invalid-credit / forge-lock, honest quorum | no — refused | n/a |
| invalid-credit / forge-lock, colluding majority | commits | yes, disputed + contagion |
| collude-q7 (4 of 7 forge) | commits | yes: M and all five colluder ledgers disputed by cld6, ref6, ref7 within 12 s |
| vault-spend (Tier 0 theft, mixed quorum) | coins move | yes: Rust producer reported, cl and Rust receivers disputed signer ledgers |
| vault-recovery-tier (Tier 1 theft) | coins move | yes (after 848485d) |
| vault-rotate-grace (rotation inside 3 blocks) | — | not accused (correct) |
| vault-rotate-late (rotation after grace) | — | **falsely accused** (documented bound) |
| vault-missed-confiscation | — | disputant excuses; a non-disputant accuses honest signers (the known limit); this run's cld2 was already tainted, so it showed nothing |
| censor-hold | censorship succeeds | **no** — the escalation lands, nothing acts (DEP-12 gap) |
| relabel, fuzz-proofs | no | n/a |
| withhold-reveal | — | **not run**: Rust members hang (below) |
| dereliction | — | **not run**: Rust members hang; also every cl key is now tainted (below) |
| rollback-depth | — | **not run**: Rust members hang |

**Blocking: Rust nodes hang in the confiscation path.** Since the vault-spend runs, ref nodes stop
logging mid-run: main thread parked in a futex, 0 CPU, all 233 threads asleep, no recovery. Every
hang (ref3, ref6, ref7; over 25 restarts on 2026-10-02) follows one of two log lines in
`dispute.rs`: `Lottery address: …` (an initiated confiscation, 2869) or `Sent confiscation_sign
request` (3153). The next step there is `fetch_fraud_proof_type_for_ledger` →
`verify_fraud_broadcast_locally`, which for `UnauthorizedVaultSpend` calls
`Wallet::confirms_block` (a **blocking** reqwest client with a 60 s timeout, from async code) and
takes the `ledgers` and `known_confiscation_txids` std mutexes. Likely a std-mutex or blocking-I/O
deadlock on the runtime. It needs a stack dump from a live hang (ptrace is not permitted in this
container; run the node with tokio-console or `RUST_BACKTRACE` + a SIGQUIT handler). Log tails
are saved as `refN/node.log.hang-HHMM`.

**Contagion taints a key for good.** A key accused once (by a real theft or by a known-limit false
accusation such as vault-rotate-late) has every new ledger it runs or cosigns disputed on sight.
All six cl keys are now tainted on this devnet, so scenarios that need an innocent member
(dereliction, missed-confiscation's limit) need fresh-key nodes. Nothing clears an accusation;
see MISSING.md.

**Facilities added:** `(:tune :full-arming-wait-blocks N)` on cl (the runner restores 720 after each
run), `RESP=` for a short arm window in `form_ledger`, `devnet/soak.sh collateral` (refills
dispute collateral when a node reports none unpledged).

### 2026-10-02 (afternoon) — fresh-key nodes; the slow scenarios run

**Why fresh keys.** Contagion taints a key for good, and all six soak cl keys were accused by
earlier runs, so every ledger they ran or cosigned was disputed on sight. Eight, then twelve
fresh-key cl nodes joined the devnet (cld7–cld18; red-team actors, not soak operators; cl 32e758c,
7200f2b). Scenarios now `pick` clean actors: a registry of burned keys (`$S/redteam-tainted`,
appended by each scenario for the keys it burns) plus each node's own view of its disputed
ledgers; too few clean nodes is a SKIP. Every scenario burns at least one key (the fraudster), so
the pool runs down; add nodes as needed.

| scenario | attack succeeds? | caught? |
|---|---|---|
| vault-missed-confiscation (clean operator) | — | the disputant excused the confiscation; cld2, which never disputed, reported it as a vault spend naming the honest confiscation signers: **the known limit, demonstrated** |
| dereliction | the derelict ignores the fraud | **yes, end to end**: a `DisputeDereliction` proof, and the derelict's own ledger disputed 178 s after the window; the acting member's ledger untouched |
| rollback-depth | the fraud stands while the honest replicas are down | yes: the restarted honest replica disputed at once; the fork branched at the last honest seq (depth 1 here) |
| withhold-reveal (cl-only quorum) | **yes — custody held indefinitely** | the confiscation lands; the withholder never reveals; 187 blocks later (past CSV-144) the lottery output is unspent |

**Withhold-reveal, in detail.** The honest armers revealed and then loop on `waiting to claim:
missing a reveal`; they never switch to the recovery path. The one node that tries recovery
(`sweep-lottery`) gathers 1 of 3 recovery signatures, because the honest armers do not take the
recovery branch. Funds sit in the lottery output with no one operating the ledger.

**Found, recorded, not fixed:**
- *A spent collateral coin vetoes the confiscation.* ref7 armed pledging a coin that was already
  spent; cl's strict check (`check-armer-collateral`, per DEP-06) then refuses the confiscation for
  everyone. A colluding member can stall a confiscation the same way on purpose. The reference
  should not pick a spent coin; the spec could drop an armer whose collateral is invalid instead of
  failing the confiscation.
- *Implementations disagree on credits beyond collateral.* The reference treats an update whose
  obligations exceed the collateral (`ExceedsCollateral`, active quorum) as non-conforming: it
  refuses to cosign, and disputes when others cosign. cl has no such rule, and the spec states
  only reserves ≥ obligations (DEP-03). On a zero-collateral ledger an honest credit is a fraud to
  the reference members. Scenario ledgers that take deposits now carry collateral.
- *A reference node deadlocked.* ref6 stopped logging for 1 h 40 m: all 116 workers parked on
  futexes, no CPU; unlike the busy loop fixed in 0db8541. Stack dump and tail in
  `ref6/node.log.hang-1002-stack` (the dump caught only the parked main thread).
- *The devnet relay died silently* (beacon, 10:52, nothing in its log); every consent timed out
  until it was restarted. The run's watchdog now restarts the relay as well as hung reference nodes.

**Harness fixes:** dereliction now keeps the derelict's ledger busy past the window (a member is
derelict only if it kept operating; the first run passed only on a manual nudge); rollback-depth
times only the honest replica's own fork (`(:forks)` also lists replicated forks, which read as an
instant dispute) and refuses a ledger disputed before the fraud; withhold-reveal's timeout fits
the chain (~5 blocks/min); `REFS=` forms a cl-only quorum; `REDTEAM_AVOID` skips busy clean nodes.

### 2026-10-02 (evening) — after the reset: rotation interop, the veto fix live, regression

The devnet was reset to fresh ledgers when the `legacy` and `cltv-offset-literal` rulesets were
removed (absolute-height recovery tiers; Tier-1 minority now ceil(n/2)-1). Node keys and the
red-team nodes cld7-18 were kept; old state is in `pre-reset-20261002/`.

**Fixed:**
- *cl members never answered the reference's `rotation_sign`*, so ledgers operated by the reference
  collected 3 of 4 signatures and never rotated. The member now rebuilds the 1-in/1-out rotation
  (input = current vault, output = next quorum's reserves, lock time = the tier's, fee ≤ 100k sats)
  and signs only that (befd453). Soak ledger B (ref2) rotated with four cl cosigners.
- *The regtest smoke flake "no armer is a lottery participant"* was real: each pledge was mined and
  armed at once under a node height cached one block behind, so every arm named a height before its
  own pledge and the DEP-03 cut excluded them all. Arming now waits for the pledge's height; pledge
  heights come from `gettxout`'s own best block (5854048). Four consecutive CI smoke runs pass.
- *Harness:* red-team nodes' member ledgers were missing from the reset env (654be86); veto-pledge
  on a mixed quorum never reached a majority for its fraud (5089ce7).

**Veto fix, live** (`attack-veto-pledge.sh`): `veto` — cld12 spent its pledge; cl and the reference
excluded the same armer at the same snapshot (14020) and the confiscation landed; `sole` — one
eligible armer took custody without a draw; `reopen` — nobody eligible, the honest armer re-armed and
took custody.

| scenario | verdict | | scenario | verdict |
|---|---|---|---|---|
| invalid-credit-honest | PASS | | collude-q7 | PASS |
| forge-lock-honest | PASS | | vault-spend | PASS |
| relabel | PASS | | vault-rotate-grace | PASS |
| fuzz-proofs | PASS | | vault-rotate-late | PASS (accused, the known grace bound) |
| censor-hold-honest | PASS | | vault-missed-confiscation | PASS (the known limit shown) |
| censor-hold | PASS (finding: escalation not acted on) | | veto-pledge / -sole / -reopen | PASS |
| invalid-credit-collude | PASS | | vault-recovery-tier | FAIL: chain could not be mined 730 blocks |
| forge-lock-collude | PASS | | withhold-reveal | FAIL: confiscation not reached in 120 s |

**New blocker (infrastructure): the signet's difficulty retargeted up 4×** at 14112. The window
12096-14111 was mined in 1.3 days by the red-team's fast mining, so the clamp-maximum increase applied
(bits 1d0377ac → 1d00ddeb). Blocks now take ~25 s each with every core busy, and `bitcoin-util grind`
sometimes exhausts its nonces (85 failures in `logs/mine.log`). `--set-block-time` cannot run ahead of
real time, so the next window cannot lower it quickly: about two weeks at real pacing. Both failures
above are this (`mine 730` advanced 37 blocks; the confiscation waits on confirmations). Scenarios
that mine past expiry need a regtest chain, or a signet reset with a short-expiry design.

### 2026-10-03 — the full suite on a regtest network

The signet can no longer mine hundreds of blocks (difficulty 4x since 14112), so the scenarios that
mine past quorum expiry moved to a persistent regtest network: `devnet/regtest-net.sh up` (bitcoind,
beacon on 7787, the Esplora shim, cld1-48, ref2-7 on their own deposits-rust build, a block every
10 s with a replacement-collateral refill, and the soak's ledgers A-L) and
`DEVNET=regtest redteam/run-all.sh`. The signet soak runs on, untouched. A full run burns about 31
keys for good (contagion), hence 48 cl nodes.

| scenario | attack succeeded? | caught? |
|---|---|---|
| invalid-credit-honest, forge-lock-honest | no: refused | n/a |
| relabel, fuzz-proofs | no | n/a |
| censor-hold-honest | no | n/a |
| censor-hold | **yes**: the transfer is never applied | escalation lands, nothing acts on it (known gap) |
| vault-rotate-grace (inside) | n/a (honest rotation) | correctly not accused |
| invalid-credit-collude, forge-lock-collude | yes: committed | yes: disputed, contagion |
| collude-q7 | yes: 4-of-7 committed | yes: M and every colluder ledger disputed |
| vault-spend (Tier 0) | yes: vault spent | yes: VAULT SPEND, contagion on the signers |
| vault-recovery-tier (Tier 1, 2 of 6) | yes, but only with the whole quorum idle | yes: reported by an idle member's vault watch |
| vault-rotate-late | n/a (honest rotation past the grace) | falsely accused: the known grace bound |
| vault-missed-confiscation | n/a | the disputant excuses it; the known limit shown |
| withhold-reveal | **yes**: custody held | **no**: lottery unspent ~450 blocks on, no CSV-144 sweep |
| veto-pledge, -sole | no: the confiscation lands | yes |
| veto-pledge-reopen | no: nobody eligible, the honest armer re-arms and the confiscation lands | yes (run 2 hit the unclaimable lottery below) |
| dereliction | yes: the derelict ignores the fraud | yes: dereliction proof, its ledger disputed |
| rollback-depth | yes while replicas are offline | yes on their return; rolled back 1 update |

**Found:**
- *A lottery made unclaimable by exclusion* (protocol, open; MISSING.md): preimages are sized for the
  quorum's n recovery voters, the claim leaf bounds them by the k participants, and the DEP-03 cut makes
  k < n. At n = 7 one exclusion leaves the lottery unclaimable ~60% of the time, and the CSV-144
  sweep then pays the original operator. veto-pledge-reopen (run 2) logged "a preimage is out of the
  claim leaf's bounds".
- *cl accused the signers of its own concluded confiscation* (fixed, cde3ca3): a fork forgets its
  confiscation once the lottery output is spent, so a disputant whose vault scan reached the
  confiscation after the winner's claim reported it as a theft. Confirmed confiscations are now kept
  per ledger (`confiscations.txt`); a gate check covers it.
- *Past expiry, the quorum confiscates its own vault within blocks* (QuorumExpired, then a full arm),
  even with a 900-block arm window, so Tier 1 (expiry + 720) is reachable only by an idle quorum. The
  recovery-tier scenario now idles every member (`:ignore-fraud`) to test detection at all.
- *Harness*: contagion scenarios hard-coded cld1-6 and failed once earlier runs had tainted them (now
  `pick` + `taint`); cld7+ had no cached pubkey (`pubkey_of`); `accused` checked once, before a vault
  watch pass over hundreds of new blocks finished (now polls); regtest disputes ran out of replacement
  collateral (ticker refill); withhold-reveal needs a cl-only quorum (a mixed one cannot reach the
  confiscation majority with a single honest disputant); veto-pledge read log lines left by earlier
  runs.

### 2026-10-06 — the subset lottery on regtest; two reference liveness bugs

The DEP-06 lottery redesign (a claim leaf per revealer subset, voter-attested; contributions 1..60;
nothing ever pays the accused) ran on a reset regtest network. Batch 1006-033953: **collude-q7,
vault-spend and withhold-reveal PASS** — the withholder only removed itself and a revealer claimed
through its subset leaf. The harness now mints fresh-key cl nodes when too few untainted ones remain
(`mint_cl`), so contagion no longer exhausts the suite.

Failures, and what they were:
- *veto-pledge-sole / -reopen*: not the lottery. The three colluders were set `:ignore-fraud`, so they
  held no fork and never signed the confiscation; with 2 of the 4 signatures needed it could not land
  at Tier 0. A majority that refuses to sign blocks Tier 0 by design. The modes now have the colluders
  arm with spent pledges (excluded), leaving the honest armer sole.
- *"add-member refN: no answer"* (recurring): a reference liveness bug. The run loop made blocking
  chain-backend calls inline (wallet sync, block-height sync, and a pledge re-check inside
  `handle_dispute`), each with a 60 s HTTP timeout that a tokio timeout cannot preempt. Against a busy
  bitcoind ref6 spent 120 s per dispute message and once 3.7 h in a single dispute drain, and every
  request it routes (consent, cosign) timed out. Fixed in deposits-rust 36961e5 and 60f1a10: those
  calls run on the blocking pool, bounded, and each drain yields after 2 s; a phase over 5 s is logged.
- *withhold-reveal `DEPS[0]: unbound variable`*: a wallet open refused on a ledger whose quorum was
  born expired (a member's commitment had lapsed); prepare-quorum now refuses that, and the harness
  reports the wallet's error.
