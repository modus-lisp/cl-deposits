# Red team: the claims the spec makes, and the attacks that test them

Devnet: `devnet/soak.sh` (six mixed ledgers) is the substrate; attacks run
against a live quorum with both implementations present.  cl nodes play the
attackers (an adversary mode on the control socket); the reference nodes are
victims and detectors, then roles are swapped where our code has the detection.
Every attack states its pass condition as what the HONEST side must do.

| # | claim (where) | attack | status |
|---|---|---|---|
| 1 | strict-majority cosign, independent validation (DEP-05 §63, whitepaper) | operator + colluding majority sign an invalid update; honest minority must refuse and dispute | |
| 2 | equivocation caught and punished (DEP-06) | equivocate with a colluding cosigner on both branches; double-spend across forks; colluder's slashing share excluded | |
| 3 | censorship provable (DEP-11, DEP-12) | operator ignores a signed request; DeliveryEmbed; clock; censorship proof; dispute | |
| 4 | inactivity moves custody (DEP-19 §1–3) | operator silent past inactivity_blocks; majority attestation; respectful custody | |
| 5 | co-sign refusal provable; withholding majority is the stated limit (DEP-19 §9) | cosigner answers all but the clock-satisfying update | |
| 6 | fraud proofs cannot be forged or replayed (DEP-06 §Verification) | malformed / stale / wrong-ledger / replayed proofs; cross-implementation acceptance rules | |
| 7 | lottery fair and spendable (DEP-03 §Custody Lottery) | out-of-range preimage; withheld reveal (partial leaf); commit≠reveal | |
| 8 | transport outside the trust model | censoring / delaying relay; replayed ephemeral requests vs nonce+expiry | |
| 9 | stated limitation: majority can spend an honest vault at Tier 0 (DEP-05 §120) | measure cost and footprint, not disprove | |

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
- **Likely mechanism (unproven):** `compact_ledger` resets the persisted count to the trimmed
  in-memory length, so an update added to memory but not yet written is counted as persisted and
  never written.  Both of ref3's holes coincide with compaction events (`RAM 51008→50000`).  It can
  hit any node holding more than ~50k updates of a ledger.
- Also fixed in 713dd7e: the relay catch-up's early stop fired on any sequence at or below our
  tip, which a heal burst of old updates triggers, so every catch-up began past the gap and
  applied nothing; the expiry watch now judges only a current replica and stands down from a
  quorum_expired dispute whose quorum returned.

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
