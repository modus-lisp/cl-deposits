# Concerns → red-team facilities

Each concern in docs/MISSING.md ("Concerns: what might happen" and the gap list
above it), mapped to the facility that exercises it.  A facility is either
already in the tree (marked **have**), or built by this work (marked **new**,
with the file).  Results of running them live go in docs/REDTEAM.md.

## Loss of funds

| Concern | Facility |
|---|---|
| Colluding majority spends an honest vault at Tier 0; nothing notices | **new** `attack-vault-spend.sh` + node `:vault-spend` command (builds the tier-0 spend of a ledger's reserves from public state, like a confiscation but to the colluders' address) + `theft_sign` request action so colluders sign each other's spends. PASS today = *theft succeeds unnoticed* (that is the finding); the run measures how long it takes and what, if anything, reacts. |
| Confiscated colluder vaults go to lottery winners, not the robbed depositors | **have** `attack-collude-q7.sh` (contagion arm) — watch where the confiscated funds land (`claim-or-yield` target). |
| Operator equivocation via honest retries; off-ledger extraction (courier leg) | **have** `member-equivocate.lisp` (self-equivocation); **new** `attack-rollback-depth.sh` — equivocate, let both branches cosign, measure how deep the rollback reaches and whether a courier leg paid against the losing branch is recoverable. |
| One implementation bug shared by a quorum majority | **have** `fuzz-proofs.lisp`, `attack1-invalid-credit.sh` (honest nodes verifying too little); implementation-diversity counting is a sim concern (below). |

## Detection failing

| Concern | Facility |
|---|---|
| Every honest replica offline at the fraud; rollback depth | **new** `attack-rollback-depth.sh` — stop the honest replicas (cld_ctl stop / kill), commit the fraud, bring them back, count how many updates roll back and how long the fraud stands. |
| Colluding majority detected but unpunishable until `quorum_expiry + 720` | **have** `attack-collude-q7.sh` (the dispute arm already measures time-to-dispute); **new** `attack-vault-spend.sh` shows the spend itself is possible *now* at Tier 0. |
| Quorum capture by strategic seating (not random) | **new** contagion_sim.py `--seating strategic` — coalition seats its keys on each other's quorums; compare max_safe_p with random seating. |
| Small vault guarding many quorums (per-key dilution, pyramid) | **new** contagion_sim.py `--dilution` (collateral split across the ledgers a key guards) and unequal vault sizes `--vaults powerlaw`. |

## Held funds

| Concern | Facility |
|---|---|
| Operator ignores transfer/exit requests with no consequence | **new** `attack-censor-hold.sh` — wallet escalates per DEP-12 (`wallet-escalate` → `delivery_embed`), operator ignores (`:ignore-requests` adversary switch); measures whether anything acts on the embed (today: nothing — `verify-censorship` has no caller; that is the finding). |
| Fee collection makes an escalated request unservable | **new** same script, second phase: after the embed, operator drains the deposit via forged fees; `verify-censorship`'s servability rule is checked offline by the script (the honest-operator-framing guard). |
| Lottery goes unclaimed: last revealer withholds | **have** `attack-withhold-reveal.sh` — one armer (adversary `:withhold-reveal`) never publishes its preimage; DEP-06 subset leaves: past the 72-block deadline a revealer claims with the voters' attestation. PASS = claimed by a revealer, never the withholder or the accused. |
| Lottery N (committed under Q, armed k) | **resolved** (DEP-06): contributions are 1..60 whatever the arming count; veto-pledge and withhold-reveal run with fewer armers than Q. |

## Honest parties punished

| Concern | Facility |
|---|---|
| Censorship proof on an unservable request frames an honest operator | **new** `attack-censor-hold.sh` honest arm — embed a request the operator *cannot* serve (double-spend the funds first); PASS = no honest node disputes on the embed alone. |
| Replayed/stale proofs re-announce disputes | **have** `fuzz-proofs.lisp` (malformed); **new** replay arm in `attack-post-confiscation.sh` — re-publish a valid old proof after the ledger changed hands. |
| Relay censors/delays/drops ephemeral events | **new** relay.py fault injection: a `faults.json` the relay polls — drop/delay by kind, author, action. `attack-reorg.sh` and the censor-hold script use it to stall cosign rounds and reveals. |

## Operations

| Concern | Facility |
|---|---|
| Confiscated operator keeps operating; wallets keep sending requests | **new** `attack-post-confiscation.sh` — after a confiscation completes, send the old operator a wallet request and fund its old reserves address; PASS = the request is refused ("in dispute state") and the funding is not credited; record what actually happens. |
| Reorg near the tip stalls cosigning | **new** `attack-reorg.sh` — signet: mine a fork deeper than the tip the updates signed (or simulate by rewinding the height source), watch cosign refusals (`*cosign-height-tolerance*`) and recovery. On signet we cannot reorg at will, so the script measures the tolerance boundary directly: publish updates at heights ± tolerance and count refusals. |
| Resigning-operator monitoring | **new** `attack-post-confiscation.sh` phase 3 — after confiscation, watch whether the old operator's *other* ledgers' members re-seat (they should not need to: contagion already disputed them) and whether the old operator can add itself to a new quorum. |

## Analysis gaps (contagion_sim.py)

| Gap | Facility |
|---|---|
| No multi-ledger operators / operator contagion | **new** `--ledgers-per-operator K` (collateral pooled per operator, contagion slashes the operator, not the key) |
| No per-key dilution | **new** `--dilution` (a key's collateral divided across the quorums it guards) |
| No strategic seating | **new** `--seating strategic\|random` |
| No unequal vaults | **new** `--vaults equal\|powerlaw` |
| No detection/punishment failure | **new** `--punish-failure P` (fraction of honest quorums that fail to confiscate a caught colluder) |

## Not built (and why)

- **Unauthorised-vault-spend fraud proof (DEP-06 type 7) verifier/watch** — that is
  protocol *implementation*, not a red-team facility; the attack script proves the
  gap exists (theft unnoticed), which is the input that justifies building it.
- **ExitRequest/splice-in** — absent from the protocol; nothing to attack.
- **Co-sign refusal proofs (Kind 9108)** — same: the facility would be the
  implementation. `relay.py` fault injection + `:ignore-requests` cover the
  *attack* side (stalling cosigning).
- **Trust signals / wallet watcher** — product surface, out of scope here.
