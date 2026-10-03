# cl-deposits devnet

Runs on the private signet at `/mnt/lisp/signet` (bitcoind + miner wallet must be up),
or on a private regtest chain of its own:

    devnet/regtest.sh   # bitcoind regtest + relay + cld1..cld4 + smoke.sh (no Lightning) + teardown; what CI runs
                        # BITCOIND=/path/bitcoind BITCOIN_CLI=/path/bitcoin-cli to pick binaries; KEEP=1 to leave it up
                        # (ports 7797 / 10201-10204 / rpc 18553, data under /tmp/cld-regtest: coexists with both networks below)

    devnet/regtest-net.sh up|down|status|reset
                        # the persistent regtest red-team network: bitcoind, beacon (7787), Esplora shim (3012),
                        # cld1..cld48 (control 10101-10148; a full suite run burns ~31 keys for good), ref2..ref7 (admin 8866-8871, its own deposits-rust
                        # build at /mnt/lisp/cargo-target/regtest-net), a block every REGTEST_BLOCK_EVERY s (10),
                        # and the soak's ledgers A..L + deposits (soak.sh setup, no soak loops).  Data under
                        # /mnt/lisp/regtest-devnet.  `mine` is instant here.
    DEVNET=regtest redteam/run-all.sh --tags slow   # the scenarios that mine past quorum expiry

`DEVNET` (or `CLD_CHAIN`) selects the network for every devnet and red-team script: `signet`
(default; the soak, real block pacing; its difficulty retargets, so mining hundreds of blocks takes
days) or `regtest`.  Same node names on both, different ports and data dirs.

The relay is beacon (`~/beacon`, a pure-CL Nostr relay), configured by `devnet/beacon-relay.lisp`:
no result cap or rate limits, ephemeral responses kept 10 minutes for REQs with `since` (the
reference daemon polls for its confiscation_sign replies), and red-team fault rules from
`$CLD_ROOT/relay.jsonl.faults.json` (drop/delay by kind, author, action, to).  Its store is
`$CLD_ROOT/beacon-data/`; on first start it imports relay.py's `relay.jsonl`.  `RELAY_IMPL=py`
runs the old `devnet/relay.py` instead, for one more cycle.

On signet:

    devnet/up.sh        # relay (beacon, ws://127.0.0.1:7777) + cld1..cld4 (cld1 operates; cld2–4 cosign, Q=3)
    devnet/smoke.sh     # quorum formation, on-chain funded QuorumBegin, deposits, transfer, Lightning rail, dispute
                        # CLD_NO_LN=1 skips the Lightning steps
    devnet/status.sh
    devnet/cld-ctl.sh cld1 '(:info)'
    devnet/cld-wallet.sh w1 <ledger> open|balance|transfer|complete ...
    devnet/down.sh [--wipe]
    devnet/mixed.sh     # cld and reference (deposits-rust) nodes in each other's quorums; see below

## Mixed quorums with the reference implementation

`up.sh` also starts `ref2` and `ref3`, two `deposits-node` daemons from
`~/workspace/deposits-rust/target/release` (override with `DEPOSITS_RUST`),
each with its own data dir under `/mnt/lisp/signet/deposits/<name>/` (seed,
wallet, node.log) and talking to the same relay, bitcoind, and Esplora shim.
`ref_cli ref2 <command>` in `_common.sh` runs their CLI against that node.
`mixed.sh` then forms ledger A (cld1 operates; cld2, ref2, ref3 cosign) and
ledger B (ref2 operates; cld2, cld3, ref3 cosign), moves funds on both from
both wallets, and has cld1 equivocate on A so that members of both
implementations fork and arm.  What we learned about driving the reference
node is in `UPSTREAM-NOTES.md`.

Data lives under `/mnt/lisp/signet/deposits/<node>/`: `node.key`, `cld.log`,
and `ledger_<id16>.json` — the same JSON-array-of-base64 format as the
reference audit fixture, so any ledger written here can be loaded as a
replica (validated update by update) or fed to the vectors gate.

## Soak: operating for a long time, at devnet scale

    devnet/soak.sh setup    # six ledgers (every node operates one, mixed quorum of three, one
                            # reference member each), 12 reference-wallet deposits + 12 cl-wallet
                            # deposits per ledger, all credited; idempotent and resumable
    devnet/soak.sh start    # a block a minute, one deposit-bot per reference deposit (swarm.sh, one
                            # swarm per ledger), 4 cl-wallet workers, a monitor every 5 min, and a
                            # chaos loop that restarts a node every 3 h
    devnet/soak.sh status   # the latest monitor snapshot: per-ledger sequence on every cl node
                            # (a spread across a row is lag), queue depths, bot send/fail counters
    devnet/soak.sh stop

State lives in `$CLD_ROOT/soak/` (`ledgers.tsv`, `deposits.tsv`, `refwallet-<L>/`,
`log/`, `status.log`).  Knobs at the top of `soak.sh`.

What the first hour of it found (2026-09-23), all fixed in the same session:

- **cl node: cosigning starved behind operator work.**  One worker handled both a
  node's operator requests (which wait up to three rounds of `*cosign-timeout*`)
  and its cosign duty; every node here is both, so the four cl nodes convoyed and
  half of all transfers timed out.  Other operators' updates and cosign requests
  now run on their own lane (`cld-cosigner`), in arrival order.  `(:info)` reports
  both queue depths (`:INBOX`, `:COSIGN-INBOX`).
- **cl node: a replica that missed one update was dead forever** ("expected seq N"
  on every later one, no gap fill); every ledger had exactly one stuck cl
  cosigner after a round of restarts.  `catch-up` fetches the operator's chain
  from the relay on a gap (in an update or a cosign request) and at startup.
- **relay.py: O(n) per publish** over 100k stored lines pinned its one loop at a
  full core; a subscriber that stalled 1 s was silently unsubscribed and never
  told; and a new subscriber was handed ten minutes of stale wallet requests to
  re-execute.  Now O(1) dedup, per-client queues (an overflowing client is
  CLOSED so it reconnects), no request replay, and a stats line every minute.
- The speculative "would it apply?" check replayed the whole history per
  operation and per cosign (16 ms at seq 1400 — real but not what hurt);
  `copy-ledger` deep-copies live state instead.

- **cl node: a killed node DELETED its ledger files.**  `save-record` rewrote the
  whole file with `:if-exists :supersede`, and SBCL removes a supersede target
  when the write is aborted — which a SIGTERM mid-save (or any error inside the
  write) does.  With a rewrite per update the node was nearly always inside one.
  Now: append the new update inside the closing bracket (O(1) per update), a
  whole-file rewrite goes to `.tmp` + rename, the loader keeps what decodes of a
  truncated tail, and a cosign request naming a ledger we do not hold rebuilds
  it from the relay if its quorum names us (`refollow-if-member`).
- **relay.py again**: a client whose queue overflowed lost its subscriptions
  but kept its socket (now closed, so it reconnects); `REQ` scanned the whole
  store (now indexed by `d` tag; a windowed fetch is ~40 ms); the ephemeral
  buffer was a list rebuilt per event (deque + set); and the pid file held the
  setsid wrapper, so two "restarts" left the old relay running.
- **cl node subscribes `since` a minute ago** — the relay used to replay its
  whole store into every fresh subscription — and catch-up fetches only the
  missing sequence numbers (`#n`), in windows; `remove-duplicates` over a
  6000-update list was quadratic and put the replica lane into a spiral.
- `(:threads)` on the control socket prints a backtrace of every thread: it is
  how the last of these was found in one sample.

After the fixes: 72 bots + 4 cl workers, ~1000 transfers per 3 minutes across
both implementations, 0 failures, every replica in step on every ledger; a node
restarts in about a minute and rejoins with its replicas current.

The first NIGHT (2026-09-24) found the next layer, at ~80k updates per ledger:

- **Heap.**  SBCL's default 1 GB heap; a node holds every replica's full
  history in memory (~1 KB per update) and the old loader held an 84 MB file as
  a 4-byte-per-character string.  cld3, cld4, cld2 died "Heap exhausted, game
  over" between 02:25 and 05:23.  Now 32 GB (`CLD_HEAP_MB`) and a streaming
  loader — which buys weeks, not years: history belongs on disk and on the
  relay, not in RAM (open).
- **Files with a gap in the middle**, left by rewrites of histories that the
  old loader had loaded past damage.  The loader now keeps the good prefix,
  marks the file for a full rewrite, and catch-up refills the rest.
- **Quorum expiry (DEP-11 §Quorum Rotation).**  The expiry is the SHORTEST
  member commitment — ~950 blocks with a reference member, ~16 h at a block a
  minute.  The reference operators rotated themselves; the cl operators have no
  rotation, so at expiry every value-moving op on A, C, D, E was refused
  ("not cosignable at TIER0-POST-EXPIRY") and the failure rate climbed to 40%.
  `soak-rotate.sh` now rotates them from outside (re-consent, fund a fresh
  reserves output, QuorumBegin).  Node-side auto-rotation, and a rotation that
  SPENDS the old vault, are open.
- **Consent requests piggyback the whole history** in one Nostr event, in both
  implementations: ~60 MB at 46k updates, over any relay's frame limit, so no
  member ever saw the rotation's consent request.  The operator now sends a
  40-update prefix (the reference must see LedgerOpen, and its client drops events over 70 KB and gap-fills the
  rest); our member catches up to the request's `ledger_sequence`.
- **Chaos restarted cld2 every time**: `start_cld` clobbered the loop counter.
  And a loop started yesterday still runs YESTERDAY's `_common.sh`: after the
  heap fix it restarted cld2 with the old 1 GB `start_cld` and cld2 died again.
  After editing `_common.sh`, `devnet/soak.sh stop && devnet/soak.sh start`.
- **The reference node's gap-fill walked the whole chain** (47k updates, 14
  pages) every time a ledger was marked stale, even one update behind; its
  main loop fell 5-9 s behind and every cosign and consent it owed timed out
  (a member's consent records a QuorumJoin on ITS OWN ledger, which needs
  cosigs).  `deposits-node/src/node/main_loop.rs` now stops paging once a page
  reaches the local tip: 1 page, request lag p50 0 ms / p90 1 s.
- **Consent requests must fit the reference client's 70 KB event cap** — its
  nostr client drops anything larger silently, so "did not consent" was the
  only symptom.  40 updates of prefix fit; 1000 (850 KB) did not.
- Consent needs a 60 s timeout (`+consent-timeout+`): a member imports,
  gap-fills and cosigns its own QuorumJoin before it answers.

- **A cosign request for a ledger we do not hold rebuilt it in full before
  asking whether we were a member**: every signature of a 90k-update ledger
  verified and a file write per update, then discarded, then again ten
  minutes later.  Now the newest QuorumBegin (one relay fetch, the `t` tag)
  decides membership first, non-members are remembered for six hours, and a
  warranted rebuild saves its file once.  Found with `(:threads)`.

- **secp256k1-fast is WRONG under SBCL 2.6.8** (right under 2.2.9): the same
  private key derives a different public key and its own Schnorr signature
  does not verify.  Two SBCLs on this box and `~/.local/bin` first on PATH, so
  the chaos loop restarted cld2 and cld3 on 2.6.8 and they came back as
  strangers to their own ledgers, rejecting every update as "bad operator
  signature".  Launchers now pin `${CLD_SBCL:-/usr/bin/sbcl}`.  Root cause
  (bisected in `deps/secp256k1-fast`): SBCL 2.6.8 open-codes the
  variable-position `(ldb (byte 64 (* i 64)) x)` in `i->fe` as a two-digit
  SHRD and, under register pressure next to the inlined field VOPs, allocates
  the shift count and the loaded digit to the SAME register — every limb
  shifted by junk.  2.2.9 called ASH.  Fixed in `field-limb.lisp` (and the
  same pattern in `field.lisp`'s `int-to-bytes32`) with a constant mask and
  constant shift; the library's tests pass under both SBCLs.  An SBCL bug,
  not yet reported upstream.

- **The operator appended to its own ledger from two threads.**  A rotation's
  QuorumAddMember (control socket) reads the tip, collects consents and cosigs
  for seconds, and commits one sequence stale because the worker committed a
  bot transfer meanwhile: "SEQUENCE (expected N+1, got N)", every 10 minutes
  for 4.5 hours, until expiry refused the competing transfers and the rotation
  finally won.  `append-operation` now holds a per-ledger lock across the whole
  append, cosign round included.
- The reference member, replaying a reference-operated ledger after its own
  restart, warns `BalanceCommitmentMismatch` on the operator's early updates
  (declared vs replayed balances) — reference validating reference, WARN only;
  noted, not chased.

- **The reference operator silently stops publishing after a relay reconnect.**
  After its 09:54 chaos restart ref2 logged "Disconnected / Connected / Failed
  to stream events: relay not connected" and from then on none of its cosign
  requests for B reached the relay (captured: zero in 45 s), while its own log
  said only "Cosign timeout: got 1/2 cosigs" every 10 s for four hours.  A
  restart cured it at once (8 requests in 30 s, B advancing).  A reference
  (nostr-sdk client) defect; the symptom to watch for is a reference-operated
  ledger whose sequence stops while the operator blames its cosigners.

- **The cl operator never appended TransferFail (DEP-11 §Transfer Timeout).**
  Every transfer whose `complete` timed out left its funds locked for good:
  after two days ledger A's bots held 640k sats of which ~9k were available
  ("a10: balance 151732, locked 151517, available 214"), throughput fell from
  15k to 4k transfers an hour, and every update the operator signed past a
  lock's `timeout_height` was, per DEP-11, provable non-conformance.  The
  reference has `auto_timeout_transfers`; ours now has a poller that appends
  `TransferFail (reason 1)` for each pending transfer past its timeout.

All four cl-operated ledgers rotated post-expiry (A, C, E, D in that order,
between 14:21 and 15:27) with their reference members consenting: DEP-11's
degraded self-rescue path, exercised across both implementations.

Night of 2026-09-25 (docs/REDTEAM.md organic #2, #3):

- **relay.py, a third time: any REQ without `#d` scanned all 670k stored
  events** — one per reference-bot transfer.  94% CPU, delivery p90 11–13 s,
  cosign rounds (16 s) and so rotations timed out; A froze at its rotation
  window.  The store is now indexed by kind, author and every single-letter
  tag, each list sorted by `created_at` so `since`/`until` bisect (0.5–1.5 s →
  1–57 ms per REQ, identical results on 11 filter shapes).  `kill -USR1` on the
  relay toggles a per-REQ trace (`relay.jsonl.trace`: peer port, filters,
  result count, ms).
- **The reference's consent_request carried the whole ledger history** (~100 MB
  for B).  The relay closed the connection on it every cycle, which is very
  likely the "silently stops publishing after a reconnect" above; nostr-sdk
  would have dropped it anyway (70 kB event limit).  Fixed in deposits-rust.
- **A cl ledger under traffic could not rotate before expiry:** `begin-quorum`
  required an unmoved tip across the funding confirmations.  It now anchors the
  prepared hash; D rotated under traffic.
- `start_ref` waited for "Wallet synced" by grepping the whole 1 GB node log
  every second (and could match a previous run); it reads only this run's part.
- soak-rotate: A rotates to cld4 in place of ref2, which has treated A as a gap
  since forking it (organic #1).
