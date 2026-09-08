# cl-deposits devnet

Runs on the private signet at `/mnt/lisp/signet` (bitcoind + miner wallet must be up),
or on a private regtest chain of its own:

    devnet/regtest.sh   # bitcoind regtest + relay + cld1..cld4 + smoke.sh (no Lightning) + teardown; what CI runs
                        # BITCOIND=/path/bitcoind BITCOIN_CLI=/path/bitcoin-cli to pick binaries; KEEP=1 to leave it up
                        # (ports 7787 / 10051-10054, data under /tmp/cld-regtest: coexists with the signet devnet)

On signet:

    devnet/up.sh        # relay (devnet/relay.py, ws://127.0.0.1:7777) + cld1..cld4 (cld1 operates; cld2–4 cosign, Q=3)
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
