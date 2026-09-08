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

Data lives under `/mnt/lisp/signet/deposits/<node>/`: `node.key`, `cld.log`,
and `ledger_<id16>.json` — the same JSON-array-of-base64 format as the
reference audit fixture, so any ledger written here can be loaded as a
replica (validated update by update) or fed to the vectors gate.
