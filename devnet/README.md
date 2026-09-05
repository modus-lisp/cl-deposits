# cl-deposits devnet

Runs on the private signet at `/mnt/lisp/signet` (bitcoind + miner wallet must be up).

    devnet/up.sh        # relay (devnet/relay.py, ws://127.0.0.1:7777) + cld1..cld3
    devnet/smoke.sh     # quorum formation, on-chain funded QuorumBegin, deposits, transfer
    devnet/status.sh
    devnet/cld-ctl.sh cld1 '(:info)'
    devnet/cld-wallet.sh w1 <ledger> open|balance|transfer|complete ...
    devnet/down.sh [--wipe]

Data lives under `/mnt/lisp/signet/deposits/<node>/`: `node.key`, `cld.log`,
and `ledger_<id16>.json` — the same JSON-array-of-base64 format as the
reference audit fixture, so any ledger written here can be loaded as a
replica (validated update by update) or fed to the vectors gate.
