# cl-deposits

A clean-room Common Lisp implementation of the
[Bitcoin Deposits](https://github.com/bitcoin-deposits/deposits) protocol:
operator-run ledgers published as signed, quorum-cosigned hash chains over
Nostr, backed by Taproot reserves whose transactions are validated with
[cl-consensus](https://github.com/modus-lisp/cl-consensus).  Sibling of
[cl-payments](https://github.com/modus-lisp/cl-payments), whose Lightning node
will serve as the ledgers' Lightning rail.

Every layer is verified against the reference implementation's own artefacts
before it is built on.  The first vector is a real ledger
(`inspect/vectors/ledger_57f60e1dbef339e2.json`): 372 published copies of 52
signed updates, whose hash chain, operator signatures and cosignatures all
verify here byte-for-byte.

    git clone --recursive https://github.com/modus-lisp/cl-deposits
    inspect/run-all.sh

The suite has five gates: `vectors` (codecs, ledger rules, reserves, rotation
and lottery scripts against reference vectors), `nodes` (operator, members,
wallets, disputes, escalation and couriers on an in-process bus), `property`
(seeded random operation sequences; `PROPERTY_SEED` reproduces a run), `chaos`
(the same flows over a relay that delays, reorders and duplicates events;
`CHAOS_SEED` reproduces a run) and `restart` (nodes stopped mid-flow and
rebuilt from their data dirs).  `inspect/mutate.sh` checks that the ledger and
update gates notice each of two dozen single-rule mutations.

See `ROADMAP.md` for what exists and what is next, and `UPSTREAM-NOTES.md` for
what we learned about the spec and the reference implementation on the way.
