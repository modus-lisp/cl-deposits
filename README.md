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

See `ROADMAP.md` for what exists and what is next.
