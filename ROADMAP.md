# cl-deposits roadmap

Verified means: checked against the reference implementation's artefacts
(fixtures, encoders, or a live node), not against our own reading of the spec.

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo, deps (cl-consensus, secp256k1-fast, cl-nostr), harness, CI | done |
| 1 | DEP-02 core: TLV, SignedLedgerUpdate, hash chain, cosign + operator digests (v1 and legacy), Schnorr verify/sign | done — 372-update fixture replays, all signatures verify |
| 2 | Operations: typed decode/encode of all 27 discriminants, fee structures; ledger state machine (DEP-05) | done — fixture chain replays; ledger_id, deposit_id and cosign-majority rules cross-checked |
| 3 | DEP-17 canonical encodings + DEP-16 descriptor evaluator (deposit authorization, fraud-proof replay) | 3a done — operation preimage/sighash, pk(K) ECDSA witnesses: reference vector + all 14 fixture wallet signatures verify; evaluator next |
| 4 | DEP-03 on-chain: NUMS key, tiered tapscript reserves, rotation tx + OP_RETURN anchor, QuorumBegin chain checks — built and spent with cl-consensus | done — fixture's real mainnet reserves address reproduced; rotation tx with OP_RETURN anchor; every tier spent and every misuse rejected under cl-consensus with Taproot+CLTV enforcement |
| 5 | Nostr transport (DEP-04): kinds 9100/39100/20101/20102 over cl-nostr; local relay for the devnet | done — cl-nostr relay adapter, worker-thread dispatch, devnet relay (devnet/relay.py) |
| 6 | Roles: operator node, quorum member (cosigner), wallet; persistence; control socket | core done — consent/QuorumJoin/QuorumAddMember handshake, QuorumBegin with cosigs from the staged set, cosign_update with chain-continuity + speculative-apply gate, deposit_open/balance/transfer_lock/transfer_complete with DEP-17 witness checks, fixture-format persistence; daemon + control socket + wallet CLI; devnet smoke passes: 3 nodes, on-chain funded QuorumBegin on signet, cosigners check the outpoint via bitcoind |
| 7 | Lightning rail: InvoiceCredit/Lock/Fulfill through cl-payments; devnet with CLN/LND | |
| 8 | Disputes: fraud proofs (DEP-06), custody lottery scripts, recovery cascade | |
