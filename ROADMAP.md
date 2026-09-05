# cl-deposits roadmap

Verified means: checked against the reference implementation's artefacts
(fixtures, encoders, or a live node), not against our own reading of the spec.

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo, deps (cl-consensus, secp256k1-fast, cl-nostr), harness, CI | done |
| 1 | DEP-02 core: TLV, SignedLedgerUpdate, hash chain, cosign + operator digests (v1 and legacy), Schnorr verify/sign | done — 372-update fixture replays, all signatures verify |
| 2 | Operations: typed decode/encode of all 27 discriminants, fee structures; ledger state machine (DEP-05) | done — fixture chain replays; ledger_id, deposit_id and cosign-majority rules cross-checked |
| 3 | DEP-17 canonical encodings + DEP-16 descriptor evaluator (deposit authorization, fraud-proof replay) | 3a done — operation preimage/sighash, pk(K) ECDSA witnesses: reference vector + all 14 fixture wallet signatures verify; evaluator next |
| 4 | DEP-03 on-chain: NUMS key, tiered tapscript reserves, rotation tx + OP_RETURN anchor, QuorumBegin chain checks — built and spent with cl-consensus | 4a done — fixture's real mainnet reserves address reproduced (cltv-offset-v2, 4 voters, vine tree, commitment leaf); spend + rotation next |
| 5 | Nostr transport (DEP-04): kinds 9100/39100/20101/20102 over cl-nostr; local relay for the devnet | |
| 6 | Roles: operator node, quorum member (cosigner), wallet; persistence; control socket | |
| 7 | Lightning rail: InvoiceCredit/Lock/Fulfill through cl-payments; devnet with CLN/LND | |
| 8 | Disputes: fraud proofs (DEP-06), custody lottery scripts, recovery cascade | |
