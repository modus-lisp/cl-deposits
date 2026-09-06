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
| 7 | Lightning rail: InvoiceCredit/Lock/Fulfill through cl-payments; devnet with CLN/LND | receive path done — make_invoice via cl-payments control socket, cosign_invoice attestation (reference digest), InvoiceCredit on settlement; devnet: CLN pays, deposit credited, replicas agree. Pay path (InvoiceLock/Fulfill) next |
| 9 | DEP-12 delivery escalation: wallet → member `delivery_embed`, DeliveryEmbed on the member's ledger, censorship proof (embed, causal link via member_ledger_hash, service deadline, no answer) | done — gate covers ignored request → escalation → proof only after the member cosigns past the embed and the deadline passes |
| 10 | DEP-13 couriers: advertisement (Kind 39102), request_route, two-leg HTLC with shorter leg-2 timeout, preimage relay back to leg 1 | done — gate moves funds from a deposit on ledger A to a deposit on ledger E through a courier |
| 8 | Disputes: fraud proofs (DEP-06), custody lottery scripts, recovery cascade | done — lottery scripts/tree/claims/armer shares/sweeps spent under cl-consensus; fraud proofs (equivocation, quorum-expired, non-conforming-update) with the reference hashing and JSON; forks, arming, confiscation via confiscation_sign, reveals (Kind 9106), winner claim + DisputeAcquire, yields; devnet smoke step 11: operator equivocates, members detect it, fork, arm, confiscate the reserves on signet, reveal, and the script-selected winner's claim confirms |

## Interoperability with the reference implementation

Verified live on the signet devnet against `deposits-rust` (built from
`~/workspace/deposits-rust`, run with `LIGHTNING_BACKEND=none`,
`CHAIN_BACKEND=bitcoind` and `--esplora` pointed at `devnet/esplora.py`):

- their `nostr validate` accepts every ledger our nodes publish;
- their wallet discovers our advertisement, opens deposits on our operator,
  requests Lightning invoices from it (cosigned attestations), and reads
  balances back after a CLN node pays;
- their node joins our quorum: consent handshake, QuorumJoin on its ledger,
  cosignatures on our DepositOpen/OnchainCredit, outpoint checks via bitcoind;
- our nodes join its quorum: it stages cld1–cld3, rotates its reserves into a
  Q=3 Taproot vault on our signet, and our three nodes cosign its QuorumBegin
  and subsequent operations; every replica sits at its tip.

Reference quirks worth knowing: its wallet `ledger validate` is stale (expects
prev_hash = content_hash) — use the node's `nostr validate`; its `quorum begin`
CLI times out after 30 s while the daemon waits for confirmations, and a rerun
resumes with the persisted vault; Q must be 3, 5 or 7; fund the per-ledger
`ledger address`, not the node's main `address`; its validator is happy only if
the genesis update is on the relay (`ledger republish` fixes a missing seq 0).
