# Upstream and protocol notes

Findings about the Bitcoin Deposits specification (`bitcoin-deposits/deposits`)
and its reference implementation (`bitcoin-deposits/deposits-rust`) made while
building cl-deposits against them.  Each entry says where it came from, what we
did about it, and whether it has been reported upstream.  Keep adding to it.

Status legend: **bug** = reference or spec defect; **gap** = the DEP text does
not say it, the code decides it; **quirk** = surprising but deliberate.

## Reference implementation bugs

1. **Partial-reveal lottery leaf can be unspendable** — bug, not reported.
   `LotteryScriptBuilder::build_lottery_script_with_bounds_n` reduces the
   contribution sum modulo the revealer count with `n` conditional
   subtractions, where `n` is the number of revealers.  In a partial-reveal
   sub-lottery the length bounds stay those of the full quorum, so the sum can
   reach `(N-1)·N` while only `N-1` subtractions of `N-1` are applied: when
   every revealer contributes the maximum, one subtraction is missing, the
   dispatch index equals `N-1`, no arm matches, and the leaf evaluates to
   false.  The funds then fall through to the recovery cascade (CSV 144+).
   The full-reveal leaf is fine (`sum ≤ N·N < N·(N+1)`).  Found by
   `inspect/lottery-test.lisp`, which now asserts the exact failing case.
   Fix upstream: run the reduction loop `bounds_n` times (or `n+1`).
   The off-chain `calculate_winner` has the matching blind spot: it bounds
   lengths by the revealer count, so it rejects a valid maximum-length
   preimage in a sub-lottery instead of computing its winner.

2. **Wallet-side `ledger validate` is stale** — bug, not reported.
   `deposits-wallet ledger validate` expects `prev_hash == content_hash`, the
   pre-cosignature chain rule.  It fails the reference's own mainnet fixture
   (51 of 52 updates) as well as every ledger we publish.  The node-side
   `deposits-node nostr validate` implements the current rule
   (`prev_hash == SHA256(content_hash || operator_signature)`) and is the one
   to trust.

3. **Genesis update not republished** — bug, not reported.
   A reference node's `ledger open` sometimes leaves sequence 0 off the relay
   (its first publish raced the relay connection).  Its own validator then
   reports the ledger invalid.  `deposits-node ledger republish <id>` fixes it.
   Our nodes were unaffected because consent requests piggyback the full
   history.

4. **`quorum begin` CLI timeout cancels the confirmation wait** — bug/quirk,
   not reported.  The CLI gives the daemon 30 s; the daemon waits up to hours
   for the vault UTXO to reach the signet depth (3 confirmations, 3 s poll).
   The request future is dropped at the CLI timeout.  The pending vault is
   persisted, so a second `quorum begin` resumes ("Detected half-finished
   QuorumBegin") and finishes.

5. **Consent signature never verified** — gap/bug, not reported.
   `QuorumAddMember.quorum_member_signature` is produced by the member
   (BIP-340 over `SHA256("COLLATERAL_CONSENT" || operator_pubkey33 ||
   ledger_id_hex_ascii)`) but no reference code path verifies it.  We verify
   it when staging a member.

## Wire facts the DEPs do not state

- **Cosignature list (tag 22)**: repeated `u16 len (=129) || pubkey33 || sig64
  || member_ledger_hash32`, no count prefix, sorted by pubkey.  DEP-02's
  prose reads as if a count came first.
- **`member_ledger_hash`** is the *content hash* (not the chain hash) of the
  cosigning member's own latest update; zero when the member has no ledger.
- **Chain hash includes the cosignature set**, so an update republished with
  more cosignatures does not change its successor's `prev_hash`; verifiers
  must resolve `prev_hash` against the copy actually chained to.
- **Transaction ids in operations are internal byte order** (rust-bitcoin
  `Txid::as_ref()`); the fixture's QuorumBegin txid reversed is a confirmed
  mainnet transaction.  Display hex must be reversed on the way in and out.
- **Deposit id** = first 16 bytes of `SHA256(descriptor text)`; **ledger id**
  = `SHA256(operator_pubkey33 || reserves_id_utf8 || genesis_block_le32)`.
- **QuorumBegin.ledger_hash** is the predecessor's chain hash; the reserves
  tapscript commits to it in a `<hash> OP_DROP OP_0` leaf.
- **Voter set** for the reserves tapscript is operator (tie-breaker) plus
  members, and the tier table is sized by the voter count, not the member
  count.  The tree is an unbalanced vine (tiers at depths 1, 2, 3, ... with
  the commitment leaf sharing the deepest level).
- **Threshold-1 recovery leaves name a single key**: the lowest sorted voter.
  "Any single member" in DEP-03 §Lottery is really that one member.
- **Depositor witnesses are compact ECDSA** (`r || s`) over the DEP-17
  operation sighash, even though the calculus text talks about `pk(K)`
  generically; keys are 33-byte compressed.
- **Signing digests have generations**: `deposits/cosign/v1` and
  `deposits/operator-update/v1` (tagged, length-prefixed message) are current;
  the reference still accepts three legacy operator digests and one legacy
  cosign digest.  Everything in the fixture is v1.
- **Even-Y protocol keys**: the reference rebuilds a compressed key from a
  Nostr x-only pubkey with an `02` prefix, so a protocol key whose Y is odd
  cannot be one identity on both layers.  Our nodes negate such keys at
  creation.
- **Nostr events are signed by a per-host delegate key** by default, so an
  event's `pubkey` says nothing about which operator or member spoke; match
  on the signatures inside the payload (cosignature pubkeys, consent
  signatures), never on the event author.
- **Request addressing**: `consent_request` (and the other "operator-only"
  actions) must carry `l = <the receiving node's own ledger id>`; a node
  drops requests for ledgers it does not operate.  Courier and agent
  requests use `l = 64 zeros` with a `p` tag.
- **`cosign_update` params**: `sequence_number`, `cosign_data_hex`
  (`seq_le8 || prev_hash || message`), `content_hash_hex`; reply
  `cosign_signature_hex`, `cosigner_pubkey`, `sequence_number`,
  `member_ledger_hash_hex`.  Requests older than 2 s are dropped as stale.
- **`confiscation_sign` params**: `sighash`, `unsigned_tx`,
  `last_valid_sequence`; the signer rebuilds the confiscation from public
  state and refuses on any mismatch.
- **Lottery reveal (Kind 9106)** signs
  `SHA256("CustodyLotteryReveal:" || ledger_id_hex || 0x00 || preimage)`.
- **Quorum size policy** `Q ∈ {3, 5, 7}` (member count, operator excluded) is
  enforced by validators, not just by the CLI.
- **`quorum_expiry` ≤ the shortest staged member's `membership_until`**;
  a QuorumBegin one block past it is refused by cosigners.
- **Reference cosigners require 3 confirmations on signet/testnet, 6 on
  mainnet, 1 on regtest** for the QuorumBegin outpoint.
- **The reference wallet syncs only through Esplora**, whatever
  `CHAIN_BACKEND` says; `devnet/esplora.py` serves the endpoints
  esplora-client 0.11 uses from bitcoind.
- **Wallet requests name deposits by `descriptor`** (make_invoice) or by
  `deposit_id` (balance_query); handlers should accept both.
- **Advertisements (Kind 39100)** must carry every non-defaulted field of the
  reference's `LedgerAdvertisement` or its wallet drops the event.
- **Delivery escalation reply** fields: `ledger_id`, `event_id`, `sequence`,
  `tip_hash`, `request_hash`.

## Specification gaps

- DEP-17's snapshot encoding omits `blocks_since_received` (u32, after
  `blocks_since_open`); the reference encodes it and the conformance vectors
  carry it.  The `blocks_since_received` value function and
  `blocks_since_received_at_least` predicate are likewise absent from the
  DEP-16 registry text.
- DEP-17 lists six obligation forms; the reference has a seventh,
  `pointlock = 0x0006`, and a witness v2 layout carrying scalars for it.

- DEP-02 does not define the cosign/operator digests (only the hash chain);
  the tagged v1 forms and their legacy predecessors live in
  `types/updates.rs`.
- DEP-03 names four tiers but the reference selects the tier table by
  *ruleset* (`legacy`, `cltv-offset-literal`, `cltv-offset-v2`,
  `fee-cap-v3`, `balance-commit-v4`) pinned in `QuorumBegin.protocol_version`;
  only `cltv-offset-v2` and later use absolute CLTV heights anchored to
  `quorum_expiry`.
- DEP-12 describes provable censorship but there is no DEP-06 fraud-proof
  type for it yet; the reference wires the embed and the clock only.
- DEP-13 route requests: the reference wallet's `transfer_lock` request is
  field-by-field (`completion_script`, `timeout_height`, ...) while ours
  carries a base64 operation; the DEP does not fix the request shape.
- DEP-06's "any single member" tiers and the lottery's script bounds (above)
  are the two places where the prose and the script disagree.

## How to reproduce the reference locally

`~/workspace/deposits-rust`, built with `cargo build --release -p
deposits-node -p deposits-wallet` (the forked miniscript is a git submodule).
Run against our devnet with `LIGHTNING_BACKEND=none CHAIN_BACKEND=bitcoind
BITCOIND_RPC_URL=http://127.0.0.1:38332 BITCOIND_COOKIE_FILE=<cookie>
deposits-node run --network signet --relay ws://127.0.0.1:7777 --esplora
http://127.0.0.1:3002 --data-dir <dir> --seed-file <seed>`.  The lottery
vectors in `inspect/vectors/lottery-reference.txt` came from a throwaway
`deposits-core/tests/cl_vector.rs`.
