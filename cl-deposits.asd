;;;; cl-deposits.asd

(defsystem "cl-deposits"
  :description "A clean-room Common Lisp implementation of the Bitcoin Deposits
                protocol (github.com/bitcoin-deposits/deposits): operator
                ledgers as signed, cosigned hash chains over Nostr, backed by
                Taproot reserves validated with cl-consensus."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("secp256k1-fast" "ironclad" "bordeaux-threads" "cl-consensus" "cl-nostr" "com.inuoe.jzon")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "util")    ; bytes, hex, integers, sha256, tagged hashes
     (:file "tlv")     ; DEP-02: BigSize TLV streams, canonical ordering
     (:file "update")  ; DEP-02: SignedLedgerUpdate, hash chain, signatures
     (:file "operation") ; DEP-02: the 27 ledger operations, typed
     (:file "ledger")  ; DEP-05: the state machine — balances, quorum, locks
     (:file "dep17")   ; DEP-17: canonical operation encoding, depositor signatures
     (:file "reserves") ; DEP-03: the Taproot reserves output and its tapscript tiers
     (:file "rotation") ; DEP-03: spending the reserves — rotation, recovery, anchors
     (:file "wire")     ; DEP-04: ledger updates, requests, responses, ads as Nostr events
     (:file "bus")      ; where events go: in-process bus (gates), Nostr relays (devnet)
     (:file "node")     ; the node: operator, quorum member, and the wallet side
     ))))
