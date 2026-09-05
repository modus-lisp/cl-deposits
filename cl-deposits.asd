;;;; cl-deposits.asd

(defsystem "cl-deposits"
  :description "A clean-room Common Lisp implementation of the Bitcoin Deposits
                protocol (github.com/bitcoin-deposits/deposits): operator
                ledgers as signed, cosigned hash chains over Nostr, backed by
                Taproot reserves validated with cl-consensus."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("secp256k1-fast" "ironclad" "cl-consensus")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "util")    ; bytes, hex, integers, sha256, tagged hashes
     (:file "tlv")     ; DEP-02: BigSize TLV streams, canonical ordering
     (:file "update")  ; DEP-02: SignedLedgerUpdate, hash chain, signatures
     ))))
