#!/usr/bin/env bash
# devnet/smoke.sh — end to end on the signet devnet:
#   cld1 operates a ledger; cld2 and cld3 join its quorum; the reserves are
#   funded on chain and QuorumBegin points at the outpoint (cosigners check it
#   against bitcoind); two wallets open deposits, one is credited, and a
#   hash-locked transfer settles — every step cosigned over the relay.
source "$(dirname "$0")/_common.sh"
set -e
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { local reply=$1; case "$reply" in *":STATUS :OK"*) echo "   $reply";; *) fail "$reply";; esac; }

step "1  nodes"
for n in $(cld_names); do cld_running "$n" || fail "$n not running (devnet/up.sh)"; done
P1=$(cld_pubkey cld1); P2=$(cld_pubkey cld2); P3=$(cld_pubkey cld3)
echo "   cld1 $P1"; echo "   cld2 $P2"; echo "   cld3 $P3"

step "2  each node opens its own ledger"
L1=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 30000000000)")" ":LEDGER")
L2=$(sx "$(cld_ctl cld2 "(:open-ledger :reserves-id \"genesis:cld2:$RANDOM\")")" ":LEDGER")
L3=$(sx "$(cld_ctl cld3 "(:open-ledger :reserves-id \"genesis:cld3:$RANDOM\")")" ":LEDGER")
[ -n "$L1" ] && [ -n "$L2" ] && [ -n "$L3" ] || fail "ledger open"
echo "   cld1 ledger $L1"

step "3  cld2 and cld3 join cld1's quorum (consent handshake over the relay)"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$L1\" :member \"$P2\")")"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$L1\" :member \"$P3\")")"
R2=$(cld_ctl cld2 "(:info)"); [[ "$R2" == *"$L1"* ]] || fail "cld2 does not replicate $L1"
echo "   cld2 replicates cld1's ledger"

step "4  prepare the reserves output and fund it on signet"
PREP=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$L1\" :expiry-blocks 4320)"); expect "$PREP"
ADDR=$(sx "$PREP" ":ADDRESS")
SATS=50000000   # 0.5 BTC = 0.2 reserves + 0.3 collateral
TXID=$(wcli sendtoaddress "$ADDR" 0.5)
mine 1
VOUT=$(bcli getrawtransaction "$TXID" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$ADDR'][0])")
echo "   funded $ADDR in $TXID:$VOUT"

step "5  QuorumBegin — cosigners verify the outpoint against bitcoind"
expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$L1\" :txid \"$TXID\" :vout $VOUT :sats 20000000 :collateral-sats 30000000)")"
INFO=$(cld_ctl cld1 "(:info)"); [[ "$INFO" == *":QUORUM :ACTIVE"* ]] || fail "quorum not active: $INFO"

step "6  wallets open deposits"
W1=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" open)" ":DEPOSIT")
W2=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" w2 "$L1" open)" ":DEPOSIT")
[ -n "$W1" ] && [ -n "$W2" ] || fail "deposit open"
echo "   w1 deposit $W1"; echo "   w2 deposit $W2"

step "7  operator credits w1 (OnchainCredit, cosigned)"
expect "$(cld_ctl cld1 "(:credit :ledger \"$L1\" :deposit \"$W1\" :msat 5000000 :txid \"$TXID\" :vout $VOUT)")"
B=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" balance "$W1"); [[ "$B" == *":BALANCE 5000000"* ]] || fail "balance: $B"; echo "   $B"

step "8  w1 -> w2 hash-locked transfer, completed with the preimage"
H=$(bcli getblockcount)
T=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" transfer "$W1" "$W2" 2000000 "$H"); echo "   $T"
TID=$(sx "$T" ":TRANSFER"); PRE=$(sx "$T" ":PREIMAGE"); [ -n "$TID" ] || fail "transfer"
"$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" complete "$TID" "$PRE" | grep -q ":STATUS :OK" || fail "complete"
B1=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" balance "$W1"); B2=$("$CLD_SRC/devnet/cld-wallet.sh" w2 "$L1" balance "$W2")
[[ "$B1" == *":BALANCE 3000000"* && "$B2" == *":BALANCE 2000000"* ]] || fail "balances: $B1 / $B2"
echo "   w1 $B1"; echo "   w2 $B2"

step "9  replicas agree"
T1=$(sx "$(cld_ctl cld1 "(:tip :ledger \"$L1\")")" ":TIP"); T2=$(sx "$(cld_ctl cld2 "(:tip :ledger \"$L1\")")" ":TIP"); T3=$(sx "$(cld_ctl cld3 "(:tip :ledger \"$L1\")")" ":TIP")
[ "$T1" = "$T2" ] && [ "$T1" = "$T3" ] || fail "tips differ: $T1 $T2 $T3"
echo "   tip $T1 on all three nodes"
echo; echo "SMOKE OK"
