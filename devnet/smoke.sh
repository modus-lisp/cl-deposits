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
P1=$(cld_pubkey cld1); P2=$(cld_pubkey cld2); P3=$(cld_pubkey cld3); P4=$(cld_pubkey cld4)
echo "   cld1 $P1"; echo "   cld2 $P2"; echo "   cld3 $P3"; echo "   cld4 $P4"

step "2  each node opens its own ledger"
L1=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 30000000000)")" ":LEDGER")
L2=$(sx "$(cld_ctl cld2 "(:open-ledger :reserves-id \"genesis:cld2:$RANDOM\")")" ":LEDGER")
L3=$(sx "$(cld_ctl cld3 "(:open-ledger :reserves-id \"genesis:cld3:$RANDOM\")")" ":LEDGER")
L4=$(sx "$(cld_ctl cld4 "(:open-ledger :reserves-id \"genesis:cld4:$RANDOM\")")" ":LEDGER")
[ -n "$L1" ] && [ -n "$L2" ] && [ -n "$L3" ] && [ -n "$L4" ] || fail "ledger open"
echo "   cld1 ledger $L1"

step "3  cld2, cld3 and cld4 join cld1's quorum (consent handshake over the relay)"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$L1\" :member \"$P2\" :member-ledger \"$L2\")")"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$L1\" :member \"$P3\" :member-ledger \"$L3\")")"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$L1\" :member \"$P4\" :member-ledger \"$L4\")")"
R2=$(cld_ctl cld2 "(:info)"); [[ "$R2" == *"$L1"* ]] || fail "cld2 does not replicate $L1"
echo "   cld2 replicates cld1's ledger"

step "4  prepare the reserves output and fund it on $CLD_CHAIN"
PREP=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$L1\" :expiry-blocks 4320)"); expect "$PREP"
ADDR=$(sx "$PREP" ":ADDRESS")
SATS=50000000   # 0.5 BTC = 0.2 reserves + 0.3 collateral
TXID=$(wcli sendtoaddress "$ADDR" 0.5)
mine 3   # the reference requires 3 confirmations
VOUT=$(bcli getrawtransaction "$TXID" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$ADDR'][0])")
echo "   funded $ADDR in $TXID:$VOUT"

step "5  QuorumBegin (Q=3) — cosigners verify the outpoint against bitcoind"
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
T1=$(sx "$(cld_ctl cld1 "(:tip :ledger \"$L1\")")" ":TIP"); T2=$(sx "$(cld_ctl cld2 "(:tip :ledger \"$L1\")")" ":TIP"); T3=$(sx "$(cld_ctl cld3 "(:tip :ledger \"$L1\")")" ":TIP"); T4=$(sx "$(cld_ctl cld4 "(:tip :ledger \"$L1\")")" ":TIP")
[ "$T1" = "$T2" ] && [ "$T1" = "$T3" ] && [ "$T1" = "$T4" ] || fail "tips differ: $T1 $T2 $T3 $T4"
echo "   tip $T1 on all four nodes"
if [ "${CLD_NO_LN:-}" = 1 ]; then echo; echo "== 10 Lightning steps skipped (CLD_NO_LN=1)"; else
step "10 Lightning rail: w1 receives 100000 msat over Lightning (cosigned attestation, InvoiceCredit)"
INV=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" invoice "$W1" 100000 "deposit top-up"); echo "   $INV"
BOLT11=$(sx "$INV" ":BOLT11"); [ -n "$BOLT11" ] || fail "no invoice"
[[ "$INV" == *":COSIGNED T"* ]] || fail "attestation not cosigned"
ln_cli cln3 pay "$BOLT11" >/dev/null 2>&1 || ln_cli cln4 pay "$BOLT11" >/dev/null || fail "payment failed"
echo "   paid from cln"
for i in $(seq 1 10); do R=$(cld_ctl cld1 "(:poll-invoices)"); [[ "$R" == *":CREDITED (\""* ]] && break; sleep 1; done
[[ "$R" == *":CREDITED (\""* ]] || fail "not credited: $R"
B1=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" balance "$W1"); [[ "$B1" == *":BALANCE 3100000"* ]] || fail "balance after LN: $B1"
echo "   w1 $B1"
T1=$(sx "$(cld_ctl cld1 "(:tip :ledger \"$L1\")")" ":TIP"); T2=$(sx "$(cld_ctl cld2 "(:tip :ledger \"$L1\")")" ":TIP")
[ "$T1" = "$T2" ] || fail "tips differ after credit"
echo "   replicas agree at $T1"
step "10b Lightning pay: w1 pays a CLN invoice from its deposit; the reference wallet pays one through our operator"
INV=$(ln_cli cln3 invoice 50000 "clpay-$RANDOM" "pay from deposit" | python3 -c "import json,sys; print(json.load(sys.stdin)['bolt11'])")
P=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" pay "$W1" "$INV" 50000 0 "$(bcli getblockcount)"); [[ "$P" == *":STATUS :OK"* ]] || fail "pay: $P"
B1=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$L1" balance "$W1"); [[ "$B1" == *":BALANCE 3050000"* ]] || fail "balance after pay: $B1"; echo "   w1 paid 50000 msat over Lightning: $B1"
RW=~/workspace/deposits-rust/target/release/deposits-wallet; if [ -x "$RW" ]; then
  export WALLET_DATA_DIR=/tmp/refwallet-smoke; rm -rf "$WALLET_DATA_DIR"; unset WALLET_SEED
  REFDEP=$(timeout 120 $RW open "$L1" --alias sm --relay $RELAY_URL --network signet 2>&1 | grep -q "created" && echo ok); [ "$REFDEP" = ok ] || fail "reference wallet open"
  RD=$(python3 -c "import json,hashlib; d=json.load(open('$WALLET_DATA_DIR/deposits.json'))[0]; print(d['deposit_id'])")
  expect "$(cld_ctl cld1 "(:credit :ledger \"$L1\" :deposit \"$RD\" :msat 200000 :txid \"$TXID\" :vout $VOUT)")"
  INV2=$(ln_cli cln3 invoice 20000 "refpay-$RANDOM" "ref pays" | python3 -c "import json,sys; print(json.load(sys.stdin)['bolt11'])")
  timeout 180 $RW pay_invoice sm "$INV2" --relay $RELAY_URL --network signet 2>&1 | grep -iE "succeeded|preimage|paid" | head -2 | sed 's/^/   /' || fail "reference pay_invoice"
  RB=$(timeout 120 $RW balance --relay $RELAY_URL --network signet 2>&1 | grep -E "sm .*sats" | head -1); echo "   reference wallet: $RB"
fi
fi   # CLD_NO_LN

step "11 dispute: cld1 equivocates; members fork, arm, confiscate the reserves on chain, reveal, and the lottery winner claims custody"
cld_ctl cld1 "(:equivocate :ledger \"$L1\")" >/dev/null; sleep 3
for n in cld2 cld3 cld4; do F=$(cld_ctl $n "(:forks :ledger \"$L1\")"); [[ "$F" == *":STATE :DISPUTED"* ]] || fail "$n did not fork: $F"; done
echo "   members detected the equivocation and forked"
for n in cld2 cld3 cld4; do   # each armer pledges replacement collateral from its own wallet (DEP-06)
  CA=$(sx "$(cld_ctl $n "(:address)")" ":ADDRESS"); CTX=$(wcli sendtoaddress "$CA" 0.01); mine 1
  CV=$(bcli getrawtransaction "$CTX" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$CA'][0])")
  expect "$(cld_ctl $n "(:arm :ledger \"$L1\" :txid \"$CTX\" :vout $CV :sats 1000000)")"
done; sleep 2
CONF=$(cld_ctl cld2 "(:confiscate :ledger \"$L1\" :fee 1000)"); expect "$CONF"; CTXID=$(sx "$CONF" ":TXID"); LOTTERY=$(sx "$CONF" ":LOTTERY")
mine 1; C=$(bcli gettxout "$CTXID" 0 | python3 -c "import json,sys; j=json.load(sys.stdin); print(j['confirmations'], j['scriptPubKey']['address'])"); [[ "$C" == "1 $LOTTERY" ]] || fail "confiscation not confirmed to the lottery output: $C"
echo "   confiscation $CTXID confirmed into lottery output $LOTTERY"
for n in cld2 cld3 cld4; do cld_ctl $n "(:reveal :ledger \"$L1\")" >/dev/null; done; sleep 2
WON=""; for n in cld2 cld3 cld4; do R=$(cld_ctl $n "(:claim :ledger \"$L1\")"); expect "$R"; [[ "$R" == *":OUTCOME :WON"* ]] && { WON=$n; CLAIM=$(sx "$R" ":TXID"); }; done
[ -n "$WON" ] || fail "no winner"; mine 1
K=$(bcli getrawtransaction "$CLAIM" true | python3 -c "import json,sys; t=json.load(sys.stdin); print(t.get('confirmations',0), t['vin'][0]['txid'])"); [[ "$K" == "1 $CTXID" ]] || fail "claim not confirmed: $K"
echo "   $WON won the lottery; claim $CLAIM confirmed, spending the lottery output"
echo; echo "SMOKE OK"
