#!/usr/bin/env bash
# devnet/mixed.sh — two implementations in each other's quorums on the signet
# devnet, the way the Lightning devnet mixes cl-payments with CLN and LND.
#
#   ledger A: cld1 operates; members cld2, cld3, ref2            (Q=3, a reference cosigner)
#   ledger B: ref2 operates; members cld2, cld3, ref3            (Q=3, two cl-deposits cosigners)
#
# (One reference member on A, not two: two reference daemons reacting to the
# same equivocation both call bitcoind's scantxoutset for their collateral, the
# loser arms without it and never re-arms, and then no reference member will
# sign any confiscation.  See UPSTREAM-NOTES.md.)
#
# Then deposits and transfers on both, from both wallets, and an equivocation
# on A that the reference members must detect and dispute alongside ours.
# Requires devnet/up.sh (relay, esplora shim, cld1..4) and the reference build.
source "$(dirname "$0")/_common.sh"
set -e
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { local reply=$1; case "$reply" in *":STATUS :OK"*) echo "   $reply";; *) fail "$reply";; esac; }
refwallet() { timeout 180 "$REF_WALLET_BIN" "$@" --relay "$RELAY_URL" --network "$CLD_CHAIN" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -vE '^\S*(INFO|WARN|ERROR)|^\[' ; }
ref_members() {   # ref_members REFNODE LEDGER — member lines of that ledger's block in `quorum list`, and nothing from the next block
  ref_cli "$1" quorum list | awk -v l="$(echo "$2" | cut -c1-16)" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'
}
retry_add() {   # retry_add REFNODE LEDGER MEMBER MEMBER_LEDGER — the reference CLI sometimes times out on its own daemon
  local n=$1 l=$2 m=$3 ml=$4 i
  for i in 1 2 3 4; do
    ref_cli "$n" quorum add "$l" "$m" "$ml" >/dev/null 2>&1 || true
    ref_members "$n" "$l" | grep -q "$(echo "$m" | cut -c1-16)" && return 0
    sleep 5
  done
  return 1
}
export WALLET_DATA_DIR="${WALLET_DATA_DIR:-/tmp/refwallet-mixed-$$}"; rm -rf "$WALLET_DATA_DIR"; unset WALLET_SEED

step "1  nodes"
for n in $(cld_names); do cld_running "$n" || fail "$n not running (devnet/up.sh)"; done
for n in $(ref_names); do ref_running "$n" || start_ref "$n" || fail "$n did not start"; done
P1=$(cld_pubkey cld1); P2=$(cld_pubkey cld2); P3=$(cld_pubkey cld3)
R2=$(ref_pubkey ref2); R3=$(ref_pubkey ref3); [ -n "$R2" ] && [ -n "$R3" ] || fail "reference identities"
echo "   cld1 $P1"; echo "   cld2 $P2"; echo "   cld3 $P3"; echo "   ref2 $R2"; echo "   ref3 $R3"
for n in $(ref_names); do   # replacement collateral for disputes lives at the reference's operator-key address
  CA=$(env $(ref_env) RUST_LOG=error "$REF_NODE_BIN" pubkey-to-p2wpkh --network "$CLD_CHAIN" --seed-file "$(ref_dir "$n")/seed.hex" --data-dir "$(ref_dir "$n")" 2>&1 | grep -oE '(tb1|bcrt1)[0-9a-z]+' | head -1)
  wcli sendtoaddress "$CA" 0.01 >/dev/null; echo "   $n collateral address $CA funded"
done
CA2=$(sx "$(cld_ctl cld2 "(:address)")" ":ADDRESS"); CTX2=$(wcli sendtoaddress "$CA2" 0.01)
CA3=$(sx "$(cld_ctl cld3 "(:address)")" ":ADDRESS"); CTX3=$(wcli sendtoaddress "$CA3" 0.01); mine 1
CVOUT2=$(bcli getrawtransaction "$CTX2" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$CA2'][0])")
CVOUT3=$(bcli getrawtransaction "$CTX3" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$CA3'][0])")
echo "   cld2 collateral $CTX2:$CVOUT2, cld3 collateral $CTX3:$CVOUT3 (1000000 sats each)"

step "2  every node has a ledger of its own"
A=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:mixed:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 30000000000)")" ":LEDGER")
L2=$(sx "$(cld_ctl cld2 "(:open-ledger :reserves-id \"genesis:cld2:$RANDOM\")")" ":LEDGER")
L3=$(sx "$(cld_ctl cld3 "(:open-ledger :reserves-id \"genesis:cld3:$RANDOM\")")" ":LEDGER")
RL2=$(ref_ledger ref2); [ -n "$RL2" ] || RL2=$(ref_cli ref2 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p')
RL3=$(ref_ledger ref3); [ -n "$RL3" ] || RL3=$(ref_cli ref3 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p')
[ -n "$A" ] && [ -n "$L2" ] && [ -n "$L3" ] && [ -n "$RL2" ] && [ -n "$RL3" ] || fail "ledger open"
echo "   A (cld1) $A"

step "3  A's quorum: cld2, cld3, ref2 consent over the relay"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$A\" :member \"$P2\" :member-ledger \"$L2\")")"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$A\" :member \"$P3\" :member-ledger \"$L3\")")"
expect "$(cld_ctl cld1 "(:add-member :ledger \"$A\" :member \"$R2\" :member-ledger \"$RL2\")")"
ref_cli ref2 quorum list | grep -q "$(echo "$A" | cut -c1-16)" || fail "ref2 does not list A"
echo "   ref2 serves on A"

step "4  fund A's reserves; QuorumBegin cosigned by the reference member"
PREP=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$A\" :expiry-blocks 4320)"); expect "$PREP"; ADDR=$(sx "$PREP" ":ADDRESS")
TXID=$(wcli sendtoaddress "$ADDR" 0.5); mine 3
VOUT=$(bcli getrawtransaction "$TXID" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$ADDR'][0])")
sleep 20   # the reference wallets sync through the shim on a timer
expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$A\" :txid \"$TXID\" :vout $VOUT :sats 20000000 :collateral-sats 30000000)")"
[[ "$(cld_ctl cld1 "(:info)")" == *":QUORUM :ACTIVE"* ]] || fail "A not active"
grep -q "cosign_update, ledger=$(echo "$A" | cut -c1-16)" "$(ref_dir ref2)/node.log" || fail "ref2 did not cosign A"
echo "   the reference member cosigned"

step "5  deposits on A from both wallets; transfers both ways"
W1=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$A" open)" ":DEPOSIT"); W2=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" w2 "$A" open)" ":DEPOSIT")
expect "$(cld_ctl cld1 "(:credit :ledger \"$A\" :deposit \"$W1\" :msat 5000000 :txid \"$TXID\" :vout $VOUT)")"
H=$(bcli getblockcount); T=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$A" transfer "$W1" "$W2" 2000000 "$H"); TID=$(sx "$T" ":TRANSFER"); PRE=$(sx "$T" ":PREIMAGE"); [ -n "$TID" ] || fail "transfer: $T"
"$CLD_SRC/devnet/cld-wallet.sh" w1 "$A" complete "$TID" "$PRE" | grep -q ":STATUS :OK" || fail "complete"
B2=$("$CLD_SRC/devnet/cld-wallet.sh" w2 "$A" balance "$W2"); [[ "$B2" == *":BALANCE 2000000"* ]] || fail "w2 balance: $B2"; echo "   cl wallet -> cl wallet on A: w2 $B2"
refwallet open "$A" --alias ma | grep -q "created" || fail "reference wallet open on A"
RA=$(python3 -c "import json; print([d['deposit_id'] for d in json.load(open('$WALLET_DATA_DIR/deposits.json')) if d['alias']=='ma'][0])")
expect "$(cld_ctl cld1 "(:credit :ledger \"$A\" :deposit \"$RA\" :msat 3000000 :txid \"$TXID\" :vout $VOUT)")"
expect "$(cld_ctl cld1 "(:advertise :ledger \"$A\")")"; sleep 2
refwallet send ma 1000 --to "$W2" | grep -q "Sent 1000 sats" || fail "reference wallet send on A"
B2=$("$CLD_SRC/devnet/cld-wallet.sh" w2 "$A" balance "$W2"); [[ "$B2" == *":BALANCE 3000000"* ]] || fail "w2 after reference send: $B2"
echo "   reference wallet -> cl wallet on A: w2 $B2"

step "6  ledger B: ref2 operates; cld2, cld3, ref3 cosign"
B=$(ref_cli ref2 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$B" ] || fail "ref2 ledger open"; echo "   B (ref2) $B"
retry_add ref2 "$B" "$P2" "$L2" || fail "add cld2 to B"; retry_add ref2 "$B" "$P3" "$L3" || fail "add cld3 to B"; retry_add ref2 "$B" "$R3" "$RL3" || fail "add ref3 to B"
[ "$(ref_members ref2 "$B" | wc -l)" -eq 3 ] || fail "B does not have three members: $(ref_members ref2 "$B" | tr '\n' ' ')"
ref_begin_quorum ref2 "$B" 0.5 || fail "quorum begin on B"; sleep 8
INFO=$(cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$B\"[^)]*\)"); [[ "$INFO" == *":QUORUM :ACTIVE :MEMBERS 3"* ]] || fail "B not active on cld2: $INFO"
[[ "$INFO" == *":COLLATERAL 0 "* ]] && fail "B has no collateral: $INFO"
echo "   B active on our replicas: $(echo "$INFO" | grep -oE ':RESERVES [0-9]+ :COLLATERAL [0-9]+')"
D=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$B" open)" ":DEPOSIT"); [ -n "$D" ] || fail "w1 open on B"
ref_cli ref2 deposit credit "$B" "$D" 5000000 "mixed-$RANDOM" | grep -q "New balance" || fail "credit on B"
refwallet open "$B" --alias mb | grep -q "created" || fail "reference wallet open on B"
RB=$(python3 -c "import json; print([d['deposit_id'] for d in json.load(open('$WALLET_DATA_DIR/deposits.json')) if d['alias']=='mb'][0])")
H=$(bcli getblockcount); T=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$B" transfer "$D" "$RB" 2000000 "$H" 4002); TID=$(sx "$T" ":TRANSFER"); PRE=$(sx "$T" ":PREIMAGE"); [ -n "$TID" ] || fail "transfer on B: $T"
"$CLD_SRC/devnet/cld-wallet.sh" w1 "$B" complete "$TID" "$PRE" | grep -q ":STATUS :OK" || fail "complete on B"
BD=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$B" balance "$D"); [[ "$BD" == *":BALANCE 3000000"* ]] || fail "w1 on B: $BD"
refwallet balance | grep -E ' mb ' | grep -q '2000 sats' || fail "reference wallet balance on B"
echo "   cl wallet -> reference wallet through the reference operator: w1 $BD, mb 2000 sats"

step "7  cld1 equivocates on A: every member, both implementations, must dispute"
cld_ctl cld1 "(:equivocate :ledger \"$A\")" >/dev/null; sleep 12
F=$(cld_ctl cld2 "(:forks :ledger \"$A\")"); [[ "$F" == *":STATE :DISPUTED"* || "$F" == *":STATE :ARMED"* ]] || fail "cld2 did not fork: $F"
[[ "$F" == *"$(echo "$R2" | cut -c1-16)"* ]] || fail "reference fork not replicated on cld2: $F"
echo "   cld2 replicates its own fork, cld3's, and the reference member's"
expect "$(cld_ctl cld2 "(:arm :ledger \"$A\" :txid \"$CTX2\" :vout $CVOUT2 :sats 1000000)")"
expect "$(cld_ctl cld3 "(:arm :ledger \"$A\" :txid \"$CTX3\" :vout $CVOUT3 :sats 1000000)")"


# The reference daemon arms on its own, pledging the UTXO at its operator-key address.
for i in $(seq 1 18); do
  if grep -q "Auto-arm replacement collateral" "$(ref_dir ref2)/node.log" && \
     [ "$(cld_ctl cld2 "(:forks :ledger \"$A\")" | grep -oE ":OPERATOR \"$(echo "$R2" | cut -c1-16)\"[^)]*:STATE :ARMED" | wc -l)" -ge 1 ]; then break; fi
  sleep 10
done
F=$(cld_ctl cld2 "(:forks :ledger \"$A\")"); echo "   forks on cld2: $F" | cut -c1-300
echo "$F" | grep -oE "\(:OPERATOR \"$(echo "$R2" | cut -c1-16)\"[^)]*\)" | grep -q ":STATE :ARMED" || fail "the reference member did not arm"
grep -q "Auto-arm replacement collateral" "$(ref_dir ref2)/node.log" || fail "the reference member armed without replacement collateral"
echo "   the reference member armed with replacement collateral"
# The reference proposes the confiscation and collects tier-0 signatures (3 of 4 voters: itself, cld2, cld3).
# Wait for the reserves outpoint to be spent on chain.
CONF=""
for i in $(seq 1 30); do
  mine 1
  if [ "$(bcli gettxout "$TXID" "$VOUT" 2>/dev/null | wc -c)" -le 1 ]; then CONF=1; break; fi
  sleep 10
done
sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir ref2)/node.log" | grep -E "$(echo "$A" | cut -c1-16)" | grep -iE "confiscation|broadcast|signature|Refusing" | tail -4 | sed "s/^/     ref2: /" | cut -c1-200
for n in cld2 cld3; do cld_ctl $n "(:log)" | grep -oE '(signed confiscation|refused confiscation_sign)[^"]*' | tail -2 | sed "s/^/     $n: /" | cut -c1-200; done
[ -n "$CONF" ] || fail "reserves outpoint $TXID:$VOUT still unspent: no confiscation reached the chain"
echo "   reserves outpoint spent: a confiscation is on chain"
# Reveals and the claim: ours by command, theirs on their own once its entropy block passes (so keep mining).
expect "$(cld_ctl cld2 "(:reveal :ledger \"$A\")")"; expect "$(cld_ctl cld3 "(:reveal :ledger \"$A\")")"
for i in $(seq 1 24); do mine 1; N=$(cld_ctl cld2 "(:reveals :ledger \"$A\")" | grep -oE '"[0-9a-f]{66}"' | wc -l); if [ "$N" -ge 3 ]; then break; fi; sleep 10; done
[ "$N" -ge 3 ] || { sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir ref2)/node.log" | grep -iE 'reveal|entropy|lottery' | tail -4 | sed 's/^/     ref2: /' | cut -c1-200; fail "only $N of 3 reveals reached cld2"; }
echo "   all three reveals held by cld2 (one of them the reference member's)"
WON=""; for n in cld2 cld3; do R=$(cld_ctl $n "(:claim :ledger \"$A\")"); expect "$R"; [[ "$R" == *":OUTCOME :WON"* ]] && WON=$n; done
mine 1; sleep 20
sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir ref2)/node.log" | grep -E "$(echo "$A" | cut -c1-16)" | grep -iE 'winner|claim|acquire|yield|lottery' | tail -4 | sed 's/^/     ref2: /' | cut -c1-200
if [ -n "$WON" ]; then echo "   $WON won the lottery and claimed custody"; else echo "   our members yielded: the reference member is the winner"; fi
echo; echo "MIXED OK"
