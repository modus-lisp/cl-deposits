#!/usr/bin/env bash
# redteam/check-ruleset-undeclared.sh — DEP-18: rulesets are named, not ordered.  A QuorumBegin
# that names a ruleset one seated member did not declare is refused, by either implementation.
#
# Both implementations declare every registered ruleset, so the cl members here withhold
# balance-commit-v4 from their declarations (the :withhold-rulesets red-team switch).
# Part 1: a cl operator names balance-commit-v4 for a quorum of cl and reference members:
# begin-quorum is refused, and no member applies a QuorumBegin.
# Part 2: a reference operator names balance-commit-v4 for a quorum with cl members: refused.  The
# same ledger then rotates with no name given; the reference policy names balance-anchor-v6, which
# every member declares, and the cl members' replicas record it.
# PASS = both refusals, and the policy-named QuorumBegin.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"
source "$(dirname "$0")/_lib.sh"
pick OP T2 T3 C1 C2
R1=${R1:-ref6}; R2=${R2:-ref7}
ruleset_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$2\"[^)]*" | grep -oE ':RULESET "[^"]*"|:RULESET NIL' | head -1; }

for n in $T2 $T3 $C1 $C2; do expect "$(cld_ctl $n '(:adversary :set :withhold-rulesets ("balance-commit-v4"))')" "withhold on $n"; done
trap 'for n in $T2 $T3 $C1 $C2; do cld_ctl $n "(:adversary :set :withhold-rulesets nil)" >/dev/null 2>&1; done' EXIT
echo "== part 1: a cl operator names a ruleset its cl members did not declare"
L=$(sx "$(cld_ctl $OP "(:open-ledger :reserves-id \"genesis:$OP:undeclared:$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER")
[ -n "$L" ] || fail "open ledger"
consent "$L" $OP $T2 $T3 $R2 >&2
prep=$(cld_ctl $OP "(:prepare-quorum :ledger \"$L\" :expiry-blocks 4320 :ruleset \"balance-commit-v4\")"); expect "$prep" "prepare-quorum"
addr=$(sx "$prep" ":ADDRESS"); txid=$(wcli sendtoaddress "$addr" 0.5); mine 3 >/dev/null
vout=$(outpoint_vout "$txid" "$addr")
r=$(cld_ctl $OP "(:begin-quorum :ledger \"$L\" :txid \"$txid\" :vout $vout :sats 25000000 :collateral-sats 25000000)")
echo "   begin-quorum: $r" | cut -c1-220
case "$r" in *":STATUS :OK"*) fail "a QuorumBegin naming an undeclared ruleset committed";; esac
case "$r" in *"did not declare"*|*"RULESET-UNSUPPORTED"*|*"ruleset_unsupported"*) ;; *) fail "refused, but not for the undeclared ruleset: $r";; esac
sleep 10
for n in $T2 $T3; do
  cld_ctl $n "(:info)" | grep -qE "\(:ID \"$L\"[^)]*:QUORUM :ACTIVE" && fail "$n applied the refused QuorumBegin"
done
echo "   refused; no cl member applied it"

echo "== part 2: a reference operator names a ruleset its cl members did not declare"
RL=$(ref_cli $R1 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$RL" ] || fail "$R1 ledger open"
rmembers() { ref_cli $R1 quorum list | awk -v l="${RL:0:16}" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'; }
radd() { local i; for i in 1 2 3 4 5 6; do ref_cli $R1 quorum add "$RL" "$1" "$2" >/dev/null 2>&1 || true; rmembers | grep -q "$(echo "$1" | cut -c1-16)" && return 0; sleep 10; done; return 1; }
for m in $C1 $C2; do radd "$(pubkey_of $m)" "$(own_ledger $m)" || fail "add $m"; done
radd "$(pubkey_of $R2)" "$(own_ledger $R2)" || fail "add $R2"
raddr=$(ref_cli $R1 ledger address "$RL" | grep -oE '(tb1|bcrt1)[0-9a-z]+' | head -1)
wcli sendtoaddress "$raddr" 0.5 >/dev/null; mine 3 >/dev/null; sleep 45
qb() { timeout 180 "$REF_NODE_BIN" quorum begin "$RL" --collateral-ratio 0.5 "$@" --network "$CLD_CHAIN" --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$(ref_dir $R1)" 2>&1 | grep -vE '^\S*\[[0-9]m|^\[2m'; }
out=$(qb --protocol-version balance-commit-v4); echo "   quorum begin --protocol-version balance-commit-v4: $(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-220)"
echo "$out" | grep -qiE 'support|declare' || fail "the reference operator did not refuse the undeclared ruleset"
for n in $C1 $C2; do
  cld_ctl $n "(:info)" | grep -qE "\(:ID \"$RL\"[^)]*:QUORUM :ACTIVE" && fail "$n applied a balance-commit-v4 QuorumBegin"
done
echo "   refused"
for i in 1 2 3 4 5 6; do out=$(qb); echo "$out" | grep -qi 'No response' || break; mine 1 >/dev/null; sleep 15; done
echo "   quorum begin (policy): $(echo "$out" | tail -1 | cut -c1-200)"
case "$out" in *rror*) fail "the policy-named quorum begin failed: $out";; esac
await_active "$RL" $C1 $C2
for n in $C1 $C2; do
  ra=$(ruleset_of $n "$RL"); echo "   $RL on $n: $ra"
  [ "$ra" = ':RULESET "balance-anchor-v6"' ] || fail "$n records $ra, not balance-anchor-v6"
done
echo "PASS: both implementations refused a QuorumBegin naming a ruleset a seated member did not declare; the policy named balance-anchor-v6"
