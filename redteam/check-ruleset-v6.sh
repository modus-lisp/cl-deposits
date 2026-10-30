#!/usr/bin/env bash
# redteam/check-ruleset-v6.sh — DEP-18 balance-anchor-v6: anchor-ladder-v5's rules plus
# balance-commit-v4's MissingBalanceCommitment, so a ledger on either loses nothing by moving.
#
# Part 1: a mixed quorum (cl and reference members) seated under anchor-ladder-v5 rotates after
# fresh consents; the reference policy names balance-anchor-v6 and every cl replica moves to it.
# Then the operator stops declaring balance commitments (the :omit-commitments switch): its credit
# must find too few cosigners, cl and reference alike refusing MissingBalanceCommitment.  With the
# switch off, the same credit commits.
# Part 2: a reference operator's ledger with reference members only, seated under
# balance-commit-v4, moves to balance-anchor-v6 by QuorumUpgrade.
# PASS = both.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"
source "$(dirname "$0")/_lib.sh"
pick OP T2 T3 T4
R1=${R1:-ref6}; R2=${R2:-ref7}; R3=${R3:-ref5}; R4=${R4:-ref4}
ruleset_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$2\"[^)]*" | grep -oE ':RULESET "[^"]*"|:RULESET NIL' | head -1; }
ctl() { printf '%s\n' "$2" | timeout 300 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port $1); cat >&3; head -n1 <&3"; }

echo "== part 1: anchor-ladder-v5 -> balance-anchor-v6 by rotation, and the commitment rule"
L=$(OPEN_RULESET=anchor-ladder-v5 form_ledger "V6$RANDOM" $OP anchor-ladder-v5 $T2 $T3 $T4 $R1 $R2) || exit 1
r0=$(ruleset_of $T2 "$L"); echo "   $L before: $r0"
[ "$r0" = ':RULESET "anchor-ladder-v5"' ] || fail "$L is not under anchor-ladder-v5: $r0"
consent "$L" $OP $T2 $T3 $T4 $R1 $R2
expect "$(ctl $OP "(:rotate-vault :ledger \"$L\" :expiry-blocks 4320)")" "rotate-vault"
mine 3 >/dev/null; sleep 20
for i in 1 2 3; do r=$(ctl $OP "(:begin-quorum :ledger \"$L\")")
  case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r" | cut -c1-200; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
mine 3 >/dev/null; sleep 20
for n in $OP $T2 $T3 $T4; do
  ra=$(ruleset_of $n "$L"); echo "   $L on $n after: $ra"
  [ "$ra" = ':RULESET "balance-anchor-v6"' ] || fail "$n did not move $L to balance-anchor-v6: $ra"
done
D=$(sx "$(cld_ctl $OP "(:deposit-open :ledger \"$L\" :descriptor \"pk($(pubkey_of $T4))\")")" ":DEPOSIT")
[ -n "$D" ] || fail "open a deposit on $L"
expect "$(cld_ctl $OP '(:adversary :set :omit-commitments t)')"
bad=$(ctl $OP "(:credit :ledger \"$L\" :deposit \"$D\" :msat 100000 :txid \"$(openssl rand -hex 32)\")")
cld_ctl $OP '(:adversary :set :omit-commitments nil)' >/dev/null
echo "   credit without a commitment: $(echo "$bad" | cut -c1-200)"
case "$bad" in *":STATUS :OK"*) fail "a credit with no balance commitment committed under balance-anchor-v6";; esac
sleep 5
refused=$(cld_ctl $T2 '(:log)' 2>/dev/null | grep -ac "MISSING-BALANCE-COMMITMENT" || true)
rref=0; for x in $R1 $R2; do c=$(tail -c 2000000 "$(ref_dir $x)/node.log" 2>/dev/null | grep -ac "MissingBalanceCommitment" || true); rref=$((rref + c)); done
echo "   refusals: cl $T2 $refused, reference $rref"
[ "$refused" -ge 1 ] || fail "$T2 did not refuse the missing commitment"
[ "$rref" -ge 1 ] || fail "no reference member refused the missing commitment"
good=$(ctl $OP "(:credit :ledger \"$L\" :deposit \"$D\" :msat 100000 :txid \"$(openssl rand -hex 32)\")")
expect "$good" "the credit with its commitment"
echo "   the credit with its commitment committed"

echo "== part 2: a reference-only balance-commit-v4 ledger moves to balance-anchor-v6 by QuorumUpgrade"
RL=$(ref_cli $R1 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$RL" ] || fail "$R1 ledger open"
rmembers() { ref_cli $R1 quorum list | awk -v l="${RL:0:16}" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'; }
radd() { local i; for i in 1 2 3 4 5 6; do ref_cli $R1 quorum add "$RL" "$1" "$2" >/dev/null 2>&1 || true; rmembers | grep -q "$(echo "$1" | cut -c1-16)" && return 0; sleep 10; done; return 1; }
for m in $R2 $R3 $R4; do radd "$(pubkey_of $m)" "$(own_ledger $m)" || fail "add $m"; done
raddr=$(ref_cli $R1 ledger address "$RL" | grep -oE '(tb1|bcrt1)[0-9a-z]+' | head -1)
wcli sendtoaddress "$raddr" 0.5 >/dev/null; mine 3 >/dev/null; sleep 45
qb() { timeout 180 "$REF_NODE_BIN" quorum begin "$RL" --collateral-ratio 0.5 "$@" --network "$CLD_CHAIN" --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$(ref_dir $R1)" 2>&1 | grep -vE '^\S*\[[0-9]m|^\[2m'; }
for i in 1 2 3 4 5 6; do out=$(qb --protocol-version balance-commit-v4); echo "$out" | grep -qi 'No response' || break; mine 1 >/dev/null; sleep 15; done
echo "   quorum begin --protocol-version balance-commit-v4: $(echo "$out" | tail -1 | cut -c1-200)"
case "$out" in *rror*) fail "the balance-commit-v4 quorum begin failed: $out";; esac
mine 2 >/dev/null; sleep 20
rs_ref() { ref_cli $1 reserves list 2>/dev/null | awk -v l="$RL" '/^=== Ledger /{on=($3==l)} on && /active_ruleset:/{print $2; exit}'; }
rs_wait() { local i v; for i in $(seq 1 12); do v=$(rs_ref $1); [ "$v" = "$2" ] && break; sleep 10; done; echo "$v"; }
b=$(rs_wait $R1 balance-commit-v4); echo "   $RL on $R1 before: $b"
[ "$b" = "balance-commit-v4" ] || fail "$RL is not under balance-commit-v4 on $R1: $b"
for i in 1 2 3 4; do up=$(ref_cli $R1 quorum upgrade "$RL" balance-anchor-v6); echo "$up" | grep -qi 'committed' && break; sleep 15; done
echo "   quorum upgrade: $(echo "$up" | tail -2 | tr '\n' ' ' | cut -c1-200)"
echo "$up" | grep -qi 'committed' || fail "the QuorumUpgrade to balance-anchor-v6 failed"
sleep 20
a=$(rs_wait $R1 balance-anchor-v6); echo "   $RL on $R1 after: $a"
[ "$a" = "balance-anchor-v6" ] || fail "$R1 did not move $RL to balance-anchor-v6: $a"
# A member's replica holds the QuorumUpgrade (discriminant 45) naming balance-anchor-v6.
V6='98,97,108,97,110,99,101,45,97,110,99,104,111,114,45,118,54'
for x in $R2 $R3 $R4; do
  f="$(ref_dir $x)/wallet/ledgers/$RL.jsonl"; ok=""
  for i in $(seq 1 12); do grep -a '"message":\[0,1,45,' "$f" 2>/dev/null | grep -q "$V6" && { ok=1; break; }; sleep 10; done
  echo "   $RL on $x: ${ok:+applied the QuorumUpgrade to balance-anchor-v6}"
  [ -n "$ok" ] || fail "$x has no QuorumUpgrade to balance-anchor-v6 for $RL"
done
echo "PASS: $L moved anchor-ladder-v5 -> balance-anchor-v6 and refused a credit without its commitment; $RL moved balance-commit-v4 -> balance-anchor-v6 by QuorumUpgrade"
