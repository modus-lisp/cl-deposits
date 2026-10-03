#!/usr/bin/env bash
# redteam/attack-fuzz-proofs.sh — malformed fraud proofs (redteam/fuzz-proofs.lisp) at a soak
# ledger's members, from a throwaway key.  PASS = every cl node still answers afterwards and no
# member of the target holds a new fork of it.   redteam/attack-fuzz-proofs.sh [LETTER]  (default D)
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
T=${1:-D}
read -r TID OP < <(awk -F'\t' -v t="$T" '$1==t{print $2, $3}' "$S/ledgers.tsv")
[ -n "$TID" ] || fail "no soak ledger $T"
OPK=$(pubkey_of $OP)
forks() { local n c=0; for n in cld1 cld2 cld3 cld4 cld5 cld6; do c=$((c + $(cld_ctl $n "(:forks :ledger \"$TID\")" 2>/dev/null | grep -o ":SEQ" | wc -l))); done; echo $c; }
before=$(forks)
echo "== fuzzing $T ($TID, operator $OP): forks before $before"
CLD_RELAYS="$RELAY_URL" timeout 600 "${CLD_SBCL:-/usr/bin/sbcl}" --non-interactive --load "$CLD_SRC/redteam/fuzz-proofs.lisp" -- "$TID" "$OPK" 2>&1 | tail -5
sleep 20
down=""; for n in cld1 cld2 cld3 cld4 cld5 cld6; do cld_ctl $n '(:info)' 2>/dev/null | grep -q ":STATUS :OK" || down="$down $n"; done
after=$(forks)
[ -z "$down" ] || fail "not answering after the fuzz:$down"
[ "$after" -le "$before" ] || fail "new forks of $T: $before -> $after"
echo "PASS: every cl node answers and nobody forked $T over malformed proofs."
