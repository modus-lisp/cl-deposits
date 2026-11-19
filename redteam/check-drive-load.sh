#!/usr/bin/env bash
# redteam/check-drive-load.sh — an aged, overloaded holder still meets a deadline.
#
# regtest 1119-111730: cld364, picked as the honest holder in 17 of 22 scenarios, had piled up ~60
# owned dispute forks; with drive slots started three per once-a-minute pass it drove each about
# every 20 minutes (425 "not driven" warnings, worst 897 s), and rotation-post-expiry, rearm-yield
# and rearm-rust missed their windows.  This keeps that holder on purpose (DRIVE_LOAD_HOLDER,
# default cld364): it requires at least DRIVE_LOAD_MIN (40) owned forks on it, then runs
# rotation-post-expiry's rescue arm with the holder as W (PICK_W), whose deadline is W's expiry
# dispute yielding within 900 s of the rotation confirming.
#   PASS = that check passes AND the holder logged no "not driven for N s, every drive slot busy"
#          while it ran.  Reports the holder's :drive-stats before and after, its slowest drives.
#   SKIP = the holder carries fewer than DRIVE_LOAD_MIN forks: the load this measures is absent.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"
source "$(dirname "$0")/_lib.sh"
H=${DRIVE_LOAD_HOLDER:-cld364}; MIN=${DRIVE_LOAD_MIN:-40}
cld_running "$H" || start_cld "$H" >/dev/null
cld_ensure_current "$H"
stats() { cld_ctl "$H" "(:drive-stats)"; }
s0=$(stats); expect "$s0" ":drive-stats on $H"
owned=$(grep -oE ':OWNED [0-9]+' <<<"$s0" | cut -d' ' -f2); live=$(grep -oE ':LIVE [0-9]+' <<<"$s0" | cut -d' ' -f2)
echo "== holder $H: $owned owned forks, $live live"
[ "${owned:-0}" -ge "$MIN" ] || { echo "SKIP: $H owns ${owned:-0} dispute forks, fewer than DRIVE_LOAD_MIN=$MIN"; exit 0; }
M=$(date -u +%FT%T)
PICK_W=$H REDTEAM_PX=${REDTEAM_PX:-DL$RANDOM} "$(dirname "$0")/check-rotation-post-expiry.sh" rescue; rc=$?
log() { sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$H/node.log" | awk -v m="$M" '$1 >= m'; }
starved=$(log | grep -c "every drive slot busy")
worst=$(log | grep -oE "not driven for [0-9]+ s" | awk '{print $4}' | sort -n | tail -1)
echo "== $H while the check ran: $starved 'not driven' warnings${worst:+, worst ${worst} s}"
echo "== $H slowest drives:"; log | grep -oE "dispute [0-9a-f]{8}: drive took [0-9]+ ms.*" | sort -t' ' -k5 -nr | head -5 | sed 's/^/   /'
echo "== $H :drive-stats after: $(stats | tr -s ' ' | cut -c1-1500)"
[ "$rc" -eq 0 ] || fail "rotation-post-expiry (rescue) with W=$H failed (rc $rc)"
[ "$starved" -eq 0 ] || fail "$H left a live dispute undriven past ${DRIVE_STARVED:-600} s ($starved warnings, worst ${worst} s)"
echo "PASS: $H, with $owned forks ($live live), met the 900 s yield and left no dispute undriven"
