#!/usr/bin/env bash
# redteam/attack-vault-recovery-tier.sh — an unauthorised vault spend through a recovery tier.
#
# DEP-06 type 7 covers every script path (Tier 0-3).  A fresh cl-only ledger (6 voters) with a
# short quorum expiry; the chain is mined past expiry + 720 so its minority tier (Tier 1:
# ceil(6/2) - 1 = 2 of 6) opens, and cld1 and cld2 alone spend through it — no majority.
# Disruptive: mines ~730 blocks, which moves every devnet ledger toward its expiry.
# PASS = an honest member (cld6) reports VAULT SPEND for the ledger.  Contagion follows on
# cld1's and cld2's ledgers.  REDTEAM_RT=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
trap 'disarm :theft-sign cld2' EXIT
X=$(FORM_EXPIRY=6 form_ledger "${REDTEAM_RT:-RT}" cld1 cltv-offset-v2 cld2 cld3 cld4 cld5 cld6) || exit 1
echo "== mining past the ledger's expiry + 720 so Tier 1 opens"; mine 730 >/dev/null; sleep 10
DEST=$(sx "$(cld_ctl cld2 '(:address)')" ":ADDRESS")
echo "== ledger $X; spending at Tier 1 (minority) to $DEST"
arm :theft-sign cld2
out=$(vault_spend cld1 "$X" "$DEST" 1); expect "$out"
echo "== spent: $(sx "$out" ":TXID") with $(sx "$out" ":SIGS") signatures"
disarm :theft-sign cld2
mine 5 >/dev/null; sleep 5
accused cld6 "$X" && echo "PASS: a Tier-1 spend outside any rotation or dispute was reported." || fail "tier-1 spend not reported by cld6"
