#!/usr/bin/env bash
# devnet/cld-wallet.sh WALLETNAME LEDGER ACTION ARGS...   (keys under $CLD_ROOT/wallets/)
source "$(dirname "$0")/_common.sh"
mkdir -p "$CLD_ROOT/wallets"; name=$1; shift
cd "$CLD_SRC" && CLD_RELAYS="$RELAY_URL" CL_SOURCE_REGISTRY="(:source-registry (:tree \"$CLD_SRC\") :inherit-configuration)" \
  sbcl --noinform --non-interactive --load bin/cl-deposits-wallet.lisp -- "$CLD_ROOT/wallets/$name.key" "$@" 2>&1 | grep -E "^\("
