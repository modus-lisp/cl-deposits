#!/usr/bin/env bash
# redteam/run-all.sh — the red-team scenario suite against the live devnet (redteam/scenarios.lisp).
#   redteam/run-all.sh --list | --dry-run | [--only a,b] [--skip a,b] [--tags safe,contagion,disruptive,slow]
cd "$(dirname "$0")/.." && exec "${CLD_SBCL:-/usr/bin/sbcl}" --script redteam/scenarios.lisp -- "$@"
