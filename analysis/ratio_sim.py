#!/usr/bin/env python3
"""Collateral ratio vs. resilience (docs/TRUST-MODEL.md §2h).

Vault = deposits (R) + operator collateral (C = 1 - R).  Capital efficiency is R/C: deposits
held per unit of operator collateral.  For each R, the largest coalition fraction p whose
best attack (seating_sim.best_attack: greedy, all-in, theft-set optimisation, with the
DEP-19 §6 dereliction cascade) is unprofitable in >= 95% of trials, under random quorums and
under seating guidance (2 anchors / 4 lot / 1 vanity), at L ledgers per operator.
"""
import random, sys, time
import seating_sim as s

def row(n, l, r, world, layout, trials, rng):
    return s.max_safe(n, l, r, 0.10, world, 1, -1, trials, rng, layout=layout)

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    Rs = [float(x) for x in (sys.argv[3].split(",") if len(sys.argv) > 3 else "0.3,0.4,0.5,0.6,0.7,0.8,0.9".split(","))]
    Ls = [int(x) for x in (sys.argv[4].split(",") if len(sys.argv) > 4 else "1,3".split(","))]
    rng = random.Random(20261002)
    print(f"max safe coalition fraction p (unprofitable in >= 95% of {trials} trials), N={n}, Q=7, roots 10%")
    print("R = deposits' share of the vault; efficiency = R/(1-R) deposits per unit of collateral")
    hdr = "  R    eff  " + "  ".join(f"rand L={l}  guid L={l}" for l in Ls)
    print(hdr)
    for r in Rs:
        cells = []
        for l in Ls:
            cells.append(row(n, l, r, "random", (2, 3, 2), trials, rng))
            cells.append(row(n, l, r, "guidance", (2, 4, 1), trials, rng))
        print(f"{r:4.2f} {r/(1-r):5.2f}  " + "  ".join(f"{x:9.2f}" for x in cells)); sys.stdout.flush()
