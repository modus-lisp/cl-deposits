#!/usr/bin/env python3
"""Entry cost (stake-blocks) per coalition key, charged at formation (docs/TRUST-MODEL.md §2f).

Each key must accumulate a fixed stake x time before it is eligible for seats; its
opportunity cost, lambda (a fraction of a vault), is charged to every coalition key when the
coalition forms, so it forms only if its best theft pays for all members. Pool stuffing is
not a separate dial here: an extra pool key is just another coalition key paying lambda."""
import random, sys
sys.path.insert(0, 'analysis')
import seating_sim as s

def profitable(n, l, p, r, world, layout, lam, rng):
    seed = rng.random(); best = -1e9
    owns = ("comply",) if world == "random" else ("comply", "deviate")
    for own in owns:
        bad, quorum, weight = s.build(n, l, p, 0.10, world, own, 1, -1, random.Random(seed), layout)
        # every coalition key paid the entry threshold (stake-blocks) at formation
        best = max(best, s.best_attack(n, l, r, bad, quorum, weight) - lam * len(bad))
    return best > 1e-9

def max_safe(n, l, r, world, layout, lam, trials, rng):
    b = 0.0
    for pp in range(0, 91, 3):
        p = pp / 100
        if sum(profitable(n, l, p, r, world, layout, lam, rng) for _ in range(trials)) / trials <= 0.05: b = p
        else: break
    return b

rng = random.Random(20261001)
print("max safe p with entry cost lambda (per coalition key, fraction of a vault); Q=7, N=60, dereliction, smart attacker")
print(f"{'seating':10s} {'lambda':>7s}   L=1,R=.5  L=1,R=.7  L=3,R=.5  L=3,R=.7")
for name, world, layout in (("random", "random", (2,3,2)), ("2/4/1", "guidance", (2,4,1))):
    for lam in (0.0, 0.025, 0.05, 0.10):
        cells = [max_safe(60, l, r, world, layout, lam, 50, rng) for l, r in ((1,.5),(1,.7),(3,.5),(3,.7))]
        print(f"{name:10s} {lam:7.3f}   " + "  ".join(f"{x:8.2f}" for x in cells)); sys.stdout.flush()
