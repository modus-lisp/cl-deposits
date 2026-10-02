#!/usr/bin/env python3
"""Enclave-attested seats as a trust root (docs/TRUST-MODEL.md §2i).

Operators are attested (key sealed in an enclave running a reproducible, policy-enforcing
image) with probability ATT, split evenly over V vendors, or unattested.  An attested key
on an intact vendor cannot sign a theft, whoever owns it.  Vendors break whole: when
vendor v is broken, every v-attested coalition key is a free agent again.

Seating: each quorum has A attested seats with at most CAP from any one vendor, and Q-A
seats drawn from anyone.  The coalition is a fraction p of operators, uniform over
attestation status.  Effective bad keys = coalition keys that are unattested or on a
broken vendor; the attacker and DEP-19 §6 cascade are seating_sim.best_attack, vault
weight 1.  Output: largest p unprofitable in >= 95% of trials.
"""
import random, sys
import seating_sim as s

Q, NEED, V = 7, 4, 3

def build(n, l, p, att, A, cap, broken, rng):
    vendor = {k: (rng.randrange(V) if rng.random() < att else None) for k in range(n)}
    coal = set(rng.sample(range(n), round(p * n)))
    bad = {k for k in coal if vendor[k] is None or vendor[k] in broken}
    quorum = {}
    for o in range(n):
        for j in range(l):
            seats, per = [], [0] * V
            pool = [k for k in range(n) if k != o and vendor[k] is not None]
            rng.shuffle(pool)
            for k in pool:
                if len(seats) == A: break
                if per[vendor[k]] < cap: seats.append(k); per[vendor[k]] += 1
            rest = [k for k in range(n) if k != o and k not in seats]
            seats += rng.sample(rest, Q - len(seats))
            quorum[(o, j)] = seats
    weight = {led: 1.0 for led in quorum}
    return bad, quorum, weight

def max_safe(n, l, r, att, A, cap, broken, trials, rng, safe=0.95):
    best = 0.0
    for pp in range(0, 100, 3):
        p = pp / 100
        prof = sum(s.best_attack(n, l, r, *build(n, l, p, att, A, cap, broken, random.Random(rng.random()))) > 1e-9
                   for _ in range(trials))
        if prof / trials <= 1 - safe: best = p
        else: break
    return best

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    l, att = 3, 0.8
    rng = random.Random(20261002)
    worlds = [("no attestation", 0, 0), ("4 attested, <=2/vendor", 4, 2),
              ("6 attested, <=2/vendor", 6, 2), ("7 attested, <=3/vendor", 7, 3)]
    print(f"max safe coalition fraction p (>= 95% of {trials} trials), N={n}, Q=7, L={l}, "
          f"{int(att*100)}% of operators attested over {V} vendors")
    print(f"{'seating':24s} {'broken':>6s}   " + "  ".join(f"R={r:.1f}" for r in (0.5, 0.6, 0.7, 0.8, 0.9)))
    for name, A, cap in worlds:
        for broken in ([()] if A == 0 else [(), (0,), (0, 1)]):
            cells = [max_safe(n, l, r, att, A, cap, set(broken), trials, rng) for r in (0.5, 0.6, 0.7, 0.8, 0.9)]
            print(f"{name:24s} {len(broken):6d}   " + "  ".join(f"{x:5.2f}" for x in cells)); sys.stdout.flush()
