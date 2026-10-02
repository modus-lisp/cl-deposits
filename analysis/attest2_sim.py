#!/usr/bin/env python3
"""Attestation classes as (vendor x platform combination): docs/TRUST-MODEL.md §2i.

A class is a vendor plus CPU family/microcode/board firmware.  Most TEE breaks hit one
class (a microcode or firmware bug); a vendor-root key compromise hits every class of
that vendor.  Seating caps attested seats per class and per vendor.  Otherwise as
attest_sim.py: an attested coalition key on an intact class cannot sign a theft.
"""
import random, sys
import seating_sim as s

Q, NEED, VEND, COMBO = 7, 4, 3, 4

def build(n, l, p, att, A, ccap, vcap, broken, rng):
    cls = {k: (rng.randrange(VEND * COMBO) if rng.random() < att else None) for k in range(n)}
    coal = set(rng.sample(range(n), round(p * n)))
    bad = {k for k in coal if cls[k] is None or cls[k] in broken}
    quorum = {}
    for o in range(n):
        for j in range(l):
            seats, pc, pv = [], {}, {}
            pool = [k for k in range(n) if k != o and cls[k] is not None]; rng.shuffle(pool)
            for k in pool:
                if len(seats) == A: break
                c, v = cls[k], cls[k] // COMBO
                if pc.get(c, 0) < ccap and pv.get(v, 0) < vcap:
                    seats.append(k); pc[c] = pc.get(c, 0) + 1; pv[v] = pv.get(v, 0) + 1
            rest = [k for k in range(n) if k != o and k not in seats]
            seats += rng.sample(rest, Q - len(seats))
            quorum[(o, j)] = seats
    return bad, quorum, {led: 1.0 for led in quorum}

def max_safe(n, l, r, att, A, ccap, vcap, broken_fn, trials, rng, safe=0.95):
    best = 0.0
    for pp in range(0, 100, 3):
        p = pp / 100
        prof = 0
        for _ in range(trials):
            t = random.Random(rng.random())
            prof += s.best_attack(n, l, r, *build(n, l, p, att, A, ccap, vcap, broken_fn(t), t)) > 1e-9
        if prof / trials <= 1 - safe: best = p
        else: break
    return best

def combos(k):   return lambda t: set(t.sample(range(VEND * COMBO), k))
def vendor(v=0): return lambda t: set(range(v * COMBO, (v + 1) * COMBO))
def vendor_plus_combo(): return lambda t: set(range(COMBO)) | {t.randrange(COMBO, VEND * COMBO)}

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    l = 3; Rs = (0.5, 0.7, 0.8, 0.9)
    rng = random.Random(20261002)
    print(f"max safe p (>= 95% of {trials} trials), N={n}, Q=7, L={l}; classes = {VEND} vendors x {COMBO} platforms")
    print(f"{'world':34s} {'broken':22s} " + "  ".join(f"R={r:.1f}" for r in Rs))
    rows = [("baseline: nobody attested", 0.0, 0, 7, 7, [("-", combos(0))]),
            ("80% attested, random seats", 0.8, 0, 7, 7, [("1 platform", combos(1)), ("1 vendor", vendor())]),
            ("7 att, <=1/platform, <=3/vendor", 0.8, 7, 1, 3,
             [("none", combos(0)), ("1 platform", combos(1)), ("2 platforms", combos(2)), ("3 platforms", combos(3)),
              ("1 vendor", vendor()), ("1 vendor + 1 platform", vendor_plus_combo())]),
            ("7 att, <=2/platform, <=3/vendor", 0.8, 7, 2, 3,
             [("1 platform", combos(1)), ("2 platforms", combos(2)), ("1 vendor", vendor())]),
            ("5 att, <=1/platform, <=2/vendor", 0.8, 5, 1, 2,
             [("1 platform", combos(1)), ("2 platforms", combos(2)), ("1 vendor", vendor())])]
    for name, att, A, cc, vc, cases in rows:
        for label, fn in cases:
            cells = [max_safe(n, l, r, att, A, cc, vc, fn, trials, rng) for r in Rs]
            print(f"{name:34s} {label:22s} " + "  ".join(f"{x:5.2f}" for x in cells)); sys.stdout.flush()
