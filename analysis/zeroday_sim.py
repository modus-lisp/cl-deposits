#!/usr/bin/env python3
"""A zero-day against an attestation class, with repricing (docs/TRUST-MODEL.md §2j).

Remote exploit: every key on a broken class signs for the attacker, whoever operates it,
and so does a coalition fraction p of the unattested operators.  A vault is capturable when
its quorum has >= 4 attacker-controlled seats.  The attacker is not deterred (the keys are
mostly honest operators'), so the question is how much it takes before containment.

Repricing: the first theft's UnauthorizedVaultSpend names its signers and so their classes;
nodes stop counting those classes as attested (no proof about the TEE, just a score) and
re-seat the quorums that rely on them.  Containment takes d windows to detect plus r to re-seat.

Spend cap: a vault can lose at most a fraction f per window (needs a covenant-style unvault
delay with a recovery path, e.g. BIP-345/CTV; f = 1 is Bitcoin today).  Loss per capturable
vault = min(1, f * (1 + d + r)).  The simulation measures the capturable fraction.
"""
import random, sys
import attest2_sim as a

def capturable(n, l, p, att, A, ccap, vcap, broken_fn, trials, rng):
    tot = 0.0
    for _ in range(trials):
        t = random.Random(rng.random())
        broken = broken_fn(t)
        cls = {k: (t.randrange(a.VEND * a.COMBO) if t.random() < att else None) for k in range(n)}
        unatt = [k for k in range(n) if cls[k] is None]
        coal = set(t.sample(unatt, round(p * len(unatt)))) if unatt else set()
        ctrl = coal | {k for k in range(n) if cls[k] is not None and cls[k] in broken}
        t2 = random.Random(t.random())
        quorum = seat(n, l, cls, A, ccap, vcap, t2)
        cap = sum(1 for mem in quorum.values() if sum(m in ctrl for m in mem) >= a.NEED)
        tot += cap / len(quorum)
    return tot / trials

def seat(n, l, cls, A, ccap, vcap, rng):
    quorum = {}
    for o in range(n):
        for j in range(l):
            seats, pc, pv = [], {}, {}
            pool = [k for k in range(n) if k != o and cls[k] is not None]; rng.shuffle(pool)
            for k in pool:
                if len(seats) == A: break
                c, v = cls[k], cls[k] // a.COMBO
                if pc.get(c, 0) < ccap and pv.get(v, 0) < vcap:
                    seats.append(k); pc[c] = pc.get(c, 0) + 1; pv[v] = pv.get(v, 0) + 1
            rest = [k for k in range(n) if k != o and k not in seats]
            seats += rng.sample(rest, a.Q - len(seats))
            quorum[(o, j)] = seats
    return quorum

if __name__ == "__main__":
    n, l, att, trials = 60, 3, 0.8, 200
    rng = random.Random(20261002)
    worlds = [("80% attested, random seats", 0, 7, 7), ("7 att, <=1/platform, <=3/vendor", 7, 1, 3)]
    breaks = [("1 platform", a.combos(1)), ("2 platforms", a.combos(2)), ("1 vendor", a.vendor()),
              ("1 vendor + 1 platform", a.vendor_plus_combo()),
              ("2 vendors", lambda t: set(range(2 * a.COMBO)))]
    print(f"share of vaults capturable by a zero-day (remote exploit), N={n}, L={l}, {trials} trials")
    print(f"{'world':32s} {'broken':22s} {'p=0':>6s} {'p=0.2':>6s} {'p=0.4':>6s}")
    caps = {}
    for wn, A, cc, vc in worlds:
        for bn, fn in breaks:
            row = [capturable(n, l, p, att, A, cc, vc, fn, trials, rng) for p in (0.0, 0.2, 0.4)]
            caps[(wn, bn)] = row
            print(f"{wn:32s} {bn:22s} " + " ".join(f"{x:6.3f}" for x in row)); sys.stdout.flush()
    print()
    print("loss as share of all deposits = capturable x min(1, f*(1+d+r)); d = 1 window to detect")
    print(f"{'world, broken (p=0.2)':56s} {'f=1':>6s} " + " ".join(f"f={f},r={r}" for f in (0.1, 0.02) for r in (1, 6)))
    for (wn, bn), row in caps.items():
        c = row[1]
        cells = [c] + [c * min(1, f * (2 + r)) for f in (0.1, 0.02) for r in (1, 6)]
        print(f"{wn + ', ' + bn:56s} " + " ".join(f"{x:6.3f}" if i == 0 else f"{x:10.4f}" for i, x in enumerate(cells)))
