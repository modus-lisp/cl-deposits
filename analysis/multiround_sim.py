#!/usr/bin/env python3
"""Does the re-entry floor rate-limit repeated collusion? (docs/TRUST-MODEL.md §2g)

The single-shot models (§2a-2f) let a coalition strike once.  Here the same network runs
for H rounds.  A key exposed in a theft is confiscated: its stake-blocks reset, so it is
ineligible for FLOOR rounds, and re-entering costs lambda again.  While a key cools it can
neither help capture a quorum nor be slashed (it is already gone).

Two coalition strategies, same network:
  all-in     strike everything in round 1; burnt keys never recover inside the horizon.
  rotate     each round, strike only with currently-eligible keys, trying to bleed steadily.

We report cumulative net per strategy against the floor, for a coalition just above the
single-shot safety boundary.  If the floor binds, cumulative net ~ single-shot (one strike
per floor); if it does not, a short floor lets a coalition bleed without end.
"""
import random, sys
sys.path.insert(0, 'analysis')
import seating_sim as s
Q, NEED = s.Q, s.NEED

def round_attack(l, r, bad_elig, quorum, weight):
    """all-in over the currently-eligible coalition keys: capture every quorum with NEED of
    them, pay the DEP-19 §6 cascade through eligible keys only.  Returns (net, exposed set)."""
    c = 1.0 - r
    hm = {led: sum(1 for m in mem if m in bad_elig) >= NEED for led, mem in quorum.items()}
    # honest-majority here means "fewer than NEED eligible coalition members"
    honest_maj = {led: sum(1 for m in mem if m in bad_elig) < NEED for led, mem in quorum.items()}
    gain = 0.0; signers = set()
    for (o, j), mem in quorum.items():
        members = sorted(m for m in mem if m in bad_elig)
        if len(members) >= NEED:
            gain += (r if o in bad_elig else 1.0) * weight[(o, j)]; signers.update(members[:NEED])
    seen = set(signers); todo = list(signers); cost = 0.0
    while todo:
        k = todo.pop()
        for j in range(l):
            if honest_maj[(k, j)]: cost += c * weight[(k, j)]
            else:
                for m in quorum[(k, j)]:
                    if m in bad_elig and m not in seen: seen.add(m); todo.append(m)
    return gain - cost, seen

def horizon(n, l, p, r, floor, strategy, H, lam, rng):
    bad, quorum, weight = s.build(n, l, p, 0.10, "guidance", "comply", 1, -1, rng, layout=(2, 4, 1))
    cooldown = {k: 0 for k in bad}; total = 0.0
    for t in range(H):
        elig = {k for k in bad if cooldown[k] == 0}
        if strategy == "all-in" and t > 0:
            pass  # struck in round 0; nothing re-enters (burnt keys stay down the horizon)
        net, exposed = round_attack(l, r, elig, quorum, weight)
        if net > 1e-9:
            total += net
            for k in exposed:
                cooldown[k] = floor
                total -= lam                      # re-entry after the floor costs lambda again
        for k in cooldown:
            if cooldown[k] > 0: cooldown[k] -= 1
        if strategy == "all-in":
            break
    return total

def mean_net(n, l, p, r, floor, strategy, H, lam, trials, rng):
    return sum(horizon(n, l, p, r, floor, strategy, H, lam, random.Random(rng.random()))
               for _ in range(trials)) / trials

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    rng = random.Random(20261001)
    H = 40; lam = 0.05; l, r = 3, 0.5
    p = 0.48                      # just above the single-shot boundary (~0.45): attacks are profitable
    print(f"cumulative net over H={H} rounds, 2/4/1, L={l}, R={r}, p={p}, lambda={lam}, N={n}")
    print("(single-shot net is the all-in value; rotate tests slow-bleed against the re-entry floor)")
    print(f"{'floor':>6s}   {'all-in':>8s}   {'rotate':>8s}   rotate/all-in")
    for floor in (1, 2, 5, 10, 20, H):
        a = mean_net(n, l, p, r, floor, "all-in", H, lam, trials, rng)
        b = mean_net(n, l, p, r, floor, "rotate", H, lam, trials, rng)
        ratio = b / a if abs(a) > 1e-9 else float('nan')
        print(f"{floor:6d}   {a:8.2f}   {b:8.2f}   {ratio:6.2f}"); sys.stdout.flush()


def safe_boundary(n, l, r, floor, H, lam, trials, rng, safe=0.95):
    """largest p at which the coalition's best cumulative net (rotate or all-in) is <= 0
    in >= safe of trials."""
    best = 0.0
    for pp in range(0, 91, 3):
        p = pp / 100
        prof = 0
        for _ in range(trials):
            seed = rng.random()
            a = horizon(n, l, p, r, floor, "all-in", H, lam, random.Random(seed))
            b = horizon(n, l, p, r, floor, "rotate", H, lam, random.Random(seed))
            if max(a, b) > 1e-9: prof += 1
        if prof / trials <= 1 - safe: best = p
        else: break
    return best
