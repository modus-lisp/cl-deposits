#!/usr/bin/env python3
"""Does contagion deter collusion, and at what capital efficiency?  (docs/TRUST-MODEL.md)

A network of N operators, each with one vault of size 1: reserves R (all owed to
depositors), collateral C = 1 - R.  Each ledger's quorum is Q other operators drawn
at random.  A coalition holds a fraction p of the operators (real keys, real vaults).

Attack (DEP-05 Tier 0): the coalition can spend any vault whose quorum it holds a
majority of.  From an honest operator's ledger it takes the whole vault (deposits and
the honest operator's collateral); from its own ledger only the deposits R (the
collateral was its own).

Cost (DEP-19 §5-6 contagion): every coalition key that signs a theft loses its own
collateral C, once, however many thefts it signs, but only if its own ledger's
quorum has an honest majority (a coalition-majority quorum will not confiscate it).
Without contagion, signing is free.

The attacker is greedy and optimal enough for a bound: it takes every capturable
target, signing each with the fewest keys needed, preferring keys that are already
exposed or not slashable.  It attacks only when the net gain is positive.

Output: for each (contagion, Q, R), the largest p at which the attack is unprofitable
in at least SAFE of the trials: the network's honesty requirement as a function of
capital efficiency (R = deposit capacity per sat locked).
"""
import random, sys

def trial(n, q, p, r, contagion, rng):
    c = 1.0 - r
    bad = set(rng.sample(range(n), round(p * n)))
    quorum = [rng.sample([j for j in range(n) if j != i], q) for i in range(n)]
    need = q // 2 + 1
    # Which coalition keys can be slashed: those whose own quorum has an honest majority.
    slashable = {k for k in bad if sum(1 for m in quorum[k] if m not in bad) >= need}
    exposed = set(); gain = 0.0
    for i in range(n):
        members = [m for m in quorum[i] if m in bad]
        if len(members) < need:
            continue
        # sign with the cheapest keys: already exposed, or unslashable, first
        members.sort(key=lambda m: (m in slashable and m not in exposed, m))
        signers = members[:need]
        loot = r if i in bad else 1.0
        new_cost = c * sum(1 for m in signers if m in slashable and m not in exposed) if contagion else 0.0
        if loot > new_cost:          # this target pays for the new exposure it needs
            gain += loot
            exposed.update(signers)
    cost = c * len(exposed & slashable) if contagion else 0.0
    return gain - cost

def max_safe_p(n, q, r, contagion, trials, safe, rng):
    best = 0.0
    for pp in range(0, 61):
        p = pp / 100
        profitable = sum(1 for _ in range(trials) if trial(n, q, p, r, contagion, rng) > 1e-9)
        if profitable / trials <= 1 - safe:
            best = p
        else:
            break
    return best

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    safe = 0.95
    rng = random.Random(20260930)
    rs = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    print(f"max safe coalition fraction p (attack unprofitable in >= {safe:.0%} of {trials} trials, N = {n})")
    print("R = reserves share of the vault = deposit capacity per sat locked")
    for contagion in (False, True):
        print(f"\ncontagion: {'on (DEP-19 §5-6)' if contagion else 'off'}")
        print("  Q   " + "  ".join(f"R={r:.1f}" for r in rs))
        for q in (3, 5, 7):
            row = [max_safe_p(n, q, r, contagion, trials, safe, rng) for r in rs]
            print(f"  {q}   " + "  ".join(f"{x:5.2f}" for x in row))
            sys.stdout.flush()
