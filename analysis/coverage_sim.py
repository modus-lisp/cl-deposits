#!/usr/bin/env python3
"""How collusion plays out under the defenses we have and the ones we lack.

Extends analysis/contagion_sim.py (docs/TRUST-MODEL.md §2a) to the concerns in
docs/MISSING.md.  N operators; each runs L ledgers, each ledger a vault of size 1
(reserves R, all owed to depositors; collateral C = 1 - R).  Each ledger's quorum
is Q other operators drawn at random.  A coalition holds a fraction p of the
operators (real keys; each key's whole stake, across all L of its ledgers, is real).

Attack (DEP-05 Tier 0): the coalition spends any vault whose quorum it holds a
majority (`need = Q//2 + 1`) of.  Loot is the whole vault (1.0) from an honest
operator's ledger, or just the deposits (R) from one of its own.

Cost = contagion.  An on-chain theft (DEP-06 type 7, unauthorised vault spend)
names *every* key whose signature is in the witness.  So each key that signs any
theft is exposed, and is then slashable on every ledger IT operates whose quorum
has an honest majority — once per such ledger.  This unifies operator and cosigner
contagion: a key is punished across all the ledgers it runs, not just the one it
cheated on.  Toggles:
  - contagion off: signing is free (no type 7, no NonConforming acted on).
  - full (operator contagion): a key is slashed on every honest-majority ledger it
    operates — one accusation, every vault it runs at risk.

The attacker is greedy and optimal enough for a bound: it takes every target whose
loot exceeds the *new* exposure it forces, cheapest signers first.

Output per (mode, Q, R): the largest coalition fraction p at which the attack is
unprofitable in >= SAFE of the trials.  Higher is safer.  L shifts the full-contagion
column: more ledgers per operator is more collateral at stake per exposed key.
"""
import random, sys

def trial(n, l, q, p, r, mode, rng):
    c = 1.0 - r
    need = q // 2 + 1
    bad = set(rng.sample(range(n), round(p * n)))
    # ledgers[(o,j)] = quorum (q distinct operators != o)
    others = {o: [x for x in range(n) if x != o] for o in range(n)}
    quorum = {(o, j): rng.sample(others[o], q) for o in range(n) for j in range(l)}
    honest_majority = {led: sum(1 for m in mem if m not in bad) >= need
                       for led, mem in quorum.items()}
    # ledgers each key operates that could slash it (own ledger, honest majority)
    slash_ledgers = {k: [j for j in range(l) if honest_majority[(k, j)]] for k in bad}

    exposed = set(); gain = 0.0
    targets = [(o, j) for o in range(n) for j in range(l)
               if sum(1 for m in quorum[(o, j)] if m in bad) >= need]
    for (o, j) in targets:
        members = [m for m in quorum[(o, j)] if m in bad]
        members.sort(key=lambda m: (m not in exposed, m))   # reuse already-exposed keys first
        signers = members[:need]
        loot = r if o in bad else 1.0
        if mode == "off":
            gain += loot; continue
        new = [m for m in signers if m not in exposed]
        new_cost = c * sum(len(slash_ledgers.get(m, [])) for m in new)   # type 7 names every signer
        if loot > new_cost:
            gain += loot; exposed.update(signers)
    if mode == "off":
        return gain
    cost = c * sum(len(slash_ledgers.get(k, [])) for k in exposed)
    return gain - cost

def max_safe_p(n, l, q, r, mode, trials, safe, rng):
    best = 0.0
    for pp in range(0, 61):
        p = pp / 100
        prof = sum(1 for _ in range(trials) if trial(n, l, q, p, r, mode, rng) > 1e-9)
        if prof / trials <= 1 - safe:
            best = p
        else:
            break
    return best

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    safe = 0.95
    rng = random.Random(20260930)
    rs = [0.3, 0.4, 0.5, 0.6, 0.7]
    print(f"max safe coalition fraction p (unprofitable in >= {safe:.0%} of {trials} trials, N={n})")
    for mode in ("off", "full"):
        for l in ([1] if mode == "off" else [1, 3, 5]):
            label = "no contagion" if mode == "off" else f"contagion (type 7 / DEP-19 §5), L={l} ledgers/operator"
            print(f"\n{label}")
            print("  Q   " + "  ".join(f"R={r:.1f}" for r in rs))
            for q in (3, 5, 7):
                row = [max_safe_p(n, l, q, r, mode, trials, safe, rng) for r in rs]
                print(f"  {q}   " + "  ".join(f"{x:5.2f}" for x in row))
                sys.stdout.flush()
