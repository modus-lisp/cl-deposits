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

The attacker takes the best of three strategies: all-in (every capturable vault),
the myopic per-target greedy, and repeated cheapest-incremental greedy passes (a key
exposed by one theft is free for the next).  That is still a lower bound on the
optimal attack, so every safety number here is an upper bound.  (An earlier version
used only the myopic greedy, which never paid a key's up-front exposure and so
overstated safety, most at large L: 0.55 at Q=7, R=0.5, L=5, against ~0.30 here.)

Output per (mode, Q, R): the largest coalition fraction p at which the attack is
unprofitable in >= SAFE of the trials.  Higher is safer.  L shifts the full-contagion
column: more ledgers per operator is more collateral at stake per exposed key.
"""
import random, sys

def network(n, l, q, p, rng):
    need = q // 2 + 1
    bad = set(rng.sample(range(n), round(p * n)))
    others = {o: [x for x in range(n) if x != o] for o in range(n)}
    quorum = {(o, j): rng.sample(others[o], q) for o in range(n) for j in range(l)}
    hm = {led: sum(1 for m in mem if m not in bad) >= need for led, mem in quorum.items()}
    return need, bad, quorum, hm

def attack(n, l, need, bad, quorum, hm, r, contagion):
    """The coalition's best net gain over several strategies (a lower bound on the
    optimum, so the safety numbers it yields are an upper bound).  A key, once
    exposed, is free for further thefts: it is slashed once per ledger it runs."""
    c = 1.0 - r
    cost_of = {k: (c * sum(1 for j in range(l) if hm[(k, j)]) if contagion else 0.0) for k in bad}
    targets = []
    for (o, j), mem in quorum.items():
        members = [m for m in mem if m in bad]
        if len(members) >= need:
            targets.append((r if o in bad else 1.0, members))

    def run(order_key, passes):
        exposed = set(); gain = 0.0; taken = set()
        for _ in range(passes):
            changed = False
            for idx in sorted(range(len(targets)), key=lambda i: order_key(i, exposed)):
                if idx in taken: continue
                loot, members = targets[idx]
                signers = sorted(members, key=lambda m: (0.0 if m in exposed else cost_of[m]))[:need]
                inc = sum(cost_of[m] for m in signers if m not in exposed)
                if loot > inc:
                    taken.add(idx); gain += loot; exposed.update(signers); changed = True
            if not changed: break
        return gain - sum(cost_of[k] for k in exposed)

    def inc_cost(i, exposed):
        loot, members = targets[i]
        signers = sorted(members, key=lambda m: (0.0 if m in exposed else cost_of[m]))[:need]
        return sum(cost_of[m] for m in signers if m not in exposed) - loot

    # all-in: every capturable target, cheapest signers
    exposed = set(); gain = 0.0
    for loot, members in targets:
        exposed.update(sorted(members, key=lambda m: (0.0 if m in exposed else cost_of[m]))[:need])
        gain += loot
    allin = gain - sum(cost_of[k] for k in exposed)
    greedy = run(lambda i, e: 0, 1)                 # the original myopic order
    multipass = run(inc_cost, 20)                   # cheapest-incremental first, repeated
    return max(allin, greedy, multipass, 0.0)

def trial(n, l, q, p, r, mode, rng):
    need, bad, quorum, hm = network(n, l, q, p, rng)
    return attack(n, l, need, bad, quorum, hm, r, mode != "off")

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
