#!/usr/bin/env python3
"""Does seating guidance, followed by wallets' deposits, make collusion harder?
(docs/TRUST-MODEL.md §2e)

Same network and attacker as analysis/coverage_sim.py (§2d): N operators, L ledgers
each, Q = 7, vault split reserves R / collateral C = 1 - R, an on-chain theft naming
every signer, each exposed key slashed on every honest-majority ledger it operates.

Two worlds on the same dials:

  random    quorums are Q operators drawn at random (§2d).
  guidance  honest operators seat 2 trust anchors (roots: whoever signs the wallet
            and the few they vouch for, honest by assumption), 3 seats drawn by
            commit-reveal lot from a pool, and 2 vanity seats of their own choosing.
            Compliance is checkable (anchors present, lot seats match the draw), and
            wallets deposit by it: a non-compliant ledger draws almost nothing;
            compliant ledgers share deposits in proportion to score^K.

Vaults follow deposits: a ledger's vault (loot and collateral alike) scales with the
deposits it holds, normalised so the average vault is 1 in both worlds.

The attacker is the best of two strategies: the myopic greedy of coverage_sim.py, and a
coordinated all-in that takes every capturable vault and pays the contagion cascade once.

The coalition's dials: POOL (its share of the lot pool is min(1, POOL*p): stuffing),
VANITY (its share of honest operators' vanity seats; default p, i.e. no more
attractive than anyone).  Its own ledgers either comply (2 anchors, lot, vanity of
its own keys) or deviate (stack all 7 seats with its keys: captured, but visibly
non-compliant, so nearly no deposits).  It takes the better of the two.

Contagion follows DEP-19 §6: an exposed key whose own quorum is coalition-captured is
not thereby safe.  The captured quorum's members are derelict when they fail to act,
and are exposed in turn, recursively, until honest majorities confiscate.

Output: the largest coalition fraction p at which the attack is unprofitable in
>= SAFE of the trials, per world and dial setting.
"""
import random, sys

Q, NEED, K = 7, 4, 2.0          # quorum, majority, deposit-weighting exponent (score^K)
EPS = 0.0                       # deposit weight of a visibly non-compliant ledger (wallets skip it)

def build(n, l, p, roots_frac, world, own, pool, vanity, rng, layout=(2, 3, 2)):
    roots = set(rng.sample(range(n), max(2, round(roots_frac * n))))
    pool_keys = [k for k in range(n) if k not in roots]
    bad = set(rng.sample(pool_keys, min(len(pool_keys), round(p * n))))   # roots are honest
    honest = [k for k in range(n) if k not in bad]
    badl = sorted(bad)
    quorum, weight = {}, {}
    for o in range(n):
        for j in range(l):
            if world == "random":
                quorum[(o, j)] = rng.sample([x for x in range(n) if x != o], Q); weight[(o, j)] = 1.0
                continue
            if o in bad and own == "deviate":
                seats = rng.sample([x for x in badl if x != o], min(Q, len(badl) - 1))
                seats += rng.sample([x for x in honest if x != o], Q - len(seats))
                quorum[(o, j)] = seats; weight[(o, j)] = EPS
                continue
            n_anchor, n_lot, n_van = layout
            # Eligibility = punishability: only keys whose own ledgers comply may fill lot or
            # vanity seats on others' ledgers.  A deviating coalition gets no such seats.
            elig_share = 0.0 if own == "deviate" else 1.0
            seats = rng.sample([r for r in roots if r != o], n_anchor)            # anchors
            def draw(share):
                pool_of = badl if rng.random() < share and badl else honest
                cand = [x for x in pool_of if x != o and x not in seats]
                return rng.choice(cand) if cand else rng.choice([x for x in range(n) if x != o and x not in seats])
            for _ in range(n_lot): seats.append(draw(elig_share * min(1.0, pool * p)))   # commit-reveal lot
            van_share = 1.0 if o in bad else elig_share * (p if vanity < 0 else vanity)  # coalition seats its own
            for _ in range(n_van): seats.append(draw(van_share))                   # vanity
            quorum[(o, j)] = seats; weight[(o, j)] = 1.0
    # compliant ledgers share deposits by score^K; score = operator stake (its ledger count is L for
    # all, so compliance is what differs) -> weights normalised to mean 1
    tot = sum(w ** K for w in weight.values())
    weight = {led: (w ** K) * len(weight) / tot for led, w in weight.items()}
    return bad, quorum, weight

def attack(n, l, r, bad, quorum, weight, dereliction=True):
    """The coverage_sim.py attacker (myopic per-target greedy, reusing exposed keys), with
    contagion that follows DEP-19 §6.  An exposed key is confiscated on each ledger it runs
    whose quorum has an honest majority.  Where its quorum is coalition-captured and does not
    act, that quorum's coalition members are derelict, so they are exposed in turn, and so on
    outward until honest majorities are reached.  Each key pays once per ledger."""
    c = 1.0 - r
    hm = {led: sum(1 for m in mem if m not in bad) >= NEED for led, mem in quorum.items()}

    def closure(exposed):
        seen = set(exposed); todo = list(exposed); cost = 0.0
        while todo:
            k = todo.pop()
            for j in range(l):
                led = (k, j)
                if hm[led]:
                    cost += c * weight[led]
                elif dereliction:
                    for m in quorum[led]:
                        if m in bad and m not in seen:
                            seen.add(m); todo.append(m)
        return cost

    exposed = set(); gain = 0.0; cur = 0.0
    for (o, j), mem in quorum.items():
        members = [m for m in mem if m in bad]
        if len(members) < NEED: continue
        members.sort(key=lambda m: (m not in exposed, m))
        signers = members[:NEED]
        loot = (r if o in bad else 1.0) * weight[(o, j)]
        new_total = closure(exposed | set(signers))
        if loot > new_total - cur:
            gain += loot; exposed.update(signers); cur = new_total
    return gain - cur

def allin(n, l, r, bad, quorum, weight):
    """Coordinated: take every capturable vault, pay the dereliction closure once.  Where
    contagion cascades, this is the binding strategy: no single vault pays for the cascade,
    so a myopic attacker never starts (it overstated safety to the top of the grid)."""
    c = 1.0 - r
    hm = {led: sum(1 for m in mem if m not in bad) >= NEED for led, mem in quorum.items()}
    gain = 0.0; signers = set()
    for (o, j), mem in quorum.items():
        members = sorted(m for m in mem if m in bad)
        if len(members) >= NEED:
            gain += (r if o in bad else 1.0) * weight[(o, j)]; signers.update(members[:NEED])
    seen = set(signers); todo = list(signers); cost = 0.0
    while todo:
        k = todo.pop()
        for j in range(l):
            if hm[(k, j)]: cost += c * weight[(k, j)]
            else:
                for m in quorum[(k, j)]:
                    if m in bad and m not in seen: seen.add(m); todo.append(m)
    return gain - cost

def smart_attack(n, l, r, bad, quorum, weight):
    """Choose the theft set that maximises net after the DEP-19 §6 cascade.  Start all-in,
    then repeatedly drop the theft whose removal most improves net (its loot is worth less
    than the cascade it alone drags in), to a fixpoint.  A set-cover-style lower bound on the
    optimal attack: tighter than all-in whenever a few vaults pull in a large cascade."""
    c = 1.0 - r
    hm = {led: sum(1 for m in mem if m not in bad) >= NEED for led, mem in quorum.items()}
    caps = []                                  # capturable vaults: (loot, frozenset signers)
    for (o, j), mem in quorum.items():
        members = sorted(m for m in mem if m in bad)
        if len(members) >= NEED:
            caps.append(((r if o in bad else 1.0) * weight[(o, j)], frozenset(members[:NEED])))

    def net(chosen):
        if not chosen: return 0.0
        signers = set().union(*(s for _, s in chosen))
        seen = set(signers); todo = list(signers); cost = 0.0
        while todo:
            k = todo.pop()
            for j in range(l):
                if hm[(k, j)]: cost += c * weight[(k, j)]
                else:
                    for m in quorum[(k, j)]:
                        if m in bad and m not in seen: seen.add(m); todo.append(m)
        return sum(loot for loot, _ in chosen) - cost

    chosen = list(caps); cur = net(chosen)
    improved = True
    while improved and chosen:
        improved = False; bestdrop = None; bestnet = cur
        for i in range(len(chosen)):
            v = net(chosen[:i] + chosen[i+1:])
            if v > bestnet: bestnet = v; bestdrop = i
        if bestdrop is not None:
            chosen.pop(bestdrop); cur = bestnet; improved = True
    return cur

def best_attack(n, l, r, bad, quorum, weight):
    return max(attack(n, l, r, bad, quorum, weight),
               allin(n, l, r, bad, quorum, weight),
               smart_attack(n, l, r, bad, quorum, weight))

def profitable(n, l, p, r, roots, world, pool, vanity, rng, layout=(2, 3, 2)):
    if world == "random":
        return best_attack(n, l, r, *build(n, l, p, roots, world, "comply", pool, vanity, rng)) > 1e-9
    seed = rng.random()
    best = max(best_attack(n, l, r, *build(n, l, p, roots, world, own, pool, vanity, random.Random(seed), layout))
               for own in ("comply", "deviate"))
    return best > 1e-9

def max_safe(n, l, r, roots, world, pool, vanity, trials, rng, safe=0.95, layout=(2, 3, 2)):
    best = 0.0
    for pp in range(0, 91, 3):
        p = pp / 100
        if sum(profitable(n, l, p, r, roots, world, pool, vanity, rng, layout) for _ in range(trials)) / trials <= 1 - safe:
            best = p
        else:
            break
    return best

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    rng = random.Random(20261001)
    print(f"max safe coalition fraction p (unprofitable in >= 95% of {trials} trials), N={n}, Q=7, roots 10%")
    print("eligibility = punishability: deviating keys get no lot or vanity seats on others' ledgers")
    print("contagion with dereliction (DEP-19 §6): a captured quorum that does not act exposes its own members")
    print("attacker: best of myopic greedy, coordinated all-in, and theft-set optimisation (upper bound)")
    print(f"{'world':22s} {'pool':>4s} {'van':>4s}   L=1,R=.5  L=1,R=.7  L=3,R=.5  L=3,R=.7")
    rows = [("random", None, 1, -1),
            ("2 anchor/3 lot/2 van", (2, 3, 2), 1, -1), ("2 anchor/3 lot/2 van", (2, 3, 2), 2, -1),
            ("2 anchor/3 lot/2 van", (2, 3, 2), 1, 0.5),
            ("2 anchor/4 lot/1 van", (2, 4, 1), 1, -1), ("2 anchor/4 lot/1 van", (2, 4, 1), 2, -1),
            ("2 anchor/4 lot/1 van", (2, 4, 1), 1, 0.5)]
    for name, layout, pool, van in rows:
        world = "random" if layout is None else "guidance"
        cells = [max_safe(n, l, r, 0.10, world, pool, van, trials, rng, layout=layout or (2, 3, 2))
                 for l, r in ((1, 0.5), (1, 0.7), (3, 0.5), (3, 0.7))]
        print(f"{name:22s} {pool:>4} {('p' if van < 0 else str(van)):>4s}   " + "  ".join(f"{x:8.2f}" for x in cells)); sys.stdout.flush()
