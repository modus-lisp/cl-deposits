#!/usr/bin/env python3
"""devnet/soak-oracle.py — the soak's oracle (docs/ADVERSARIAL.md §Oracle).

Every published accusation is judged against who is adversarial:

  PASS    a fraud proof against an adversarial key or ledger (scheduled attacks: in time)
  MISS    a scheduled attack ($SOAK/attacks.tsv) with no proof against it inside its window
  ALARM   a fraud proof against an honest party, or a challenge of an honest spend that
          lapsed unanswered
  EXPIRY  a QuorumExpired proof (a liveness finding on that ledger, not an accusation)

The evidence is what nodes publish on the relay, so it is the same for both
implementations: kind 9101 (fraud proofs: proof_type, accused, ledger_id), 9111 (spend
challenges) and 9112 (their answers).  Refusals to cosign are not counted: they follow
from a dispute, which follows from one of the above.

Adversaries ($SOAK/adversaries.tsv, '#' comments):   key <hex prefix> [label]
                                                    ledger <id prefix> [label]
                                                    pool <key> [label]
A pool key is a red-team actor (devnet/soak-attackers.sh): adversarial once a scenario burns it
(it is then in $SOAK/redteam-tainted), honest otherwise.  A proof against a pool key that is not
burned yet waits ORACLE_POOL_GRACE_S (1800) for the scenario to record it before it is an ALARM.
Scheduled attacks ($SOAK/attacks.tsv, appended by attackers):
    <unix time> <attack> <ledger id> <accused key prefix> <window s>

  soak-oracle.py --loop SECONDS     poll the relay, judge, append $SOAK/log/oracle.log
  soak-oracle.py --once             one pass
  soak-oracle.py --replay FILE      judge a JSONL file of events (an archived relay's), print
Writes $SOAK/oracle/summary (one line, for soak.sh status) and keeps the events it has seen
in $SOAK/oracle/events.jsonl.
"""
import asyncio, json, os, sys, time

SOAK = os.environ.get("SOAK") or os.path.join(os.environ.get("CLD_ROOT", "/mnt/lisp/signet/deposits"), "soak")
RELAY = os.environ.get("RELAY_URL", "ws://127.0.0.1:7777")
# DEP-06 spend challenge window: service_response_blocks (72) at the soak's one block a minute, with slack
POOL_GRACE_S = int(os.environ.get("ORACLE_POOL_GRACE_S", "1800"))
CHALLENGE_WINDOW_S = int(os.environ.get("ORACLE_CHALLENGE_WINDOW_S", str(72 * 60 * 3 // 2)))
KINDS = (9101, 9111, 9112)


def load_table(path):
    rows = []
    try:
        for line in open(path):
            line = line.split("#", 1)[0].strip()
            if line:
                rows.append(line.split())
    except FileNotFoundError:
        pass
    return rows


def xonly(k):
    """A key as its x coordinate: compressed (66 hex) and Nostr (64 hex) keys compare equal."""
    k = (k or "").lower()
    return k[2:] if len(k) == 66 else k


class World:
    def __init__(self, soak):
        rows = load_table(os.path.join(soak, "adversaries.tsv"))
        self.adv_keys = [(xonly(r[1]), " ".join(r[2:])) for r in rows if r[0] == "key"]
        self.adv_ledgers = [(r[1].lower(), " ".join(r[2:])) for r in rows if r[0] == "ledger"]
        self.pool = {xonly(r[1]) for r in rows if r[0] == "pool"}
        self.names = {}
        for t in ("names.tsv", "nostr.tsv"):        # <node> <pubkey>: protocol keys, and the keys nodes publish with
            for r in load_table(os.path.join(soak, t)):
                self.names[xonly(r[1])] = r[0]
        for f in os.listdir(soak) if os.path.isdir(soak) else []:
            if f.startswith("pubkey."):
                k = open(os.path.join(soak, f)).read().strip()
                if k:
                    self.names[xonly(k)] = f.split(".", 1)[1]
        self.ledger_names = {r[1].lower(): r[0] for r in load_table(os.path.join(soak, "ledgers.tsv")) if len(r) >= 2}
        self.attacks = [r for r in load_table(os.path.join(soak, "attacks.tsv")) if len(r) >= 5]
        # <unix time> <attack> <scenario verdict> <seconds>: each live attack's end-to-end result
        # (devnet/soak-attackers.sh), e.g. confiscated and the depositors paid
        self.outcomes = [r for r in load_table(os.path.join(soak, "attack-outcomes.tsv")) if len(r) >= 3]
        # Known false accusations whose cause is fixed ($SOAK/alarms-resolved.tsv: <accused prefix>
        # <ledger prefix> <note...>).  They stay counted as ALARMs; the summary also says how many are
        # resolved, so a new ALARM stands out.
        self.resolved = [r for r in load_table(os.path.join(soak, "alarms-resolved.tsv")) if len(r) >= 2]
        burned = {r[0] for r in load_table(os.path.join(soak, "redteam-tainted"))}
        self.burned = {k for k, n in self.names.items() if n in burned}

    def resolution(self, accused, ledger):
        for r in self.resolved:
            want = r[0].lower()
            if (accused.lower().startswith(want) or xonly(accused).startswith(want[2:] if len(want) % 2 == 0 and want[:2] in ("02", "03") else want)) \
                    and ledger.lower().startswith(r[1].lower()):
                return " ".join(r[2:]) or "resolved"
        return None

    def adversarial_key(self, k):
        x = xonly(k)
        return bool(x) and (x in self.burned or any(x.startswith(p) for p, _ in self.adv_keys))

    def pool_key(self, k):
        return xonly(k) in self.pool

    def adversarial_ledger(self, l):
        l = (l or "").lower()
        return bool(l) and any(l.startswith(p) for p, _ in self.adv_ledgers)

    def who(self, k):
        x = xonly(k)
        return self.names.get(x) or next((n for full, n in self.names.items() if x and full.startswith(x)), x[:12])

    def lname(self, l):
        l = (l or "").lower()
        return next((n for full, n in self.ledger_names.items() if l and full.startswith(l)), l[:12])


def judge(events, world, now=None):
    """events: dicts with kind, pubkey, created_at, content.  Returns (verdicts, counts)."""
    now = now or time.time()
    proofs, challenges, answers = [], {}, set()
    for e in sorted(events, key=lambda e: e["created_at"]):
        try:
            c = json.loads(e["content"])
        except Exception:
            continue
        if e["kind"] == 9101:
            p = c.get("proof", {})
            proofs.append((e, p.get("proof_type", "?"), p.get("accused", ""), p.get("ledger_id", "")))
        elif e["kind"] == 9111:
            key = (c.get("challenged_ledger_id", ""), c.get("txid", ""))
            challenges.setdefault(key, e)
        elif e["kind"] == 9112:
            answers.add((c.get("challenged_ledger_id", ""), c.get("txid", "")))
    verdicts, counts = [], {"PASS": 0, "MISS": 0, "ALARM": 0, "resolved": 0, "EXPIRY": 0, "challenged": 0, "answered": 0, "pending": 0}
    seen = set()
    for e, typ, acc, led in proofs:
        k = (typ, acc, led)
        dup = k in seen
        seen.add(k)
        if typ == "QuorumExpired":
            v = "EXPIRY"
        elif world.adversarial_key(acc) or world.adversarial_ledger(led):
            v = "PASS"
        elif world.pool_key(acc) and now - e["created_at"] < POOL_GRACE_S:
            counts["pending"] += 0 if dup else 1
            continue
        else:
            v = "ALARM"
        note = world.resolution(acc, led) if v == "ALARM" else None
        if not dup:
            counts[v] += 1
            if note:
                counts["resolved"] += 1
        verdicts.append((e["created_at"], v, dup,
                         f"{typ} against {world.who(acc)} on {world.lname(led)} (published by {world.who(e['pubkey'])})"
                         + (f" [resolved: {note}]" if note else "")))
    for (led, txid), e in challenges.items():
        counts["challenged"] += 1
        adv = world.adversarial_ledger(led)
        if (led, txid) in answers:
            counts["answered"] += 1
            verdicts.append((e["created_at"], "INFO", False,
                             f"challenge of {world.lname(led)}'s spend {txid[:12]} by {world.who(e['pubkey'])}: answered"))
        elif now - e["created_at"] < CHALLENGE_WINDOW_S:
            counts["pending"] += 1
        elif not adv:
            counts["ALARM"] += 1
            verdicts.append((e["created_at"], "ALARM", False,
                             f"challenge of honest {world.lname(led)}'s spend {txid[:12]} by {world.who(e['pubkey'])} lapsed unanswered"))
    for t, attack, led, acc, window in world.attacks:
        t, window = float(t), float(window)
        hit = any(typ != "QuorumExpired" and e["created_at"] >= t - 60 and e["created_at"] <= t + window
                  and (led.lower() == "-" or led2.lower().startswith(led.lower()))
                  and (xonly(acc2).startswith(xonly(acc)) if acc != "-"
                       else world.adversarial_key(acc2) or world.adversarial_ledger(led2))
                  for e, typ, acc2, led2 in proofs)
        if not hit and now > t + window:
            counts["MISS"] += 1
            verdicts.append((t, "MISS", False, f"{attack} on {world.lname(led)} (accused {acc[:12]}): no proof within {int(window)} s"))
    per = {}
    for r in world.outcomes:
        ok = r[2].startswith("PASS")
        moot = r[2].startswith(("INVALID", "SKIP"))   # the scenario's precondition did not arise: no verdict
        a = per.setdefault(r[1], [0, 0, 0])
        if moot:
            a[2] += 1
        else:
            a[0] += ok; a[1] += 1
        if not ok:
            verdicts.append((float(r[0]), "ATTACK", False, f"{r[1]}: scenario verdict {r[2]}"))
    counts["attacks"] = per
    return verdicts, counts


def summary_line(counts):
    line = ("oracle: PASS {PASS}  MISS {MISS}  ALARM {ALARM} ({resolved} resolved)  expiry {EXPIRY}  challenges {challenged}"
            " (answered {answered}, pending {pending})").format(**counts)
    per = counts.get("attacks") or {}
    if per:
        line += "  attacks " + " ".join(f"{a}={p}/{n}" + (f"+{m}moot" if m else "") for a, (p, n, m) in sorted(per.items()))
    return line


async def fetch(since):
    import websockets
    out = []
    async with websockets.connect(RELAY, max_size=None) as ws:
        await ws.send(json.dumps(["REQ", "oracle", {"kinds": list(KINDS), "since": since}]))
        while True:
            m = json.loads(await asyncio.wait_for(ws.recv(), 60))
            if m[0] == "EVENT":
                out.append(m[2])
            elif m[0] in ("EOSE", "CLOSED"):
                break
    return out


def one_pass(state_dir, log_path):
    os.makedirs(state_dir, exist_ok=True)
    store = os.path.join(state_dir, "events.jsonl")
    events, ids = [], set()
    if os.path.exists(store):
        for line in open(store):
            e = json.loads(line)
            ids.add(e["id"]); events.append(e)
    since = max((e["created_at"] for e in events), default=0) - 600
    new = [e for e in asyncio.run(fetch(max(since, 0))) if e["id"] not in ids]
    with open(store, "a") as f:
        for e in new:
            f.write(json.dumps(e) + "\n"); events.append(e)
    world = World(SOAK)
    verdicts, counts = judge(events, world)
    reported_path = os.path.join(state_dir, "reported")
    reported = set(open(reported_path).read().splitlines()) if os.path.exists(reported_path) else set()
    with open(log_path, "a") as log, open(reported_path, "a") as rep:
        for t, v, dup, text in verdicts:
            key = f"{int(t)} {v} {text}"
            if dup or key in reported:
                continue
            log.write(f"{time.strftime('%FT%T', time.localtime(t))} {v:6} {text}\n")
            rep.write(key + "\n"); reported.add(key)
    line = summary_line(counts)
    with open(os.path.join(state_dir, "summary"), "w") as f:
        f.write(time.strftime("%FT%T ") + line + "\n")
    return line


def main():
    a = sys.argv[1:]
    if a[:1] == ["--replay"]:
        events = [json.loads(l) for l in open(a[1])]
        soak = a[2] if len(a) > 2 else SOAK
        verdicts, counts = judge(events, World(soak), now=time.time())
        for t, v, dup, text in sorted(verdicts):
            if not dup:
                print(time.strftime("%FT%T", time.gmtime(t)) + "Z", f"{v:6}", text)
        print(summary_line(counts))
        sys.exit(1 if counts["ALARM"] or counts["MISS"] else 0)
    state, log = os.path.join(SOAK, "oracle"), os.path.join(SOAK, "log", "oracle.log")
    if a[:1] == ["--once"]:
        print(one_pass(state, log)); return
    every = int(a[1]) if a[:1] == ["--loop"] and len(a) > 1 else 120
    while True:
        try:
            print(time.strftime("%FT%T "), one_pass(state, log), flush=True)
        except Exception as ex:
            print(time.strftime("%FT%T "), "oracle pass failed:", ex, flush=True)
        time.sleep(every)


if __name__ == "__main__":
    main()
