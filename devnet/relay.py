#!/usr/bin/env python3
"""A minimal NIP-01 relay for the devnet: EVENT / REQ / CLOSE, in-memory with
JSONL persistence.  Ephemeral kinds (20000-29999) are delivered but not stored;
replaceable kinds (0, 3, 10000-19999, 30000-39999) keep the latest per
(pubkey, kind, d).  No signature checks: the clients verify."""
import asyncio, json, os, signal, sys, time
from bisect import bisect_left, bisect_right, insort
from collections import deque
import websockets

PORT = int(os.environ.get("RELAY_PORT", "7777"))
STORE = os.environ.get("RELAY_STORE", "/tmp/cld-relay.jsonl")
events = []          # dicts, oldest first (replaced/superseded entries are tombstoned in `dead` and compacted)
seen = {}            # id -> stored event: dedup in O(1) — at 100k events the old any() scan per publish
                     # pinned the single asyncio loop at a full core and every subscriber timed out
latest = {}          # (pubkey, kind, d) -> current event, for replaceable kinds
dead = set()         # ids of superseded replaceable events still sitting in `events`
index = {}           # ("kind", k) | ("author", pk) | ("#x", v) | ("all",) -> [events] sorted by created_at.
                     # A REQ reads the smallest list its filter names, bisected on since/until.  It
                     # used to scan the whole store (675k events) for any filter without "#d" — every
                     # bot's reply subscription — which pinned the loop, pushed delivery to 10-50 s,
                     # and timed out cosign rounds and so rotations (ledgers A and F froze past expiry).
outq = {}            # websocket -> asyncio.Queue of outbound text: a slow client waits in its own
                     # queue and never delays the others; it is dropped only when its socket closes
                     # or the queue overflows (it used to be silently UNSUBSCRIBED after one 1 s stall,
                     # which is how the cl operators stopped hearing wallet requests under load)
OUTQ_MAX = 500000    # above any history replay: a cl node subscribing to every update kind is handed the whole store
recent = deque()     # ephemeral events kept in memory for RECENT_TTL seconds: the reference
recent_ids = set()   # ... indexed, and expired from the left: it holds ~40 events/s x TTL under load
                     # daemon collects confiscation_sign responses (kind 20102) by fetching
                     # them from the relay rather than from its subscription
RECENT_TTL = 600
subs = {}            # websocket -> {subid: [filters]}
TRACE = None         # file: every REQ with its peer, filters, result count and time.  kill -USR1 toggles it
TRACE_PATH = os.environ.get("RELAY_TRACE", STORE + ".trace")

def toggle_trace(*_):
    global TRACE
    if TRACE: TRACE.close(); TRACE = None
    else: TRACE = open(TRACE_PATH, "a", buffering=1)
    print(f"relay: trace {'on -> ' + TRACE_PATH if TRACE else 'off'}", flush=True)

def d_tag(ev):
    for t in ev.get("tags", []):
        if len(t) >= 2 and t[0] == "d": return t[1]
    return ""

def replaceable(kind): return kind in (0, 3) or 10000 <= kind < 20000 or 30000 <= kind < 40000
def ephemeral(kind): return 20000 <= kind < 30000

def matches(f, ev):
    if "ids" in f and not any(ev["id"].startswith(x) for x in f["ids"]): return False
    if "authors" in f and not any(ev["pubkey"].startswith(x) for x in f["authors"]): return False
    if "kinds" in f and ev["kind"] not in f["kinds"]: return False
    if "since" in f and ev["created_at"] < f["since"]: return False
    if "until" in f and ev["created_at"] > f["until"]: return False
    for k, vals in f.items():
        if k.startswith("#"):
            name = k[1:]
            tagvals = [t[1] for t in ev.get("tags", []) if len(t) >= 2 and t[0] == name]
            if not any(v in tagvals for v in vals): return False
    return True

def store(ev):
    if ephemeral(ev["kind"]):
        cutoff = time.time() - RECENT_TTL
        while recent and recent[0]["created_at"] <= cutoff: recent_ids.discard(recent.popleft()["id"])
        if ev["id"] not in recent_ids: recent_ids.add(ev["id"]); recent.append(ev)
        return
    if ev["id"] in seen: return
    if replaceable(ev["kind"]):
        key = (ev["pubkey"], ev["kind"], d_tag(ev))
        cur = latest.get(key)
        if cur is not None:
            if cur["created_at"] > ev["created_at"]: return
            dead.add(cur["id"])
        latest[key] = ev
    seen[ev["id"]] = ev; events.append(ev)
    for k in index_keys(ev): insort(index.setdefault(k, []), ev, key=created)
    if len(dead) > 5000: compact()
    with open(STORE, "a") as f: f.write(json.dumps(ev) + "\n")

def compact():
    events[:] = [e for e in events if e["id"] not in dead]
    for k in list(index): index[k] = [e for e in index[k] if e["id"] not in dead]
    for i in dead: seen.pop(i, None)
    dead.clear()

def created(ev): return ev["created_at"]

def index_keys(ev):
    ks = {("all",), ("kind", ev["kind"]), ("author", ev["pubkey"])}
    ks.update(("#" + t[0], t[1]) for t in ev.get("tags", []) if len(t) >= 2 and len(t[0]) == 1)
    return ks

def candidates(f):
    """Stored events that might match F: the smallest index list F names, cut to since/until."""
    if "ids" in f and all(len(x) == 64 for x in f["ids"]):
        return [seen[x] for x in f["ids"] if x in seen and x not in dead]
    groups = [[("kind", k) for k in f["kinds"]]] if "kinds" in f else []
    if "authors" in f and all(len(a) == 64 for a in f["authors"]): groups.append([("author", a) for a in f["authors"]])
    groups += [[(k, v) for v in vals] for k, vals in f.items() if k.startswith("#") and len(k) == 2]
    keys = min(groups, key=lambda g: sum(len(index.get(k, ())) for k in g)) if groups else [("all",)]
    out = []
    for k in keys:
        lst = index.get(k, [])
        lo = bisect_left(lst, f["since"], key=created) if "since" in f else 0
        hi = bisect_right(lst, f["until"], key=created) if "until" in f else len(lst)
        out.extend(e for e in lst[lo:hi] if e["id"] not in dead)
    return out

def load():
    if os.path.exists(STORE):
        with open(STORE) as f:
            for line in f:
                try: ev = json.loads(line)
                except Exception: continue
                if ephemeral(ev.get("kind", 20000)): continue
                store_only = STORE; globals()["STORE"] = os.devnull; store(ev); globals()["STORE"] = store_only
    compact()
    print(f"relay: {len(events)} stored events", flush=True)

async def writer(ws):
    q = outq[ws]
    try:
        while True:
            await ws.send(await q.get())
    except Exception:
        pass

def deliver(ws, text):
    q = outq.get(ws)
    if q is None: return
    if q.qsize() >= OUTQ_MAX:            # a client that has not drained 20k messages is gone:
        subs.pop(ws, None); outq.pop(ws, None)   # CLOSE it, so it reconnects and re-subscribes
        asyncio.ensure_future(ws.close(1013, "outbound queue overflow")); return
    q.put_nowait(text)

async def handler(ws):
    subs[ws] = {}; outq[ws] = asyncio.Queue(); wtask = asyncio.create_task(writer(ws))
    try:
        async for raw in ws:
            try: msg = json.loads(raw)
            except Exception: continue
            if not isinstance(msg, list) or not msg: continue
            if msg[0] == "EVENT" and len(msg) >= 2:
                ev = msg[1]
                store(ev)
                deliver(ws, json.dumps(["OK", ev["id"], True, ""]))
                for other, ss in list(subs.items()):
                    for sid, filters in ss.items():
                        if any(matches(f, ev) for f in filters):
                            deliver(other, json.dumps(["EVENT", sid, ev]))
            elif msg[0] == "REQ" and len(msg) >= 3:
                sid, filters = msg[1], msg[2:]; t0 = time.perf_counter()
                subs[ws][sid] = filters
                # Stored events, plus recent ephemeral RESPONSES (the reference daemon fetches
                # its confiscation_sign replies) — never recent REQUESTS: a subscriber that
                # was handed ten minutes of stale wallet requests re-executed them all.
                # ... and only to a filter that asks with `since`: the reference daemon does; a
                # wallet subscribing for its reply does not, and was handed ~15k stale responses.
                rec = [e for e in recent if e["kind"] != 20101] if any("since" in f for f in filters) else []
                out = {}
                for f in filters:
                    for e in candidates(f) + rec:
                        if matches(f, e): out[e["id"]] = e
                out = sorted(out.values(), key=created)
                limit = min([f["limit"] for f in filters if "limit" in f] or [len(out)])
                for e in out[-limit:]:
                    deliver(ws, json.dumps(["EVENT", sid, e]))
                deliver(ws, json.dumps(["EOSE", sid]))
                if TRACE: TRACE.write(f"{time.strftime('%FT%T')} {ws.remote_address[1]} {sid} n={len(out)} {1000*(time.perf_counter()-t0):.1f}ms {json.dumps(filters)[:400]}\n")
            elif msg[0] == "CLOSE" and len(msg) >= 2:
                subs[ws].pop(msg[1], None)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        subs.pop(ws, None); outq.pop(ws, None); wtask.cancel()

async def stats():
    while True:
        await asyncio.sleep(60)
        qs = sorted((q.qsize() for q in outq.values()), reverse=True)[:3]
        print(f"relay: {len(subs)} clients, {sum(len(s) for s in subs.values())} subs, {len(events)} events, "
              f"{len(recent)} recent, busiest queues {qs}", flush=True)

async def main():
    load()
    signal.signal(signal.SIGUSR1, toggle_trace)
    asyncio.ensure_future(stats())
    async with websockets.serve(handler, "127.0.0.1", PORT, max_size=4 * 1024 * 1024,
                                ping_interval=10, ping_timeout=10):
        print(f"relay: ws://127.0.0.1:{PORT}", flush=True)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
