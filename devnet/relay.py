#!/usr/bin/env python3
"""A minimal NIP-01 relay for the devnet: EVENT / REQ / CLOSE, in-memory with
JSONL persistence.  Ephemeral kinds (20000-29999) are delivered but not stored;
replaceable kinds (0, 3, 10000-19999, 30000-39999) keep the latest per
(pubkey, kind, d).  No signature checks: the clients verify."""
import asyncio, json, os, sys, time
import websockets

PORT = int(os.environ.get("RELAY_PORT", "7777"))
STORE = os.environ.get("RELAY_STORE", "/tmp/cld-relay.jsonl")
events = []          # dicts, oldest first
recent = []          # ephemeral events kept in memory for RECENT_TTL seconds: the reference
                     # daemon collects confiscation_sign responses (kind 20102) by fetching
                     # them from the relay rather than from its subscription
RECENT_TTL = 600
subs = {}            # websocket -> {subid: [filters]}

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
        now = time.time()
        recent[:] = [e for e in recent if e["created_at"] > now - RECENT_TTL]
        if not any(e["id"] == ev["id"] for e in recent): recent.append(ev)
        return
    if replaceable(ev["kind"]):
        key = (ev["pubkey"], ev["kind"], d_tag(ev))
        events[:] = [e for e in events if (e["pubkey"], e["kind"], d_tag(e)) != key or e["created_at"] > ev["created_at"]]
        if any((e["pubkey"], e["kind"], d_tag(e)) == key for e in events): return
    if any(e["id"] == ev["id"] for e in events): return
    events.append(ev)
    with open(STORE, "a") as f: f.write(json.dumps(ev) + "\n")

def load():
    if os.path.exists(STORE):
        with open(STORE) as f:
            for line in f:
                try: events.append(json.loads(line))
                except Exception: pass
    print(f"relay: {len(events)} stored events", flush=True)

async def deliver(ws, text):
    try:
        await asyncio.wait_for(ws.send(text), timeout=1.0)
    except Exception:
        subs.pop(ws, None)

async def handler(ws):
    subs[ws] = {}
    try:
        async for raw in ws:
            try: msg = json.loads(raw)
            except Exception: continue
            if not isinstance(msg, list) or not msg: continue
            if msg[0] == "EVENT" and len(msg) >= 2:
                ev = msg[1]
                store(ev)
                await ws.send(json.dumps(["OK", ev["id"], True, ""]))
                # Fan out concurrently with a per-send timeout: one dead socket
                # (a restarted daemon) must not delay delivery to the others.
                sends = []
                for other, ss in list(subs.items()):
                    for sid, filters in ss.items():
                        if any(matches(f, ev) for f in filters):
                            sends.append(deliver(other, json.dumps(["EVENT", sid, ev])))
                if sends: await asyncio.gather(*sends, return_exceptions=True)
            elif msg[0] == "REQ" and len(msg) >= 3:
                sid, filters = msg[1], msg[2:]
                subs[ws][sid] = filters
                out = [e for e in events + recent if any(matches(f, e) for f in filters)]
                limit = min([f["limit"] for f in filters if "limit" in f] or [len(out)])
                for e in out[-limit:]:
                    await ws.send(json.dumps(["EVENT", sid, e]))
                await ws.send(json.dumps(["EOSE", sid]))
            elif msg[0] == "CLOSE" and len(msg) >= 2:
                subs[ws].pop(msg[1], None)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        subs.pop(ws, None)

async def main():
    load()
    async with websockets.serve(handler, "127.0.0.1", PORT, max_size=4 * 1024 * 1024,
                                ping_interval=10, ping_timeout=10):
        print(f"relay: ws://127.0.0.1:{PORT}", flush=True)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
