#!/usr/bin/env python3
"""devnet/soak-nostr-keys.py — each soak operator's Nostr publishing key, as "<node> <key>" lines.

A cl node publishes with its protocol key; a reference node with a separate Nostr key.  The key a
node publishes with is the author of most of the recent ledger updates (kind 9100) of the ledger
it operates ($SOAK/ledgers.tsv: name, id, operator).  The network chaos loop needs it, to fault
what a node publishes, and the oracle names publishers by it."""
import asyncio, collections, json, os, sys, time, websockets
SOAK = os.environ.get("SOAK", "/mnt/lisp/signet/deposits/soak")
RELAY = os.environ.get("RELAY_URL", "ws://127.0.0.1:7777")
async def main():
    ops = {}
    for line in open(os.path.join(SOAK, "ledgers.tsv")):
        f = line.split()
        if len(f) >= 3: ops[f[1][:16]] = f[2]
    by = collections.defaultdict(collections.Counter)
    async with websockets.connect(RELAY, max_size=None) as ws:
        await ws.send(json.dumps(["REQ", "k", {"kinds": [9100], "since": int(time.time()) - 1800, "limit": 50000}]))
        while True:
            m = json.loads(await asyncio.wait_for(ws.recv(), 60))
            if m[0] == "EVENT":
                d = [t[1] for t in m[2]["tags"] if t[0] == "d"]
                if d and d[0][:16] in ops: by[d[0][:16]][m[2]["pubkey"]] += 1
            elif m[0] in ("EOSE", "CLOSED"): break
    for lid, c in by.items():
        print(ops[lid], c.most_common(1)[0][0])
asyncio.run(main())
