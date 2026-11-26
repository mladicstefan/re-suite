#!/usr/bin/env python3
"""Two builds of a toy game backend, each recorded as a HAR file, plus save records of each build.

Build 2 renames the score endpoint, turns the balance into a string, drops the
legacy ping, leaves the profile alone, and puts four more bytes into a save record."""
import hashlib, hmac, json, os, struct, sys
KEY = bytes.fromhex("5ca1ab1e0ddba11c0ffee123")
def entry(method, url, body, headers, status, response):
    e = {"request": {"method": method, "url": url, "headers": [{"name": k, "value": v} for k, v in headers.items()]},
         "response": {"status": status, "headers": [], "content": {"text": json.dumps(response)}}}
    if body is not None: e["request"]["postData"] = {"text": body}
    return e
def build(n):
    api, entries = f"https://game.example/api/v{n if n == 2 else 1}", []
    for i in range(6):
        body = json.dumps({"player": 1000 + i, "score": 137 * (i + 1)}, separators=(",", ":"))
        sig = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()
        score = f"https://game.example/api/v{n}/score"
        entries.append(entry("POST", score, body, {"X-Signature": sig}, 200, {"ok": True, "rank": 1 + i}))
        balance = 1000 - 10 * i if n == 1 else f"{1000 - 10 * i}.00"
        entries.append(entry("POST", "https://game.example/api/v1/purchase", "{}", {}, 200, {"ok": True, "balance": balance}))
        entries.append(entry("GET", f"https://game.example/api/v1/profile/{1000 + i}", None, {}, 200, {"id": 1000 + i, "level": 3 + i, "name": f"p{i}"}))
        if n == 1:
            entries.append(entry("POST", "https://game.example/api/v1/legacy/ping", "{}", {}, 200, {"ok": True}))
    json.dump({"log": {"version": "1.2", "entries": entries}}, open(f"build{n}.har", "w"))
    os.makedirs(f"saves{n}/SaveRecord", exist_ok=True)
    for i in range(4):
        extra = b"" if n == 1 else struct.pack("<I", 0xC0FFEE)
        open(f"saves{n}/SaveRecord/{i}.bin", "wb").write(b"SAVE" + extra + struct.pack("<II", 7, 10 + i) + b"hero\0\0\0\0")
build(1); build(2)
open("score.key", "wb").write(KEY)
