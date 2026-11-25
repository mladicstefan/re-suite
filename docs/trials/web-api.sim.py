#!/usr/bin/env python3
"""A toy game backend and its client. Every request the server receives and every
response the client gets is saved under captures/, the way a proxy would."""
import base64, hashlib, hmac, json, os, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

KEY_SCORE, KEY_SHOP, KEY_LEGACY = bytes.fromhex("5ca1ab1e0ddba11c0ffee123"), b"shop-secret-7", b"legacy!"
os.makedirs("captures", exist_ok=True)
seen = {}

def save(kind, endpoint, doc):
    n = seen[(kind, endpoint)] = seen.get((kind, endpoint), 0) + 1
    name = endpoint.strip("/").replace("/", "_")
    json.dump(doc, open(f"captures/{kind}.{name}.{n}.json", "w"))

class Backend(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        save("request", self.path, {"headers": dict(self.headers.items()), "body": body})
        req = json.loads(body)
        if self.path == "/api/v1/score":
            out = {"ok": True, "rank": 1 + req["score"] % 97, "best": req["score"] > 500, "player": {"id": req["player"], "level": req["score"] // 100}}
        elif self.path == "/api/v1/purchase":
            out = {"ok": True, "balance": 1000 - 10 * req["item"], "item": {"id": req["item"], "name": f"item-{req['item']}", "gift_from": None if req["item"] % 3 else "friend"}}
        else:
            out = {"ok": True, "session": hashlib.sha1(body.encode()).hexdigest()[:16], "expires_in": 3600}
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

def post(port, path, payload, headers):
    body = json.dumps(payload, separators=(",", ":"))
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body.encode(), headers={"Content-Type": "application/json", **headers(body)})
    with urllib.request.urlopen(req) as r:
        save("response", path, {"response": json.loads(r.read())})

server = HTTPServer(("127.0.0.1", 0), Backend); port = server.server_port
threading.Thread(target=server.serve_forever, daemon=True).start()
for i in range(8):
    post(port, "/api/v1/score", {"player": 1000 + i, "score": 137 * (i + 1)},
         lambda b: {"X-Signature": hmac.new(KEY_SCORE, b.encode(), hashlib.sha256).hexdigest()})
    post(port, "/api/v1/purchase", {"player": 1000 + i, "item": i + 1},
         lambda b: {"X-Sig": base64.b64encode(hmac.new(KEY_SHOP, b.encode(), hashlib.sha1).digest()).decode()})
    ts = str(1795000000 + i)
    post(port, "/api/v1/session", {"player": 1000 + i, "device": f"dev-{i}"},
         lambda b: {"X-Timestamp": ts, "X-Auth": hmac.new(KEY_SCORE, f"{ts}.{b}".encode(), hashlib.sha256).hexdigest()})
    post(port, "/api/v1/legacy/ping", {"n": i},
         lambda b: {"X-Check": hashlib.md5(KEY_LEGACY + b.encode()).hexdigest().upper()})
server.shutdown()
print(len(os.listdir("captures")), "captures")
