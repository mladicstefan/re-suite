// Loads pages in headless Chromium and saves every HTTP exchange the browser makes, one JSON file each.
// usage: node capture.mjs <out dir> <url>...
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [out, ...urls] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "capture-"));
const chrome = spawn("chromium", ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--no-first-run", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
const endpoint = await new Promise((resolve) => chrome.stderr.on("data", (d) => { const m = /ws:\/\/\S+/.exec(String(d)); if (m) resolve(m[0]); }));
const ws = new WebSocket(endpoint);
await new Promise((r) => (ws.onopen = r));
let next = 0; const waiting = new Map(); const listeners = [];
ws.onmessage = (m) => { const msg = JSON.parse(m.data); if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); } else listeners.forEach((l) => l(msg)); };
const send = (method, params = {}, sessionId) => new Promise((r) => { const id = ++next; waiting.set(id, (m) => r(m.result ?? {})); ws.send(JSON.stringify({ id, method, params, sessionId })); });
const list = (h = {}) => Object.entries(h).flatMap(([name, v]) => String(v).split("\n").map((value) => ({ name, value })));
let n = 0;
for (const url of urls) {
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const seen = new Map();
  const on = (msg) => {
    if (msg.sessionId !== sessionId) return;
    const p = msg.params, e = seen.get(p?.requestId) ?? {};
    if (msg.method === "Network.requestWillBeSent") Object.assign(e, { method: p.request.method, url: p.request.url, reqHeaders: p.request.headers, postData: p.request.postData, hasPost: p.request.hasPostData });
    else if (msg.method === "Network.requestWillBeSentExtraInfo") e.reqWire = p.headers;
    else if (msg.method === "Network.responseReceived") Object.assign(e, { status: p.response.status, respHeaders: p.response.headers, protocol: p.response.protocol });
    else if (msg.method === "Network.responseReceivedExtraInfo") Object.assign(e, { respWire: p.headers, wireStatus: p.statusCode });
    else if (msg.method === "Network.loadingFinished") e.done = true;
    else return;
    seen.set(p.requestId, e);
  };
  listeners.push(on);
  await send("Network.enable", { maxPostDataSize: 1 << 20 }, sessionId);
  await send("Page.navigate", { url }, sessionId);
  await new Promise((r) => setTimeout(r, 9000));
  for (const [requestId, e] of seen) {
    if (!e.url || !e.url.startsWith("http") || e.status === undefined) continue;
    const exchange = { request: { method: e.method, url: e.url, http_version: e.protocol ?? null, headers: list(e.reqWire ?? e.reqHeaders) }, response: { status: e.wireStatus ?? e.status, headers: list(e.respWire ?? e.respHeaders) } };
    let post = e.postData;
    if (post === undefined && e.hasPost) post = (await send("Network.getRequestPostData", { requestId }, sessionId)).postData;
    if (post !== undefined) exchange.request.body = { text: post };
    if (e.done) {
      const body = await send("Network.getResponseBody", { requestId }, sessionId);
      if (body.body !== undefined && body.body.length <= 1 << 20) exchange.response.body = body.base64Encoded ? { base64: body.body } : { text: body.body };
      else if (body.body !== undefined) exchange.response.body_omitted = body.body.length;
    }
    writeFileSync(join(out, `${String(++n).padStart(4, "0")}.json`), JSON.stringify(exchange));
  }
  listeners.splice(listeners.indexOf(on), 1);
  await send("Target.closeTarget", { targetId });
  console.log(`${url}: ${seen.size} requests seen`);
}
ws.close(); chrome.kill();
console.log(`${n} exchanges saved`);
