#!/usr/bin/env python3
"""One call to the ledger's MCP server, for an agent that has a shell and no MCP client.

    ledger-call.py <ledger.db> <tool> '<json arguments>'     arguments as JSON text
    ledger-call.py <ledger.db> <tool> @arguments.json        or read from a file
    ledger-call.py <ledger.db> schema                        the tools and their input schemas

The server binary is $LEDGER_MCP. Every call is appended to <ledger.db>.session.jsonl."""
import json, os, subprocess, sys, time


def call(db, tool, args):
    server = subprocess.Popen([os.environ["LEDGER_MCP"], db], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def send(message):
        server.stdin.write(json.dumps(message) + "\n")
        server.stdin.flush()

    def reply(to):
        for line in server.stdout:
            message = json.loads(line)
            if message.get("id") == to:
                return message
        sys.exit("the ledger server stopped without answering")

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "ledger-call", "version": "0"}}})
    reply(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    if tool == "schema":
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        answer = json.dumps(reply(2)["result"]["tools"], indent=1)
    else:
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": tool, "arguments": args}})
        message = reply(2)
        if "error" in message:
            answer = "REJECTED " + message["error"]["message"]
        else:
            answer = "\n".join(part.get("text", "") for part in message["result"]["content"])
    server.stdin.close()
    server.wait()
    return answer


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    db, tool = sys.argv[1], sys.argv[2]
    text = sys.argv[3] if len(sys.argv) > 3 else "{}"
    if text.startswith("@"):
        text = open(text[1:]).read()
    args, start = json.loads(text), time.monotonic()
    response = call(db, tool, args)
    if tool != "schema":
        with open(db + ".session.jsonl", "a") as log:
            log.write(json.dumps({"tool": tool, "args": args, "response": response,
                                  "request_chars": len(text), "response_chars": len(response),
                                  "seconds": round(time.monotonic() - start, 4)}) + "\n")
    print(response)
