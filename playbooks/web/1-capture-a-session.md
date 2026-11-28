# 1. Capture a session

**What it is for.** Every other web playbook reads a session: one visit to the site
in Chromium, with every exchange in the order it was sent, the script and line that
sent each request, and the source of every script the pages ran.

**When it applies.** The ledger holds no session yet, or the one it holds does not
reach the part of the site you need. Everything else is done on saved evidence; this
is the one step that contacts the site.

**You cannot run the capture.** Only a person at a terminal can. The tool asks them
to type the first host before anything is sent, and it stops when nobody is there to
answer. Do not try to get past that question, and do not fetch the site yourself.

## Ask the person to run this

From the re-suite checkout:

```
nix develop -c cargo run --release -p ledger-cli --bin ledger-capture -- \
  web --host <host> [--host <host> ...] [--headed] <file> <address> ...
```

- `--host` once for each host they approve: `shop.example`, or `127.0.0.1:8080` with
  its port. A request to any other host is refused before it is sent.
- `--headed` opens a window, so they can log in and use the site themselves. The
  capture ends when they close the browser. Without it, each address loads until the
  page settles.
- Every address must be on an approved host. `<file>` must not exist yet.

Say which hosts you need and why. Ask for as few as the task needs.

## What comes back

The tool prints the file it wrote, how many exchanges and scripts it holds, and the
blocked hosts. When the person gives you the file, store it:

```
add_evidence kind=session path=<file>
```

The reply counts the exchanges and scripts, lists the approved and blocked hosts,
and names the session's evidence. Each exchange is now `http_exchange` evidence and
each script's source is `artifact` evidence, named in the session by id.

## What to do next

- If a blocked host matters, tell the person what it is and why. Only they can
  approve it, by capturing again with `--host` for it.
- `ask about=evidence subject="GET <host>/<path>"` lists the captures of an endpoint.
- `ask about=playbooks` lists what applies now.
