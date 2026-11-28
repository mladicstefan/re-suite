# Trying the pinned web tools on real input

28 November 2026. Before any playbook is built on a tool, each one was run
once on real input from this machine. Nothing was sent anywhere.

**Input:** the trace viewer that ships inside Playwright, a Vite build with
no source maps: one 640 KB minified file, two of about 300 KB, a 6 KB
entry. For the fingerprint tool, one made-up response with common headers
and HTML.

| Tool | Version | What it did | Verdict |
| --- | --- | --- | --- |
| Wakaru | 1.17.0 | Split the 640 KB file into 105 readable modules in 2.5 s, with a `provenance.json` that maps each module to its byte range in the input | First choice for unbundling |
| webcrack | 2.16.0 | Handled the 6 KB file; crashed on the 640 KB one in its JSX step | Second choice, for obfuscated code only |
| ast-grep | 0.51.3 | The pattern `fetch($$$A)` found 15 calls in the minified files, with the address expression of each | The way to search code |
| retire.js | 6.1.2 | Found no library in the bundled files, which hold React, CodeMirror and xterm | Not for bundled code; not yet tried on a library served as its own file |
| jsluice | 2023 snapshot | Found 9 addresses, one of the 15 `fetch` calls | Dropped: unmaintained since 2024 and weaker than ast-grep here |
| Wappalyzer rules (wappalyzergo 0.3.11, through `ledger-fingerprint`) | | From saved headers and HTML: Cloudflare and its bot management, Next.js, Nginx 1.25.3, WordPress 6.4.2, jQuery 3.6.0, and what those imply | Works offline |

Not tried yet: mitmproxy, wabt, wasm-tools and prettier, which are pinned
for later playbooks, and any of the tools on an obfuscated bundle.
