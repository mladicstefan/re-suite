# Trial 3: real websites

26 November 2026. Real traffic first, then the model: the capture format
and the endpoint rules in `ledger-core` were written after looking at
what these captures contain, and the trial then ran on them.

## Capture

`real-sites.capture.mjs` loads pages in headless Chromium over the
DevTools protocol and saves every HTTP exchange the browser makes, one
JSON file each. 21 page loads of four public sites (crates.io,
open-meteo.com, hn.algolia.com, pokeapi.co), no logins, gave 804
exchanges.

What real captures look like, and what the format took from it:

| Seen in the captures | Consequence |
| --- | --- |
| 211 of the first 230 exchanges were HTTP/2 and 13 HTTP/3: header names in lower case, plus `:method`, `:path` and `:authority`. HTTP/1.1 had mixed case. | Headers are a list of name and value, looked up without regard to case; method and URL are fields of their own. |
| Header names repeat (`server-timing`). | A list, not a map. |
| 42 bodies were binary, one was over 1 MiB, four 204 responses had none. | A body is text or base64, and optional. |
| Statuses were 200, 204 and 404. A 404 body has another shape than a 200 body. | A response-schema claim names its status. |
| 15 of 230 exchanges were JSON API calls; the rest were scripts, styles, fonts and images, across a dozen hosts. | An endpoint names its host, and captures of anything else are refused. |
| Parameters travel in the query string and in path segments. | An endpoint is `METHOD [host]/path` with `{name}` segments; the query is not part of it. |

## What held

Evidence was the JSON API exchanges plus twelve unrelated ones as noise.

| Claim | Held on | Attempts |
| --- | --- | --- |
| 200 responses to `GET crates.io/api/v1/crates/{name}`: a crate record | 6 | 3 |
| 404 responses to the same endpoint: a list of errors with a detail | 2 | 1 |
| 200 responses to `GET api.open-meteo.com/v1/forecast` | 4 | 3 |
| 200 responses to `GET pokeapi.co/api/v2/pokemon/{id}` | 5 | 2 |
| 200 responses to the Algolia search behind hn.algolia.com | 4 | 1 |

## What was caught

Each first guess came from one page load. The ledger refuted four of
them against the other captures, one mistake per attempt:

- crate `documentation` is not always null (`"https://docs.rs/regex" is
  not of type "null"`), and `homepage` is sometimes null;
- a forecast has `current` only if the request asked for it;
- a pokemon can hold items.

## Metrics

1. **Deliberately wrong claims caught: 14 of 15.** The one that held,
   "a crate record lists one version", is true of these captures: the
   site asks for `include=default_version` and gets exactly one. It is
   wrong for the endpoint in general, and no capture here can show that.
2. **Attempts per accepted claim: 10 for 5 (2.0)**, about 600 tokens of
   tool traffic per accepted claim. Schemas are bulky to send.
3. **Claims that passed and later failed:** not measured; every claim was
   filed on all of its captures at once.

## Trial 2's wrong answers, replayed

The simulated signed backend was re-recorded as exchanges and the four
wrong answers of trial 2 replayed. All four are now right: the true
score claim holds on mixed-case and lower-case captures, a claim under a
made-up endpoint and a claim replayed on another endpoint's requests are
refused as `evidence_not_applicable`, and a damaged base64 signature is
refuted. The true score claim stays held.

Captures that are not about a claim were refused in every case tried:
another status, another host, page-load noise, another method.

## Findings

- **Fixed: a counterexample could be 3,000 characters long.** The schema
  validator quotes the failing value. Details are cut at 300 characters.
- **Fixed afterwards: the response depends on the query string, and an
  endpoint ignored it.** The forecast has `current` only when asked for;
  a crate record has one version or all of them. An endpoint can now
  name query conditions: `?name`, `?name=value`, `?!name`. Re-run on
  these captures plus two crate records fetched without `include`: the
  unscoped "one version" claim is refuted, the same claim scoped to
  `?include=keywords,categories,downloads,default_version` holds on the
  six page-load captures, and a forecast claim scoped to `?current` can
  require `current` again and holds on the three captures that asked
  for it. Captures that do not meet the conditions are refused.
- **Fixed afterwards: a signature claim had no status.** A capture of a
  request the server rejected would have refuted a true claim about
  accepted requests. Captures answered with 400 or above are now refused
  as not applicable.
- **Fixed afterwards: the agent had to know which captures belong to an
  endpoint.** `add_evidence` now takes a HAR file and stores one piece
  of evidence per entry, and `ask about=evidence` lists the captures of
  an endpoint. The 804 exchanges of this trial, written as one 16 MB HAR
  file, import in a single call.
- **No real request signatures were found.** Public pages without a
  login do not sign requests, so the signature kind was only exercised
  on the simulation. The Algolia search sends an API key in a header,
  which is a different kind of claim.
- **Still open from trial 2:** schema sentences are all alike, and one
  counterexample per check.
