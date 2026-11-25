# Trial 2: web traffic

26 November 2026. The same exercise as trial 1, for the two web claim
kinds: request signatures and response schemas.

## Setup

- **Simulated backend:** `web-api.sim.py` runs a toy game backend on
  localhost and a client that calls four endpoints eight times each. The
  server saves every request it receives and the client every response,
  as a proxy would. Three endpoints sign the body (HMAC-SHA256 as hex,
  HMAC-SHA1 as base64, MD5 of key and body as upper-case hex); the fourth
  signs a timestamp and the body together.
- **Real captures:** ten responses from GitHub's public
  `GET /repos/{owner}/{repo}`, fetched once with plain `curl`.
- **Variants made from the captures:** the score requests with header
  names in lower case, as an HTTP/2 capture has them, and the purchase
  requests with the base64 signature's case changed, which makes the
  signature invalid.
- **Agent, ledger, record:** as in trial 1. Claude filed every claim
  through the real `ledger-mcp` binary; the ledger was on tmpfs;
  `web-api.session.jsonl` has every call except the 82 `add_evidence`
  calls. The keys in it are the simulation's own.

The simulation was written by the same agent that then "analysed" it, so
this trial measures the ledger, not the difficulty of the analysis.

## What held

| Claim | Held on |
| --- | --- |
| Score requests carry HMAC-SHA256 of the body in `X-Signature`, hex | 8 requests |
| Purchase requests carry HMAC-SHA1 of the body in `X-Sig`, base64 | 8 requests |
| Legacy requests carry MD5 of key and body in `X-Check`, hex | 8 requests |
| Score responses match a closed schema with typed fields and a rank of 1 to 97 | 8 responses |
| Purchase responses: `gift_from` is a string or null | 8 responses |
| GitHub repository records: sixteen typed fields, `organization` optional | 10 responses |

## What was caught

- **Purchase signature guessed as hex.** Refuted, with the header value
  and the recomputed value side by side; the claim with base64 held.
- **`gift_from` is always null.** Held on the first two responses,
  refuted on all eight: `"friend" is not of type "null" at
  /item/gift_from`.
- **Every repository has an `organization`.** A schema written from one
  organisation-owned repository was refuted by a user-owned one.
- **The session endpoint signs only the body.** Correctly refuted. The
  true scheme, a MAC over timestamp and body, cannot be written as a
  claim at all.

## Metrics

1. **Deliberately wrong claims caught: 19 of 19.** Nine signature claims
   (wrong key, algorithm, encoding or header) and ten schema claims
   (wrong type, bound, enum, pattern or required field).
2. **Attempts per accepted claim: 10 hypotheses for 6 accepted claims
   (1.67).** Tool input and output for the session's 16 own proposals
   was 12,167 characters, about 500 tokens per accepted claim.
3. **Claims that passed and later failed: 1 of 1.** The `gift_from`
   claim above.

## Wrong answers from the ledger

Four results were wrong, two in each direction.

- **Fixed: a true claim refuted by header case.** The score claim names
  `X-Signature`; the lower-case captures have `x-signature`, and the
  checker reported the header missing. Header names are now matched
  without regard to case.
- **Fixed: an invalid signature accepted.** Signatures were compared
  without regard to case for both encodings. The purchase requests with
  a damaged base64 signature "held". Only hex ignores case now.
- **Open: the claimed endpoint is never checked.** A capture records
  headers and a body, not the method, URL or status. The score claim
  filed under `/api/v9/nowhere` held on the score requests.
- **Open: unrelated evidence refutes a true claim.** Replaying the score
  claim on purchase requests refuted it ("header missing"), and one
  refuted verdict makes a claim refuted for good. In the trial ledger the
  true score claim ends up refuted. This is the same gap as the previous
  point: nothing ties a capture to an endpoint.

## Other findings

- **A signature claim can only say "MAC of the body".** Timestamps,
  nonces, paths and query strings in the signed input are common and
  cannot be expressed.
- **Schema sentences are all alike.** Every schema claim reads "Responses
  from X match the recorded JSON Schema", so the ten wrong schema claims
  and the true one cannot be told apart in a list.
- **One counterexample per check.** A schema with several mistakes needs
  one round trip per mistake.
- **A root-level failure reads "... is a required property at"** with
  nothing after "at".
- **The signing key is in the claim**, so it is in the event log and in
  this session record. Already an open question in the roadmap.
