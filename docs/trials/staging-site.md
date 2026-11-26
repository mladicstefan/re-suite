# Trial 5: the staging site

26 November 2026. A trial on a live site the owner approved as a target.
Its address was given at run time and is written nowhere in this
repository; the session record is not kept here either, because it
echoes full addresses.

## Setup

- **Capture:** `real-sites.capture.mjs`, five page loads in headless
  Chromium: the home page, three linked pages, and one address that
  does not exist. 101 exchanges, 86 of them from the site itself and 15
  from a third party the pages load a script from.
- **The site:** server-rendered pages with script chunks, images and
  fonts. No JSON API is called on a page load, so the claims are about
  statuses and headers.
- **Agent, ledger:** as before. Claude filed every claim through the
  real `ledger-mcp` binary; the ledger was on tmpfs. Endpoints were
  written without a host.

The owner's main site was tried first. It sits behind a bot wall that
turned the headless browser away, and that was not worked around.

## What held

| Claim | Held on |
| --- | --- |
| One-segment paths answer 200 or 404 | 18 captures |
| Their 200 responses send `strict-transport-security` with a max-age | 17 |
| Their 200 responses send `x-frame-options: DENY` | 17 |
| The 404 page sends `x-frame-options: DENY` too | 1 |
| The home page itself is HTML | 1 |
| The home page is served from the framework's cache | 1 |
| Data requests (`?_rsc`) carry `rsc: 1` | 8 |
| Data requests carry `next-router-prefetch: 1` | 8 |
| Script chunks only answer 200 | 55 |
| Script chunks are cached as immutable | 55 |

## What was caught

Each first guess was made from the home page alone.

- **"One-segment paths only answer 200."** Refuted by the address that
  does not exist: `answered 404`.
- **"They are HTML."** Refuted: `GET /{page}` also covers the logo, the
  icon and other files in the site's root, 14 of 17 captures.
- **"They come from the framework's cache."** Refuted for the same
  reason: files are not pages.
- **"The home page is HTML."** Refuted by 8 of 9 captures: without a
  query condition, `GET /` also covers the page's data requests. The
  claim holds once the endpoint is written `GET /?!_rsc`.

## Metrics

1. **Deliberately wrong claims caught: 8 of 8.**
2. **Attempts per accepted claim: 15 proposals for 11 accepted claims
   (1.36)**, about 120 tokens of tool traffic per accepted claim. Header
   and status claims are small.
3. **Claims that passed and later failed:** none staged. One true claim
   was refuted for a wrong reason; see the first finding.

## Findings

- **Fixed: the capture was not what the server sent.** On the first
  capture, "every 200 response sends `strict-transport-security`" was
  refuted by 6 of 17 captures. The site was not at fault: a file loaded
  again on a later page came from the browser's cache, and Chromium
  drops that header from cached responses. With the cache disabled all
  86 of the site's responses carry it and the claim holds. A capture is
  only evidence of what its tool recorded.
- **Added: a response-header claim kind.** Before it, almost nothing
  about this site could be claimed.
- **Added: `propose` on all captures.** The evidence listing returns
  every capture of an endpoint; a claim about status 200 was refused
  nine times in a row because one of them was a 404. `propose` can now
  pick the captures a claim is about by itself.
- **Fixed: unrelated claims were called revisions.** A claim about one
  header was reported as replacing a refuted claim about another header
  of the same endpoint.
- **Open: an endpoint template cannot say "pages only".** `GET /{page}`
  matches any one-segment path, files included. Telling them apart
  needs the response's content type as part of what a claim covers.
- **Open: nothing can be claimed about a page as a whole.** Which hosts
  a page load contacts, for instance: these pages load a script from a
  third party, and no claim kind can say "and from nowhere else".
- **Open: HTML is opaque.** Titles, links and forms are in the captures
  and no claim kind reads them.
