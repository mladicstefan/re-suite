# 2. Fingerprint the stack

**What it is for.** Before you read any code, learn what the site is built on: its
framework, its server, its CDN, a bot wall, and the libraries the rules know. The
answer picks the next playbook.

**When it applies.** The ledger holds a session that no fingerprint run has read.

**It is all offline.** The Wappalyzer rules read the session's saved responses:
headers, cookies, HTML pages and the script addresses in them. Nothing is sent to
the site.

## Run it

```
add_evidence kind=technology_facts tool=fingerprint inputs=["<session id>"]
```

The session id is on the `evidence` line of the reply to `add_evidence kind=session`.
A session is read once per version of the tool; asking again returns the same facts.

## What comes back

The facts' id, the run that made them, and one line per host that answered:

```
shop.example: Cloudflare, Nginx 1.25.3, Next.js 14.2.3
```

A name is the one the rules use. A version is there only when the rules read one.
`nothing the rules know` means the host answered and no rule matched.

This is what the rules read in saved responses, not proof of what runs. A header can
lie, and a page can carry an old script tag. Script contents are not read, so a
library bundled into a script is not found.

## File what matters

```
propose claim={"kind": "uses_technology", "host": "shop.example", "technology": "Nginx", "version": "1.25.3"} evidence=["<facts id>"]
```

Leave out `version` to claim the technology alone. The claim holds when the facts
list it for that host. It is refuted, with what the rules did read there, when they
do not. Facts from a session the host did not answer in cannot check it. File the
findings your next step depends on, not every line.

## What to do next

- **A bot wall.** The reply says `bot wall or other security service`. Stop and tell
  the person what was found and on which host. The session may hold the wall's
  challenge instead of the site. Never try to get around it: do not study its scripts
  or cookies to pass it, and do not ask for a capture that hides what the browser is.
  Only the person decides what happens next, for example capturing in their own
  browser with `--headed`, or asking the site's owner.
- **A bundler or a JavaScript framework**, such as Webpack, Vite, Next.js, Nuxt.js,
  React or Vue.js. The code is in the session's scripts. Recover readable source from
  them (playbook 3), then find the API in that code (playbook 4).
- **A GraphQL marker**, such as GraphQL, Apollo or Hasura. The API speaks GraphQL
  (playbook 8).
- **Only a server or a CDN.** Map the API from the captured traffic (playbook 5).

Playbooks 4 onward are not written yet. Until they are, file the claims, say what was
found, and tell the person which playbook comes next.
