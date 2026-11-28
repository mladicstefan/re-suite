# 3. Recover source from minified JavaScript

**What it is for.** A site's code reaches the browser bundled and minified: one file
holds many modules, with short names and no layout. This playbook splits a captured
script back into modules and makes each one readable, as files you read with your own
tools. It files no claim. Finding the API in that code is playbook 4.

**When it applies.** A session holds a script that no source tree was recovered from.

**It is all offline.** Wakaru reads the script's saved source. Nothing is sent to the
site.

## List the scripts

```
ask about=evidence subject=<session id>
```

One row per script: its id, its size, the address it was loaded from, and either the
tree already recovered from it or `no tree yet`. The query string of an address is
not shown.

Recover the site's own code first: an entry script, or a file under the site's build
path such as `/static/js/` or `/_next/static/`, with a hashed name. Leave a library
served as its own file, such as `jquery.min.js`, for later. What playbook 2 found
helps: Webpack, Vite and Next.js each name their bundles in their own way.

## Recover one

```
add_evidence kind=source_tree tool=wakaru inputs=["<script id>"]
```

A script is read once per version of Wakaru. Asking again starts no run and gives the
same reply.

## What comes back

```
4 modules, read as webpack5 and split structurally
files in /home/you/ledger.db.sources/<tree id>
largest: module-907.js 196 bytes, module-318.js 162 bytes, module-642.js 53 bytes
```

- Each module is `artifact` evidence of its own. The same module in another script or
  another version of the site is the same evidence.
- `structurally` means Wakaru read the bundler's own module table. `by a heuristic`
  means the bundle merged its modules into one scope, as Vite and Rollup do, and where
  one module ends is Wakaru's guess.
- `read as unknown` with one module means the script is no bundle Wakaru knows. You
  get the whole script made readable.
- The tree records which bytes of the script each module came from. That is how a
  request's stack frame is traced to its module (playbook 6).

## Read the files

The directory holds one file per module, at the path Wakaru gave it. Read and search
them with your own tools. Do not edit them: they are a copy of the evidence, written
once. If the directory is gone, the same `add_evidence` call lays it out again.

Names in the code are Wakaru's guesses. What a function does is your reading, not a
fact the ledger checked. Say so when you report it.

## Source maps

A row can say the script has a source map. Its original sources would beat anything
recovered here.

- **At an address.** Nothing here fetches it. Tell the person the address. Only they
  can get it, by capturing that address in a new session.
- **Inline.** Reading the original sources out of it is not built yet.

Recover the script with Wakaru meanwhile.

## What to do next

- Find the endpoints, GraphQL documents and keys the code names (playbook 4). It is
  not written yet: until it is, search the files yourself and say what you found.
- `ask about=playbooks` lists what applies now.
