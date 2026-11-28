# cart.bundle.js

A small bundle for the Wakaru tests: three modules and an entry, minified, in the
shape webpack 5 writes for a production build. Wakaru reads it as `webpack5` and
splits it by its module table.

It was written by hand. The flake has no bundler or minifier, and nothing may be
downloaded, so the shape was typed out: a table of module functions keyed by number,
the `require` function `r` that runs each once, `r.d` for export getters, `r.o`, and
`r.r` to mark an ES module. No code was copied from webpack or any other project.

These are the modules it is the minified form of:

```js
// 318: src/api.js
const BASE = "https://api.shop.example/v1";
export function getCart(user) {
  return fetch(BASE + "/cart/" + user, { credentials: "include" }).then((r) => r.json());
}

// 642: src/money.js
export const money = (cents) => (cents / 100).toFixed(2) + " €";

// 907: src/main.js, the entry
import { getCart } from "./api.js";
import { money } from "./money.js";
async function show(user) {
  const cart = await getCart(user);
  document.title = cart.items.length + " items, " + money(cart.total);
}
show("me");
```

The euro sign is 3 bytes in UTF-8, so module 907 starts at a byte offset that differs
from its offset in characters. The file ends with one line break.
