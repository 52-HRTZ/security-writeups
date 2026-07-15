# From a `postMessage` Listener to OAuth Token Theft

If you ask me, `postMessage` is one of the most fun bug classes to hunt.

Most of the time you'll spend hours reading JavaScript just to end up
with another harmless message listener. But every once in a while, you
find one that makes you stop and think, *"Wait... this shouldn't be
doing that."*

That's exactly what happened here.

What started as a simple `postMessage` listener eventually turned into a
DOM XSS that could be used to obtain OAuth access tokens across six
different providers.

------------------------------------------------------------------------

# Understanding the Flow

Before jumping into the bug, here's a quick overview of how
`postMessage` is commonly used.

`postMessage` is commonly used when different browser windows need to
communicate with each other. You'll often see it in OAuth flows, where a
popup handles authentication and then sends the result back to the main
application.

While testing this target, I came across a feature that allowed users to
connect their Google Photos account and import photos directly into the
application.

From the user's perspective, the flow looked completely normal. After
clicking **"Connect Google Photos"**, the application first opened an
intermediate subdomain owned by the application. That subdomain then
launched the Google Photos OAuth flow.

Once authentication was complete, Google returned the OAuth response to
the same subdomain, which finished the authorization process and passed
the result back to the main application.

The authentication flow looked like this:

``` text
┌────────────────────┐
│ Main Application   │
└─────────┬──────────┘
          │
          │ Click "Connect Google Photos"
          ▼
┌────────────────────┐
│ OAuth Handler      │
│ (Subdomain)        │
└─────────┬──────────┘
          │
          │ Opens Google OAuth popup
          ▼
┌────────────────────┐
│ Google Photos      │
│ OAuth              │
└─────────┬──────────┘
          │
          │ User grants permission
          │
          │ OAuth Response (Code/Token)
          ▼
┌────────────────────┐
│ OAuth Handler      │
│ (Subdomain)        │
└─────────┬──────────┘
          │
          │ Completes authorization
          │
          │ Sends result to the main app
          ▼
┌────────────────────┐
│ Main Application   │
└────────────────────┘
```

At this point, everything looked perfectly normal. The interesting part
wasn't the OAuth flow itself---it was how the main application and the
OAuth handler communicated after authentication.

------------------------------------------------------------------------

# Digging into the OAuth Flow

At this point, I wanted to understand how the intermediate subdomain
received the OAuth response and passed it back to the main application.

Instead of starting the flow from the main site every time, I opened the
subdomain directly in a new tab.

The page itself looked almost empty. There was no login form, no UI,
nothing particularly interesting.

What immediately caught my attention was something else.

Although the main application only exposed **Google Photos**, the
JavaScript on this page already contained support for six different
providers:

-   Google
-   Facebook
-   Dropbox
-   Instagram
-   Flickr
-   Skydrive

It looked like the same OAuth handler was designed to support multiple
providers, even if some of them weren't yet exposed through the main
application's UI.

Whenever I investigate a JavaScript-heavy feature, the first thing I do
is start reading the JavaScript bundles. My goal isn't to look for
payloads---it's to understand how the feature actually works.

After a few minutes of tracing the code, one thing immediately stood
out.

The page accepted messages from its opener without performing any origin
validation.

In other words, if an attacker could become the opener of this page,
they could freely send `postMessage` events to it.

While tracing the message handler, I found the following code:

``` javascript
t = function() {
    var e, t, r;
    t = "logged_in:" + document.location.href;
```

This was an interesting clue.

The handler expected messages prefixed with `logged_in:` and eventually
used the supplied value to update the current location.

My first test was intentionally simple.

**Could I send my own `logged_in:` message?**

I created a minimal proof of concept:

``` html
<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC</title>
</head>
<body>
    <iframe id="target-frame" src="https://sub.target.com" width="800" height="600"></iframe>
    <script>
        document.getElementById('target-frame').onload = function() {
            document.getElementById('target-frame').contentWindow.postMessage(
                'logged_in:javascript:alert(document.domain)', '*'
            );
        };
    </script>
</body>
</html>
```

As soon as the iframe finished loading, the payload executed.

There was no origin validation, no whitelist, and no security check
preventing an attacker-controlled page from sending arbitrary messages.

At this point, I had a working **DOM XSS via postMessage**.

For many reports, this is where the research ends.

For me, this was only the starting point.

------------------------------------------------------------------------

# Looking Beyond `alert(1)`

A JavaScript popup is nice for proving code execution, but it rarely
represents the real impact.

The interesting part was that this wasn't just any page.

This subdomain was responsible for handling OAuth responses from
multiple identity providers.

That immediately raised another question:

> **Could the XSS be executed during the OAuth flow itself?**

While analyzing one of the providers, I noticed that the OAuth response
was returned through the URL fragment (`#access_token=...`).

That gave me the idea for the final exploit.

Instead of simply executing JavaScript, I could:

1.  Embed the OAuth handler inside an attacker-controlled page.
2.  Trigger the vulnerable `postMessage` handler.
3.  Execute JavaScript in the OAuth handler's origin.
4.  Launch the provider's OAuth popup.
5.  Wait for the OAuth flow to complete.
6.  Read the returned access token from the fragment.
7.  Exfiltrate the token to the attacker.

The exploitation flow looked like this:

``` text
Attacker Page
      │
      │ iframe
      ▼
OAuth Handler
      │
      │ postMessage("logged_in:javascript:...")
      ▼
DOM XSS
      │
      │ Opens OAuth popup
      ▼
OAuth Provider
      │
      │ User authenticates
      ▼
OAuth Handler
      │
      │ Receives access token
      ▼
Injected JavaScript
      │
      │ Reads token
      ▼
Attacker
```

## Final Exploit

``` html
<!-- Final exploit code goes here -->
```

After a few iterations and some debugging, the exploit worked as
expected.

The exact same technique was also applicable to Facebook, Flickr,
Dropbox, Instagram, and Skydrive, so I've kept the write-up focused on a
single provider to avoid repeating the same flow multiple times.

------------------------------------------------------------------------

# Final Thoughts

One thing I've learned from bug hunting is that the best bugs are often
hidden behind complex application flows.

Before looking for vulnerabilities, spend time understanding how the
feature actually works. Once you understand the application's logic, the
bugs have a way of revealing themselves.
