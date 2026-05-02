This vulnerability was discovered in a private program on HackerOne, which resulted in a $3,000 bounty.  

<img width="292" height="740" alt="Screenshot_20260503033458" src="https://github.com/user-attachments/assets/e79c92bf-87f1-4efc-9e1b-74565d9297c8" />


  
In the world of security, the most devastating bugs are often hidden in the simplest logic. Today, I’ll cover a **Full Account Takeover (ATO)** bug I found that wasn't about complex exploits, but a pure logic flaw in the backend.  
  
~The Root Cause: Stateless Trust  
Modern systems often use a "Stateless" approach to handle logins. The server issues a temporary `verificationId` to track the process. The vulnerability occurs when this ID is not "bound" to a specific user identity on the server side.  
  
~The Black-Box Hypothesis

Based on the server's behavior, I suspected the backend mapped the OTP code to the `verificationId` but failed to verify **which email** the ID was generated for.

The backend logic likely looked like this:

```plaintext
{
  "verificationId": "KC:6BE2634:7FD2...",
  "meta": {
    "otp_code": "123456",
    "is_verified": false
  }
}

```

### Analyzing the Flow

The login system had a two-step process:

**Step 1: Initiation**  
I entered my email to get an OTP and a tracking ID:  
`POST /public/auth/email` -> `{"loginId":"attacker@example.com"}`  
  
**Response:** `{"verificationId":"KC:6BE2..."}`

**Step 2: Verification**  
In this step, I noticed the application sends the `loginId` again in the request body.

### The Breakthrough: Identity Injection

I decided to swap my email with the victim's email at the final second.

**The Manipulated Request:**  
I had a valid code for my own email. I intercepted the request in Burp Suite and changed the `loginId`:

```plaintext
PUT /public/auth/email
{
  "loginId": "victim@example.com",  <-- Target email injected here
  "otp_code": "123456",             <-- Attacker's valid OTP
  "verificationId": "KC:6BE2..."    <-- Attacker's valid ID
}

```

### The Result: Full Takeover

The server responded with a 200 OK and issued a full suite of JWT tokens for the victim's account. The server verified that the code was correct for the verificationId, but it blindly trusted the loginId provided in the PUT body. I received the AccessToken, IdToken, and RefreshToken.
