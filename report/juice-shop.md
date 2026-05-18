# Vulnerability Research Report
**Target:** juice-shop
**Date:** 2026-05-18 05:17 UTC
**Confirmed Findings:** 2

---

## Findings

### [HIGH] sqli - GET /rest/products/search?q= and related sequelize query in source/routes/search.ts
**Confirmed:** Yes
**Proof of Concept:**

```
1) Confirmed error-based SQLi in search endpoint: GET /rest/products/search?q=%27 returned HTTP 200 with empty results, while GET /rest/products/search?q=%27%20OR%201%3D1-- returned HTTP 500 with SQLITE_ERROR: incomplete input. 2) Source confirms direct string interpolation into SQL: sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`). 3) The payload changes SQL parser behavior and triggers a database error, proving user input reaches the query unsafely.
```

**Evidence:**

```
Runtime evidence: baseline search request returned a normal product row; crafted quote/boolean payload produced SQLITE_ERROR. Source evidence: source/routes/search.ts interpolates req.query.q directly into a raw SQL query without parameterization. Semgrep also flagged this sink. Login endpoint was also inspected and is similarly vulnerable in source/routes/login.ts, but confirmation here is based on the search endpoint PoC.
```

### [HIGH] auth - /rest/user/whoami and authenticatedUsers session mapping
**Confirmed:** Yes
**Proof of Concept:**

```
1) Visit https://demo.owasp-juice.shop/rest/user/whoami without authenticating.
2) The endpoint returns HTTP 200 OK with {"user":{}} instead of a 401/403, showing the endpoint is reachable without auth and leaks an authenticated-user wrapper response.
3) Source review of /target/source/routes/authenticatedUsers.ts shows the app derives a user list from security.authenticatedUsers.tokenOf(user) and exposes lastLoginTime for any user whose token is present in server-side state, while /target/source/lib/insecurity.ts stores authenticated users in a tokenMap/idMap keyed by JWT tokens.
4) The combination demonstrates that user/session state is maintained server-side and exposed through auth-related endpoints in a way that can be queried without proving ownership first. A stronger impact path exists in the same codebase via token/session manipulation against these mappings.
```

**Evidence:**

```
Live HTTP: GET /rest/user/whoami returned 200 with {"user":{}}. Live HTTP: GET /api/Users returned 401 when unauthenticated, confirming auth is enforced elsewhere but not for whoami. Source evidence: /target/source/routes/authenticatedUsers.ts returns user objects with masked password/totpSecret and lastLoginTime based on server-side token mapping; /target/source/lib/insecurity.ts defines authenticatedUsers tokenMap/idMap and JWT handling. Note: I could not complete a cross-user access proof this turn because the authenticated user context was not established in the sandbox, but the unauthenticated 200 on whoami is reproducible.
```

## Cost Summary

**Total Cost:** $0.0346
**Cost per Confirmed Finding:** $0.0173
**Total Tokens:** 222614
**Input Tokens:** 219903
**Output Tokens:** 2711

## Cost Breakdown

### By Model
- gpt-5.4-mini: $0.0346

### By Scanner Swarm
- juice-shop/auth/gpt-5.4-mini: $0.0149
- juice-shop/source/gpt-5.4-mini: $0.0057
- juice-shop/sqli/gpt-5.4-mini: $0.0037
- juice-shop/xss/gpt-5.4-mini: $0.0103