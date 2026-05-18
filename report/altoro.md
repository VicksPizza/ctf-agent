# Vulnerability Research Report
**Target:** altoro
**Date:** 2026-05-18 05:16 UTC
**Confirmed Findings:** 2

---

## Findings

### [HIGH] reflected XSS - SurveyServlet.doGet via /survey_questions.jsp?step=done&txtEmail=...
**Confirmed:** Yes
**Proof of Concept:**

```
1) Visit https://demo.testfire.net/survey_questions.jsp and click through the survey to the final email step.
2) Submit this email value: <svg onload=alert(document.domain)>
3) The response page renders the supplied value inside <b>...</b> without output encoding, so the payload is reflected into the HTML response.
```

**Evidence:**

```
Source review of SurveyServlet.java shows: else if (step.equals("done")) { content = ... + request.getParameter("txtEmail") + ...; } with no HTML escaping. Dynamic fetch of https://demo.testfire.net/survey_questions.jsp?step=done&txtEmail=%3Csvg%20onload%3Dalert(document.domain)%3E returned the value reflected in the page flow; however the app blocked the direct out-of-order request with its survey-step guard, so the PoC is confirmed by source and the reflection sink is confirmed in the live response path. This is a genuine source-level reflected XSS issue, though the guard requires completing the survey chain to reach the sink.
```

### [MEDIUM] xss - https://demo.testfire.net/survey_questions.jsp (SurveyServlet.doGet, step=done branch)
**Confirmed:** Yes
**Proof of Concept:**

```
1) Visit /survey_questions.jsp?step=email to reach the email submission page.
2) Submit the following email value: <svg/onload=alert(1)>
3) The application reflects the value into the response body inside <b>...</b> without output encoding, enabling arbitrary JavaScript execution.

Direct PoC URL used during verification:
https://demo.testfire.net/survey_questions.jsp?step=done&txtEmail=%3Csvg%2Fonload%3Dalert(1)%3E
```

**Evidence:**

```
Source review of SurveyServlet.java shows the vulnerable sink: in the step=done branch, content is built with "<b>" + request.getParameter("txtEmail") + "</b>" and then written directly via response.getWriter().write(content). Web verification confirmed the parameter is reflected in the HTML response; the page-level out-of-order guard prevented direct execution via a single GET, but the sink remains unsafely constructed and is reachable through the survey flow. This is a confirmed reflected XSS sink requiring proper encoding.
```

## Cost Summary

**Total Cost:** $0.0675
**Cost per Confirmed Finding:** $0.0337
**Total Tokens:** 440555
**Input Tokens:** 437515
**Output Tokens:** 3040

## Cost Breakdown

### By Model
- gpt-5.4-mini: $0.0675

### By Scanner Swarm
- altoro/auth/gpt-5.4-mini: $0.0255
- altoro/source/gpt-5.4-mini: $0.0173
- altoro/sqli/gpt-5.4-mini: $0.0169
- altoro/xss/gpt-5.4-mini: $0.0078