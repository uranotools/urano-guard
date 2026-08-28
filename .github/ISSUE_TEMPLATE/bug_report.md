---
name: Bug Report / False Positive
about: Report a false positive, uncaught error, or bug in the SDK
title: '[BUG] '
labels: bug
---

**Describe the bug or False Positive**
A clear description of what happened.

**Inspector / Adapter Involved**
- Adapter (Express, Fastify, Edge, Native Http)
- Inspector (e.g. PromptInjection, MaliciousUrl, PaddingEvasion, ReplayGuard)

**Sample Payload (Sanitized)**
```json
{
  "example": "data"
}
```

**Expected Behavior**
Should this request have been ALLOWED or BLOCKED?
