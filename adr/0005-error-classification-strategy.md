# Error Classification & Observation Strategy

---
**Status:** Accepted
**ADR ID:** 0005
**Date:** 2025-07-17
**Tags:** errors, alerting, api, observability
---
Two-level taxonomy: **Kind** + **Code**.
Kind maps to HTTP & alert posture. Code is stable machine identifier.

### Middleware Single-Observation-Point
On response finalize: log, metric, span, http response mapping.

### Example
ValidationError -> 400 no alert
UnavailableError -> 503 alert+retry
