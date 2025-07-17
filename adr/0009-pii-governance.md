# PII Governance & Exposure Modes

---
**Status:** Accepted
**ADR ID:** 0009
**Date:** 2025-07-17
**Tags:** security, pii, logging, compliance
---
Tiered redaction strategy controlling PII surfaces per env.

See ../pii/pii-matrix.md for field-by-field matrix.
Environment flags: LOG_USER_ID_MODE, LOG_EMAIL_MODE, TRACE_PII_MODE.

Never include PII in metrics labels.
