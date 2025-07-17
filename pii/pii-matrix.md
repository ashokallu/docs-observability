# PII Exposure Mode Matrix

**Last Updated:** 2025-07-17  
See ADR-0009 for governance rationale.

| Field | Dev | Staging | Prod | Metric Labels | Span Attr | Notes |
|-------|-----|---------|------|---------------|-----------|-------|
| User ID | Full | Hash | Hash | NO | Hash | |
| Email | Full | Domain | Domain | NO | Domain | |
| IP | Full | Truncate | Omit | NO | Hash | |
| Session Token | Redact | Redact | Redact | NO | NO | |
| Phone | Full | Redact | Redact | NO | Redact | |
| Order ID | Full | Hash | Hash | Template | Hash | |

Env flags: LOG_USER_ID_MODE, LOG_EMAIL_MODE, TRACE_PII_MODE.
