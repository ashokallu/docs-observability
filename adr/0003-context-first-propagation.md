# Context-First Propagation Policy

---
**Status:** Accepted
**ADR ID:** 0003
**Date:** 2025-07-17
**Tags:** go, context, tracing, logging
---
Always pass `context.Context` first. Enables tracing, logging enrichment, cancellation, deadlines.

### Rules
(1) `ctx context.Context` is 1st param after receiver.
(2) Never store ctx in struct fields.
(3) Do not pass nil ctx.
(4) Use derived ctx for timeouts.

### Middleware Hooks
- LoggerFromContext
- SpanFromContext
- Auth claims
