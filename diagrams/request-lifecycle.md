---
title: Request Lifecycle – Context, Logging, Tracing, Metrics
last_updated: 2025-07-17
---

# Request Lifecycle Cheat Sheet

This doc ties code to diagrams: exactly *what happens where* in the observability middleware chain.

---

## 1. Lifecycle Diagram (Middleware Focus)

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant G as Gin Handler
  participant L as Logger Enricher
  participant Tr as Tracer
  participant Met as Metrics Recorder
  participant S as Service
  participant Err as Error Observer

  C->>G: HTTP Inbound
  G->>L: Build request logger (req id, method, route, remote addr)
  L->>Tr: Start server span + inject into ctx
  Tr->>S: Call downstream (ctx carries span)
  S-->>Tr: Return result/error
  Tr->>Err: If error, mark span error
  Err->>L: Structured log w/ error_kind, code
  Err->>Met: Increment errors_total{kind}
  Tr-->>G: End span
  Met-->>G: Observe RED
  G-->>C: HTTP Response
```

---

## 2. Instrumentation Checklist

- [ ] Use `context.Context` on every call path.
- [ ] At ingress, create **request‑scoped logger** (EAGER pattern).
- [ ] Inject **trace_id** + **span_id** into logger fields.
- [ ] Template the route (`/users/{id}`) before recording metrics.
- [ ] Convert status to class (`2xx`,`4xx`...).  
- [ ] Record duration histograms **after** response written.
- [ ] Observe errors *once* (middleware).

---

## 3. Code Hook Map

| Layer | Function | Obs Hook | Package |
|-------|----------|----------|---------|
| Gin Middleware | `LoggerMiddleware` | EAGER enrichment | `internal/api/middleware` |
| Gin Middleware | `TracingMiddleware` | Root span create | same |
| Gin Middleware | `MetricsMiddleware` | RED, cardinality | same |
| Gin Middleware | `ErrorHandlerMiddleware` | Single observation | same |
| Domain Service | Business logs | `log.LoggerFromContext` |
| Domain Service | Span child | `tracer.Start` |
| Repo / External | DB span, error wrap | repo pkg |

---

## 4. Performance Guardrails

- Avoid allocating new loggers per sub‑call.
- Use pre‑allocated arg slices (pool) in hot paths.
- Log at `debug` only in dev.
- Use sampling logger for noisy paths.

See performance dashboards in Grafana for validation.

