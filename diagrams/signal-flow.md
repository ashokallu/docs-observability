---
title: Telemetry Signal Flow – Logs, Metrics, Traces
last_updated: 2025-07-17
---

# Telemetry Signal Flow

This doc shows how each telemetry signal originates in code, moves through middleware, and lands in its storage backend. Use it when instrumenting *new* features.

---

## 1. Unified Signal Fanout (Context‑First)

```mermaid
flowchart LR
  subgraph App["Go App"]
    direction TB
    MW[Obs Middleware] --> SVC[Service Layer]
    SVC --> REPO[Data / External Calls]
  end

  App --> COL[OTel Collector]

  COL -->|metrics| PROM[(Prometheus / Cloud Monitoring)]
  COL -->|traces| TEMPO[(Tempo / Cloud Trace)]
  COL -->|logs| LOGS[(Loki / Cloud Logging)]

  PROM --> GR[Grafana]
  TEMPO --> GR
  LOGS --> GR
```

---

## 2. Request Lifecycle With Signal Hooks

```mermaid
sequenceDiagram
  autonumber
  participant CL as Client
  participant API as Gin Router
  participant MW as Obs Middleware
  participant SVC as Domain Service
  participant OC as OTel Collector
  participant P as Prometheus
  participant T as Tempo
  participant L as Logs

  CL->>API: HTTP Request
  API->>MW: Enter middleware
  MW->>MW: Extract / create Trace & Span
  MW->>MW: Enrich Logger (req id, user hash, trace id)
  MW->>MW: Start RED timers
  MW->>SVC: Call service w/ context
  SVC-->>MW: Result / error
  MW->>MW: Observe error (single point)
  MW-->>API: Write response
  MW->>OC: OTLP batch (metrics/logs/traces)
  OC-->>P: Metrics scrape / push
  OC-->>T: Spans export
  OC-->>L: Log export
```

---

## 3. Source‑of‑Truth Table

| Signal | Generated Where | Transport | Backend | Query Tool | Retention | Notes |
|--------|----------------|-----------|---------|------------|-----------|-------|
| **Logs** | Middleware + domain services via `log.Logger` | stdout → Collector | Loki / Cloud Logging | Grafana Logs / GCP Logs Explorer | 7d dev / 30d prod | PII redaction |
| **Metrics** | Middleware (RED), domain (business) | scrape (Prom), OTLP (Cloud) | Prometheus / GCM | Grafana / Cloud Metrics Explorer | 14d dev / 13mo prod (rollup) | Cardinality budget |
| **Traces** | Middleware span root + service spans | OTLP HTTP | Tempo / Cloud Trace | Tempo UI / GCP Trace | 3d dev / 7d prod | Sampling active |

---

## 4. Error Correlation Hook Points

- Structured error created in domain (`AppError`)
- Returned up stack; *not* logged in leaf functions
- Observed once in middleware: span error + log + metrics counter increment
- Error code ↔ HTTP status ↔ alert routing

---

See `request-lifecycle.md` for code‑level instrumentation patterns.
