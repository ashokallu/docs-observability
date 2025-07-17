---
title: Architecture Overview – Go Observability Mastery
last_updated: 2025-07-17
---

# Architecture Overview

This document provides the **end‑to‑end high‑level system view** for the Go Observability Mastery reference implementation. It shows the *runtime data plane* (requests flowing through the app) and the *telemetry control plane* (signals exported to the observability stack).

---

## 1. High‑Level Runtime + Telemetry (Compact)

```mermaid
flowchart LR
  subgraph Client
    U[User / CLI / Test Harness]
  end

  subgraph App["Go Monolith API (Gin)"]
    H[HTTP Router + Middleware]
    D[Domain Services]
  end

  U -->|HTTP| H --> D
  D --> OC[OTel Collector]

  %% telemetry fanout
  OC -->|metrics| P[(Prometheus)]
  OC -->|traces| Te[Tempo]
  OC -->|logs| Lo[Loki / Log Sink]

  %% viz
  P --> Gr[Grafana]
  Te --> Gr
  Lo --> Gr
```

---

## 2. Expanded – With Local vs Cloud Personas

```mermaid
flowchart TB
  %% define styles
  classDef local fill:#d8fdd8,stroke:#0a0,color:#000;
  classDef cloud fill:#d8e8ff,stroke:#06c,color:#000;
  classDef prod fill:#ead8ff,stroke:#7057ff,color:#000;
  classDef saas fill:#ffe5cc,stroke:#ff8b19,color:#000;

  %% nodes
  Dev[(Developer Laptop)]:::local
  VS["VS Code Dev Container"]:::local
  LocalAPI["API (Gin) - Local"]:::local
  LocalOC["OTel Collector - Local"]:::local
  LocalProm[(Prometheus - Local)]:::local
  LocalTempo[(Tempo - Local)]:::local
  LocalLogs[(Local Logs / STDOUT)]:::local
  LocalGraf[Grafana - Local]:::local

  subgraph GCP["GCP Project – Staging / Prod"]
    CR[Cloud Run Service]:::cloud
    GCP_OC["Managed OTel Collector / Ops Agent"]:::cloud
    GMon[(Cloud Monitoring Metrics)]:::cloud
    GTrace[(Cloud Trace)]:::cloud
    GLog[(Cloud Logging)]:::cloud
    BigQ[(BigQuery Export)]:::cloud
  end

  subgraph SaaS["Optional External SaaS"]
    DD[(Datadog)]:::saas
    NR[(New Relic)]:::saas
    PD[(PagerDuty)]:::saas
    Sen[(Sentry)]:::saas
  end

  Dev --> VS --> LocalAPI --> LocalOC
  LocalOC --> LocalProm
  LocalOC --> LocalTempo
  LocalOC --> LocalLogs
  LocalProm --> LocalGraf
  LocalTempo --> LocalGraf
  LocalLogs --> LocalGraf

  LocalAPI -. "deploy CI/CD" .-> CR
  LocalOC -. "ship telemetry" .-> GCP_OC
  GCP_OC --> GMon
  GCP_OC --> GTrace
  GCP_OC --> GLog
  GMon --> BigQ
  GTrace --> BigQ
  GLog --> BigQ

  GMon -. "export" .-> DD
  GTrace -. "export" .-> NR
  GLog -. "error feed" .-> Sen
  GMon -. "alert" .-> PD
```

---

## 3. Environment Swimlane – Request + Telemetry Path

```mermaid
sequenceDiagram
  autonumber
  participant U as User / Client
  participant G as Gin API
  participant M as Obs Middleware
  participant S as Service Layer
  participant OC as OTel Collector
  participant B as Backends (Prom/Tempo/Logs)
  participant Gr as Grafana / UI

  U->>G: HTTP Request
  activate G
  G->>M: Enter middleware chain
  M->>M: Create request-scoped logger (EAGER)
  M->>M: Extract / create Trace + Span
  M->>M: Enrich Context (user, req id, pii mode)
  M->>S: Call domain service w/ ctx
  activate S
  S-->>M: Response / error
  deactivate S
  M-->>G: Record metrics, finalize span, log
  G-->>U: HTTP Response
  deactivate G
  M-->>OC: OTLP batch (metrics/logs/traces)
  OC-->>B: Export fanout
  Gr-->>B: Query & visualize
```

---

## 4. Data Plane vs Telemetry Plane

Your production deployment separates *user‑facing traffic* from *observability egress*. Telemetry exporters should be non‑blocking; backpressure / retries handled in the Collector layer; metric cardinality enforced at instrumentation time.

---

## 5. Trace‑Log Correlation Points

1. **Request ID** generated at ingress (fallback).  
2. **Trace & Span IDs** injected into logger fields in middleware.  
3. **Error Observation Point** ensures *single* metrics increment + span error + structured log.  
4. **User Hash / Pseudonym** optional (compliance mode).  

---

See also: `request-lifecycle.md` for a line‑by‑line breakdown of middleware enrichment.
