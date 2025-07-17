---
title: Reusable Mermaid Diagram Snippets
last_updated: 2025-07-17
---

# Mermaid Snippets Library

Copy/paste blocks below into READMEs, PRs, or Slack conversations. All have been validated in GitHub Markdown preview.

---

## Compact Signals Fanout

```mermaid
flowchart LR
  App[Go API] --> OC[OTel Collector]
  OC -->|metrics| P[(Prometheus)]
  OC -->|traces| Te[Tempo]
  OC -->|logs| Lo[Loki]
  P --> Gr[Grafana]
  Te --> Gr
  Lo --> Gr
```

---

## Request Lifecycle Sequence

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant G as Gin
  participant M as Middleware
  participant S as Service
  participant OC as Collector
  participant B as Backends

  C->>G: HTTP req
  G->>M: wrap ctx
  M->>M: start span + logger
  M->>S: call service
  S-->>M: result/error
  M->>OC: emit telemetry
  G-->>C: response
```

---

## Env Split Mini

```mermaid
flowchart LR
  Dev[Local] --> Stg[Staging] --> Prod[Prod]
  Dev -->|CI| Stg
  Stg -->|Promote| Prod
```

---

If you discover a snippet that breaks GitHub rendering, open an issue and paste the failing snippet so we can patch it.

---
