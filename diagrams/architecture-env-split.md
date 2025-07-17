---
title: Environment Split – Local vs Staging vs Production
last_updated: 2025-07-17
---

# Environment Split Guide

This doc visually contrasts **Local Dev**, **Shared Staging**, and **Production Cloud** telemetry flows so teams understand *what runs where*, *what's mocked vs managed*, and *what changes when you promote builds*.

---

## Legend

- **Green** – Runs on developer laptop (Docker Compose)
- **Blue** – Shared staging environment (GCP project `-staging`)
- **Purple** – Production environment (GCP project `-prod`)
- **Orange** – Optional SaaS vendor integration (Datadog, Sentry, PagerDuty, etc.)

---

## Combined Environment Map

```mermaid
flowchart LR
  classDef dev fill:#d8fdd8,stroke:#0a0,color:#000;
  classDef stg fill:#d8e8ff,stroke:#06c,color:#000;
  classDef prd fill:#ead8ff,stroke:#7057ff,color:#000;
  classDef saas fill:#ffe5cc,stroke:#ff8b19,color:#000;

  subgraph Dev["Local Dev"]
    LAPI["API (Gin) - Dev"]:::dev
    LOC["OTel Collector - Dev"]:::dev
    LP[("Prometheus - Dev")]:::dev
    LT[("Tempo - Dev")]:::dev
    LL[("Logs / STDOUT")]:::dev
    LG["Grafana - Dev"]:::dev
  end

  subgraph Stg["GCP Staging"]
    SRV["Cloud Run Staging"]:::stg
    SOC["Collector / Ops Agent"]:::stg
    SM[("Cloud Monitoring")]:::stg
    ST[("Cloud Trace")]:::stg
    SL[("Cloud Logging")]:::stg
  end

  subgraph Prd["GCP Production"]
    PRV["Cloud Run Prod"]:::prd
    POC["Collector / Ops Agent"]:::prd
    PM[("Cloud Monitoring")]:::prd
    PT[("Cloud Trace")]:::prd
    PL[("Cloud Logging")]:::prd
  end

  subgraph SaaS["Optional SaaS"]
    DD[("Datadog")]:::saas
    NR[("New Relic")]:::saas
    PD[("PagerDuty")]:::saas
    Sen[("Sentry")]:::saas
  end

  LAPI --> LOC
  LOC --> LP
  LOC --> LT
  LOC --> LL
  LP --> LG
  LT --> LG
  LL --> LG

  LAPI -. "CI/CD" .-> SRV
  SRV --> SOC
  SOC --> SM
  SOC --> ST
  SOC --> SL

  SRV -. "promote" .-> PRV
  PRV --> POC
  POC --> PM
  POC --> PT
  POC --> PL

  PM -. "export" .-> DD
  PT -. "export" .-> NR
  PL -. "export errors" .-> Sen
  PM -. "alerts" .-> PD
```

---

### Promotion Rules

| Signal | Dev | Staging | Production | Notes |
|--------|-----|---------|------------|-------|
| Metrics | Local Prom | Cloud Monitoring | Cloud Monitoring | Export to Datadog optional |
| Traces | Local Tempo | Cloud Trace | Cloud Trace | Sample rates differ by env |
| Logs | stdout / file | Cloud Logging | Cloud Logging | PII mode strict in prod |
| Alerts | none / local | test PD integration | prod PD escalation | Controlled via Terraform |

---

### Sampling Matrix (default)

| Env | Sampling | Error Override | High‑Value Ops | Notes |
|-----|----------|----------------|----------------|-------|
| Dev | 100% | N/A | N/A | Learn everything |
| Staging | 10% | 100% always | 50% targeted | Perf cost reduction |
| Prod | 1% base | 100% errors | 10% curated | Budget aware |

---
