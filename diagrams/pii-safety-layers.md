---
title: PII Safety Layers & Data Classification
last_updated: 2025-07-17
---

# PII Safety Layers

Observability frequently leaks personal data. This doc defines **data classes**, **allowed exposure modes**, **redaction responsibilities**, and **runtime controls** that apply across all services that adopt the Go Observability Mastery stack.

---

## 1. Data Classification Matrix

| Class | Examples | Allowed in Logs | Allowed in Metrics | Allowed in Traces | Notes |
|-------|----------|----------------|--------------------|-------------------|-------|
| **Class 0 (Safe)** | http method, route template, status class | ✅ | ✅ | ✅ | Always OK |
| **Class 1 (Low Sensitivity)** | hashed user id, feature flag name, tier | ✅ (masked) | ✅ (enum label) | ✅ | Hash or enum only |
| **Class 2 (Moderate)** | email domain, org name | ✅ (domain only) | ⚠️ (enum whitelist) | ✅ (attr redacted) | No full email |
| **Class 3 (High)** | full email, IP, internal ids | ❌ (unless debug+dev) | ❌ | ⚠️ (redacted in attr) | Allowed only in secured trace attrs |
| **Class 4 (Restricted)** | PII/PHI/PCI: SSN, CC#, DOB | ❌ | ❌ | ❌ | Strip at ingress |

---

## 2. Runtime PII Modes

| Mode | Logging Behavior | Trace Attr Behavior | Default Env |
|------|------------------|--------------------|-------------|
| `full` | full user ids, emails | full | *local only* |
| `redact` | user hash, email domain only | hashed | *staging* |
| `none` | no user fields recorded | none | *production high compliance* |

---

## 3. Data Flow Redaction Points

```mermaid
flowchart LR
  U[(Inbound Request Data)]
  F[Field Parser / Auth Layer]
  L[Logger Enricher]
  T[Span Attr Filter]
  M[Metrics Label Filter]
  E[Exporter / Collector]
  B[(Backends)]

  U --> F --> L --> T --> M --> E --> B
  classDef red fill:#ffe5e5,stroke:#f00,color:#000;
  classDef green fill:#d8fdd8,stroke:#0a0,color:#000;
  classDef filt fill:#fff0b3,stroke:#ffae00,color:#000;

  class F filt
  class L filt
  class T filt
  class M filt
  class E green
  class B green
```

---

## 4. Security Controls

- Redaction functions unit‑tested w/ golden samples.
- CI fails if `PII_GUARD=on` + grep finds email regex in log fixtures.
- Metrics interface *never* accepts raw user input for labels.
- Span attribute helper auto‑hashes when env != dev.

---

## 5. Integration With Cloud DLP (Optional)

For regulated industries, integrate GCP Cloud DLP or 3rd‑party scanning on archived logs; automatically redact matched findings. See `decision-matrix.md` for when to adopt managed DLP.

---
