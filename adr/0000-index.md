# ADR Index

---
**Status:** Accepted
**ADR ID:** 0000
**Date:** 2025-07-17
**Tags:** index, adr
---
The Architecture Decision Records in this knowledge pack capture *stable*, *reviewed* technical
decisions that govern observability architecture across participating projects.

ADRs are **immutable historical records**. To change direction, write a *new ADR* that supersedes
an old one.

---

## ADR Lifecycle

1. **Proposed** – Draft under review.
2. **Accepted** – Approved; governing.
3. **Superseded** – Replaced by newer ADR; retained for traceability.
4. **Deprecated** – Intentionally sunset; should not be used in new work.

---

## Table of ADRs

| ADR | Title | Status | Key Areas | Notes |
|-----|-------|--------|-----------|-------|
| 0001 | Monolith-First Strategy | Accepted | Architecture, Delivery | Learn fast; extract later. |
| 0002 | Zero Global State Architecture | Accepted | Testability, Config | All deps injected; env-driven. |
| 0003 | Context-First Propagation | Accepted | Go Idioms, Tracing | Use `context.Context` for all x-cut concerns. |
| 0004 | Metric Cardinality Budget | Accepted | Prometheus, Cost | ≤1k active series per svc; enforced. |
| 0005 | Error Classification Strategy | Accepted | Alerting, UX | Kind + Code; actionable. |
| 0006 | Local-First Observability | Accepted | Learning, Cost | Full local stack; cloud later. |
| 0007 | Gin Framework Strategy | Accepted | Web Layer, DX | Gin for velocity; strict boundaries. |
| 0008 | GCP-First Cloud Strategy | Accepted | Cloud, Ops | Cloud Run + Operations Suite. |
| 0009 | PII Governance & Exposure Modes | Accepted | Security, Compliance | Tiered logging controls. |
| 0010 | Performance Budgets | Accepted | SRE, Perf | Latency, mem, log vol, etc. |
| 0011 | Signal Access & Retention | Draft | Security | Role-based signal access. |

---

### Contributing a New ADR

Copy `../templates/adr-template.md`, assign next numeric id, submit PR linking to motivating issue,
include tradeoff analysis, and update the table above.
