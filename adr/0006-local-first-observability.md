# Local-First Observability Development Environment

---
**Status:** Accepted
**ADR ID:** 0006
**Date:** 2025-07-17
**Tags:** devx, observability, localstack, learning
---
Deliver full local stack via Docker Compose: Prometheus, Grafana, Tempo, OTEL Collector, Loki.

Benefits: offline demos, onboarding, predictable iteration.
Risks: resource heavy; config drift vs prod.
Mitigation: config parity lint.
