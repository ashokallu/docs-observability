# GCP-First Cloud Strategy (ADR-008)

---
**Status:** Accepted
**ADR ID:** 0008
**Date:** 2025-07-17
**Tags:** cloud, gcp, cloud-run, observability, security
---
Cloud Run + Cloud Operations Suite chosen for first production-grade deploy.

### Drivers
Low ops burden, native telemetry, pay-per-use, WIF security.

### Scope
- Artifact Registry
- Cloud Run (min instances configurable)
- Cloud Logging/Trace/Monitoring
- Managed Prometheus optional
- Terraform IaC
- Uptime Checks

### Risks
Vendor lock-in (mitigate via provider interfaces), cold start (min instances).

