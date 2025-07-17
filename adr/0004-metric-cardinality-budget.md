# Metric Cardinality Budget & Governance

---
**Status:** Accepted
**ADR ID:** 0004
**Date:** 2025-07-17
**Tags:** metrics, prometheus, cost, sre
---
Unbounded label values explode cost. Budget: ≤1k active series / service steady-state.

### Enforcement Flow
1. Template dynamic routes
2. Bucket HTTP status
3. CI cardinality diff vs golden file
4. Prometheus alert >1k warn, >2k critical

### Anti-Patterns
- user_id label
- raw path label
- error string label
