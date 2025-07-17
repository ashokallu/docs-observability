# Gin Framework Strategy (ADR-007)

---
**Status:** Accepted
**ADR ID:** 0007
**Date:** 2025-07-17
**Tags:** web, gin, framework, go, dx
---
**Accepted w/ Boundaries.**

### Why Gin?
Velocity, ecosystem, tutorials, otelgin support.

### Concerns
Non-stdlib ctx, potential coupling.

### Mitigation
Framework quarantine: Gin limited to adapter layer. Domain code receives stdlib ctx + DTOs.
Static import linter forbids domain->gin import.

### Migration Path
Swap router in adapter; domain untouched.

### Observability Integration
EAGER middleware attaches ctx logger; otelgin starts server spans; metrics wrapper templates routes.

