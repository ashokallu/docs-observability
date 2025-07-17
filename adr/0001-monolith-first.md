# ADR-0001: Monolith-First Delivery & Learning Strategy

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** architecture, delivery, migration, learning, microservices

## Context

Building a greenfield backend platform with the primary objective of **observability mastery**. Teams need to learn, demo, and refine production-grade observability patterns quickly without premature distributed system complexity.

### Problem Statement

How do we balance learning velocity with production realism when implementing observability patterns? Early microservices architecture introduces:

- **Network failure modes** that mask instrumentation bugs
- **Multi-process debugging** requiring container orchestration
- **Distributed sampling** decisions becoming consensus problems
- **Context propagation failures** appearing as missing spans
- **Operational complexity** overwhelming learning objectives

### Forces & Considerations

| Force | Monolith Direction | Microservices Direction | Weight |
|-------|-------------------|------------------------|---------|
| **Learning Velocity** | Single debug target, faster iteration | Multiple services complicate debugging | High |
| **Production Realism** | May not represent final architecture | Matches production topology | Medium |
| **Team Size** | Optimal for small teams | Requires multiple teams | High |
| **Fault Isolation** | Single point of failure | Better blast radius control | Medium |
| **Technology Diversity** | Limited to single stack | Polyglot possibilities | Low |
| **Scaling Patterns** | Vertical scaling limits | Horizontal scaling patterns | Medium |

### Options Considered

#### Option 1: Pure Monolith

**Pros:**

- Simplest deployment model
- Single database transactions
- Minimal infrastructure requirements

**Cons:**

- No service boundaries
- Difficult to extract later
- Single technology stack

#### Option 2: Modular Monolith (Chosen)

**Pros:**

- Clear internal boundaries
- Single-process observability
- Extraction-ready architecture
- Faster feedback loops

**Cons:**

- Requires discipline to maintain boundaries
- Hidden coupling risks
- Single deployment unit

#### Option 3: Early Microservices

**Pros:**

- Production-realistic topology
- Technology diversity
- Independent deployment

**Cons:**

- Complex observability setup
- Network failure modes
- Operational overhead

#### Option 4: FaaS Fragments

**Pros:**

- Serverless operational model
- Auto-scaling
- Event-driven patterns

**Cons:**

- Cold start issues
- Limited observability tooling
- Vendor lock-in

### Decision

Adopt **Modular Monolith** with strict internal boundaries designed for eventual microservice extraction.

### Rationale

#### Learning Acceleration

- **Unified context propagation**: No network hops means `context.Context` flows deterministically
- **Faster feedback loops**: Trace/log correlation visible immediately without container complexity
- **Easier debugging**: Single debugger session covers full request lifecycle
- **Single observability pipeline**: One set of exporters, collectors, and dashboards

#### Production Readiness Path

- **Clean extraction boundary**: Strict module boundaries make service splitting surgical
- **Interface-based design**: All module interactions honor service-like interfaces
- **No leaked types**: Domain objects don't cross module boundaries
- **Dependency injection**: All external dependencies injected, not globals

#### Risk Mitigation

- **Import boundary enforcement**: Custom linting prevents domain→framework coupling
- **Contract testing**: Internal APIs tested as if they were remote services
- **Strangler fig preparation**: Extract patterns tested with traffic splitting in Phase 8

### Implementation Guidelines

#### Module Structure

```
internal/
├── api/middleware/          # Framework-specific code (Gin)
├── users/                   # Domain module (extractable)
│   ├── service.go          # Business logic
│   ├── repository.go       # Data access interface
│   └── handler.go          # HTTP handlers (adapter)
├── orders/                  # Domain module (extractable)
└── platform/obs/           # Shared observability platform
    ├── log/                # Logging interfaces
    ├── metrics/            # Metrics interfaces
    └── trace/              # Tracing interfaces
```

#### Boundary Enforcement

```bash
# Custom golangci-lint rule
scripts/check-imports.sh
# Ensures:
# - Domain packages only import platform interfaces
# - No framework code in domain logic
# - No package-level mutable state
```

#### Service Extraction Readiness

- **Interface contracts**: All module interactions via interfaces
- **Data isolation**: Each module owns its data schema
- **Async communication**: Event patterns for cross-module communication
- **Observability hooks**: Metrics, logs, traces at all boundaries

### Phase 8 Exit Criteria

Module ready for extraction when:

- [ ] Zero import violations in `make lint-imports`
- [ ] Independent data schema with migration scripts
- [ ] Contract tests cover all interface interactions
- [ ] Observability signals demonstrate module independence
- [ ] Load testing shows acceptable performance under extraction load
- [ ] Circuit breaker patterns implemented for resilience

### Consequences

**Positive:**

- Faster observability pattern learning
- Lower infrastructure complexity during development
- Unified debugging and troubleshooting experience
- Clear path to microservices when organizationally ready

**Negative:**

- Cannot demonstrate distributed tracing patterns immediately
- Single point of failure during development
- Requires discipline to honor module boundaries
- May delay learning of service mesh patterns

**Mitigation Strategies:**

- **Boundary validation**: Automated import checking in CI
- **Contract testing**: Test internal interfaces as if remote
- **Observability simulation**: Use feature flags to simulate network calls
- **Regular extraction practice**: Monthly exercises extracting test modules

### Related ADRs

- [ADR-0002: Zero Global State](#adr-0002-zero-global-state) - Enables clean module extraction
- [ADR-0006: Local-First Observability](#adr-0006-local-first-observability) - Supports learning objectives
- [ADR-0007: Gin Framework Strategy](#adr-0007-gin-framework-strategy) - Framework isolation strategy

### References

- *Building Microservices* (Sam Newman): "Monolith-first approach reduces early complexity"
- *Microservices Patterns* (Chris Richardson): "Extract services when boundaries are proven"
- [Monolith First - Martin Fowler](https://martinfowler.com/bliki/MonolithFirst.html)
