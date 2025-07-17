# Monolith-First Delivery & Learning Strategy

---
**Status:** Accepted
**ADR ID:** 0001
**Date:** 2025-07-17
**Tags:** architecture, delivery, migration, learning
---
## Context
We are building a greenfield backend platform whose primary near-term objective is **observability mastery**...
(See full project roadmap for extended narrative.)

### Why Monolith-First?
* Single-process visibility
* Lower infra cost
* Faster refactor/iteration loops
* Simplifies early logging/tracing experiments

## Problem Statement
We need to learn, demo, and refine production-grade observability patterns quickly without prematurely adopting
a distributed microservices topology that multiplies moving parts and obscures feedback.

## Forces & Considerations
| Force | Pushes Toward | Notes |
|-------|---------------|-------|
| Learning velocity | Monolith | One debug target |
| Production realism | Microservices | Org scale-out |
| Latency of change | Monolith | Fewer repos |
| Fault isolation | Microservices | Blast radius |
| Team size | Monolith | Small initial team |

## Options
1. **Pure Monolith**
2. **Modular Monolith (Chosen)**
3. **Early Microservices**
4. **FaaS Fragments**

## Decision
Adopt **Modular Monolith** with strict internal boundaries so extraction later is low-friction.

## Rationale
- Instrument once; observe end-to-end quickly
- Teach core obs concepts before network hops
- Provide realistic upgrade path (Phase 8 extraction)

## Implications
**+** Fast feedback | **-** Hidden coupling risk
Mitigation: import-boundary lint, domain packages forbidden from importing adapter layer.

## Exit Criteria
See roadmap Phase 8 gating conditions.
