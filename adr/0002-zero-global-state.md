# Zero Global State Architecture

---
**Status:** Accepted
**ADR ID:** 0002
**Date:** 2025-07-17
**Tags:** architecture, testability, config, go
---
## Context
Package-level mutable state kills test determinism...

## Decision Rules
- No mutable package-level vars (except constants, error sentinels)
- All infra deps constructed in `main` (composition root) and injected
- Observability provider surfaces interfaces only
- `init()` funcs forbidden from side-effectful runtime config

## Enforcement
Custom `golangci-lint` rule + CI script greps for globals.

## Benefits
Deterministic tests, multi-instance safety, easier fuzzing.
