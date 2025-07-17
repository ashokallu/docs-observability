# Observability Architecture Knowledge Pack

**Version:** 1.0.0  
**Last Updated:** 2025-07-17  
**License:** Apache-2.0  

This repository is a **vendor-able, multi-project observability documentation pack** containing
Architecture Decision Records (ADRs), policy docs, PII governance matrices, performance budgets,
operational checklists, and implementation guides. It is designed to be imported as a **Git submodule**
or copied into any Go (or polyglot) backend project to bootstrap *production-grade observability*.  

> ⚠️ This repo is **documentation only**. For a full working reference implementation, see the
> companion code repository: `github.com/ashok/go-observability` (Phase-based implementation path).

---

## Contents

| Path | Description |
|------|-------------|
| `adr/` | Canonical architecture decisions. |
| `policies/` | DOs/DON'Ts, logging policy, data retention, access controls. |
| `pii/` | PII exposure mode matrix + redaction guidance. |
| `budgets/` | Performance, reliability & cost budgets. |
| `checklists/` | Launch, production readiness, security, PII, observability health. |
| `guides/` | Deep-dive implementation & operations guides (logging, tracing, metrics, cloud). |
| `templates/` | ADR template, PR checklist, issue templates. |
| `diagrams/` | Mermaid source diagrams (architecture, signal flow, data lifecycle). |

---

## How to Use Across Projects

### Option 1 – Git Submodule (Recommended)

```bash
git submodule add https://example.com/docs-observability.git docs/observability
git commit -m "add observability docs pack"
```

Update submodule when upstream changes:

```bash
git -C docs/observability pull origin main
git add docs/observability
git commit -m "bump observability docs pack"
```

### Option 2 – Copy / Vendor Snapshot

Download an archive and unpack into `docs/observability/` in your project. Track upstream
changes manually or via a scheduled diff job.

### Option 3 – Documentation Build Import

If you build docs with MkDocs / Docusaurus / Hugo, point to this repo as an *external docs source*
and include the ADR index in your build pipeline.

---

## Versioning Strategy

This pack follows **semantic versioning** (MAJOR.MINOR.PATCH) with alignment to key ecosystem
milestones (e.g., Go / OpenTelemetry / Prometheus / Cloud vendor major API changes).

- **MAJOR:** Breaking policy change or removed ADR. Requires migration notes.
- **MINOR:** Backward-compatible additions (new ADRs, guides, updated diagrams).
- **PATCH:** Typos, clarifications, formatting fixes.

> Track the version you vendor in your project root or in your platform manifest.

---

## Contributing

PRs welcome! Follow the ADR process described in `adr/0000-index.md`. Use the templates under
`templates/` for new decisions, policy docs, or checklists. Ensure **traceability**: link ADRs to
commits, policies, and runbooks.

---

## Quick Links

- 👉 [ADR Index](adr/0000-index.md)
- 👉 [DOs / DON'Ts Enterprise Observability Policy](policies/dos-and-donts.md)
- 👉 [PII Exposure Mode Matrix](pii/pii-matrix.md)
- 👉 [Performance Budgets](budgets/performance-budgets.md)
- 👉 [Production Readiness Checklist](checklists/production-readiness.md)
- 👉 [GCP-First Cloud Strategy (ADR-008)](adr/0008-gcp-first-cloud-strategy.md)
- 👉 [Gin Framework Strategy (ADR-007)](adr/0007-gin-framework-strategy.md)

---

> **Maintainer Note:** Update all cross-links when adding new ADRs. Run `scripts/validate-links.sh`
> (if vendored from the code repo) to ensure doc integrity.
