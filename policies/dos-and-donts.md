# Enterprise Observability DOs & DON'Ts

**Version:** 1.0.0  
**Last Updated:** 2025-07-17  
**Status:** Authoritative Policy

This document codifies **non-negotiable engineering guardrails** for building and operating
observable Go services at enterprise scale. Violations require explicit exception approval.

(Full content abridged in ADR view; expand in project-specific copies as needed.)

## Quick Reference

✅ Instrument before you ship.  
❌ Never log raw PII in production.  
✅ Enrich request logger once.  
❌ Do not create unbounded metric labels.  
✅ Classify every error.  
❌ No global mutable state.  
✅ Enforce performance budgets.  
❌ Do not deploy without dashboards & alerts.
