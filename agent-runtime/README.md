# FreightLogic Agent Runtime — Phase A

This subtree is the isolated, production-dark Agent service seam for AIAG-TASK-0003.

## Boundary

- The FreightLogic PWA remains the deterministic authority for True RPM, grade, verdict and bid calculations.
- Existing Worker v30 remains the only public authentication, CORS, rate-limit and privacy boundary.
- This service is designed to be reached only through a private Cloudflare Service Binding.
- `workers_dev` and preview URLs are disabled.
- The feature flag defaults OFF.
- There is no model call in Phase A. Requests that would require inference return `recommendation: "UNKNOWN"`.
- The SQLite Durable Object stores only idempotency/routing/confidence metadata; it does not replicate loads, backups, payment data, credentials or chat history.
- No Workflows, Queues, MCP, sub-agents, public Agent routes or transcript persistence are included.

## Privacy

The event envelope is strict and allowlisted. Model projection removes internal IDs, actor scope, load ID, correlation ID and provenance. Restricted or unknown fields fail closed before any model path.

When AI Gateway is added in a later approved phase, operational requests must set `cf-aig-collect-log-payload: false` so prompts and responses are not persisted in Gateway logs.

## Tests

Run the pure contract suite:

```bash
node agent-runtime/tests/phase-a.spec.mjs
```

Production deployment and existing Worker integration are explicitly outside this Phase A slice.
