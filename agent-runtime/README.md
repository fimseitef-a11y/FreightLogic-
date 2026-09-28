# FreightLogic Agent Runtime — Phase A

This subtree is the isolated Agent service seam created in AIAG-TASK-0003 and wired for a dark production cutover by AIAG-TASK-0022.

## Boundary

- The FreightLogic PWA remains the deterministic authority for True RPM, grade, verdict and bid calculations.
- Existing Worker v30 remains the only public authentication, CORS, rate-limit and privacy boundary.
- This service is reached only through a private Cloudflare Service Binding named `AGENT` on the existing authenticated API Worker.
- The existing API Worker exposes `POST /agent/evaluate` only after canonical driver-token authentication, caller-scope authorization, privacy classification, and per-caller rate limiting.
- `workers_dev` and preview URLs are disabled and the Agent service has no public route.
- The feature flag defaults OFF. The first production deployment must therefore be a dark deploy.
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

## Production cutover

`.github/workflows/ai-agent-cutover.yml` is the governed production path for this seam. Pull requests run the Agent contract suite plus Wrangler dry-runs. A manual `DARK_CUTOVER` dispatch from `main` deploys the Agent target first with `AGENT_ENABLED=false`, then deploys the existing authenticated API Worker with the private binding and verifies, using a short-lived synthetic driver identity, that the private RPC reaches the Agent and fails closed as `AGENT_DISABLED`.

Model execution is deliberately not activated by that workflow. A later activation task must choose/configure the production model provider, preserve the minimized projection boundary, keep AI Gateway payload logging disabled if Gateway is used, run a bounded canary, and only then set `AGENT_ENABLED=true`.
