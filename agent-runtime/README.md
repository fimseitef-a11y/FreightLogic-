# FreightLogic Agent Runtime — Phase A

This subtree is the isolated Agent service seam created in AIAG-TASK-0003 and wired for a dark production cutover by AIAG-TASK-0022.

## Boundary

- The FreightLogic PWA remains the deterministic authority for True RPM, grade, verdict and bid calculations.
- Existing Worker v30 remains the only public authentication, CORS, rate-limit and privacy boundary.
- This service is reached only through a private Cloudflare Service Binding named `AGENT` on the existing authenticated API Worker.
- The existing API Worker exposes `POST /agent/evaluate` only after canonical driver-token authentication, caller-scope authorization, privacy classification, and per-caller rate limiting.
- `workers_dev` and preview URLs are disabled and the Agent service has no public route.
- The feature flag defaults OFF in source control. Production activation is performed only by the bounded canary workflow after dark deployment passes.
- Model execution uses the private Cloudflare Workers AI binding; no separate model API key is stored in this subtree. High-confidence explanations use the configured small model and ambiguous explanations use the configured strong model.
- The SQLite Durable Object stores only idempotency/routing/confidence metadata; it does not replicate loads, backups, payment data, credentials or chat history.
- No Workflows, Queues, MCP, sub-agents, public Agent routes or transcript persistence are included.

## Privacy

The event envelope is strict and allowlisted. Model projection removes internal IDs, actor scope, load ID, correlation ID and provenance. Restricted or unknown fields fail closed before any model path.

AI Gateway is not used for this activation path. If it is added later, operational requests must set `cf-aig-collect-log-payload: false` so prompts and responses are not persisted in Gateway logs.

## Tests

Run the pure contract suite:

```bash
node agent-runtime/tests/phase-a.spec.mjs
```

## Production cutover

`.github/workflows/ai-agent-cutover.yml` is the governed production path for this seam. Pull requests run the Agent contract suite plus Wrangler dry-runs. A manual `DARK_CUTOVER` dispatch from `main` deploys the Agent target first with `AGENT_ENABLED=false`, then deploys the existing authenticated API Worker with the private binding and verifies, using a short-lived synthetic driver identity, that the private RPC reaches the Agent and fails closed as `AGENT_DISABLED`.

After the dark cutover passes, the same workflow exposes an explicit `ACTIVATE_CANARY` mode. It deploys the private Agent with Workers AI and `AGENT_ENABLED=true`, then uses a short-lived synthetic driver identity to require a real model response, unchanged canonical calculations, stable idempotent replay, and conflict rejection. Any canary failure triggers an automatic redeploy with `AGENT_ENABLED=false`. The committed Wrangler file itself remains default-off.
