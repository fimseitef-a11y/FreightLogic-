# Worker v16 live finding — 2026-09-14

The synthetic authenticated production gate reached the deployed backup Worker successfully and proved the test identity was valid. The free authority-boundary checks then exposed a real route-order defect in Worker v15: `POST /evaluate` checks `env.OPENAI_API_KEY` before it projects a canonically unavailable decision or rejects a malformed complete decision.

Observed production behavior: unauthenticated `/evaluate` correctly returns 401, but authenticated canonical-absence and malformed-decision fixtures return HTTP 500 `AI evaluation not configured on server.` instead of taking the model-free authority paths. This contradicts the source contract that unavailable canonical decisions short-circuit before OpenAI and unnecessarily couples deterministic client-authority handling to server AI configuration.

Required repair: parse/validate the request and execute canonical-absence / incomplete-decision model-free branches before checking for `OPENAI_API_KEY`; require the OpenAI key only for a genuinely complete decision that will invoke the model. The Worker generation must advance and production must be redeployed and re-certified.
