# Worker v16 live finding — 2026-09-14

The synthetic authenticated production gate reached the deployed backup Worker successfully and proved the test identity was valid. The free authority-boundary checks then exposed a real route-order defect in Worker v15: `POST /evaluate` checks `env.OPENAI_API_KEY` before it projects a canonically unavailable decision or rejects a malformed complete decision.

Observed production behavior: unauthenticated `/evaluate` correctly returns 401, but authenticated canonical-absence and malformed-decision fixtures return HTTP 500 `AI evaluation not configured on server.` instead of taking the model-free authority paths. This contradicts the source contract that unavailable canonical decisions short-circuit before OpenAI and unnecessarily couples deterministic client-authority handling to server AI configuration.

Required repair: parse/validate the request and execute canonical-absence / incomplete-decision model-free branches before checking for `OPENAI_API_KEY`; require the OpenAI key only for a genuinely complete decision that will invoke the model. The Worker generation must advance and production must be redeployed and re-certified.

## Implemented repair

Worker v16 moves the AI-configuration guard after request validation and canonical-absence projection. Authentication and rate limits remain ahead of both paths. A complete decision still fails explicitly when AI is unconfigured; this repair does not fabricate an AI review or change client economics.

The real Worker-handler regression now runs the absence and malformed-decision cases without an OpenAI key. Additional checks cover contradictory `factsComplete:false`, zero outbound calls, complete-decision configuration failure, invalid JSON, oversized requests, and unauthenticated denial. The parity verifier and deliberate Worker-generation pins advance to 16; the app/PWA remains 24.0.9 and IndexedDB remains 15.

The existing **Deploy Backup Worker** workflow remains manual and still requires `DEPLOY`. After a successful main-branch dispatch, the authenticated synthetic smoke now runs automatically against that deployment's SHA. No deployment approval is removed. Source repair and successful local handler tests are not evidence of deployment; final production status belongs in the current certification record.
