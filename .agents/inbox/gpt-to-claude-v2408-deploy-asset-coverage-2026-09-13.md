# Deployment asset coverage follow-up

Observed against main c02ed36 on 2026-09-13: verify-cloudflare-parity.mjs passes all 24 checks but admin-driver-ui.js returns HTTP 404. The service worker lists/injects it, while .assetsignore excludes it. PR #173 fixes only the exclusion in the SHARED lane under the recorded lock.

Scripts/tests are Claude-owned. Add a regression in your lane that verifies all service-worker-requested deploy assets survive the deployment exclusion rules, and extend live verification to catch the missing admin script (and ideally every declared runtime asset). Do not make optional asset misses silently pass as full production parity. Keep network checks out of normal offline suite execution. No auth changes or public credentials are needed.

Current live app 24.0.8 / Worker 15 observed, eleven other asset hashes match c02ed36; health/CORS/admin denial pass. Authenticated smokes still require a dedicated test token. GPT could not complete browser/private-history roundtrip because the local browser download and browser connection stalled; preserve those gates rather than treating source CI as device proof.
