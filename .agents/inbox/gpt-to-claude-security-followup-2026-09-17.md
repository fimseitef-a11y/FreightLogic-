# GPT → Claude: post-v24.0.15 security follow-up

PR #223 is the current integration boundary for v24.0.15. Do not mix the items below into that PR unless its current integrated head fails for a directly related reason.

After #223 lands, current `.agents/LANES.md` in that candidate retires the old temporary GPT runtime/test exceptions and returns the affected runtime/security/test paths to Claude (with `app.js` still SHARED/serialized and requiring `lock/app-js`). The following open issues are therefore next-owner work, not safe GPT presentation-lane edits:

1. **#219 — untrusted local import can overwrite persistent credentials/config.** Needs a real `app.js` repair plus a regression proving attacker-supplied secret/security settings cannot replace existing local credential/config state while permitted non-secret preferences still import correctly. Also fix settings `mode=skip` semantics for keyPath `key` rather than relying on `id`.

2. **#220 — remove unverified jsDelivr executable fallback for Tesseract OCR.** Crosses `app.js`, `vendor/`, `_headers`, service-worker/deploy coverage and tests. Preferred property in the issue: production executable code is self-hosted/version-reviewed; do not weaken CSP to preserve the CDN fallback.

3. **#221 — retire raw `token=` setup-link ingestion and make Worker driver auth canonical-user-authoritative.** Crosses SHARED `app.js`, `cloud-backup-worker.js`, Worker regressions, release generation and live Worker verification. Preserve the zero-token `#i=` claim flow. The issue also calls out stale legacy Pages origins in Worker CORS.

4. **#222 — repository branch protection/security scanning** is control-plane work, not application code. The connected GitHub App can verify the gap but lacks administration mutation authority; keep this open until the repository settings are actually changed.

Suggested ordering after #223: security trust-boundary items #219/#221 first, then executable-supply-chain #220, while respecting release-generation discipline and full-suite/live-parity/Worker gates. Do not claim #222 closed from source changes.

GPT review note: no honest new `styles.css` delta was found before #223. The current `NEXT PRESENTATION` block is the exact operator-requested PR #206 contribution carried forward deliberately, so GPT did not overwrite it with the older mockup merely to create work.

— gpt, 2026-09-17
