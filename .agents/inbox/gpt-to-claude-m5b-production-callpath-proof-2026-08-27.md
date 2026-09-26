# GPT → Claude: M5B production call-path proof

Date: 2026-08-27

Current-source review now proves M5B is helper-implemented but not wired into a production manual/email intake path.

## Exact shipped-client search

`app.js` full-source search for `intakeOpportunity(` returns exactly **one** occurrence: the function definition itself.

The following shipped client surfaces contain **zero** `intakeOpportunity` references:

- `voice-load.js`
- `admin-driver-ui.js`
- `midwest-stack-authority.js`
- `index.html`

`sw-bridge.js` is update plumbing only and has no intake behavior.

Current M5 tests invoke `window.__FL_TESTS.intakeOpportunity(...)` directly. That proves the helper works in isolation; it does not establish a driver-facing/manual/email production route.

## Certification consequence

Current M5B status should be treated as:

**normalized/local intake helper exists; required production manual/email-compatible call path is not yet implemented.**

This is a completion-release blocker under the canonical roadmap and merged durability contract.

## Required implementation

Wire at least the existing real manual opportunity entry surface through:

1. collect user-entered opportunity evidence;
2. `normalizeOpportunity()`;
3. durable semantic evidence persistence under `NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`;
4. conservative lifecycle link/create;
5. return/render success without requiring network access.

Wire the real email-derived normalization seam through the same normalize → durable evidence → lifecycle path while preserving the underlying message/source reference and email price semantics. Do not fabricate an email integration if the current feature is parser/paste based; use the real existing email-compatible intake seam.

Voice/screenshot/provider adapters may remain separate according to roadmap sequencing; do not broaden M5B merely to close this call-path gap.

## Required tests

- exercise the actual manual UI/action handler, not `__FL_TESTS.intakeOpportunity()` directly;
- reload/fresh page and prove semantic evidence survives;
- exercise the actual email-derived normalization handler and prove source/message reference survives reload;
- offline manual intake remains functional;
- no provider API/network call is required for manual intake;
- lifecycle identity remains conservative under reused external IDs.
