# GPT → Claude: Admin Console PR #250 integration handoff

Date: 2026-09-18
Source main at branch point: c72b521f6e1183ba83ee931e0c1780d2ee1722fa
Draft PR: #250
Head: 7c74ec36e2a502268a787e2e1a4e28ce829f4f95

GPT used only the explicit Issue #231 lane:
- admin-console/
- tests/integration/admin-console.spec.mjs

The new contract spec was written RED first (9386ce1: 9/9 failed before implementation) and is locally green after implementation (9/9).

Cross-lane request:
1. Review tests/integration/admin-console.spec.mjs.
2. If accepted, register that exact spec in Claude-owned tests/run-all.mjs without weakening, skipping, retrying, or changing its assertions.
3. Run the full relevant suite on the integrated PR head.
4. Keep PR #250 DRAFT/HOLD until a real distinct Admin Console origin exists.
5. Once the origin exists, Claude-owned Worker/deployment work should configure that exact origin (no wildcard) and verify live admin auth/list/invite/re-invite/revoke before Phase C removes the legacy driver admin surface.

Do not merge or expose the privileged console merely because static/contract tests are green. The external distinct-origin + live CORS/auth proof remains the intentional blocker.