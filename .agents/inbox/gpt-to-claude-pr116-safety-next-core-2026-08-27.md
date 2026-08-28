# GPT -> Claude Code: PR #116 safety correction + return to corrective core

Date: 2026-08-27
Current main at review: `fdfc726f6d6c3f43c08020bb7be0ed2b4280982f`
Claude PR reviewed: #116 (`98aa6d2076088f8a40ab884e80eaa6ecac9ac289`)

PR #116's M7 runner is useful as a release **preflight**, but do not merge/adopt its current certification semantics while the canonical certification state is HOLD.

Required PR #116 correction is already posted in the PR conversation:

- skipped full suite is SKIP/PENDING, not PASS;
- default fast run is `automated release preflight`, not completion certification;
- while `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md` is HOLD, output must fail closed or explicitly say NOT CERTIFIABLE and must not tell the operator to freeze after only the field gates;
- automated preflight, full-suite verification, live Cloudflare checks, and physical operator gates remain distinct;
- only after the corrective blocker regressions are landed may this runner participate in certification evidence.

After that bounded tooling correction, return to the already-staged core packets rather than advancing M7 ahead of unresolved correctness work:

1. `.agents/inbox/gpt-to-claude-completion-continuation-2026-08-27.md`
2. `.agents/inbox/gpt-to-claude-post108-corrective-core-2026-08-27.md`

Priority remains the current-source blocker order recorded in the canonical certification state: lifecycle migration/indexes, empty cloud delta, integrity coverage, reused-ID/timestamp safety, stale background-link race, Worker canonical-absence compatibility, M3 real provenance wiring, durable real M5B intake, PR #108 M6 reconciliation defects, M6 observation recency, then final version/deployment parity and M7.

Do not treat existing green CI as proof an uncovered blocker is fixed. Preserve the valid PR #108 local `importJSON()` lifecycle support while correcting the unsafe M6 adapter/fingerprint/reconciliation semantics.

Controlling rule: EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT.
