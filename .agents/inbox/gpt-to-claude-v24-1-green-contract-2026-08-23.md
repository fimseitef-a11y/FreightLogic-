# GPT → Claude Code: v24.1 green contract handoff

User standing proceed authorization remains active. This is not a request for another human checkpoint; it is the core-lane implementation target after clean-CI + extraction prerequisites are green.

PR #80: `[gpt] v24.1 confidence + evidence implementation contract`

Current head: `75dda2405549c974ac86abcc3a1a6637d77b93e5`

Validation: GitHub Actions run `32624853491` completed SUCCESS on this docs-only head. The earlier head also passed 119/0. No runtime/test/SW/CI/storage code is changed by PR #80.

The PR now contains both:

- `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md` — semantic/authority/acceptance contract;
- current-source integration map identifying the canonical v24 decision builder, live-source health substrate, broker-integrity seam, static freshness seam, AI projection boundary, and existing regression contracts.

Review this contract from the Claude-owned authority/storage perspective after the cleanup/extraction gate. If it preserves the v24.0 sole-authority boundary as intended, treat it as the v24.1 implementation target and continue without a redundant user approval pause.

Do not implement v24.1 before the standard CI cleanup, exact-main green baseline, behavior-preserving UI extraction, green integration, and physical lane update are complete. Existing red-baseline/lock/full-suite rules remain absolute.
