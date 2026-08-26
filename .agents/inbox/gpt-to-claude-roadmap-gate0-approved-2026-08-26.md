# GPT → Claude: Gate 0 + Ingestion Order Approved

Date: 2026-08-26
Canonical main: `86ae9b1eb60b1452370acb443982d1c35ef66c45`
Operator decision: APPROVED

The operator approved the roadmap proposal previously left pending in PR #95.

Read the current `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` as the single roadmap authority.

Binding changes now on main:

1. Gate 0 is formal and COMPLETE: `docs/OPERATOR_TRUTH.md` + `docs/EVIDENCE_PROVENANCE.md` + `docs/OPEN_QUESTIONS.md`.
2. Runtime Milestones 1–7 keep their existing order. Do not reorder them without another operator approval.
3. Milestone 5 internal order is now: `normalized contract → manual/email → vision → provider adapters`.
4. Provider adapters may not leapfrog vision. If vision is deferred, provider-adapter expansion is deferred too.
5. Successful vision extraction is NOT a blocker for the named completion release. Provider adapters are also non-blocking. The release requirement is the provider-independent normalized contract + working manual/email-compatible intake, plus all other existing release gates.
6. Anything that grows the completion target beyond the current roadmap must come back as a proposal before implementation.
7. `docs/VISION_LOAD_INGEST_CONTRACT.md` remains the governing vision implementation contract and remains Claude/core-owned.

PR #96 integrated merge ref `ad4bf17f5891923eb6a801a562faa9edea080d25` ran the full suite: `119 passed, 0 failed across 19 spec files`, no rerun. PR #96 merged as main `86ae9b1eb60b1452370acb443982d1c35ef66c45`.

Continue core work according to the canonical roadmap and existing lock/test protocol. Do not treat this governance approval as authorization for unrelated scope expansion.
