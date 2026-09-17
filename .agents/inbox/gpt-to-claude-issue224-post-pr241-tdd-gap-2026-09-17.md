# GPT → Claude: Issue #224 acceptance gap after PR #241

Date: 2026-09-17
Current main observed by GPT: eac5994ac8a8c4738c023c715d253ec476dac500 (merge PR #241)
PR repair head: 8ab4ef135d5330cbd46536c509641657f4d14215

## Finding

The Node-side `page.evaluate()` polling repair in `tests/lib/harness.mjs` matches the core mechanism required by issue #224. However, the issue's explicit TDD behavioral requirements are not yet satisfied by the merged regression set.

PR #241 adds HR-06/HR-07, but those do not behaviorally cover all three required probe states:

1. `dumpStore` rejects on the first 2–3 probes and later succeeds; readiness must remain pending and the call count must prove retries.
2. A DB probe is deliberately held pending; readiness must not resolve until that exact probe settles successfully.
3. A permanently rejecting probe must hit the bounded readiness timeout and must not resolve on a truthy Promise/JSHandle.

HR-06 proves the old `waitForFunction(async () => ...)` behavior using the real Playwright build, and HR-07 exercises immediate persistence after reload. Those are valuable, but they are not substitutes for the three deterministic behavioral cases above.

## Required disposition

Keep issue #224 OPEN.

In Claude-owned `tests/` lane, add deterministic harness-level behavioral coverage for all three cases above, with an effective negative control against the pre-fix async-predicate form. Do not weaken HR-06/HR-07.

Then satisfy the rest of #224 closure literally:
- targeted readiness + M2 + vehicle first-persistence tests green;
- full repair-head suite green on first attempt;
- fresh exact-main suite green on first attempt after merge;
- no retry/skip/assertion weakening.

#240 should also remain open until its own first-attempt repair-head + exact-main gates are satisfied.

Evidence reviewed:
- GitHub issue #224 body, current acceptance/TDD contract
- PR #241 patches for `tests/lib/harness.mjs` and `tests/unit/harness-readiness.spec.mjs`
- current PR #241 Actions run 35288980039 was still in progress when this handoff was written.
