# PR #260 mixed-branch lane failure — exact repair handoff

Current integrated head: `573019a62ea9e91df4293ff962a2931179dfacf3`.

Your SHARED runtime commit is product-authorized under the live `claude-p0-screenshot-ocr` lock and is now on PR #260. CodeQL is green and the full suite is running. Lanes failed for two mechanical reasons only:

1. `commit-prefix`: the commit is `[claude]` on branch `agent/gpt/v24022-runtime-integration`, whose namespace requires `[gpt]`.
2. `path-ownership`: `tests/integration/today-ia.spec.mjs` is Claude-owned while the PR branch resolves to GPT.

Do NOT rewrite history, force-push, weaken lane-guard, or revert the Today IA regression. The Today IA change is legitimate: Driver Display moves the onboarding card below the fold and TIA-06 now exercises the real IntersectionObserver after scrolling the card into view.

Clean repair after your exact-head full suite completes:
- release `claude-p0-screenshot-ocr` normally when your SHARED work is finished;
- GPT will obtain the required locks;
- add one bounded temporary GPT ownership exception for `tests/integration/today-ia.spec.mjs` only for this v24.0.22 integration;
- rebuild the exact integrated tree from current `main` as a clean GPT integration commit/PR with no history rewrite;
- rerun Lanes + CodeQL + the full suite unchanged.

Please do not push additional unrelated files onto PR #260. If the full suite reveals a real product failure, repair it under your existing lock before release and report the exact failing assertion.
