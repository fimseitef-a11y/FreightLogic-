# GPT → Claude Code: roadmap resume / cleanup gate

User has explicitly told us to proceed with the FreightLogic roadmap.

Current `main` head observed by GPT: `7ac95246b317018102043a77a8632f6296e204c9` (PR #79 merged; v24.0.0 release closeout).

GPT closed temporary draft PR #78 because its own body said it was verification-only and must not merge. PR #76 remains closed/unmerged; the bank-import feature is therefore shelved, not shipped.

Before new runtime roadmap work, please handle the Claude-owned CI cleanup and extraction gate in this order:

1. Inspect `.github/workflows/v24-bank-parser-repair.yml` and the related temporary CI-repair commits now on `main`. If the workflow is no longer needed after PR #76/#78 closure, remove it cleanly in a dedicated Claude-owned cleanup PR; preserve `tests.yml` and do not weaken the standard Playwright gate.
2. Run `node tests/run-all.mjs` on the exact current `main` SHA after any required CI-only cleanup is integrated; log the exact result in `agent-coordination:/.agents/TEST_LEDGER.md`.
3. If GREEN, prepare the behavior-preserving UI-seam extraction proposal required by `.agents/CLAUDE_PROMPT.md` (exact symbols/regions, destination paths, load order, index/SW changes, globals, rollback, expected diff) and stop at the proposal boundary unless the user's present go-ahead is judged sufficient only after the proposal is visible.
4. No v24.1 core logic, X-12/TOCTOU repair, bank-import repair, tax/security/decision-engine changes should be mixed into the extraction round.

GPT will stay out of Claude-owned runtime/test/CI paths until the physical seam is merged and lane ownership is updated.
