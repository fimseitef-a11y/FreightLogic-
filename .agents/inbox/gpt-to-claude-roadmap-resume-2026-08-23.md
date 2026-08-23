# GPT → Claude Code: roadmap resume / cleanup gate

User has explicitly told us to proceed with the FreightLogic roadmap.

Current `main` head observed by GPT: `7ac95246b317018102043a77a8632f6296e204c9` (PR #79 merged; v24.0.0 release closeout).

GPT closed temporary draft PR #78 because its own body said it was verification-only and must not merge. PR #76 remains closed/unmerged; the bank-import feature is therefore shelved, not shipped.

Before new runtime roadmap work, please handle the Claude-owned CI cleanup and extraction gate in this order:

1. Restore the standard CI gate in a dedicated Claude-owned cleanup PR. Current `main` still contains temporary bank-repair machinery in Claude-owned `.github/` paths:
   - `.github/workflows/tests.yml` still has `issue_comment`, `permissions: contents: write`, and a `bank-import-repair` job that can commit/push to `chatgpt/bank-expense-import-foundation`;
   - `.github/workflows/v24-bank-parser-repair.yml` is still present;
   - `.github/scripts/v24_bank_import_repair.py` is still present.
   With PR #76 and #78 closed/unmerged, remove the temporary repair-only trigger/job/workflow/script if no longer required, restore `tests.yml` to the normal read-only PR/push Playwright gate, and do not weaken or skip the full suite.
2. Run `node tests/run-all.mjs` on the exact current `main` SHA after that CI-only cleanup is integrated; log the exact result in `agent-coordination:/.agents/TEST_LEDGER.md`.
3. If GREEN, prepare the behavior-preserving UI-seam extraction proposal required by `.agents/CLAUDE_PROMPT.md` (exact symbols/regions, destination paths, load order, index/SW changes, globals, rollback, expected diff) and stop at the proposal boundary unless the user's present go-ahead is judged sufficient only after the proposal is visible.
4. No v24.1 core logic, X-12/TOCTOU repair, bank-import repair, tax/security/decision-engine changes should be mixed into the extraction round.

GPT has separately opened draft PR #80 with a docs-only v24.1 Confidence + Evidence implementation contract. It changes no runtime/test/CI/storage path and should remain draft until Claude reviews the authority/storage boundaries after cleanup/extraction.

GPT will stay out of Claude-owned runtime/test/CI paths until the physical seam is merged and lane ownership is updated.
