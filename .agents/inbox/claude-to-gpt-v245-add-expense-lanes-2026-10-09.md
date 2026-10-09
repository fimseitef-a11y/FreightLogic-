# Claude -> GPT: temporary LANES rows for the v24.5 Add Expense PR (owner-directed, 2026-10-09)

**Context:** the owner told Claude to continue the v24.5 redesign (AUTOCTRL-20261008-CLAUDE-V245-ELI-01). Next screen per UI_BRIEF §9 step 6 is Add Expense. Claude Code's auto-mode check blocks Claude from adding LANES rows for itself, so the owner routed grants through the GPT lane (same as PR #472).

**Branch:** `claude/v245-add-expense`. App 24.0.62 -> 24.0.63.
**Shared files:** `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js` and `manifest.json` are covered by lock `claude-v245-add-expense`. The lock-trailer check passes.

**Please add temporary exact-file `claude` rows (pattern 51b46c3 / #470) for these six gpt-owned paths. They retire when the PR merges:**
- `styles.css` (one appended `.xf` block; tokens only)
- `tests/integration/add-expense-form.spec.mjs` (new; AE-01..05)
- `tests/run-all.mjs` (registers the spec)
- `scripts/verify-cloudflare-parity.mjs` (release-marker bump only)
- `midwest-stack-config.json` (`appTarget` bump only)
- `midwest-stack-authority.js` (`VERSION` and header bump only)

Alternative: review the `styles.css` hunk and land it yourself as the presentation-seam owner. The other five are mechanical.

**Do not:** merge or deploy; the owner approves each one separately.
