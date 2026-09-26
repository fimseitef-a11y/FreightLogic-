# GPT → Claude: Milestone 2 Ready Gate

Date: 2026-08-26
Operator instruction: **Proceed**
Canonical roadmap: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
Current pre-M1 main observed by GPT: `ef3b84014c24e2f1498a1f9ba390183cdbca10bb`
Existing defect packet: `/.agents/inbox/gpt-to-claude-m2-toctou-confirmed-2026-08-25.md`

## Start condition

**Do not begin M2 until the active Milestone-1 implementation has integrated green to `main` and its M1 lock is released.**

Once M1 is green, proceed directly to **Milestone 2 — Close remaining money/data-integrity risks** without returning for redundant operator approval. Rebase from the then-current M1-integrated `main`; do not implement from the pre-M1 SHA above.

## Confirmed target

Primary defect: `R-TOCTOU-EXPENSE-FUEL`.

The repair remains narrowly bounded:

- reuse the proven trip optimistic-concurrency pattern;
- preserve original expected revision/`updatedAt` through expense and fuel edit forms;
- compare expected token to the current stored row inside the same IndexedDB readwrite transaction;
- abort and surface `FL_CONFLICT` when stale rather than performing an unconditional full-object overwrite;
- refresh/reload the latest record into the stale form consistently with existing trip conflict behavior;
- do not let sanitization/update construction overwrite or fabricate the expected token before comparison;
- keep add/create behavior unchanged except for genuinely shared behavior-preserving helpers;
- preserve accounting, backup, delta, restore, import, and export contracts;
- no broad storage/refactor cleanup in this milestone.

## Required regressions

Add two-tab Playwright coverage for both expense and fuel:

1. Tabs A and B open the same existing row.
2. Tab A changes field A and saves successfully.
3. Tab B remains on the stale snapshot, changes field B, and attempts save.
4. Tab B receives the conflict path instead of silently overwriting.
5. Tab A's newer field A remains stored.
6. The UI surfaces/reloads the latest stored record consistently.
7. A fresh retry after conflict can be applied normally.

Also retain all existing trip TOCTOU coverage and verify backup/restore/import/export behavior remains green.

Any `app.js` change still requires the enforced lock with `paths: app.js` and the full `node tests/run-all.mjs` suite on exact implementation head. Log exact SHA/result in `TEST_LEDGER.md` and disposition in `STATUS.md` before PR integration.

## Next gate after M2

Only after M1 + M2 are both integrated green may PR #87 / Milestone 3 v24.1 Confidence + Evidence be reconciled onto current main. Do not blind-merge the stale branch.
