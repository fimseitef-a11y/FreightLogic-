# GPT → Claude: M1 Worker UNKNOWN projection blocker

Date: 2026-08-26
PR: #103
Target owner: Claude (`cloud-backup-worker.js`, `tests/`)

## Why this blocks M1 integration

Milestone 1 correctly makes UNKNOWN/null a valid canonical decision state. Current Worker v12 predates that contract and still contains:

- `canonicalGrade(g)` -> invalid/missing input defaults to `F`;
- `canonicalTrueRpmLabel(decision)` -> `Number(decision?.economics?.trueRPM)`, so `null` becomes `0` and publishes `$0.00 / true mile`;
- the same family of projection helpers must be checked for missing bid/verdict values so missing canonical facts never become zero/default-authoritative values.

This creates false precision only after M1 lands: the client correctly says UNKNOWN/UNAVAILABLE while `/evaluate` can manufacture F / $0.00 in the AI review surface.

## Required bounded repair

1. Preserve canonical missing/UNKNOWN semantics in Worker projection. Missing grade remains missing/UNKNOWN, not `F`; missing True RPM remains absent/empty/UNKNOWN, not `$0.00`.
2. Do not introduce a Worker-side decision calculation or competing confidence model.
3. Audit canonical verdict/bid projection helpers for the same null-to-default family so UNKNOWN cannot become REJECT or `$0` merely because the Worker sanitized it.
4. Add regression coverage that sends an M1-style canonical decision with unavailable/null authority/economics/bid facts and proves the Worker response cannot publish zero/F/REJECT as manufactured substitutes.
5. Keep the change bounded to Worker projection + tests. Worker version may stay v12 unless existing release policy requires a bump; if bumped, update release parity surfaces consistently.

## Integration state

PR #103 is open from `claude/audit-reconcile-lane-mechanics-hteibi` at M2 head `e59360e...` into current main. Claude local full suite is green 166/0 but is not environment-equivalent to GitHub Actions. Do not merge PR #103 until this Worker repair is on the PR head and the integrated Actions `Tests` + `Lanes` gates are green.
