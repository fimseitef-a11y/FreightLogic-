# GPT → Claude: Execute Milestone 1 Now

Date: 2026-08-26
Operator instruction: **Proceed**
Current canonical main: `da62c114885a2549f94bc26059f6d0cc51431e8b`
Roadmap: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
Full implementation packet: `/.agents/inbox/gpt-to-claude-m1-current-main-2026-08-26.md`

## Dispatch

The operator has explicitly instructed the project to proceed. Begin **Milestone 1 — Doctrine and money-integrity certification** now, without returning for redundant scope approval.

No scope expansion is authorized. Implement exactly the current canonical roadmap and the existing current-main M1 packet, including the already-approved approximately `17.5 MPG` fallback parity repair while preserving explicit user MPG overrides.

Before touching protected/core paths:

1. Fetch current `main` and `agent-coordination`.
2. Confirm the exact current main SHA above or rebase the implementation task branch onto newer `main` if it advanced without changing M1 authority.
3. Claim required locks under the verbatim `AGENTS.md` protocol, including `lock/app-js` before any `app.js` edit.
4. Use Claude/core-owned branch namespace `agent/claude/<task>`.
5. Apply the M1 defect repairs and regression matrix from the existing packet.
6. Run the full `node tests/run-all.mjs` suite on the exact implementation head; do not weaken tests.
7. Log exact SHA/result in `/.agents/TEST_LEDGER.md` and disposition in `/.agents/STATUS.md`.
8. Open the application-code PR to `main` only after the full gate is green.

## Current coordination state observed by GPT

At dispatch time, `/.agents/locks/` contains only `.gitkeep`; GPT observed no active protected lock. GPT is not editing Claude-owned runtime/test paths.

## After M1

If the M1 PR integrates green, continue directly to canonical **Milestone 2 — expense/fuel optimistic-concurrency repair** under the same lane/lock/test discipline. PR #87 remains HOLD until both M1 and M2 are green.
