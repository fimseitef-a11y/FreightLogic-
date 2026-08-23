# GPT → Claude Code handoff: Round 1B gate

Status: READY FOR CLAUDE BASELINE + SEAM PROPOSAL

Current `main` head:

`9675ce3f799c3ec3e13c85f8be3a3c9152b18baf`

Current `main` tree:

`818356f0a8ef4f192bb21eae516a313f1aae2f53`

PR #77 (protocol-only coordination setup) is merged. No application code, tests, service worker, manifest, or runtime file was changed by that PR.

Observed integrated-PR evidence: final PR merge ref `79d65abfaa4df5c954ae2ee626baa78460aa72bd` has the SAME tree `818356f0a8ef4f192bb21eae516a313f1aae2f53` as merged `main` and passed the real full suite: **119 passed, 0 failed across 19 spec files**. This is strong content-parity evidence, but per protocol it does NOT replace the required fresh baseline on your exact starting `main` SHA.

Read on `main` before doing anything:
- `/AGENTS.md`
- `/.agents/LANES.md`
- `/.agents/AUDIT_TRIAGE.md`
- `/.agents/CLAUDE_PROMPT.md`

Read on `agent-coordination`:
- `/.agents/STATUS.md`
- `/.agents/TEST_LEDGER.md`
- `/.agents/locks/`
- `/.agents/inbox/`

## Required next action — baseline only

1. Fetch current `main` and confirm the exact SHA you will work from. If it is not `9675ce3f799c3ec3e13c85f8be3a3c9152b18baf`, record the new SHA and inspect only what changed.
2. Run `node tests/run-all.mjs` on that exact starting SHA.
3. Log the observed run to `agent-coordination:/.agents/TEST_LEDGER.md` with SHA, environment, totals, failures, duration if observed, and rerun reason if any.
4. If RED: do not modify application code, do not skip/quarantine/weaken tests, and STOP with the exact failures.
5. If GREEN: append status, inspect `app.js`, and prepare the UI-seam proposal required by `/.agents/CLAUDE_PROMPT.md`.

## HARD STOP

Do NOT execute the extraction yet.

Return the seam proposal with exact source symbols/regions, exact destination paths, dependency/load-order constraints, `index.html` changes, service-worker precache changes, core-global dependencies, rollback plan, and expected diff shape. Then STOP for human approval.

No X-12 repair, expense/fuel TOCTOU repair, bank-import repair, tax/security/decision-engine work, or opportunistic cleanup in this round.
