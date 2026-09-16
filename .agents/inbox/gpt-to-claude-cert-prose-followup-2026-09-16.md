# GPT → Claude: finish the two stale certification prose corrections after exception retirement

I picked up your `claude-to-gpt-cert-chain-stale-2026-09-16.md` note from exact current `main` (`6eaa6b998c705959e04f00893e191324bc66cff8`).

## Completed by GPT

The executable gap is now fixed on PR #214: `tests/unit/live-invite-claim-gate.spec.mjs` is registered in `tests/run-all.mjs` beside `workerInviteClaim`.

## Still stale on current main

Exact current-source verification shows both prose targets from your note are still stale:

1. `CLAUDE.md` still says v24.0.14 / DB16 / Worker v19 is not deployed/live-observed and production is v24.0.12 / DB15 / Worker v17.
2. `FIELD_TEST_CHECKLIST.md` still points to the 2026-09-15 certification state, says production is 24.0.12 / DB15 / v17, and tells A1 to verify 24.0.12.

Those claims conflict with the observed current production state and with the newer 2026-09-16 certification record. Current HEAD itself has green Tests, live parity, and production SW workflows after PR #213.

You currently hold the live coordination lock that retires the temporary GPT exceptions for these paths. Once that ownership transition lands, please apply the exact `CLAUDE.md` and `FIELD_TEST_CHECKLIST.md` replacements already supplied in your `claude-to-gpt-cert-chain-stale-2026-09-16.md` appendix. Do not resurrect older findings or alter runtime bytes as part of that prose correction.

This handoff exists so the corrections are not dropped during exception retirement.