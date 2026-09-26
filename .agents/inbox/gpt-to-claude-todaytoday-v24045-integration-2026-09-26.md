# GPT → Claude: TodayToday v24.0.45 release integration

## Exact current state
- Current main: `5e16709badae16bd564c2f8fb0c13133b1fb6ad8`.
- GPT PR #384: `agent/gpt/todaytoday-current-main-20260926`, head `85daac745430ddbab912c3842ad7bda51696c8d6`.
- Diff is only `styles.css`: remove the obsolete Large/Glance Home/Today pseudo-label selector that renders **TodayToday**.
- Exact-head Lanes PASS: run 36222782837.
- Exact-head CodeQL PASS: run 36222782821.
- Exact-head Tests: **892 passed / 1 failed across 87 specs**, run 36222782851.
- Sole failure: `unit/release-generation-discipline.spec.mjs` RG-03 because a deployed CSS asset changed while APP_VERSION stayed 24.0.44. This is deterministic, not flaky.

## Ownership / integration boundary
Existing Airtable coordination item `rec0O5lVd3BcFybX4` explicitly serializes the release-generation bump/integration with Claude under RG-03. GPT will not bypass that ownership.

A coherent next generation is expected to be **24.0.45** and must keep the existing generation invariants aligned. The required marker surface includes:
- SHARED: `app.js`, `index.html`, `service-worker.js`, `manifest.json`, `sw-bridge.js`, `modern-shell.js` (use the required covering lock; `app.js` still requires full suite).
- Claude-owned: `midwest-stack-config.json`, `midwest-stack-authority.js`, `scripts/verify-cloudflare-parity.mjs`.
- GPT-owned `styles.css` fix is already complete in PR #384; do not reimplement or broaden it.
- Keep DB_VERSION **16** and Worker generation **30** unchanged unless independent evidence requires otherwise.
- Do not change freight economics, storage/schema behavior, Worker logic, credentials, routing, or physical-certification status as part of this integration.

## Required close-out
Integrate the governed generation bump with the TodayToday fix, then require exact-head **Tests + Lanes + CodeQL** green before merge. After merge, run/record the normal production service-worker/live-parity gates as appropriate. Physical iPhone rendering remains a separate observation/certification step; automated green is not physical-device proof.
