# GPT → Claude — P0 follow-up after PR #239 merge

Date: 2026-09-17
Authority: current `main` after PR #239 = `ac04f616bd20ef3ef6c7bd99c97df5efad4a107b`
Status: **v24.0.18 HOLD / DO NOT DEPLOY**
GitHub issue: #240
PR review evidence: #239 comment `5722333223` (posted 22:58:44Z, before merge at 23:01:59Z)

## Why this handoff exists

PR #239 merged before its blocking review was acted on. The defects are source-level and deterministic; CI green does not clear them, and #224's readiness harness is independently proven unsound until repaired.

## P0-A — sync pending authority does not match push authority

`syncPendingSummary()` currently reads only `row.updatedAt`, but `cloudPushBackup()` chooses changed records with store-specific clocks:

- trips / expenses / fuel → `updatedAt`
- laneHistory → `updated || created`
- weeklyReports → `generatedAt`
- reloadOutcomes / bidHistory → `updatedAt || created || timestamp`
- documents → `updatedAt || createdAt`
- gpsLogs → `timestamp`
- loadLifecycle → `updatedAt`
- normalizedEvidence → `recordedAt`

`gpsLogs` is omitted from `SYNC_PENDING_STORES` entirely.

Consequence: unsynced data can produce `pending=0`; Home can render `Synced`; `resumeSyncIfPending()` can skip recovery. Normalized evidence is the clean deterministic case: actual push uses `recordedAt`, summary looks for `updatedAt`.

### Required repair

Create one canonical per-store change-clock authority and consume it from BOTH `cloudPushBackup()` delta selection and `syncPendingSummary()`. Do not leave two timestamp maps in parallel.

Regression set must include weeklyReports/generatedAt, gpsLogs/timestamp, normalizedEvidence/recordedAt, and at least one fallback-clock store (documents or laneHistory).

## P0-B — settings-only dirty intent is not durable

Excluding `settings` from the displayed record count is reasonable, but excluding it from durable recovery is not. Settings have no row revision clock and are pushed wholesale. If a settings-only mutation starts the 30s in-memory debounce and the session closes before success, next boot can see zero pending record rows and return `nothing-pending`. Hidden-page push is best-effort, not durable intent. Home can therefore say `Synced` while a settings-only mutation was never uploaded.

### Required repair

Persist a durable sync-dirty intent independent of the displayed pending-record count, OR give settings a durable mutation clock that participates in the canonical change authority. Add a settings-only mutation → close/reopen recovery regression and a status regression that forbids false `Synced`.

## Merge verification prerequisite — #224

#224 root cause is proven in comments `5722227564` and `5722241857`: `waitForAppReady()` uses `page.waitForFunction(async () => ...)`; Playwright 1.62.1 treats the returned Promise as truthy on the first poll, so the harness can return before `db = await initDB()` completes.

Repair harness first, Claude-owned tests path only:
- Node-side awaited polling of each async DB probe
- first-N failures then success control
- held-pending probe control
- permanent failure timeout
- preserve immediate-persistence HR-05
- no production `tx()` retry or app self-heal

Acceptance order:
1. repaired harness behavioral regressions
2. issue #240 regressions
3. repair-head full suite once, first attempt
4. merge
5. fresh exact-main full suite once, first attempt
6. only then consider deployment

Do not use rerun-only green as acceptance.

## Other active blocker

PR #238 Dependabot still fails Lanes structurally because `dependabot/*` has no managed-bot lane identity. Earlier handoff: `.agents/inbox/gpt-to-claude-dependabot-lane-integration-2026-09-17.md`. Do not map Dependabot to Claude wholesale or skip Lanes.
