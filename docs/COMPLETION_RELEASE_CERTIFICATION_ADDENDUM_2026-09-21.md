# Completion release certification addendum — source 24.0.28 / last observed production 24.0.27 / DB16 / Worker v21

Date: 2026-09-21
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-21.md
Status: **HOLD — v24.0.28 source/runtime CI is green, while the last directly observed production generation is v24.0.27. Physical iPhone A1-A13, v24.0.28 live parity/service-worker observation, authenticated live vision-provider invocation/real-image benchmark, guarded Admin Console live proof, later #278 economics-policy work, repository-admin controls, and Safari/native Apple work remain open.**

This addendum supersedes the 24.0.26 certification state without rewriting it. It also
preserves the directly observed v24.0.27 production evidence while recording that source/main
has advanced to v24.0.28. It is a dated evidence checkpoint, not a claim that all FreightLogic
work is complete and not a claim that production already serves v24.0.28.

## Current source candidate — v24.0.28

PR #294 merged as `764ea091e2ae3157a9c9d7a532ab802147388220`.
Its exact PR head `121e1188c8fbd7eb02145c21bd9f27bc65e62abb` passed:

- full suite `35657810077`, job `106525656602`: **746 passed / 0 failed across 72 spec files**;
- Lanes `35657810158`: **PASS**;
- CodeQL `35657810273`: **PASS**.

v24.0.28 repairs two confirmed iPhone defects without changing DB or Worker generation:
an explicitly entered `$0.00/gal` fuel price can no longer become authoritative free fuel,
and the grade-A hero verdict can no longer claim a Tier 1 destination when no destination
was supplied. The relevant regressions are `ECON278-15`, `ECON278-16`, the expanded
`ECON278-10`, and `SSI-19`.

**Deployment/live boundary:** the runs in the next sections directly observed **v24.0.27**,
not v24.0.28. At this checkpoint no v24.0.28 live-parity or production-service-worker run has
been observed through the available GitHub connector. Source and observed production are
therefore intentionally recorded as different facts. After deployment settles, re-dispatch
the live gates and require direct 24.0.28 observation before updating this record to production
24.0.28.

## Preserved production observation — why v24.0.27 required its own record

PR #291 repaired F-9: FreightLogic has one shared toast surface, and an informational
service-worker/install notice could overwrite the one-time GPS-loss reassurance while the
driver's trip remained degraded. The production repair prevents an informational toast from
replacing a **visible warning**; warning escalation remains unrestricted. Because the repaired
`app.js` must reach installed PWAs, the governed app/service-worker/cache generation advanced
**24.0.26 → 24.0.27**. DB stays **16** and the backup/API Worker stays **v21**. No freight
economics, routing, storage schema or Worker semantics changed in this release.

## Exact runtime and automated evidence

Runtime merge: `e160d94e8a16396904ac31508c92900bbfeff91d` (PR #291).

- Exact-main full suite: run `35649355528`, job `106497614211` —
  **743 passed / 0 failed across 72 spec files**.
- The F-9 regression is included in that suite: a cosmetic notice cannot erase a visible safety
  warning, warning escalation remains possible, and the ordinary trip/GPS resilience coverage
  remains green.
- A later governance-only commit `8a520bc060ddd11bbb9db5fe3cbd612aecc79456`
  (PR #292) changes only `.agents/LANES.md`; it does not alter runtime or test bytes.
- CodeQL on that later checkpoint: run `35651336944`, job `106504214226` — **PASS**.

PR #292's pull-request suite had one first-attempt failure caused by a second informational
service-worker "installed" toast arriving during the new informational-to-informational F-9
assertion: **742 passed / 1 failed**. No runtime or assertion was changed. One controlled rerun,
per repository protocol, passed **743/0** (run `35649695991`, attempt 2, job
`106501642241`). This is retained as intermittent test-interference evidence, not represented
as a production repair and not used to erase the first result.

## Live production observation of record

The later governance-only checkpoint gives a settled observation of the runtime introduced by
PR #291.

### Live all-asset parity

Run `35651336959`, job `106504221124`, commit `8a520bc`: **VERDICT: PASS**.

Observed directly in the job log:

- source markers: app/SW/manifest **24.0.27**;
- production index references `app.js?v=24.0.27` and `sw-bridge.js?v=24.0.27`;
- production service worker reports **24.0.27**;
- manifest reports `FreightLogic v24.0.27`;
- Worker `/health` returns **v21**;
- all **22** declared runtime assets load from the app origin;
- no runtime asset is served as an HTML fallback;
- all **20** repository-only paths remain non-public;
- admin endpoint rejects an unauthenticated request;
- `VERDICT: PASS`.

The earlier push-triggered parity run on the runtime merge itself (`35649355602`,
job `106498003307`) also returned PASS and directly observed 24.0.27. The later checkpoint is
used as the observation of record because it occurred after deployment had additional time to
settle and its runtime bytes are unchanged.

### Production service worker

Run `35651336872`, job `106504213816`, commit `8a520bc`: **VERDICT: PASS**.

Observed directly in the job log:

- deployed worker reaches **ACTIVATED** and controls the page after one reload;
- current precache is `freightlogic-24.0.27`;
- all **22** declared runtime assets are present in that precache;
- after reload the driver shell renders **five tabs and a visible Today surface**;
- exactly **one** generation cache survives, with no stale app generation left behind;
- `VERDICT: PASS`.

The runtime-merge push run (`35649355381`, job `106497612847`) also observed the same
24.0.27 cache and passed. These are production observations; they are not physical-device
certification and do not imply every iPhone-only behavior was exercised.

## What remains open

| Item | Current state |
|---|---|
| Physical iPhone A1-A13 (#226) | **OPEN / deferred** to the final post-v24.5 candidate. Use the real-device runner/checklist. Headless/CI evidence cannot mark a physical row PASS. |
| Authenticated live vision provider (#252) | **UNOBSERVED** for the privileged production invocation. The synthetic `--vision` verifier exists, but Worker `/health` v21 does not prove the provider binding executes. |
| Real screenshot quality (#252) | **NOT RUN**. Requires an operator-controlled real/sanitized screenshot corpus and reviewed expected fields outside the public repository. |
| Admin Console (#231) | **OPEN**. Source/integration exists; guarded deployment plus live authenticated list/invite/re-invite/revoke evidence is still required before treating it as live-complete. |
| Later economics authority (#278) | **OPEN**. Rate-basis/settlement, regional/dynamic fuel provenance, chain/exit economics, DEACTIVATED/WITHDRAWN semantics, contextual long-haul policy and evidence-driven market calibration remain subject to the required independent Claude audit/joint-consensus gate. |
| Repository administration (#222) | **OPEN**. Repository protection/security settings are account/admin state, not proven by the app test suite. |
| Safari/macOS + native Apple work (#204/#205) | **OPEN / NOT RUN** where it requires real Safari/macOS or native Apple tooling. |

## Preserved completion facts

Authentic **M6 Gate C remains PASS** and is not reopened by this release: five source files,
216 source rows reconciled into 149 deterministic records; 141 unknown and eight positive
deadhead values, zero fabricated zeros. No importer/reconciliation semantics changed in
v24.0.27. The separate unavailable 125-row master remains separate and must never be
reconstructed from summaries.

Voice Load remains deliberately removed from v24.0.17 onward. The current runtime inventory
is 22 assets; a missing `voice-load.js` is expected, not a deployment defect.

This documentation successor changes no acceptance threshold, freight policy, manual A-row result,
credential, workflow trigger, database schema, or Worker generation. The v24.0.28 runtime-byte
changes are the separately reviewed PR #294 described above; this file does not itself deploy them.
