# Completion release certification addendum — production 24.0.28 / DB16 / Worker v21

Date: 2026-09-21
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-21.md
Status: **HOLD — v24.0.28 exact-main automated tests, CodeQL, live all-asset parity and production service-worker checks are directly observed and passing. Physical iPhone A1-A13, authenticated live vision-provider invocation/real-image benchmark, guarded Admin Console live proof, later #278 economics-policy work, repository-admin controls, and Safari/native Apple work remain open.**

This addendum supersedes the 24.0.26 certification state without rewriting it. It preserves
the directly observed v24.0.27 production evidence as history and records the later direct
v24.0.28 production observation. It is a dated evidence checkpoint, not a claim that all
FreightLogic work is complete.

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

**Current exact-main observation of record:** checkpoint
`675e6fb0140f0e226219fc52955932703fc07a1c` passed Tests `35661894446`
(job `106538812253`) at **746/0 across 72 spec files**, CodeQL `35661894363`,
Live Parity `35661894518` (job `106538813802`) and Production Service Worker
`35661894391` (job `106538814618`). The two live gates directly observe
app/SW/manifest **24.0.28**, Worker **v21**, all **22** declared runtime assets,
**20** repository-only paths withheld, `freightlogic-24.0.28` with all 22 assets
in precache, five tabs + Today after reload, no uncaught page errors, and exactly one
app-generation cache.

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

PR #292's pull-request suite had one first-attempt F-9 control failure: **742 passed / 1 failed**;
one controlled rerun passed **743/0** (run `35649695991`, attempt 2, job
`106501642241`). Later test-only commit `0fc250cb0523bc040049cd25fbf6f12e9a5b376c`
(PR #298) reproduced the control failure and removed two unnecessary asynchronous sleeps from
the regression sequence. `app.js` remained byte-identical, both negative controls still failed
when the severity guard was removed, and the exact-head/current checkpoint suite passed
**746/0**. Preserve the earlier failure as test-control evidence; it was not a second product
defect and did not require a runtime generation change.

## Live production observation of record — v24.0.28

Current observation checkpoint: `675e6fb0140f0e226219fc52955932703fc07a1c`.
The commits after runtime PR #294 and before this checkpoint are test/governance-only; the
deployed runtime generation remains 24.0.28.

### Exact-main automated evidence

- Tests `35661894446`, job `106538812253`: **746 passed / 0 failed across 72 spec files**.
- CodeQL `35661894363`, job `106538813341`: **PASS**.
- F-9 test stabilization `0fc250c` changed the regression only; `app.js` stayed byte-identical.

### Live all-asset parity

Run `35661894518`, job `106538813802`: **VERDICT: PASS**.

Observed directly in the job log:

- production index references the v24.0.28 app and bridge;
- production service worker reports **24.0.28**;
- manifest reports `FreightLogic v24.0.28`;
- Worker `/health` returns **v21**;
- all **22** declared runtime assets load from the app origin;
- no runtime asset is served as an HTML fallback;
- all **20** repository-only paths remain non-public;
- `VERDICT: PASS`.

### Production service worker

Run `35661894391`, job `106538814618`: **VERDICT: PASS**.

Observed directly in the job log:

- deployed worker reaches **ACTIVATED** and controls the page after one reload;
- current precache is `freightlogic-24.0.28`;
- all **22** declared runtime assets are present in that precache;
- after reload the driver shell renders **five tabs and a visible Today surface**;
- there are **no uncaught page errors** during install/reload;
- exactly **one** app-generation cache survives;
- the cached shell requests the current generation's assets;
- `VERDICT: PASS`.

These are production observations, not physical-device certification. They do not mark any
A1-A13 row PASS and do not prove the authenticated vision provider, real-screenshot quality,
Admin Console privileged flow, repository-admin state, or Safari/native Apple behavior.

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
v24.0.28. The separate unavailable 125-row master remains separate and must never be
reconstructed from summaries.

Voice Load remains deliberately removed from v24.0.17 onward. The current runtime inventory
is 22 assets; a missing `voice-load.js` is expected, not a deployment defect.

This documentation successor changes no acceptance threshold, freight policy, manual A-row result,
credential, workflow trigger, database schema, or Worker generation. The v24.0.28 runtime-byte
changes are the separately reviewed PR #294 described above; this file does not itself deploy them.
