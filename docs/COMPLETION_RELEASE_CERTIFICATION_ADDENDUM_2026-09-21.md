# Completion release certification addendum — production 24.0.29 / DB16 / Worker v21

Date: 2026-09-21
Updated: 2026-09-22 UTC
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-21.md
Status: **HOLD — v24.0.29 exact PR-head automated tests, CodeQL, live all-asset parity and production service-worker checks are OBSERVED and PASSING. Physical iPhone A1-A13, authenticated live vision-provider invocation/real-image benchmark, guarded Admin Console live proof, later #278 economics-policy work, repository-admin controls, and Safari/native Apple work remain open.**

This addendum supersedes the 24.0.26 certification state without rewriting it. It preserves
the directly observed v24.0.27 and v24.0.28 evidence as history and records the later direct
v24.0.29 production observation. It is a dated evidence checkpoint, not a claim that all
FreightLogic work is complete.

## Current source candidate — v24.0.29

PR #306 merged runtime v24.0.29 as `ca99d50abf18557682f38e641c2b023041088ea6`.
Its exact PR head `cbdc36e133fc8e265e7c410dd3a6c29920ce6348` passed:

- full suite `35678726412`: **748 passed / 0 failed across 73 spec files**;
- Lanes `35678726404`: **PASS**;
- CodeQL `35678726418`: **PASS**.

v24.0.29 repairs Issue #304 without changing DB or Worker generation. Edit Trip → Delete and
swipe-delete now share one stable-id pending-delete queue; the target is suppressed from every
trip-list render immediately during the Undo window, duplicate queueing is refused, Undo/failure
restores the row, and commit deletes only the exact stable-id record. TDS-01/TDS-02 prove immediate
suppression, cross-render suppression, Undo restoration, exact-target deletion, and neighboring
record survival. Historical order `960760` remains a separate data-history question and is not
attributed to this defect without proof.

## v24.0.29 live production observation of record

Settled observation checkpoint: `98e447e3dc1ffe5d00e5793ab0725bde4e6a063a`.
PR #307 is governance-only, so this checkpoint serves the same v24.0.29 runtime bytes merged by #306.

- Live Parity `35679841528`, job `106594200002`: **VERDICT: PASS**. The log directly
  observes app/SW/manifest **24.0.29**, Worker **v21**, all **22** declared runtime assets,
  no runtime asset served as HTML, and **20** repository-only paths withheld.
- Production Service Worker `35679841496`, job `106594196748`: **VERDICT: PASS**.
  The worker reaches ACTIVATED, controls after reload, precaches `freightlogic-24.0.29`
  with all 22 assets, renders five tabs + Today after reload, and leaves exactly one
  generation cache.
- CodeQL `35679841490`, job `106594197964`: **PASS**.
- Exact-main full suite `35679841575`, job `106594197228`: **748 passed / 0 failed across 73 spec files**.

The runtime-merge push preserved the deployment-propagation boundary rather than hiding it.
Live Parity `35679161628` and Production Service Worker `35679161632` first observed the
prior v24.0.28 generation while Cloudflare was still settling, then both passed on attempt 2
with no code change once v24.0.29 was actually served. The first observations remain valid
evidence about production at that instant; the settled passes are the release evidence.

## Preserved source evidence — v24.0.28


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

## Preserved live production observation — v24.0.28

Current documentation checkpoint: `675e6fb0140f0e226219fc52955932703fc07a1c`.

- Live Parity `35661894518`, job `106538813802`: **VERDICT: PASS**. The log directly
  observes app/SW/manifest **24.0.28**, Worker `/health` **v21**, all **22** declared
  runtime assets loading, no runtime asset served as HTML, and **20** repository-only paths
  withheld.
- Production Service Worker `35661894391`, job `106538814618`: **VERDICT: PASS**.
  The worker reaches ACTIVATED, controls after reload, precaches
  `freightlogic-24.0.28` with all 22 assets, renders five tabs + Today after reload,
  and leaves exactly one generation cache.
- CodeQL `35661894363`, job `106538813341`: **PASS**.
- Exact-main full suite `35661894446`, job `106538812253`: **746 passed / 0 failed across 72 spec files**.

The runtime-merge push Live Parity run `35658640376` failed while deployment was still
settling. A later explicit dispatch on the runtime merge, `35658734732` (job
`106528647843`), directly observed v24.0.28 and passed. The runtime-merge Production
Service Worker run `35658640358` (job `106528337742`) also passed. This retains both
the race and the settled observation rather than erasing either.

The runtime-merge push Tests run `35658640366` recorded **745/1** in F-9. Claude later reproduced the failure as a **test-control timing dependency**: the test inserted two `await sleep(20)` yields between synchronous toast calls and reads, allowing the auto-hide timer or another caller to interfere. Test-only commit `0fc250cb0523bc040049cd25fbf6f12e9a5b376c` removed those yields; `app.js` stayed byte-identical, both negative controls still failed when the real severity guard was removed, and current exact-main Tests `35661894446` returned **746/0**. This stabilization changed no runtime asset and required no release-generation bump.


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
v24.0.28 or in the later test-only F-9 stabilization. The separate unavailable 125-row master remains separate and must never be
reconstructed from summaries.

Voice Load remains deliberately removed from v24.0.17 onward. The current runtime inventory
is 22 assets; a missing `voice-load.js` is expected, not a deployment defect.

This documentation successor changes no acceptance threshold, freight policy, manual A-row result,
credential, workflow trigger, database schema, or Worker generation. The v24.0.28 runtime-byte
changes are the separately reviewed PR #294 described above; this file does not itself deploy them.
