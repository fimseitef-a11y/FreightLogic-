# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-14.** Exact runtime candidate `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` is **FreightLogic v24.0.9 / IndexedDB v15 / Worker v15 source**. The exact runtime suite is green at **431/0 across 45 spec files**. Read-only release tooling/docs subsequently advanced repository `main` to `578acaeec1c67e25bad2e58967d81138186dae5f` without changing shipped runtime files; current `main` suite `34799469734` is green at **442/0 across 46 spec files**. Cloudflare successfully built/deployed the exact runtime SHA for `freightlogic-v2` (build `8caa3ac9-511f-4d9d-835f-cf6ba916cca7`, version `ba1edf4d-f9c5-4836-a1b8-e2be1d0f6b0f`). Source-side deployment coverage derives the full runtime inventory (23 assets) and specifically proves `admin-driver-ui.js` is requested, present, and deployable. A manual/read-only **Verify Live Parity** GitHub Actions runner is now merged and ready, but the exact v24.0.9 live all-asset origin sweep is still **NOT RUN / UNOBSERVED** until that workflow is actually dispatched. Authenticated Worker authority/backup smokes are **NOT RUN**, the recovered private-history bundle still needs the real application round trip/idempotence/conflict review, six-width + physical-iPhone acceptance remain open, and the rollback verifier itself needs a bounded v24.0.9/Worker-v15 tooling correction before it can supply final B5 evidence. Formal certification remains **HOLD**.

Current certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md`.

Vision ingestion and provider-adapter expansion remain approved but non-blocking. Do not enlarge the completion definition to chase new providers, booking, or model features.

## Roadmap discipline

1. This file is the single active roadmap; GitHub Issue #119 is the execution/certification tracker, not a second roadmap.
2. Operator corrections and primary evidence outrank summaries or inference.
3. UNKNOWN is not zero. Loaded, deadhead, displayed-total, map-estimated, and reposition mileage remain distinct facts.
4. Price semantics remain explicit; shipper/bookable, bid, target, benchmark, carrier payout, and settled amount are not interchangeable.
5. The Unified Decision Engine is the sole client authority for verdict, grade, economics, and canonical bid range. Evidence, overlays, providers, and AI may explain or supply bounded evidence but may not become a competing decision engine.
6. Green tests never overrule a newly proved correctness defect; a proved invariant violation is repaired inside existing scope rather than treated as scope expansion.
7. Provider-account access is not API/partner authorization.
8. Raw private operator financial/history source files remain outside the public repository unless explicitly authorized.
9. Successful vision-model extraction, provider approval, provider booking, and provider-adapter expansion are not required to freeze this completion release.
10. Live deployment evidence outranks stale deployment assumptions in docs/scripts. A dead hostname, missing runtime asset, or stale Worker must be corrected rather than rationalized once a reachable production probe proves the mismatch.
11. A successful Cloudflare build/deploy is deployment evidence, not byte/content parity. Exact live-origin verification remains a separate gate.
12. UNOBSERVED is not FAILURE and is not PASS. A live verifier may return UNOBSERVED only when no HTTP observation is possible; an actual 4xx/5xx response is observed and must be judged as pass/failure evidence.

## Gate 0 — Operator truth and evidence provenance

Status: **COMPLETE.**

Durable operator-truth, evidence-provenance, and open-question contracts exist. External IDs are not destructive identity; source mileage/price/status semantics remain typed; uncertain facts remain unresolved instead of promoted by inference.

A Canada-rate authority conflict is intentionally retained in `docs/OPEN_QUESTIONS.md`: materially different cross-border numbers exist with different provenance, and no runtime protective floor may be changed by inference until explicit operator correction or stronger primary evidence resolves whether each figure is a floor, target, or market observation.

## Milestone 1 — Doctrine and money integrity

Status: **IMPLEMENTED; EXACT-CANDIDATE REGRESSIONS GREEN.**

The current invariant set includes:

- Level X+ grade bands and ordinary/DZ floors;
- Cincinnati, Toledo, and the Chicago/Gary belt as intended Tier-1 geography;
- canonical Gary, Indiana mapping that cannot be confused with Calgary;
- blank/underspecified markets fail closed;
- explicit deadhead `0` remains a known zero while missing/invalid deadhead remains UNKNOWN/null through parser, evaluator, persistence, and history;
- default usable cargo length is 121 inches unless a provenance-bearing operator override exists;
- operator-measured 54.8-inch wheel-well and 3,000-pound practical payload boundaries are enforced by regression coverage;
- True Profit/precise economics are unavailable when required cost or mileage denominators are not defensible;
- advisory Midwest evidence cannot own canonical verdict/grade/bid authority;
- approved MPG fallback remains subordinate to explicit operator settings;
- v24.0.9 pickup feasibility runs before economics only when the operator supplies enough facts: no default planning speed is invented, unknown deadhead never becomes zero, an unreachable/passed cutoff blocks, and a reachable narrow window is advisory only.

## Milestone 2 — Expense/fuel concurrency integrity

Status: **IMPLEMENTED; GREEN.**

Optimistic concurrency protects trip, expense, and fuel edits; stale writes fail rather than silently overwriting newer data. Same-millisecond revision behavior is regression-tested.

## Milestone 3 — Confidence + Evidence

Status: **IMPLEMENTED; GREEN.**

Confidence is categorical and descriptive, source-aware, and cannot relax floors or replace canonical decisions. Successful zero observations remain distinct from failed/unobserved evidence. Persisted snapshots are secret-free and backward-compatible.

## Milestone 4 — Load Lifecycle

Status: **IMPLEMENTED; GREEN.**

Opportunity, execution, and settlement remain separate dimensions. `EXPIRED`, `LOST`, `CANCELLED`, `FELL_THROUGH`, `DELIVERED`, and `PAID` are not collapsed. Stable lifecycle identity does not depend on reused external IDs. Backup/delta/restore/export/import and revision-conflict semantics are covered.

## Milestone 5 — Freight-source ingestion foundation

Status: **5A + 5B IMPLEMENTED; 5C + 5D NON-BLOCKING.**

Approved sequence remains:

**normalized contract -> manual/email-compatible intake -> vision -> provider adapters**

The shipped foundation preserves provenance, price/mileage semantics, UNKNOWN values, conservative lifecycle state, and provider-independent durable evidence. A shipper/bookable price, bid, target, or benchmark cannot silently become canonical carrier revenue. Future vision/provider integrations must enter through this contract.

## Milestone 6 — Historical import + Personal Intelligence calibration

Status: **MACHINERY IMPLEMENTED AND SYNTHETIC REGRESSIONS GREEN; PRIVATE SOURCE BUNDLE RECOVERED; REAL APPLICATION ROUND TRIP / IDEMPOTENCE / CONFLICT REVIEW STILL OPEN.**

Implemented rules include idempotent/collision-resistant import, conservative linking, per-field provenance, source-timestamp recency, no broker guessing, distinct status classes, DZ exclusion from normal-market calibration, `WON / (WON + LOST)` denominators, and exclusion of unknown RPM/deadhead rather than coercion to zero.

The original August 27 five-file M6 bundle was recovered privately in an earlier session. Existing preflight evidence reports **216 source rows -> 149 deterministic candidate records** under the unchanged adapter. Those candidates still must pass the actual FreightLogic import -> reload -> export/re-import path, repeated-import/idempotence checks, and source-conflict review before this milestone can be certified on real data.

The raw five files are not mounted in the current execution session; searches of the connected File Library, Dropbox, and Google Drive under the recorded bundle/source filenames found no copy. Therefore the application round trip remains NOT RUN rather than being reconstructed from summaries.

The separate **125-row master** referenced by an older handoff remains unavailable. Do not reconstruct it from summaries, do not invent missing rows, and do not treat the recovered 216-row bundle as proof that the distinct 125-row master has been found.

## Milestone 7 — Completion release certification

Status: **SOURCE/CI + EXACT CLOUDFLARE BUILD + LIVE-RUNNER TOOLING GREEN; ACTUAL LIVE PARITY / AUTHENTICATED WORKER SMOKES / PRIVATE DATA / VISUAL / IPHONE / FINAL ROLLBACK EVIDENCE STILL BLOCKING.**

### Automated/source evidence

Exact runtime candidate `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` has:

- PR #175 full suite: **431 passed / 0 failed across 45 spec files** in run `34796439138`;
- post-merge runtime `main` Tests run `34796618850`: **SUCCESS** on the same exact runtime SHA;
- lane/path/lock CI green;
- deterministic built-in test server and IndexedDB-ready launch contract;
- app/PWA/service-worker/cache/manifest generation checks green for v24.0.9;
- static CSP/source parity green;
- backup/full-delta/restore and local export/import integrity regressions green;
- Worker-v15 health/CORS regressions green;
- operator-measured 54.8-inch wheel-well and 3,000-pound payload regressions green;
- pickup-feasibility regressions protecting unset planning speed, unknown-vs-zero deadhead, unreachable cutoff, reachable cutoff, already-passed cutoff, and tight-window advisory behavior;
- deployment-asset coverage derived from the runtime declarations rather than a curated subset, currently **23 assets**, including `admin-driver-ui.js`.

Current read-only tooling/docs `main` additionally has:

- PR #177 merged: manual/read-only **Verify Live Parity** workflow plus PASS/FAILURE/UNOBSERVED semantics and 11 dedicated runner assertions;
- PR #178 merged: backup-contract parity through v24.0.9 including durable optional `planningAvgMph` and absent-means-absent behavior;
- Tests run `34799469734`: **442 passed / 0 failed across 46 spec files**.

### Production evidence already observed

Cloudflare's GitHub production check completed **SUCCESS** for exact runtime SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` on service `freightlogic-v2`:

- build `8caa3ac9-511f-4d9d-835f-cf6ba916cca7`;
- version `ba1edf4d-f9c5-4836-a1b8-e2be1d0f6b0f`.

That proves Cloudflare accepted/built/deployed the exact candidate. It does **not** prove all 23 runtime assets at the live origin match the source bytes/content. The exact v24.0.9 all-asset live sweep remains **NOT RUN / UNOBSERVED** until the merged GitHub Actions runner is actually dispatched.

The backup/API Worker did not change in v24.0.9. On 2026-09-13 Worker v15 was directly observed live with:

- `GET /health` HTTP 200 / version 15;
- exact `https://freightlogic-v2.fimseitef.workers.dev` CORS on health GET;
- backup preflight OPTIONS HTTP 204 with the exact production origin;
- unauthorized admin request denied HTTP 401.

This discharges the old Worker-v14/v15 deployment-parity blocker for free health/CORS/auth-boundary probes. It does **not** discharge authenticated authority/backup smokes.

### Deployment-asset defect and repair status

The v24.0.8 audit proved a real deployment blind spot: the old curated parity list could be green while `admin-driver-ui.js` was absent in production. The source exclusion was repaired, and PR #174 introduced a derived complete runtime inventory shared by source deploy-coverage tests and the live verifier. PR #177 then made that live verifier runnable from GitHub's network without deployment privileges or secrets.

The next gate is observation, not more parity-runner engineering: dispatch **Actions -> Verify Live Parity -> Run workflow** on `main`, leave both optional origins blank, and record the actual verdict. PASS closes the all-asset network observation; FAILURE names a real mismatch to fix; UNOBSERVED makes no product claim.

### Blocking evidence still required

1. **Exact live v24.0.9 production parity** — dispatch the merged **Verify Live Parity** workflow; prove every derived runtime asset matches/has valid content and reject HTML-shell masquerade for static requests.
2. **Service-worker / offline production check** — prove the exact v24.0.9 candidate, including the formerly missing admin runtime asset, survives normal update/reload/offline behavior without destructive clearing.
3. **Authenticated Worker authority + backup checks** — with a dedicated non-published test identity, prove `/evaluate` and `/extract` authority behavior plus full/delta backup, restore, and in-place token rotation without exposing credentials or risking real data.
4. **Private operator-history reconciliation** — run the recovered M6 source bundle through the actual application round trip, repeated import/idempotence, export/re-import, and source-conflict review. Do not fabricate the separate unavailable 125-row master.
5. **Six-width visual acceptance** — complete the documented 320/375/390/393/430/440 checks, dark/light, touch targets, and overflow on the same final candidate.
6. **Physical iPhone certification** — finite A1-A10 checks in `FIELD_TEST_CHECKLIST.md` against the same live candidate, including installed-PWA update/offline behavior and v24.0.9 pickup feasibility.
7. **Rollback/fix-forward evidence** — repair the stale `scripts/verify-rollback.mjs` candidate/Worker-v14 assumptions, then record the exact safe fix-forward/rollback evidence for the final frozen candidate. Known-regression older builds must not be presented as safe rollback targets merely because they exist.

Do not mark unobserved private/device/authenticated/live-origin gates PASS by inference. Do not clear Safari website data or delete the installed PWA merely to force an update because that can destroy IndexedDB evidence.

## Completion definition

The named release is complete when one named source/runtime candidate has:

- one canonical decision authority and correct doctrine/economics/UNKNOWN semantics;
- durable lifecycle and normalized evidence with provenance;
- production manual/email-compatible intake;
- historical import/calibration machinery plus real private-bundle reconciliation proof;
- deterministic green automated suite and repository governance;
- backup/restore/import/export integrity with secret exclusion;
- exact live production app/all-asset parity and controlled service-worker/offline behavior;
- live Worker-v15 health/CORS plus authenticated authority/backup smokes;
- six-width visual acceptance;
- finite physical-iPhone field checks;
- truthful release and rollback/fix-forward SHAs/procedure recorded in a superseding certification-state document.

## Execution order from here

1. Dispatch **Verify Live Parity** on current `main` with both optional origin inputs blank and record PASS / FAILURE / UNOBSERVED.
2. Repair and run the stale rollback verifier so B5 evidence is about v24.0.9 / Worker v15 rather than an obsolete candidate.
3. Run authenticated Worker authority/backup/restore/rotation smokes using a dedicated non-published test identity.
4. Run the recovered private M6 bundle through actual application reconciliation and review conflicts/idempotence without publishing sensitive raw data.
5. Complete six-width visual acceptance on the same candidate.
6. Run the finite physical-iPhone A1-A10 checks on the same candidate.
7. Record the safe rollback/fix-forward reference for the final frozen release.
8. If a gate fails, repair the cause and repeat the affected exact-candidate gates.
9. When all blocking evidence is PASS, create a new certification-state/addendum document that supersedes the current HOLD authority, records release/rollback evidence, and closes Issue #119.

Do not reorder this sequence merely to add more live sources or convenience features.