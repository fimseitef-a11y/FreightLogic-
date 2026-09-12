# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-12.** The app/PWA candidate remains **FreightLogic v24.0.5 / IndexedDB v15**. A real production probe proved the v24.0.5 app assets are live at `https://freightlogic-v2.fimseitef.workers.dev`, but also proved the separate backup/API Worker deployment is stale: production `/health` returned 401 instead of the repository contract's unauthenticated health response. The bounded source repair therefore advances the backup/API Worker contract to **v14** and aligns its CORS default with the real production app origin. Formal certification remains HOLD until Worker v14 is actually deployed/verified, the real private-history source bundle is reconciled, and the finite physical-iPhone gate passes.

Current certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-12.md`.

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
10. Live deployment evidence outranks stale deployment assumptions in docs/scripts. A dead hostname or stale Worker must be corrected rather than rationalized as an environment issue once a reachable production probe proves the mismatch.

## Gate 0 — Operator truth and evidence provenance

Status: **COMPLETE.**

Durable operator-truth, evidence-provenance, and open-question contracts exist. External IDs are not destructive identity; source mileage/price/status semantics remain typed; uncertain facts remain unresolved instead of promoted by inference.

## Milestone 1 — Doctrine and money integrity

Status: **IMPLEMENTED; EXACT-CANDIDATE REGRESSIONS GREEN.**

The current invariant set includes:

- Level X+ grade bands and ordinary/DZ floors;
- Cincinnati, Toledo, and the Chicago/Gary belt as intended Tier-1 geography;
- canonical Gary, Indiana mapping that cannot be confused with Calgary;
- blank/underspecified markets fail closed;
- explicit deadhead `0` remains a known zero while missing/invalid deadhead remains UNKNOWN/null through parser, evaluator, persistence, and history;
- default usable cargo length is 121 inches unless a provenance-bearing operator override exists;
- True Profit/precise economics are unavailable when required cost or mileage denominators are not defensible;
- advisory Midwest evidence cannot own canonical verdict/grade/bid authority;
- approved MPG fallback remains subordinate to explicit operator settings.

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

Status: **MACHINERY IMPLEMENTED AND SYNTHETIC REGRESSIONS GREEN; PRIVATE REAL-BUNDLE RERUN BLOCKED ON MISSING RAW SOURCE FILE.**

Implemented rules include idempotent/collision-resistant import, conservative linking, per-field provenance, source-timestamp recency, no broker guessing, distinct status classes, DZ exclusion from normal-market calibration, `WON / (WON + LOST)` denominators, and exclusion of unknown RPM/deadhead rather than coercion to zero.

The accessible project/File Library does not contain the raw row-level historical master. A recovered handoff states that a 125-row master once existed but explicitly warns not to reconstruct missing rows from summaries. Therefore the real-bundle gate remains **SOURCE FILE MISSING / NOT RUN** until the actual raw source is recovered or re-exported.

## Milestone 7 — Completion release certification

Status: **APP SOURCE + PRODUCTION APP PARITY READY; WORKER DEPLOYMENT / PRIVATE DATA / IPHONE STILL BLOCKING.**

### Automated/source evidence

Before the Worker-v14 repair, the v24.0.5 candidate had:

- 372 passed / 0 failed across 40 spec files;
- lane/path/lock CI green;
- deterministic built-in test server and IndexedDB-ready launch contract;
- app/PWA/service-worker/cache/manifest generation checks green;
- static CSP/source parity green;
- backup/full-delta/restore and local export/import integrity regressions green;
- no remaining source blocker from the v24.0.3 reconciliation.

The Worker-v14 origin repair must independently re-pass those gates before merge.

### Production evidence already observed

The 2026-09-12 live probe proved:

- `freightlogic-v2.fimseitef.workers.dev` is the production app origin;
- v24.0.5 index/app/voice/SW bridge/service worker/overlay/manifest assets passed the live parity verifier;
- `freightlogic.pages.dev` does not resolve and must not remain the verifier/default production authority;
- unauthenticated `/admin/users` on the backup Worker returns 401 as required;
- backup Worker `/health` returns 401 `Missing token` instead of the source contract's unauthenticated health response, proving the deployed backup Worker is stale/different from current source.

### Bounded Worker v14 repair

Worker v14 is not an app feature expansion. It closes the live deployment invariant proved by the probe:

- production/default CORS origin = `https://freightlogic-v2.fimseitef.workers.dev`;
- legacy Pages origins may remain accepted during migration but are not fallback authority;
- `/health` remains unauthenticated and reports Worker v14;
- live verifier defaults to the real app origin and requires Worker v14;
- regression coverage protects production-origin CORS and health/version semantics.

`wrangler.jsonc` deploys the separate `freightlogic-v2` app/assets service. It is **not** a safe standalone deployment configuration for `cloud-backup-worker.js`; do not overwrite the app service or guess KV binding identifiers merely to force the Worker gate green.

### Blocking evidence still required

1. **Backup/API Worker deployment parity** — deploy the merged Worker-v14 source through the actual Worker deployment path; then prove `/health` 200/version14, production-origin CORS, auth boundaries, `/evaluate`/`/extract` where applicable, and authenticated backup/delta/restore smokes.
2. **Private operator-history reconciliation** — recover/re-export the real raw source bundle and run current M6 reconciliation; do not fabricate it from summaries.
3. **Physical iPhone certification** — finite A1-A9 checks in `FIELD_TEST_CHECKLIST.md` against the same live candidate. Prior v23.7.0 installed-PWA evidence remains unresolved until safely retested.
4. **Rollback evidence** — record an executable rollback SHA/procedure for the final frozen candidate.

Do not mark unobserved private/device/authenticated gates PASS by inference. Do not clear Safari website data or delete the installed PWA merely to force an update because that can destroy IndexedDB evidence.

## Completion definition

The named release is complete when one named source/runtime candidate has:

- one canonical decision authority and correct doctrine/economics/UNKNOWN semantics;
- durable lifecycle and normalized evidence with provenance;
- production manual/email-compatible intake;
- historical import/calibration machinery plus real private-bundle reconciliation proof;
- deterministic green automated suite and repository governance;
- backup/restore/import/export integrity with secret exclusion;
- live production app parity;
- live Worker-v14 parity and authority/backup smokes;
- finite physical-iPhone field checks;
- approved release and rollback SHAs recorded in a superseding certification-state document.

## Execution order from here

1. Merge the bounded Worker-v14 origin repair only after full CI and lane enforcement are green.
2. Deploy Worker v14 through the actual backup-Worker deployment path without disturbing the `freightlogic-v2` app/assets service or guessing bindings/secrets.
3. Rerun the live parity and authenticated authority/backup checks.
4. Recover/re-export the real private M6 source bundle and reconcile it without publishing sensitive raw data.
5. Run the finite iPhone checks against the same live candidate.
6. If a gate fails, repair the cause and repeat the affected exact-candidate gates.
7. When all blocking evidence is PASS, create a new certification-state document that supersedes `COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-12.md`, records release/rollback SHAs, and closes Issue #119.

Do not reorder this sequence merely to add more live sources or convenience features.
