# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-11.** The source/tooling candidate reviewed is `556f5b0141cf658ba76a8ed32105e5bf9258bb20`, running **FreightLogic v24.0.5 / IndexedDB v15 / Worker v13**. The exact post-repair integration gate is **372 passed / 0 failed across 40 spec files**, with lane/path/lock enforcement green. The source defects discovered after v24.0.3 are closed. The named completion release remains **HOLD only for evidence that cannot be manufactured from repository source**: private operator-history reconciliation, exact live Cloudflare production parity, and the finite physical-iPhone certification gate.

Current certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`.

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

Opportunity, execution, and settlement remain separate dimensions. `EXPIRED`, `LOST`, `CANCELLED`, `FELL_THROUGH`, `DELIVERED`, and `PAID` are not collapsed into one another. Stable lifecycle identity does not depend on reused external IDs. Backup/delta/restore/export/import and revision-conflict semantics are covered.

## Milestone 5 — Freight-source ingestion foundation

Status: **5A + 5B IMPLEMENTED; 5C + 5D NON-BLOCKING.**

Approved sequence remains:

**normalized contract -> manual/email-compatible intake -> vision -> provider adapters**

The shipped foundation preserves provenance, price/mileage semantics, UNKNOWN values, conservative lifecycle state, and provider-independent durable evidence. A shipper/bookable price, bid, target, or benchmark cannot silently become canonical carrier revenue. Future vision/provider integrations must enter through this contract.

## Milestone 6 — Historical import + Personal Intelligence calibration

Status: **MACHINERY IMPLEMENTED AND SYNTHETIC REGRESSIONS GREEN; PRIVATE REAL-BUNDLE RERUN REMAINS.**

Implemented rules include idempotent/collision-resistant import, conservative linking, per-field provenance, source-timestamp recency, no broker guessing, distinct status classes, DZ exclusion from normal-market calibration, `WON / (WON + LOST)` denominators, and exclusion of unknown RPM/deadhead rather than coercion to zero.

The remaining M6 gate is evidentiary: run the exact current importer/reconciliation path against the private operator source bundle and record only non-sensitive reconciliation results. Repository fixtures cannot substitute for that private-source proof.

## Milestone 7 — Completion release certification

Status: **AUTOMATED/SOURCE GATE COMPLETE; FORMAL CERTIFICATION HOLD.**

### Automated/source gate — complete

Current proof on the exact post-repair candidate:

- FreightLogic v24.0.5 / DB v15 / Worker v13;
- 372 passed / 0 failed across 40 spec files;
- lane/path/lock CI green;
- deterministic built-in test server and IndexedDB-ready launch contract;
- app/PWA/service-worker/cache/manifest generation regression checks green;
- static CSP/source parity green;
- backup/full-delta/restore and local export/import integrity regressions green;
- no remaining proof-backed source blocker from the v24.0.3 reconciliation;
- normal repository ownership restored and temporary completion locks released.

### Blocking evidence still required

1. **Private operator-history reconciliation** — real private M6 source bundle on the current importer.
2. **Live Cloudflare production parity** — production app/PWA/service-worker generation, Worker `/health`, auth boundaries, `/evaluate`/`/extract` where deployed, and backup/delta/restore smokes on the exact candidate.
3. **Physical iPhone certification** — the finite blocking checks in `FIELD_TEST_CHECKLIST.md` on the same production candidate. Prior evidence of an installed v23.7.0 PWA remains an unresolved A1 observation until safely retested.

Do not mark an unobserved live/device/private gate PASS by inference. Preview deployment success is not production parity. Do not clear Safari website data or delete the installed PWA merely to force an update because that can destroy IndexedDB evidence.

## Completion definition

The named release is complete when all of the following are true on one named source/runtime candidate:

- one canonical decision authority and correct doctrine/economics/UNKNOWN semantics;
- durable lifecycle and normalized evidence with provenance;
- production manual/email-compatible intake;
- historical import/calibration machinery plus the private-bundle reconciliation proof;
- deterministic green automated suite and repository governance;
- backup/restore/import/export integrity with secret exclusion;
- live Cloudflare production parity and authority-boundary smoke checks;
- finite physical-iPhone field checks;
- approved release and rollback SHAs recorded in a superseding certification-state document.

## Execution order from here

1. Preserve `556f5b0141cf658ba76a8ed32105e5bf9258bb20` as the source/tooling evidence head for v24.0.5 unless a new proved defect requires source change.
2. Run the private M6 operator-history reconciliation without committing sensitive source files.
3. Verify exact live Cloudflare production parity using `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`.
4. Run the finite iPhone checks in `FIELD_TEST_CHECKLIST.md` against the same live candidate.
5. If any gate fails, repair the cause and repeat the affected exact-candidate gates.
6. When all blocking evidence is PASS, create a new certification-state document that explicitly supersedes `COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`, records the approved release/rollback SHAs, and closes Issue #119.

Do not reorder this sequence merely to add more live sources or convenience features.