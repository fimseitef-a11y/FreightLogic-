# GPT → Claude: PR #108 / M6 reconciliation required before merge

Date: 2026-08-27
Current main: `3fba27a16cebf22a20a54191101b17cc27feac6e`
Draft PR: #108
Draft head reviewed: `9cd624edcb60cbfb740e97f94d43cf0497ab367f`
Valid fixes on branch: `d9d01a7` bounded fingerprint; `9cd624e` local `importJSON()` lifecycle parity.

## Status

Keep PR #108 DRAFT / DO NOT MERGE. The two runtime defects above are valid and should be preserved, but the one-time historical adapter and the merged M5/M6 persistence model do not yet satisfy the governing operator-truth/provenance contracts.

The real bundle exercise was valuable: it proved 132/136 completed-order rows have unknown deadhead and therefore cannot support defensible True RPM, and it exposed both fingerprint truncation and local-file import loss. Do not weaken those UNKNOWN conclusions merely to make calibration populate.

## A. One-time adapter blockers (`scripts/m6-import.mjs`)

### A1. Order-number-only reconciliation can false-merge distinct shipments

The adapter creates `const orders = new Map()` keyed by `orderNo.toUpperCase()`.

Governing history says order-ID dedup is allowed only when records truly refer to the same shipment. Future/load-observation identity must preserve composite distinguishing facts (ID + origin + destination + pickup date/time where available). A repeated order number may not force a destructive merge.

Repair: use a conservative composite order identity / explicit source-link strategy. If two records share an ID but route/date facts conflict, preserve both or mark unresolved; do not silently choose one.

Regression: same order ID, different lane/date => two records or explicit unresolved conflict, never one merged row.

### A2. First-source-wins violates operator-correction precedence

`upsertOrder()` only fills empty fields. A later operator-confirmed correction cannot replace an earlier non-empty value.

Repair: field-level precedence must follow `docs/EVIDENCE_PROVENANCE.md`: current explicit operator correction > primary source > operator-confirmed history > weaker/secondary summaries. Preserve superseded lineage.

Regression: earlier secondary populated value + later operator-confirmed correction => later correction wins with provenance retained.

### A3. Per-field provenance is lost during reconciliation

A later source can fill a field while top-level `sourceName/rawEvidenceRef` still describe the first-created row. `_sources` is then deleted before output. That can make a correct number carry the wrong source.

Repair: retain per-field provenance or a linked evidence array sufficient to establish which source supplied each material money/mileage/status fact. Do not flatten conflicting sources into one untraceable row.

### A4. DRY RUN handling contradicts the governing history

The adapter sends `dry_run` rows to `withheld[]` and excludes them from the imported lifecycle rows. The Aug-24 operator-confirmed ledger rule is: DRY RUN entries are completed but must remain separately flagged; they are excluded from normal freight economics, not deleted from completed operational history.

Repair: import dry runs as completed operational records with a dedicated cohort/type flag that excludes them from normal-market/normal-earnings calibration.

Regression: dry-run row remains queryable as completed operational history but never enters ordinary winning-range/normal-freight economics.

### A5. Unknown RECOVERED statuses may be promoted to award evidence

For every non-dry RECOVERED row the adapter currently writes `awarded:true`, even when derived `opportunity` is `SEEN` for an unrecognized status.

Repair: only set award/completion evidence when the exact status/source proves it. Unknown secondary status remains unknown/SEEN and unawarded.

Regression: unrecognized RECOVERED status => no `awarded:true`, no fabricated WON.

### A6. `Carrier` must not silently become `broker`

The `text 2.csv` mapping uses `broker: str(r.Carrier)`. Verify the source column semantics. If it names the carrier/operator rather than broker, retain it under carrier/source-company semantics and leave broker unknown.

Regression/fixture should prove a carrier-labelled field cannot create broker identity unless source documentation/field meaning establishes that.

## B. M5/M6 durability blocker already live on main

### B1. Normalized evidence is transient

`normalizeOpportunity()` creates amount, price semantic, canonical revenue, loaded/deadhead values, mileage semantic, and provenance. `intakeOpportunity()` passes only identity/route/state to `linkLifecycle()`. After reload, the normalized evidence is gone.

### B2. Historical importer repeats the same loss

`importHistoricalOpportunities()` calls `normalizeOpportunity()` but persists a lifecycle object containing only identity, route/date, opportunity/execution/settlement, cohort, migration tokens and sourceRefs. It does NOT persist:

- `amount`
- `priceSemantic`
- `canonicalRevenue`
- `loadedMi` / `deadMi`
- `mileageSemantic`
- `sourceDisplayedRpm`
- normalized provenance (`sourceType`, sourceName/timestamp, raw evidence ref, confirmation/confidence)

Therefore PR #107's M6-08 test title/claim that "price semantic and source provenance survive import" is not proven. M6-08 only checks `lastMutation.source`, `migration.importedLegacy`, and token count.

Repair: introduce a durable, additive normalized-evidence representation linked by stable lifecycle/evidence ID (or another architecture that satisfies the same contract) with full backup/delta/restore/export/import parity. Do not overload lifecycle state into an unbounded blob if a bounded evidence store is cleaner.

Required regressions:
- manual/email normalized amount + semantics + provenance survive app reload;
- historical imported amount/mileage semantics/source evidence survive reload;
- source RPM remains SOURCE RPM and cannot become True RPM when deadhead is unknown;
- backup/delta/restore + local export/import preserve durable evidence;
- old payloads with no evidence records remain valid.

### B3. Complete semantic vocabulary before real calibration

Reconcile M5 enum coverage with `docs/EVIDENCE_PROVENANCE.md`, including at minimum `BOARD_TARGET_RATE`, `POSTED_RATE`, `MARKET_BENCHMARK`, and `POST_DELIVERY_REPOSITION_MILES`, plus required observed/source-health/platform/company distinctions. Unknown semantics remain isolated from canonical revenue.

## C. Calibration guardrails

### C1. No durable RPM evidence = no real calibration

`calibrateFromLifecycle()` currently requires an external `rpmLookup`. Until historical money/mileage evidence is durably linked, a reload cannot reproduce the calibration inputs. Do not claim M6 Personal Intelligence calibration complete from transient in-memory adapter objects.

### C2. Undated evidence gets full recency weight

`calibrateWinningRange()` currently returns weight 1 when `observedAt` is null. That makes unknown-age evidence as fresh as current evidence. Reconcile this with confidence/freshness doctrine: unknown age must not receive an implicit freshness advantage. Use an explicit conservative policy or exclude from recency-weighted calibration; test it.

### C3. Preserve current correct outcome: no fabricated calibration

The real bundle reportedly has zero recorded losses and no defensible True-RPM samples. Keep win rate/range NOT CALIBRATABLE unless new verified evidence changes those facts.

## D. Earlier release blockers still precede freeze

PR #108 fixes do not close the post-merge M3/M4 integrity hold. Carry forward and repair before any completion-release/freeze claim:

- DB-v14 lifecycle indexes not created because catch-all `ensureStore('loadLifecycle')` precedes the v14 indexed-create block;
- cloud delta sync `lc` initialization/ordering defect if still present on current source;
- lifecycle checksum/integrity coverage;
- conservative linking/reused-ID + UI lookup ambiguity;
- legacy lifecycle backfill/restart safety;
- pickup/delivery time precision and persisted fell-through semantics;
- Worker canonical UNKNOWN/UNAVAILABLE/?/null/suppressed projection;
- explicit fuel write-point provenance;
- NWS successful-zero vs no-observation/failure;
- evaluation-history evidence snapshot;
- real lane/broker/vehicle-fit evidence wiring;
- coherent app/PWA/Worker release generation and deployment parity.

Re-verify each against current main rather than assuming old packet state.

## E. PR #108 readiness gate

Do not mark ready until:

1. A1-A6 corrected and tested.
2. B1-B3 durable ingestion/provenance gap resolved or separated into an earlier blocking PR that PR #108 explicitly depends on.
3. C1-C3 calibration semantics proven.
4. Real bundle rerun after adapter repair; report changed counts/statuses and unresolved conflicts, but do NOT commit raw financial CSVs.
5. `d9d01a7` fingerprint fix and `9cd624e` local JSON lifecycle-import fix remain intact.
6. Full suite + lane guards green on the final exact head.
7. No release/freeze claim until the D blockers and M7 field/live certification are green.

Raw operator financial CSVs remain private/uncommitted unless the operator explicitly authorizes repository storage.