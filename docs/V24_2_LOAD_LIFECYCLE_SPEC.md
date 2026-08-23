# FreightLogic v24.2 — Load Lifecycle Contract

Status: implementation specification only. No runtime/storage behavior changes in this document.

## Purpose

v24.2 gives FreightLogic one durable operational identity for a load from first sighting through bid/award, physical execution, invoicing, and payment. It replaces today’s fragmented interpretation of `bidHistory`, `trips`, tracking state, and payment fields with an additive lifecycle record while preserving every legacy store during transition.

The goal is **not** a single lossy status. Opportunity, execution, and settlement remain separate dimensions and the UI derives a human-readable stage from them.

This phase is a data-contract/storage phase. It does not change the v24.0 Unified Decision Engine’s authority over verdict, grade, economics, or canonical bid range, and it does not introduce v24.3 self-calibration yet.

## Current-source constraints this design must preserve

Current `main` is DB version 13. Relevant persisted structures already include:

- `trips` keyed by `orderNo`, with trip economics, dates, `isPaid`, `paidDate`, DZ fields, and optimistic concurrency via `updatedAt`;
- `bidHistory` keyed by generated `id`, indexed by broker/lane/date, with multiple record flavors including bid outcomes and broker/post-trip evidence;
- `laneHistory`, `reloadOutcomes`, and weekly reports as derived/history stores;
- cloud/local backup and restore paths that explicitly enumerate stores;
- import sanitation and broker-key normalization;
- v13 broker migration that marks ambiguous pre-chain bid records `legacyUnkeyed` instead of guessing identity.

The existing bid-outcome writer currently records `outcome: won | expired | rejected`. The existing trip record does **not** prove delivery merely because a scheduled `deliveryDate` exists. Migration must therefore be conservative and must not manufacture operational facts from scheduled dates or fuzzy matching.

## Canonical lifecycle dimensions

### Opportunity

Allowed values:

- `SEEN`
- `QUOTED`
- `BID`
- `WON`
- `LOST`
- `EXPIRED`
- `CANCELLED`

Rules:

- `EXPIRED` means no known award decision. It is not `LOST` and is excluded from the ordinary win-rate denominator.
- `CANCELLED` means broker/customer/load withdrawal. It is not `LOST` and is excluded from the ordinary win-rate denominator.
- Ordinary win-rate calibration uses only known `WON` and `LOST` outcomes.
- A board item disappearing without a known broker decision must remain `EXPIRED`, not be converted to `LOST`.

### Execution

Allowed values:

- `NOT_STARTED`
- `EN_ROUTE_PICKUP`
- `PICKED_UP`
- `DELIVERED`
- `FELL_THROUGH`

Rules:

- execution states are meaningful only after a load is won/accepted or otherwise explicitly committed;
- a scheduled pickup/delivery date does not prove physical execution;
- GPS/tracking actions may advance execution only when they are linked to the lifecycle identity;
- `FELL_THROUGH` preserves a won/accepted opportunity that did not complete physically; it must not rewrite the opportunity result as a loss.

### Settlement

Allowed values:

- `NOT_INVOICED`
- `INVOICED`
- `OVERDUE`
- `PAID`
- `BAD_DEBT`

Rules:

- payment/invoice state is independent of execution state;
- `PAID` is not a substitute for `DELIVERED`, though migrated legacy evidence may use paid status as corroboration that execution occurred;
- `OVERDUE` is derived only from an actual invoiced/due state, not merely from a populated date that may have been defaulted by an older sanitizer;
- `BAD_DEBT` is explicit user/accounting state, never inferred from age alone.

## Known/unknown semantics

The three state vocabularies intentionally stay small. To avoid lying during migration, each dimension also carries whether the state is actually known:

```text
DimensionState
  state             one allowed state above
  known             boolean
  stateAt           timestamp when known; null when unknown
  source            USER | BOARD | IMPORT | TRACKING | TRIP | PAYMENT | MIGRATION | SYSTEM
  sourceRef         optional legacy/external record reference
  inferred          boolean
  reasons[]         deterministic explanation when inferred/unknown
```

When `known=false`, the UI displays the dimension as unknown/needs confirmation even though a storage-safe placeholder state exists. Analytics/calibration must exclude unknown dimensions rather than treating the placeholder as operational truth.

## New canonical store

v24.2 should bump IndexedDB from v13 to **v14** and add one store:

`loadLifecycle`

Recommended record shape:

```text
LoadLifecycleRecord
  id                    stable FreightLogic UUID / lifecycle identity
  schemaVersion         "24.2"

  aliases[]
    type                LIFECYCLE_ID | LOAD_ID | ORDER_NO | BROKER_REF | IMPORT_FINGERPRINT | OTHER
    namespace           source/platform namespace when known
    value               normalized exact identifier

  sourceRefs[]
    store               bidHistory | trips | import | tracking | other
    key                 exact legacy/source key

  brokerKey             normalized broker identity when explicit
  brokerDisplay         display form when known
  origin
  destination
  laneKey
  pickupWindow          optional structured/compact pickup window
  deliveryWindow        optional structured/compact delivery window

  opportunity           DimensionState
  execution             DimensionState
  settlement            DimensionState

  isDZExit              boolean
  firstSeenAt
  createdAt
  updatedAt

  events[]               append-only lifecycle transition/correction events
  migration             optional migration provenance
```

The implementation may adjust field names to fit source conventions, but the semantic contract must remain equivalent.

## Event history

Lifecycle state changes must be auditable. Each lifecycle record keeps an append-only event list sufficient to explain how its current dimensions were reached:

```text
LifecycleEvent
  id
  at
  dimension             OPPORTUNITY | EXECUTION | SETTLEMENT | IDENTITY | NOTE
  from                  previous state/value when applicable
  to                    new state/value
  source
  sourceRef
  reason
  correction            boolean
```

Corrections append a correcting event; they do not silently rewrite history. The current state fields are a materialized view of the latest valid events.

No event may include credentials, API tokens, full email bodies, bank data, or other secrets.

## Identity resolution

Identity matching must be conservative because a false merge permanently corrupts lane/broker learning.

Automatic identity attachment is allowed only when there is an exact, trustworthy link such as:

1. existing lifecycle `id`;
2. exact source-namespaced load/order identifier already stored as an alias;
3. an explicit legacy/source reference previously bound to the lifecycle record.

The following may identify a **candidate** but must never auto-merge two lifecycle records by themselves:

- same broker + lane;
- similar pickup time;
- same weight/rate/miles;
- fuzzy city matching;
- same screenshot text;
- same customer field.

If two existing lifecycle records claim the same exact alias, surface an identity conflict for deterministic/manual resolution. Do not silently pick one.

## DB migration strategy

### Schema upgrade

`DB_VERSION` moves 13 -> 14. `onupgradeneeded` should perform only the structural store/index creation needed by IndexedDB:

- create `loadLifecycle` with keyPath `id`;
- add indexes useful for exact lookup/operational filtering where supported by the chosen physical shape (for example `updatedAt`, current opportunity state, broker key);
- do not delete/rename any legacy store or mutate legacy records in the schema-upgrade transaction.

Complex data backfill should run after a successful DB open through a separately testable, idempotent runtime migration function rather than turning `onupgradeneeded` into a large cross-store inference engine.

### Additive backfill

The migration is additive. Existing `trips`, `bidHistory`, `laneHistory`, `reloadOutcomes`, settings, and other records remain untouched.

Backfill creates lifecycle records only from evidence that can be represented without inventing facts.

Safe mappings include:

- explicit bid-outcome `won` -> opportunity `WON`, known=true;
- explicit bid-outcome `expired` -> opportunity `EXPIRED`, known=true;
- explicit bid-outcome `rejected` -> opportunity `LOST`, known=true **only when that record flavor is the actual bid-outcome log**; a generic broker-memory `rejected` value must not be reinterpreted as a board award decision;
- a real `trip` record may establish a committed/won load identity, but execution must remain unknown unless there is separate physical evidence;
- `isPaid=true` can establish settlement `PAID` and is strong corroboration of a completed real load; migration still records that this conclusion came from legacy evidence;
- legacy rows with ambiguous broker/load identity remain unmerged and carry migration uncertainty rather than being matched from `trip.customer` or lane similarity.

Scheduled `pickupDate` / `deliveryDate`, defaulted `invoiceDate`, or mere presence in a historical store must not be used alone to fabricate `PICKED_UP`, `DELIVERED`, `INVOICED`, or `OVERDUE`.

### Idempotency

The migration must be safe to run repeatedly:

- same source record -> same lifecycle identity/sourceRef;
- no duplicate lifecycle records;
- no duplicate migration events;
- migration checkpoint/version stored in settings;
- partial/interrupted migration can resume without starting over or duplicating records.

Because the migration is additive, rollback does not require destructive restoration of legacy stores. A failed v24.2 implementation can stop reading the new store while legacy data remains intact.

## Dual-write transition

v24.2 does not flip every existing feature to the new store at once.

During transition:

- legacy stores remain authoritative for existing v24.0/v24.1 UI and calculations that have not been explicitly migrated;
- every **new state-changing operation** that has a lifecycle equivalent writes both the legacy representation and `loadLifecycle`;
- where both records are IndexedDB data, dual writes should share one `readwrite` transaction whenever practical so one side cannot commit without the other;
- lifecycle writes must update `updatedAt` so cloud delta sync can identify them.

Minimum dual-write seams:

1. bid/quote outcome logging -> `bidHistory` + opportunity lifecycle event;
2. trip creation/update -> `trips` + lifecycle identity link/state where known;
3. trip tracking start/pickup/delivery actions -> execution lifecycle transition when linked;
4. invoice/payment changes -> trip/accounting legacy fields + settlement lifecycle transition;
5. cancellation/fall-through actions -> correct independent opportunity/execution dimension rather than overwriting one with the other.

A dual-write failure must be surfaced as a write failure; it must not quietly leave two divergent truths.

## Read transition

New lifecycle-specific UI/analytics reads `loadLifecycle` first.

Existing v24.0/v24.1 features continue using their proven legacy reads until a later, separately tested migration explicitly replaces them. v24.2 is not permission to rewrite lane intelligence, tax exports, broker scoring, or the Unified Decision Engine in the same PR.

This prevents a big-bang storage cutover and makes rollback practical.

## Derived display stage

The driver-facing stage is derived and is never the stored source of truth.

Example precedence:

1. if opportunity is unresolved/pre-award, display its opportunity stage (`Seen`, `Quoted`, `Bid`);
2. if opportunity is `LOST`, `EXPIRED`, or `CANCELLED`, display that terminal opportunity outcome;
3. after `WON`, prefer active execution (`En route`, `Picked up`, `Delivered`, `Fell through`);
4. after delivery, settlement may add/replace a secondary financial label (`Not invoiced`, `Invoiced`, `Overdue`, `Paid`, `Bad debt`).

Unknown dimensions must display as unknown rather than using their placeholder state text.

## Calibration/analytics contract

Lifecycle data must improve denominators, not distort them.

### Ordinary win rate

```text
wins = opportunity == WON and known
losses = opportunity == LOST and known
denominator = wins + losses
```

Exclude:

- `SEEN`, `QUOTED`, `BID` still unresolved;
- `EXPIRED`;
- `CANCELLED`;
- unknown/migrated-ambiguous outcome;
- records that are not actual board/bid opportunity outcomes (for example broker pay-speed feedback rows).

### Dead Zone Exit cohort

DZ-Exit loads remain operational truth and can be counted in raw interaction/history metrics, but they are a separate calibration cohort and must not upgrade ordinary-market winning-range/floor calibration.

### Settlement and execution analytics

Do not compute delivery reliability or payment-speed metrics from dimensions with `known=false` or from fabricated/defaulted legacy dates.

## Backup / restore / import / cloud requirements

A lifecycle migration is not complete until every data-protection path understands the new optional store.

Required changes include:

- JSON export includes `loadLifecycle`;
- JSON import accepts backups both with and without `loadLifecycle`;
- replace/merge/skip import modes handle the new store safely;
- backup checksum is calculated over the actual exported payload including lifecycle data;
- cloud full backup includes lifecycle records;
- cloud delta backup filters lifecycle records by `updatedAt`;
- cloud restore/merge includes lifecycle records and preserves newer-record conflict semantics;
- backup-count/status metadata includes lifecycle counts where counts are surfaced;
- old backups remain restorable;
- new backups restored into v24.2 reproduce lifecycle state/events exactly;
- the legacy `XpediteOps_v1` migration does not need to invent a historical lifecycle store; legacy records can be lifecycle-backfilled only after they are safely migrated into current legacy stores.

The Worker should not need to inspect lifecycle plaintext if the backup remains opaque/encrypted; any Worker contract change must be justified separately rather than assumed.

## Import / notification / screenshot future-proofing

v24.2 should make future email/notification/screenshot ingestion able to attach observations to a lifecycle identity without creating parallel load databases.

New intake paths should produce or attach:

- source namespace;
- exact external load/order reference when present;
- first-seen timestamp;
- broker identity only when explicit;
- parsed lane/time/rate/weight as attributes/evidence, not as identity keys.

v24.6 screenshot-first workflow should feed this lifecycle contract rather than create a new status model.

## Concurrency

Lifecycle updates are subject to the same multi-tab lost-update risk as trips.

Implementation must use an optimistic-concurrency or event-append strategy that prevents a stale tab from silently overwriting a newer lifecycle transition. If the current record changed after the caller loaded it, the stale write must be rejected/reconciled explicitly.

Do not introduce a second lock mechanism that can strand the app after a tab crash.

## Acceptance contract

v24.2 is not complete unless regression coverage proves at least:

1. DB v13 -> v14 upgrade creates the lifecycle store without deleting/modifying legacy records.
2. Upgrade/backfill is idempotent across repeated boots.
3. Explicit `won`, `expired`, and true bid-outcome `rejected` records map to `WON`, `EXPIRED`, and `LOST` correctly.
4. `EXPIRED` and `CANCELLED` never enter the ordinary win-rate loss denominator.
5. Ambiguous legacy broker/history rows are not auto-merged by customer/lane similarity.
6. A scheduled delivery date alone does not mark a migrated record `DELIVERED`.
7. Legacy `isPaid=true` maps settlement to known `PAID` without fabricating unrelated timestamps.
8. Exact external aliases attach new observations to the same lifecycle record deterministically.
9. Alias collisions are surfaced rather than silently merging unrelated loads.
10. Bid logging dual-writes atomically to legacy + lifecycle state.
11. Trip/payment/tracking transitions update the appropriate independent lifecycle dimension without destroying the others.
12. Stale concurrent lifecycle writes cannot silently overwrite a newer transition.
13. Old JSON backups without lifecycle data still restore.
14. New JSON backups preserve lifecycle records/events on round-trip.
15. Cloud full + delta backup/restore preserve lifecycle records, including records changed only in lifecycle state.
16. Existing trip, bid-history, backup/restore, DZ, tax, security, and v24 authority suites remain green.
17. The v24.0 canonical decision remains sole verdict/grade/economics/bid authority.
18. Full repository Playwright gate is green on the integrated PR head and on the final merged main content.

## Implementation sequence

After v24.1 is fully implemented and released/verified:

1. lock core/storage paths and bump DB 13 -> 14 with the new structural store only;
2. add pure lifecycle state/identity/transition helpers;
3. add idempotent legacy backfill with explicit migration provenance;
4. add dual-write at bid opportunity seams;
5. add trip/execution/settlement dual-write seams;
6. add backup/import/cloud support;
7. add lifecycle read UI/derived stage without replacing proven legacy analytics;
8. run migration/backup/concurrency/full regression gates;
9. only after v24.2 is stable may v24.3 use lifecycle outcomes for self-calibration.

## Out of scope for v24.2

- numeric win-probability claims;
- recency-weighted/self-calibrating market bands (v24.3);
- Next-Move command behavior (v24.4);
- broad Driver Mode redesign (v24.5);
- screenshot-first UX redesign (v24.6);
- new bank connections/load-board integrations;
- replacing the v24.0 decision authority;
- destructive deletion of legacy stores.
