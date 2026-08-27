# FreightLogic v24.2 — Load Lifecycle Contract

Status: **implementation contract / docs only**. No runtime, schema, migration, Worker, service-worker, or test code is changed by this document.

This is the governing contract for roadmap milestone **v24.2 Load Lifecycle** under `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`, the only active roadmap on `main`. It turns the adopted lifecycle state model into an implementation-ready migration and compatibility plan.

## 1. Objective

FreightLogic currently records several related facts in different places: opportunities and bid outcomes in `bidHistory`, operational trips in `trips`, reload outcomes in `reloadOutcomes`, GPS execution evidence in `gpsLogs`, and settlement/accounting facts elsewhere. v24.2 must give one freight opportunity/load an accumulating operational identity without discarding the existing records that already work.

The lifecycle layer is a **record-linking and state-normalization layer**, not a new scoring engine. It must not create a second source of truth for verdicts, bid floors, taxes, expenses, GPS, backups, or AI evaluation.

## 2. Non-negotiable state model

Do not collapse real operations into one lossy linear enum. Persist independent dimensions and derive a display stage.

### Opportunity

`SEEN | QUOTED | BID | WON | LOST | EXPIRED | CANCELLED`

### Execution

`NOT_STARTED | EN_ROUTE_PICKUP | PICKED_UP | DELIVERED | FELL_THROUGH`

### Settlement

`NOT_INVOICED | INVOICED | OVERDUE | PAID | BAD_DEBT`

### Locked semantics

- **EXPIRED is not LOST.** No known award decision; exclude from ordinary win-rate denominator.
- **CANCELLED is not LOST.** Broker/load withdrawal is a separate terminal opportunity state.
- **WON does not imply DELIVERED.** A won load may fall through before or after pickup.
- **DELIVERED does not imply PAID.** Operational completion and settlement are separate.
- **DZ-EXIT remains a separate calibration cohort.** It may count in raw broker interaction totals but must be excluded from normal-market winning-range/floor calibration.

## 3. Canonical lifecycle identity

Add one new canonical lifecycle object per load/opportunity. The object must have a stable generated ID independent of broker order numbers because order numbers may be absent, reused, reformatted, or unknown when the opportunity is first seen.

Recommended identity shape:

```js
{
  lifecycleId: 'lc_<time>_<random>',
  createdAt: 0,
  updatedAt: 0,
  revision: 1,

  opportunity: 'SEEN',
  execution: 'NOT_STARTED',
  settlement: 'NOT_INVOICED',

  orderNo: '',
  broker: '',
  carrier: '',
  origin: '',
  destination: '',
  pickupAt: null,
  deliveryAt: null,

  sourceRefs: {
    bidHistoryIds: [],
    tripIds: [],
    reloadOutcomeIds: [],
    gpsTrackingIds: []
  },

  cohort: {
    deadZoneExit: false,
    normalMarketEligible: true
  },

  migration: {
    importedLegacy: false,
    migratedFrom: []
  }
}
```

The exact field names may change during implementation, but the semantics above are required.

## 4. Matching and linking rules

Linking must be conservative. A false merge is worse than a duplicate lifecycle record.

### Strong evidence

A record may auto-link when one of these is true and no conflicting fact exists:

1. An existing explicit `lifecycleId` is present.
2. An exact internal record reference already maps the records together.
3. A normalized broker/order number pair matches and route/time facts are compatible.

### Supporting evidence

Supporting facts may strengthen a match but must not create one by themselves:

- normalized origin/destination,
- pickup/delivery dates,
- broker name,
- revenue/pay,
- loaded miles,
- tracking ID,
- load/customer reference text.

### Forbidden inference

Never auto-link solely from ambiguous `trip.customer`, generic customer text, city pair alone, dollar amount alone, or approximate dates alone. v23.9 broker-integrity rules remain in force: ambiguous legacy identity stays unresolved rather than being guessed.

### Conflict behavior

If two plausible lifecycle records compete for the same legacy record, do not silently choose one. Mark the legacy record as unresolved for lifecycle linking and surface it in diagnostics/review tooling.

## 5. Derived display stage

UI may show one friendly stage, but it is derived from the three persisted dimensions. It must never be stored as the authoritative state.

Suggested precedence:

1. `settlement === PAID` -> `PAID`
2. `settlement === BAD_DEBT` -> `BAD DEBT`
3. `settlement === OVERDUE` -> `OVERDUE`
4. `execution === DELIVERED` -> `DELIVERED`
5. `execution === PICKED_UP` -> `IN TRANSIT`
6. `execution === EN_ROUTE_PICKUP` -> `EN ROUTE TO PICKUP`
7. `execution === FELL_THROUGH` -> `FELL THROUGH`
8. `opportunity === WON` -> `WON / NOT STARTED`
9. `opportunity === BID` -> `BID SUBMITTED`
10. `opportunity === QUOTED` -> `QUOTED`
11. `opportunity === EXPIRED` -> `EXPIRED`
12. `opportunity === CANCELLED` -> `CANCELLED`
13. `opportunity === LOST` -> `LOST`
14. otherwise -> `SEEN`

This order is presentation logic only. Analytics must query the underlying dimensions.

## 6. Transition rules

Transitions are monotonic where reality is monotonic, but corrections are allowed through explicit user actions and must update `revision`/`updatedAt`.

### Opportunity examples

- `SEEN -> QUOTED -> BID -> WON`
- `SEEN -> QUOTED -> EXPIRED`
- `BID -> LOST`
- `BID -> CANCELLED`

Do not require every intermediate state. Imported history may legitimately enter at `WON`, `LOST`, or `EXPIRED`.

### Execution examples

- `NOT_STARTED -> EN_ROUTE_PICKUP -> PICKED_UP -> DELIVERED`
- `NOT_STARTED -> FELL_THROUGH`
- `PICKED_UP -> FELL_THROUGH`

### Settlement examples

- `NOT_INVOICED -> INVOICED -> PAID`
- `INVOICED -> OVERDUE -> PAID`
- `OVERDUE -> BAD_DEBT`

A later correction from a terminal-looking state is allowed only as an explicit edit; it must not happen implicitly from unrelated background activity.

## 7. Database and migration contract

v24.2 **requires a DB version bump**. The migration must be additive and reversible at the record-shape level.

### Required migration properties

- Existing stores remain readable during transition.
- Existing primary keys are never rewritten merely to fit lifecycle IDs.
- New lifecycle data is additive.
- Old records remain valid if no lifecycle link exists.
- Migration must be idempotent: reopening the upgraded DB cannot duplicate lifecycle records or links.
- Migration must not infer ambiguous broker/order identity.
- Migration must be restart-safe if the browser/app is interrupted during upgrade or post-open backfill.

### Store strategy

Preferred design: add a dedicated lifecycle store rather than overloading `trips` or `bidHistory` as the new universal record.

Suggested store name: `loadLifecycle`.

Recommended indexes, only if implementation proves them necessary:

- `updatedAt`
- normalized `orderNo`
- normalized `broker`
- optional compound/reference lookup for explicit source IDs

Do not add speculative indexes that have no query path.

## 8. Dual-write transition

For the transition period, existing record writes stay intact and the lifecycle record is updated alongside them.

Examples:

- `logBid()` continues writing `bidHistory`; it also links/updates lifecycle opportunity state.
- a won/accepted load updates lifecycle to `WON` without replacing the operational trip record.
- trip start/pickup/delivery updates execution state while the `trips` store remains authoritative for trip operational details.
- invoice/payment actions update settlement state without moving accounting data into lifecycle.

Dual-write must be ordered so an error cannot leave the old authoritative record unwritten merely because the new lifecycle update failed. During v24.2, compatibility beats aggressive consolidation.

## 9. Backup, delta, restore, import, export

The existing backup contract remains binding.

When `loadLifecycle` is introduced, the same implementation change must update:

- full cloud backup payload,
- delta backup payload/change tracking,
- restore/merge path,
- JSON export,
- JSON import,
- backup contract documentation,
- backup/restore parity regression coverage.

### Merge rules

Lifecycle restore/import merge must use stable `lifecycleId` plus revision/update metadata. Never create duplicate lifecycle records solely because the same object arrived from a full backup and one or more deltas.

Source-reference arrays must merge as de-duplicated unions unless a later implementation contract establishes a stronger event-log model.

### Backward compatibility

- v24.2 must accept backups/exports created before lifecycle existed.
- Missing lifecycle data is valid legacy input, not corruption.
- A v24.2 export must preserve old stores during the dual-write era so a lifecycle rollout cannot strand operational history behind one new structure.

## 10. Analytics and calibration rules

Lifecycle exists partly to make predicted-vs-actual learning trustworthy, so denominator rules must be explicit.

### Ordinary win rate

Include known adjudicated bid outcomes only:

- numerator: `WON`
- denominator: `WON + LOST`

Exclude `EXPIRED` and `CANCELLED`.

### Delivery reliability

Measure only opportunities that became `WON`.

Recommended cohort split:

- delivered,
- fell through before pickup,
- fell through after pickup.

### Payment performance

Measure settlement independently from execution. A delivered load remains operationally successful even if settlement becomes overdue or bad debt.

### Dead Zone calibration

`cohort.deadZoneExit === true` excludes the lifecycle from ordinary market-rate/floor calibration. Preserve it for a dedicated recovery/survival cohort.

## 11. Event provenance

Every lifecycle mutation should be attributable without turning the lifecycle record into an unbounded audit log.

Minimum mutation metadata:

```js
{
  updatedAt,
  revision,
  lastMutation: {
    source: 'USER | BID_HISTORY | TRIP | GPS | IMPORT | RESTORE | MIGRATION',
    sourceId: '',
    reason: ''
  }
}
```

If full event history is later required, design it as a separate bounded/event store. Do not grow one lifecycle row indefinitely.

## 12. Concurrency and duplicate suppression

Lifecycle writes must not reintroduce the update races already identified elsewhere in FreightLogic.

Required implementation behavior:

- compare expected revision when mutating an existing lifecycle row;
- retry/re-read on a revision conflict rather than blindly overwriting newer state;
- make create/link operations deterministic enough that two near-simultaneous writes do not create duplicate lifecycle objects for the same explicit source reference;
- never let a background update downgrade a newer user-confirmed state.

The exact helper/API is implementation-owned, but lifecycle state must have optimistic concurrency semantics from day one.

## 13. UI contract

v24.2 UI is functional, not the v24.5 visual overhaul.

Minimum UI requirements:

- show derived lifecycle stage where a load/trip history record is reviewed;
- expose the three underlying dimensions on detail/edit surfaces;
- clearly distinguish `EXPIRED`, `LOST`, and `CANCELLED`;
- provide an explicit way to correct a misclassified state;
- show unresolved legacy links without forcing the user to guess;
- do not add a second competing trip/history screen if existing surfaces can consume the lifecycle projection.

## 14. AI boundary

The Worker may summarize lifecycle facts but does not own lifecycle transitions.

It may say, for example, that an opportunity is `BID` and execution is `NOT_STARTED` because the client supplied those canonical fields. It must not convert EXPIRED to LOST, infer WON from conversational language, mark DELIVERED from an AI guess, or decide PAID from text without a client-owned confirmation path.

## 15. Acceptance tests required before release

At minimum, implementation coverage must prove:

1. DB upgrade from current DB version to the v24.2 version is additive and idempotent.
2. Legacy data opens with no lifecycle fields and remains usable.
3. Strong-evidence legacy records link correctly.
4. Ambiguous records remain unresolved rather than guessed.
5. `EXPIRED` and `CANCELLED` are excluded from ordinary win-rate denominator.
6. DZ-EXIT records are excluded from normal-market calibration cohort.
7. Bid -> won -> pickup -> delivered -> invoiced -> paid progression preserves all three dimensions.
8. Fell-through paths do not get mislabeled as ordinary LOST.
9. Dual-write keeps existing `bidHistory`/`trips` behavior intact.
10. Backup full + deltas + restore preserves lifecycle rows and links without duplication.
11. Export/import round-trip preserves lifecycle rows and source references.
12. Pre-v24.2 backup/import remains accepted.
13. Revision conflict does not overwrite a newer state.
14. Full Playwright suite remains green.
15. Version/service-worker/manifest/deployment parity is updated according to the release checklist when runtime implementation lands.

## 16. Implementation sequencing

The runtime implementation should land in bounded steps:

1. schema/store + pure state helpers + migration tests;
2. conservative legacy backfill/linker;
3. dual-write from bid/opportunity paths;
4. dual-write from trip execution paths;
5. settlement integration;
6. backup/delta/restore/import/export parity;
7. minimal lifecycle UI;
8. analytics denominator/cohort switch-over;
9. release/version parity and full regression gate.

Do not combine v24.3 self-calibration math or v24.5 visual overhaul into this milestone.

## 17. Definition of done

v24.2 is complete only when one load can accumulate opportunity, execution, and settlement truth under one stable lifecycle identity while all existing operational/accounting records remain intact and backward-compatible.

A lifecycle object that merely displays a status label without migration, dual-write, restore parity, explicit denominator semantics, and concurrency protection does **not** satisfy this milestone.
