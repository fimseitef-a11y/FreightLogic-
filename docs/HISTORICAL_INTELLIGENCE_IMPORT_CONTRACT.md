# FreightLogic Historical Intelligence Import Contract

Status: implementation contract / docs only.

Purpose: import operator-verified historical orders, completed loads, bid outcomes, and quote-board observations into FreightLogic without corrupting lifecycle denominators, mileage provenance, broker identity, or future Personal Intelligence calibration.

## 1. Governing principle

Historical import is a **data migration and provenance problem**, not a shortcut to a new pricing engine.

Imported data may inform Personal Intelligence only after it has been normalized through the same lifecycle, price-semantic, mileage-provenance, and confidence rules used by live FreightLogic records.

## 2. Record classes

Every imported row must declare or resolve to one of these classes:

### `LOAD_ORDER`

A real load/order with an operator-confirmed operational status.

Possible lifecycle mapping may include WON, execution state, and settlement state when those facts are actually known.

### `BID_OUTCOME`

A submitted bid with a known adjudicated outcome such as WON or LOST.

### `QUOTE_OBSERVATION`

A board/load observation that may contain route, miles, target/posted rate, pickup/delivery times, freight details, and a quote/load ID, but is **not** a completed load merely because it appeared on the board.

### `UNKNOWN_LEGACY`

A row whose business meaning cannot be proven. Preserve for review; do not put it into calibrated denominators.

## 3. Stable identity and deduplication

### Order records

Preferred key order:

1. exact source/platform + explicit Order ID;
2. exact explicit internal FreightLogic ID when re-importing an export;
3. otherwise unresolved/manual review.

If an Order ID exists, deduplicate by Order ID within the relevant source/platform namespace unless an existing migration contract proves IDs are globally unique.

### Quote observations

Preferred key order:

1. source/platform + explicit Quote ID;
2. source/platform + explicit board record ID;
3. otherwise unresolved/manual review.

Do **not** collapse two rows merely because origin/destination and dollar amount match.

### Later corrections

When the operator has explicitly corrected a status or fact later, the later user-confirmed value wins. Preserve provenance indicating that the value was corrected rather than silently rewriting history with no trace.

## 4. Status mapping

Never infer lifecycle semantics from visual appearance alone.

### Opportunity

- confirmed awarded/accepted -> `WON`
- confirmed submitted bid that was adjudicated against the operator -> `LOST`
- board item marked expired with no known award decision -> `EXPIRED`
- broker/load withdrawn -> `CANCELLED`
- bid submitted but result unknown -> `BID`
- seen/quoted but not bid -> `SEEN` or `QUOTED` as evidence supports

### Execution

- accepted/won does not imply delivery
- confirmed picked up -> `PICKED_UP`
- confirmed completed/delivered -> `DELIVERED`
- confirmed fell through -> `FELL_THROUGH`
- otherwise -> `NOT_STARTED` or the strongest explicit known state

### Settlement

Only populate settlement from explicit accounting/payment evidence. Do not infer PAID from DELIVERED.

## 5. Denominator rules

### Ordinary bid win rate

Numerator: `WON`

Denominator: `WON + LOST`

Exclude:

- `EXPIRED`
- `CANCELLED`
- unknown outcome
- seen/quoted-only observations

### Normal-market pricing calibration

Exclude:

- DZ-EXIT / recovery-survival cohort
- non-adjudicated quote observations when computing operator win/loss curves
- rows whose price semantic is unknown
- rows whose essential mileage/revenue inputs are unknown

Preserve excluded rows for their appropriate separate evidence cohorts.

## 6. Mileage provenance

Never collapse multiple mileage meanings into one field.

Recommended import shape:

```js
mileage: {
  sourceDisplayedLoaded: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
  loaded: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
  deadhead: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
  totalPrimary: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
  inferredRoad: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
  repositionAfterDelivery: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' }
}
```

Rules:

- preserve the board/source-displayed mileage exactly when present;
- preserve separately any later estimated/inferred road mileage;
- never replace a source-displayed value with a newly calculated road estimate;
- a real zero is valid and remains distinct from missing/unknown;
- do not calculate historical True RPM if required revenue or denominator mileage is unknown.

## 7. Price semantics

Reuse `docs/FREIGHT_SOURCE_INGESTION_CONTRACT.md` semantics when that contract is merged.

Possible historical meanings include:

- `CARRIER_PAYOUT`
- `POSTED_CARRIER_RATE`
- `BROKER_TARGET`
- `OPERATOR_BID`
- `SHIPPER_BOOKABLE_PRICE`
- `MARKET_ESTIMATE`
- `UNKNOWN`

Do not treat the same dollar field as both operator bid and winning carrier payout.

A bid that lost is still valid `OPERATOR_BID` evidence but is not a market-clearing carrier payout.

## 8. Broker/carrier/customer identity

Identity mapping must be conservative.

- preserve explicit broker name when the source labels it as broker;
- preserve explicit carrier/company when the source labels it as carrier;
- do not infer broker identity from ambiguous `customer` text;
- do not merge two companies because their normalized names look similar without explicit mapping evidence;
- keep an alias table only when aliases are operator-confirmed or source-confirmed.

## 9. Import trust/provenance

Recommended metadata:

```js
importMeta: {
  batchId: '',
  importedAt: '',
  sourceFile: '',
  sourceType: 'OPERATOR_VERIFIED | APP_EXPORT | BOARD_OBSERVATION | OTHER',
  operatorVerified: false,
  rowNumber: null,
  corrections: [],
  rawRecordHash: ''
}
```

Operator-verified source blocks should be treated as trusted input facts unless a later operator correction supersedes them. Import code must not independently "fix" those values from geocoding or external lane estimates.

## 10. Preview before commit

Historical import must have a deterministic preview/dry-run step before persistent mutation.

Preview must report at minimum:

- rows parsed;
- rows accepted;
- exact duplicates;
- updates to existing identities;
- unresolved identities;
- invalid rows;
- rows excluded from calibration and why;
- records with unknown mileage/revenue that cannot produce economics;
- lifecycle mapping summary.

The preview output must be reproducible from the same file + current database state.

## 11. Idempotence

Re-importing the exact same source batch must not duplicate records.

Use stable source IDs plus `rawRecordHash`/batch metadata as supporting evidence, but do not let a changed operator-confirmed status get blocked merely because an older row hash already exists.

Idempotence tests must cover:

- same file twice;
- same rows reordered;
- later corrected status;
- one duplicate Order ID within a batch;
- one duplicate Quote ID within a batch;
- same route/rate but distinct IDs.

## 12. Relationship to v24.2 lifecycle

Preferred implementation sequence is lifecycle-first.

After v24.2 exists:

- `LOAD_ORDER` and `BID_OUTCOME` rows link/create lifecycle records conservatively;
- quote observations may create opportunity-only lifecycle records when identity is strong enough;
- execution/settlement dimensions remain untouched unless explicit facts support them;
- source references remain attached for auditability;
- EXPIRED/CANCELLED semantics are preserved exactly.

Pre-lifecycle source hardcoding is prohibited.

## 13. Personal Intelligence eligibility

Imported data is eligible for Personal Intelligence only when the feature can explain why the row is included.

Recommended eligibility gates:

- explicit outcome for win-rate models;
- known price semantic;
- known loaded/relevant denominator miles for RPM models;
- sufficient identity to assign lane/market cohort;
- not an ordinary-market exclusion such as DZ-EXIT when computing normal-market floors;
- source timestamp/date sufficient for recency weighting.

No percentage win-probability output should be introduced merely because a historical import exists. Calibration requires predicted-vs-actual records collected under a stable model version.

## 14. Recency and sample size

Historical evidence should carry:

- observation date;
- sample count for aggregates;
- cohort definition;
- model/doctrine generation where known.

Older observations may be down-weighted later, but import must preserve them rather than deleting them.

Any recency weighting must be deterministic, testable, and visible in diagnostics.

## 15. DZ-EXIT cohort

Dead Zone/recovery outcomes remain operationally valuable but are not ordinary market evidence.

Imported DZ-EXIT rows must carry an explicit cohort marker such as:

```js
cohort: {
  deadZoneExit: true,
  normalMarketEligible: false
}
```

Do not allow those rows to lower ordinary-market bid floors or winning-range calibration.

## 16. Source formats

Completion release should support at least one documented machine-readable historical import format, preferably CSV and/or JSON.

### CSV

- explicit headers;
- UTF-8;
- deterministic date parsing;
- no locale-dependent currency parsing;
- blank numeric field -> null, never zero;
- preserve source text for fields that cannot be normalized safely.

### JSON

- versioned schema;
- additive future fields tolerated;
- unknown enum values rejected or quarantined, not silently remapped.

XLSX may use the existing bundled SheetJS path if the implementation chooses to expose it, but the canonical import contract must not depend on an external CDN.

## 17. Backup/export parity

Once imported records are persisted, they are first-class FreightLogic data.

The same implementation release must update as needed:

- full backup;
- delta backup/change tracking;
- restore/merge;
- JSON export;
- relevant CSV/XLSX export;
- schema/version documentation;
- backup/restore tests.

Imported provenance must survive backup/restore.

## 18. Failure handling

A malformed row must not abort an otherwise valid batch unless atomic-batch semantics are explicitly chosen.

Preferred behavior:

- parse all rows;
- quarantine invalid rows with exact reason;
- show preview;
- commit only accepted rows after user-approved import action;
- preserve enough raw source reference to correct/re-import rejected rows.

Do not partially commit during the preview phase.

## 19. Required regression tests

At minimum:

1. exact Order ID deduplication;
2. exact Quote ID deduplication;
3. later operator-confirmed correction wins;
4. EXPIRED does not become LOST;
5. CANCELLED does not become LOST;
6. WON does not imply DELIVERED;
7. DELIVERED does not imply PAID;
8. quote observation does not become completed load;
9. source-displayed mileage survives separately from inferred road mileage;
10. blank mileage/revenue stays unknown;
11. real zero deadhead survives as zero;
12. unknown price semantic is excluded from revenue/calibration;
13. DZ-EXIT excluded from normal-market cohort;
14. ambiguous broker/customer identity remains unresolved;
15. same batch re-import is idempotent;
16. backup/export/restore preserves import provenance and lifecycle links;
17. full existing v24 authority suite remains green.

## 20. Definition of done

Historical intelligence import is complete when the operator can import a verified history batch repeatedly and obtain the same lifecycle/evidence result without duplicates, false outcomes, fabricated mileage/economics, or contamination of normal-market calibration.

A parser that merely adds CSV rows to `trips` or `bidHistory` without lifecycle identity, provenance, denominator rules, and idempotence does **not** satisfy this contract.
