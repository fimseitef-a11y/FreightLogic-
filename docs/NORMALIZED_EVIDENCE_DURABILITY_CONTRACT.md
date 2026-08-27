# FreightLogic Normalized Evidence Durability Contract

Status: implementation contract for completion-release M5/M6 correction.

Date: 2026-08-27

Authority: subordinate to `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`, `docs/EVIDENCE_PROVENANCE.md`, `docs/V24_2_LOAD_LIFECYCLE_SPEC.md`, and current operator-confirmed corrections. This file does not create a second roadmap and does not enlarge completion-release scope.

## Purpose

M5 introduced a provider-independent `normalizeOpportunity()` shape and M6 routes historical records through it. Current runtime, however, persists mainly lifecycle identity/state and can discard the normalized evidence object after the call returns. That is not sufficient for the existing M5/M6 requirements to preserve price semantics, mileage semantics, source provenance, confidence/confirmation state, and later auditability.

This contract defines the minimum durable behavior required before M5/M6 can be certified.

## Architectural boundary

`loadLifecycle` remains a lifecycle state/linking structure. It must not become a second accounting ledger, trip ledger, bid-history ledger, or catch-all copy of every source payload.

Durable normalized evidence may be implemented as a dedicated evidence store or another bounded additive structure, but it must satisfy every semantic and migration rule below. The implementation choice remains core-owned.

## Required durable evidence identity

Every persisted evidence record needs a stable internal `evidenceId` that is independent of provider/order/quote IDs.

An evidence record may link to a `lifecycleId`, but the evidence must remain representable when lifecycle linking is unresolved.

External identifiers are evidence attributes, not universally unique primary keys. Reused quote/load/order IDs must never force destructive deduplication.

For deterministic import idempotency, use a bounded collision-resistant fingerprint of the full normalized identity/provenance input. A single 32-bit non-cryptographic hash is not sufficient for a data-deduplication key.

## Minimum durable fields

The persisted shape must be able to retain, directly or through normalized linked structures:

- `evidenceId`
- `lifecycleId` when resolved; null/unresolved when not
- `source_type`
- `source_name`
- `platform` when known
- `broker` when explicitly established
- `carrier` when explicitly established
- `company`/customer/shipper label only in its actual semantic role
- `observed_at`
- `source_timestamp` when available
- `raw_evidence_ref` or another stable source correlation identifier when available
- external order/quote/reference identifiers as evidence attributes
- origin/destination and pickup/delivery timestamp evidence when actually known
- money amount plus `price_semantic`
- mileage values plus `mileage_semantic`, keeping loaded, deadhead, displayed total, and post-delivery reposition distinct
- `confirmation_state`
- `field_confidence` or bounded machine-extraction confidence when applicable
- `operator_confirmed_at` when applicable
- source-health/freshness metadata when applicable
- derived-value links back to their input evidence rather than relabeling the derived value as a new observation

Unknown values remain null/unknown; missing facts must never be materialized as zero.

## Canonical revenue gate

Persistence does not authorize promotion into canonical revenue.

Only a semantically valid carrier-revenue amount may populate canonical revenue under the governing evidence contract, including:

- `CARRIER_PAYOUT`;
- lifecycle-appropriate `SETTLED_AMOUNT`;
- an explicitly operator-confirmed expected-revenue amount.

`OPERATOR_BID`, `BOARD_TARGET_RATE`, `SHIPPER_BOOKABLE_PRICE`, `POSTED_RATE`, `MARKET_BENCHMARK`, `CONTRACT_RATE` where not proven applicable, and `UNKNOWN_PRICE_SEMANTIC` remain evidence only unless later evidence/operator confirmation changes their semantic authority.

## Mileage preservation

Durable evidence must distinguish at least:

- `LOADED_MILES`
- `DEADHEAD_MILES`
- `DISPLAYED_TOTAL_MILES`
- `POST_DELIVERY_REPOSITION_MILES`
- `MAP_ESTIMATE`
- `UNKNOWN_MILEAGE_SEMANTIC`

A source-displayed RPM may be retained as source evidence but must never be silently relabeled `True RPM` unless the underlying carrier revenue, loaded miles, and deadhead miles are semantically valid for the canonical True RPM formula.

## Lifecycle linking

Evidence-to-lifecycle linking uses the same conservative identity doctrine as v24.2.

Strong automatic evidence may include:

1. explicit `lifecycleId`;
2. exact internal source reference;
3. normalized broker/order pair only when route/time evidence is compatible and no competing candidate exists.

Never auto-link from:

- quote/load/order ID alone;
- city pair alone;
- money alone;
- approximate date alone;
- ambiguous customer text.

When candidates compete, preserve the evidence and mark the link unresolved. A duplicate is safer than a false merge.

## Historical reconciliation precedence

For M6 imports, reconciliation must obey the evidence precedence already defined in `EVIDENCE_PROVENANCE.md`:

1. latest explicit operator correction;
2. primary documentary evidence;
3. operator-confirmed historical data;
4. canonical contracts/doctrine;
5. verified external documentation;
6. deterministic derived math;
7. AI summaries/handoffs only as discovery aids.

A first-source-wins/fill-blanks algorithm is insufficient when later higher-authority evidence contradicts an already populated field.

When values are merged from multiple sources, preserve field-level provenance or another auditable representation sufficient to identify which source supplied each material fact. Do not leave a row-level `sourceName` pointing to one file when material values came from another.

## Status-class preservation

Historical intake must preserve status classes rather than flatten them:

- accepted/completed loads;
- live/open quotes;
- submitted bids;
- lost bids;
- expired opportunities;
- cancelled opportunities;
- dry runs;
- board observations;
- external market quotes.

`EXPIRED` is not automatically `LOST`.

`DRY RUN` must not disappear into ordinary completed-load economics or be silently discarded; it remains separately flagged operational history and excluded from normal-market calibration as appropriate.

Unknown/secondary statuses may not set `awarded: true` or otherwise promote a record into WON/completed truth without supporting evidence.

## Backup / export / import / restore parity

Any new durable normalized evidence must participate in all applicable data-protection paths before certification:

- retained/pre-mutation backup where required;
- full cloud backup;
- delta cloud backup;
- cloud restore;
- local JSON export;
- local JSON import in merge/replace modes as applicable;
- export integrity checksum coverage;
- pre-change backup compatibility.

A data class that exports but is dropped on import is a release blocker.

The export integrity checksum must cover the durable evidence being represented as protected history; otherwise the export can be modified without the integrity check detecting that evidence mutation.

## Optimistic concurrency

User-editable durable evidence or evidence-link corrections must not silently overwrite a newer record. Reuse the repository's established revision/expected-version conflict semantics and surface `FL_CONFLICT` or the repository-equivalent conflict contract.

Machine/background linking may not bypass the same compare-before-write boundary merely because the mutation is automated.

## M5 manual/email requirement

Completion-release M5B is not complete merely because a normalization helper exists.

There must be an actual working manual/email-compatible intake call path that:

1. normalizes the evidence;
2. persists the durable evidence;
3. links or creates lifecycle state conservatively;
4. preserves the underlying message/source reference;
5. works offline for manual intake;
6. does not fabricate provider/API authorization.

## M6 calibration boundary

Personal Intelligence/calibration may consume only semantically defensible durable inputs.

- Ordinary win-rate denominator: `WON / (WON + LOST)`.
- `EXPIRED` and `CANCELLED` are excluded from ordinary loss denominator.
- DZ-EXIT remains a separate cohort.
- Unknown RPM is excluded, never zero.
- Source-displayed RPM is not automatically True RPM.
- A winning RPM range is unavailable when the defensible sample is below the configured minimum.
- Recency/sample weighting must remain deterministic and inspectable.

The presence of imported rows alone does not make calibration valid.

## Required regression coverage

Before M5/M6 certification, tests must cover at least:

1. normalized money/mileage/provenance survives a reload;
2. local export/import round-trip preserves durable evidence;
3. cloud full + delta + restore preserve durable evidence;
4. integrity checksum detects durable-evidence mutation;
5. reused external IDs with incompatible lane/time evidence remain separate;
6. later operator correction supersedes lower-authority earlier evidence without erasing provenance;
7. field values merged from different files retain auditable field provenance;
8. dry-run records remain separately represented and excluded from normal-market calibration;
9. unknown/secondary status cannot be promoted to award/WON automatically;
10. a deliberately colliding legacy 32-bit fingerprint pair remains distinct under the replacement fingerprint;
11. re-import of the identical long-provenance observation is idempotent;
12. source-displayed RPM remains evidence and cannot silently become True RPM;
13. the real manual/email-compatible intake path persists evidence rather than returning it only transiently;
14. full repository suite remains green with existing authority assertions unchanged.

## Privacy boundary

Raw operator financial/history CSVs do not belong in the public repository merely to make tests pass. Use synthetic deterministic fixtures in CI. Real source files may be processed locally/off-repo, and only non-sensitive aggregate validation results should be committed unless the operator explicitly authorizes otherwise.

## Certification rule

M5A/M5B and M6 remain **implemented but not release-certified** until the durable semantic evidence path and its backup/import/export/concurrency requirements above are green on the integrated runtime.
