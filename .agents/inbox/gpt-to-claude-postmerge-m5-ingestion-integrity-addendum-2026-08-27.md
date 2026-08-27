# GPT → Claude: POST-MERGE M5A/5B INTEGRITY ADDENDUM

Date: 2026-08-27
Current main reviewed: `ade0a6f2b66b8cb29f8cf33ac88420c2292fcaa4` (runtime tree from PR #105 plus GPT docs-only #106)
Dependency: repair alongside/before the M3/M4 integrity hotfix; do not let M6 learn from this shape yet.

Exact current-main review of M5A/5B found additional contract failures not covered by `m5-opportunity-ingestion.spec.mjs`.

## 1. Normalized evidence is not durable

`intakeOpportunity()` computes the full `normalizeOpportunity()` object, but persists only this lifecycle projection through `linkLifecycle()`:

- lifecycleId
- orderNo
- broker
- origin/destination
- pickupAt/deliveryAt
- opportunity state

It does **not** persist the normalized object's:

- `amount`
- `priceSemantic`
- `canonicalRevenue`
- `loadedMi` / `deadMi`
- `mileageSemantic`
- provenance (`sourceType`, `sourceName`, `sourceTimestamp`, `rawEvidenceRef`, confirmation, confidence, operator-confirmed timestamp)

Those values exist only in the return value of the current JavaScript call and disappear on reload. That is not a durable ingestion foundation and cannot support M6 historical calibration or future 5C/5D adapters without reconstructing semantics from something else.

Required:
- persist the provider-independent normalized opportunity/evidence object durably under a stable identity;
- lifecycle remains lifecycle state, not a lossy substitute for the evidence object;
- if a new store/schema is required, update DB migration, cloud full+delta backup, restore, JSON export/import, checksums, and compatibility in the same bounded change;
- restart/reload test proves semantic evidence survives app closure and reopen;
- restore/import test proves it round-trips without semantic promotion.

## 2. No production manual/email call site uses `intakeOpportunity()`

Current `app.js` contains the helper definition but no actual production call site from the existing manual/unified intake or email-normalization workflow. M5-12/M5-13 call the helper directly from the test harness.

So the current tests prove the helper can be called, not that the completion-release requirement "working manual/email-compatible intake" is wired into the app.

Required:
- wire at least the real manual opportunity intake surface through the normalized contract;
- wire the actual email-derived opportunity/confirmation normalization path through the same contract where that path exists;
- preserve the underlying message/evidence reference;
- test through the real production call/UI pathway, not `window.__FL_TESTS.intakeOpportunity()` alone.

If no real email ingestion surface currently exists, do not call M5B complete; implement the smallest working email-normalization path the roadmap requires or explicitly reclassify the milestone until it exists.

## 3. M5 semantic vocabularies are narrower than canonical EVIDENCE_PROVENANCE.md

Canonical price semantics include:
- CARRIER_PAYOUT
- OPERATOR_BID
- BOARD_TARGET_RATE
- SHIPPER_BOOKABLE_PRICE
- POSTED_RATE
- MARKET_BENCHMARK
- CONTRACT_RATE
- SETTLED_AMOUNT
- UNKNOWN_PRICE_SEMANTIC

Current `PRICE_SEMANTIC` omits `BOARD_TARGET_RATE`, `POSTED_RATE`, and `MARKET_BENCHMARK`. A known target/posted/benchmark amount therefore degrades to UNKNOWN and loses what the source actually said.

Canonical mileage semantics include `POST_DELIVERY_REPOSITION_MILES`; current `MILEAGE_SEMANTIC` omits it.

Required: normalized vocabulary must be a parity mirror of `docs/EVIDENCE_PROVENANCE.md`; tests assert every canonical enum value is retained and remains non-revenue unless expressly revenue-eligible.

## 4. Required provenance dimensions are missing

`docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` M5A requires provenance fields that distinguish platform, broker/carrier/company where known, source/source timestamp, price/mileage semantics, health/confidence, and confirmation state. `docs/EVIDENCE_PROVENANCE.md` also requires `observed_at` for externally sourced material evidence.

Current normalized shape has broker + sourceName + sourceTimestamp + fieldConfidence, but no explicit:
- platform
- carrier/company distinction
- observedAt
- source health

Do not overload `sourceName` to silently stand for several different provenance dimensions.

Required: preserve these dimensions explicitly or through a stable linked evidence record, and cover them with round-trip tests.

## 5. Timestamp handling is not evidence-safe

`sourceTimestamp` is normalized through `knownNum()`. Any ordinary ISO timestamp string from an email/provider (for example `2026-08-27T01:15:00-05:00`) becomes null unless every caller first converts it to epoch milliseconds. The normalized contract does not state such a prerequisite.

Likewise pickup/delivery date-times are currently discarded by the date-only validator (already in the M4 hotfix packet).

Required:
- accept/preserve a validated timestamp representation without inventing precision;
- distinguish observation time from source-visible timestamp;
- tests for ISO source timestamps and date-only inputs.

## 6. One generic `mileageSemantic` cannot safely label multiple mileage facts

The normalized shape can simultaneously contain `loadedMi` and `deadMi`, but it carries one shared `mileageSemantic`. That allows contradictory meaning (e.g. both numeric fields present while the single semantic says DISPLAYED_TOTAL_MILES) and cannot distinguish loaded, deadhead, displayed-total, map-estimate, and post-delivery reposition evidence independently.

Required: mileage evidence must be field-specific/typed (or represented as an evidence array keyed by semantic), so each numeric mileage value retains its own meaning and provenance. Never infer components of DISPLAYED_TOTAL_MILES.

## Required M5 re-certification

Before M6 historical import/calibration reads normalized opportunity data:
1. durable normalized evidence persistence exists;
2. actual manual/email production paths use it;
3. canonical provenance vocabularies/fields are complete;
4. timestamp and typed-mileage semantics are lossless;
5. any added store participates in DB/backup/delta/restore/export/import/checksum parity;
6. full suite is green with real-path tests;
7. exact-source review confirms no semantic data is transient or silently downgraded.

M5C vision and M5D provider adapters remain non-blocking; this addendum concerns the completion-release-required 5A/5B foundation already marked complete in PR #105.
