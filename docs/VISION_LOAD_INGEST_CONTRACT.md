# FreightLogic Vision Load Ingest Contract

Version: 1.0.0
Date: 2026-08-26
Owner lane: GPT specification (`docs/`)
Implementation owner: Claude/core lane
Status: SPECIFICATION ONLY — GPT must not implement core/runtime changes

## 1. Purpose

Tesseract OCR did not work reliably enough in field use. The replacement path is **photo/screenshot → vision model → strict structured draft → deterministic validation → operator confirmation → normalized FreightLogic opportunity intake**.

This is not permission to create a second decision engine, a second lifecycle, or provider-specific hidden state. Vision is an intake adapter only.

The image is primary evidence. The model response is derived evidence. The canonical FreightLogic decision engine remains downstream and unchanged in authority.

## 2. Non-negotiable principles

1. **Unknown stays unknown.** Missing, cropped, unreadable, or ambiguous fields return `null`; they never become `0`, an inferred city, an inferred date, or a guessed rate.
2. **One offer per extraction.** If multiple distinct load cards/offers are visible and a single offer cannot be unambiguously isolated, return `MULTIPLE_OFFERS`; do not merge fields from different cards.
3. **No hidden derivation by the model.** The model may transcribe visible facts and classify visible labels; route mileage, ZIP lookup, geocoding, timezone lookup, arithmetic totals, True RPM, fit, bid, verdict, and lifecycle state are deterministic downstream functions, not vision tasks.
4. **Price semantics are explicit.** A visible `$500` without a provable label is `UNKNOWN_PRICE_SEMANTIC`, not carrier revenue.
5. **Source evidence is required for non-null material fields.** Confidence alone is insufficient.
6. **No quote-ID-only identity.** Reused IDs are known in real operator history.
7. **Offline-first PWA behavior cannot depend on the vision service.** Capture/manual entry must remain usable when offline or when the model/Worker is unavailable.
8. **No client-side model/API secrets.** The browser may call the existing/approved FreightLogic Worker extraction boundary; provider credentials stay server-side.
9. **Vision never overrides confirmed manual data.** A delayed extraction result cannot replace a field already confirmed by the operator.
10. **No Tesseract success-path fallback.** If vision is unavailable, the fallback is local save + manual confirmation/entry, not silent reversion to unreliable OCR.

## 3. Normalized extraction object

The vision model returns exactly one JSON object conforming to the schema below. The model does not add Markdown, commentary, prose, or keys outside the schema.

### 3.1 JSON Schema — `freightlogic.cargo-van-load-offer.vision.v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "freightlogic.cargo-van-load-offer.vision.v1",
  "title": "FreightLogic Cargo Van Load Offer Vision Extraction v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "document_type",
    "extraction_status",
    "platform",
    "quote_id",
    "origin",
    "destination",
    "mileages",
    "pickup",
    "delivery",
    "freight",
    "prices",
    "flags",
    "visible_notes",
    "warnings"
  ],
  "properties": {
    "schema_version": { "const": "1.0.0" },
    "document_type": { "const": "CARGO_VAN_LOAD_OFFER" },
    "extraction_status": {
      "enum": ["COMPLETE", "PARTIAL", "UNREADABLE", "MULTIPLE_OFFERS", "NO_OFFER_FOUND"]
    },
    "platform": { "$ref": "#/$defs/stringField" },
    "quote_id": { "$ref": "#/$defs/stringField" },
    "origin": { "$ref": "#/$defs/location" },
    "destination": { "$ref": "#/$defs/location" },
    "mileages": {
      "type": "array",
      "maxItems": 6,
      "items": { "$ref": "#/$defs/mileageObservation" }
    },
    "pickup": { "$ref": "#/$defs/timeWindow" },
    "delivery": { "$ref": "#/$defs/timeWindow" },
    "freight": { "$ref": "#/$defs/freight" },
    "prices": {
      "type": "array",
      "maxItems": 8,
      "items": { "$ref": "#/$defs/priceObservation" }
    },
    "flags": {
      "type": "object",
      "additionalProperties": false,
      "required": ["hot", "hazmat", "temperature_controlled", "team_required"],
      "properties": {
        "hot": { "$ref": "#/$defs/booleanField" },
        "hazmat": { "$ref": "#/$defs/booleanField" },
        "temperature_controlled": { "$ref": "#/$defs/booleanField" },
        "team_required": { "$ref": "#/$defs/booleanField" }
      }
    },
    "visible_notes": {
      "type": "array",
      "maxItems": 20,
      "items": { "$ref": "#/$defs/stringField" }
    },
    "warnings": {
      "type": "array",
      "uniqueItems": true,
      "items": {
        "enum": [
          "CROPPED",
          "LOW_RESOLUTION",
          "GLARE_OR_BLUR",
          "CONFLICTING_VISIBLE_VALUES",
          "AMBIGUOUS_LABEL",
          "MULTIPLE_OFFERS_VISIBLE",
          "RELATIVE_DATE_VISIBLE",
          "PARTIAL_LOCATION",
          "PARTIAL_PRICE",
          "PARTIAL_MILEAGE"
        ]
      }
    }
  },
  "$defs": {
    "stringField": {
      "type": "object",
      "additionalProperties": false,
      "required": ["value", "confidence", "evidence_text"],
      "properties": {
        "value": { "type": ["string", "null"], "maxLength": 500 },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
        "evidence_text": { "type": ["string", "null"], "maxLength": 1000 }
      }
    },
    "numberField": {
      "type": "object",
      "additionalProperties": false,
      "required": ["value", "confidence", "evidence_text"],
      "properties": {
        "value": { "type": ["number", "null"] },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
        "evidence_text": { "type": ["string", "null"], "maxLength": 1000 }
      }
    },
    "integerField": {
      "type": "object",
      "additionalProperties": false,
      "required": ["value", "confidence", "evidence_text"],
      "properties": {
        "value": { "type": ["integer", "null"], "minimum": 0 },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
        "evidence_text": { "type": ["string", "null"], "maxLength": 1000 }
      }
    },
    "booleanField": {
      "type": "object",
      "additionalProperties": false,
      "required": ["value", "confidence", "evidence_text"],
      "properties": {
        "value": { "type": ["boolean", "null"] },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
        "evidence_text": { "type": ["string", "null"], "maxLength": 1000 }
      }
    },
    "location": {
      "type": "object",
      "additionalProperties": false,
      "required": ["facility", "city", "state", "postal_code"],
      "properties": {
        "facility": { "$ref": "#/$defs/stringField" },
        "city": { "$ref": "#/$defs/stringField" },
        "state": { "$ref": "#/$defs/stringField" },
        "postal_code": { "$ref": "#/$defs/stringField" }
      }
    },
    "mileageObservation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["semantic", "miles", "label_text"],
      "properties": {
        "semantic": {
          "enum": [
            "LOADED_MILES",
            "DEADHEAD_MILES",
            "DISPLAYED_TOTAL_MILES",
            "POST_DELIVERY_REPOSITION_MILES",
            "UNKNOWN_MILEAGE_SEMANTIC"
          ]
        },
        "miles": { "$ref": "#/$defs/numberField" },
        "label_text": { "$ref": "#/$defs/stringField" }
      }
    },
    "timeWindow": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "date_local",
        "relative_date_text",
        "start_time_local",
        "end_time_local",
        "timezone_label",
        "asap"
      ],
      "properties": {
        "date_local": { "$ref": "#/$defs/stringField" },
        "relative_date_text": { "$ref": "#/$defs/stringField" },
        "start_time_local": { "$ref": "#/$defs/stringField" },
        "end_time_local": { "$ref": "#/$defs/stringField" },
        "timezone_label": { "$ref": "#/$defs/stringField" },
        "asap": { "$ref": "#/$defs/booleanField" }
      }
    },
    "freight": {
      "type": "object",
      "additionalProperties": false,
      "required": ["pieces", "total_weight_lb", "commodity", "dimensions"],
      "properties": {
        "pieces": { "$ref": "#/$defs/integerField" },
        "total_weight_lb": { "$ref": "#/$defs/numberField" },
        "commodity": { "$ref": "#/$defs/stringField" },
        "dimensions": {
          "type": "array",
          "maxItems": 20,
          "items": { "$ref": "#/$defs/dimensionObservation" }
        }
      }
    },
    "dimensionObservation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["count", "length_in", "width_in", "height_in", "weight_lb", "evidence_text"],
      "properties": {
        "count": { "type": ["integer", "null"], "minimum": 1 },
        "length_in": { "type": ["number", "null"], "minimum": 0 },
        "width_in": { "type": ["number", "null"], "minimum": 0 },
        "height_in": { "type": ["number", "null"], "minimum": 0 },
        "weight_lb": { "type": ["number", "null"], "minimum": 0 },
        "evidence_text": { "type": ["string", "null"], "maxLength": 1000 }
      }
    },
    "priceObservation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["semantic", "amount", "currency", "label_text", "semantic_confidence"],
      "properties": {
        "semantic": {
          "enum": [
            "CARRIER_PAYOUT",
            "OPERATOR_BID",
            "BOARD_TARGET_RATE",
            "SHIPPER_BOOKABLE_PRICE",
            "POSTED_RATE",
            "MARKET_BENCHMARK",
            "CONTRACT_RATE",
            "UNKNOWN_PRICE_SEMANTIC"
          ]
        },
        "amount": { "$ref": "#/$defs/numberField" },
        "currency": { "$ref": "#/$defs/stringField" },
        "label_text": { "$ref": "#/$defs/stringField" },
        "semantic_confidence": { "type": "number", "minimum": 0, "maximum": 1 }
      }
    }
  }
}
```

### 3.2 Null/evidence invariant

For every `*Field` wrapper:

- when `value` is non-null, `evidence_text` must be non-null/non-empty;
- when the model cannot point to visible supporting text, `value` must be `null`;
- a null value should normally carry confidence `0` unless the model is confident that the field is explicitly shown as blank/not provided; the validator may normalize null confidence to `0`.

`dimensionObservation` is the only compact exception to the generic wrapper shape. A non-null dimension component is valid only when `evidence_text` contains the visibly corresponding dimensions/weight string.

## 4. Vision prompt

Use schema-constrained/structured output at the API layer when the selected model supports it. The semantic prompt is:

```text
You are a freight-document extraction engine for a cargo-van operator.

Return ONLY one JSON object matching the provided FreightLogic cargo-van-load-offer vision schema. Do not return Markdown or prose.

Extract only facts visibly supported by the image.

HARD RULES:
1. Never guess or infer a missing value. If a value is cropped, hidden, unreadable, ambiguous, or absent, return null for that value.
2. Never turn a missing numeric field into 0.
3. Never calculate route miles, total miles, RPM, True RPM, totals, bids, grades, fit, or verdicts.
4. Never geocode. Do not fill a city from a ZIP, a state from a city, or a ZIP from a city/state unless all are visibly present.
5. Do not resolve TODAY, TOMORROW, ASAP, or similar relative text into a calendar date. Put the literal relative text in relative_date_text and leave date_local null unless an actual date is visibly printed.
6. Do not infer timezone from location. Only extract a timezone label if it is visibly printed.
7. Preserve loaded miles, deadhead/empty miles, displayed total miles, and other mileage labels as separate observations.
8. Preserve each visible money amount as a separate price observation. Choose a price semantic only when the visible label or explicit platform/document mapping supports it. Otherwise use UNKNOWN_PRICE_SEMANTIC.
9. A target rate is not carrier payout. An operator bid is not a winning rate. A shipper bookable price is not carrier payout.
10. A quote/load ID is just a displayed field. Do not use it to combine or deduplicate offers.
11. If multiple distinct offers/cards are visible and one cannot be unambiguously isolated, set extraction_status to MULTIPLE_OFFERS, include MULTIPLE_OFFERS_VISIBLE in warnings, and return null/empty material offer fields rather than mixing cards.
12. For every non-null material value, include the exact visible evidence text that supports it and a confidence between 0 and 1.
13. If the image is too poor to extract reliably, prefer PARTIAL or UNREADABLE with null fields instead of guessing.
14. Do not add keys that are not in the schema.
```

## 5. Deterministic validation after model response

Model confidence is advisory. FreightLogic must run a local deterministic validator before any field appears as accepted.

### 5.1 Structural validation

Reject the response as a whole when:

- JSON parse fails;
- schema version is unknown;
- JSON Schema validation fails;
- `additionalProperties` are present;
- `document_type` is wrong;
- more than one logical offer appears to have been merged;
- non-finite numbers appear.

A rejected response produces no normalized load fields. The image/manual-entry path remains available.

### 5.2 Evidence validation

For each non-null material field:

- `evidence_text` must exist;
- normalized numeric value must be visibly represented in the evidence text, allowing only formatting normalization such as `$`, commas, spaces, decimal punctuation, or explicit unit suffixes;
- a location component must appear in the supporting visible location text;
- quote ID must be present literally in supporting evidence;
- date/time must be visibly present and must not have been resolved from relative language by the model;
- a price semantic must be supported by the visible label or an explicit versioned provider mapping;
- a mileage semantic must be supported by its visible label.

If the evidence check fails, reject **that field** to UNKNOWN even when model confidence is `1.0`.

### 5.3 Hallucination rejection rules

The validator must reject/drop a model field when any of the following occurs:

- model supplies a non-null value with no evidence text;
- model supplies a city/state/ZIP not present in the image;
- model supplies a loaded/deadhead number not visibly labelled;
- model supplies `CARRIER_PAYOUT` for a generic target/bookable/posting amount without supported label semantics;
- model resolves `today/tomorrow` using the model's current date;
- model calculates total mileage from loaded + deadhead rather than transcribing a displayed total;
- model converts units or dimensions without preserving the visible source value;
- model fills a hidden/cropped quote ID;
- model produces values from another visible card in a multi-card screenshot.

No rejected field is replaced by an inferred fallback.

### 5.4 Cross-field consistency warnings

Do not silently “fix” conflicting source values.

Examples:

- displayed total miles differs from loaded + deadhead;
- two different weights are visible;
- origin ZIP conflicts with visibly printed city/state;
- pickup end precedes pickup start;
- pieces conflict with dimension counts.

Preserve the visible observations, mark `CONFLICTING_VISIBLE_VALUES`, and require operator confirmation.

## 6. Confidence and confirmation policy

Confidence controls review workflow, not source authority.

### 6.1 Per-field threshold

After deterministic evidence validation:

- `>= 0.99` — **AUTO-ACCEPT INTO EDITABLE DRAFT**. Field may be prefilled without an individual confirmation tap.
- `0.90–0.989999` — **REQUIRE FIELD CONFIRMATION**. Prefill/highlight, but the operator must explicitly confirm or edit it.
- `< 0.90` — **DO NOT ACCEPT**. Treat as UNKNOWN/manual-entry required.

The deterministic validator can always downgrade/reject regardless of confidence.

### 6.2 Hard-confirm conditions

Require explicit operator confirmation even above `0.99` when:

- price semantic is `CARRIER_PAYOUT` and the source is not already a trusted structured/rate-confirmation mapping;
- hazmat is `true` or ambiguous;
- a dimension/weight would materially drive a vehicle-fit rejection/acceptance;
- the image contains conflicting visible values;
- a relative date must be resolved;
- provider price semantics are `UNKNOWN_PRICE_SEMANTIC`;
- extraction status is `PARTIAL`.

### 6.3 Offer-level confirmation gate

Even when every field is high-confidence, vision output becomes an **editable draft**, not an immediately committed canonical opportunity.

Before the extracted offer can be treated as operator-confirmed/canonical ingestion, the UI must show the normalized fields and require one explicit **Confirm extracted load** action.

That confirmation records:

- extraction ID/local evidence reference;
- schema version;
- confirmation timestamp;
- fields accepted as-is;
- fields edited by the operator;
- rejected/unknown fields.

A future product decision may reduce confirmation friction only after measured field accuracy supports it; this contract does not authorize silent canonical ingestion.

## 7. Relative date/time resolution

Vision does not resolve relative time.

Example image text:

`Pickup: TODAY ASAP by 7:00 PM EDT`

Vision output:

- `pickup.relative_date_text.value = "TODAY"`
- `pickup.date_local.value = null`
- `pickup.end_time_local.value = "7:00 PM"`
- `pickup.timezone_label.value = "EDT"`
- `pickup.asap.value = true`

After extraction, FreightLogic may deterministically resolve `TODAY` using the image capture timestamp/user locale and store the resolved date as a **derived** field with provenance. The raw relative text must remain available.

## 8. Price handling

Vision never writes generic `revenue`.

Every visible amount enters `prices[]` with an explicit semantic.

Examples:

- DispatchLand `Target Rate $400` → `BOARD_TARGET_RATE`
- visible operator-submitted `Bid $450` → `OPERATOR_BID`
- Warp all-inclusive bookable quote → `SHIPPER_BOOKABLE_PRICE`
- explicit carrier rate confirmation amount → candidate `CARRIER_PAYOUT`, subject to source mapping/confirmation policy
- `$500` with no visible semantic → `UNKNOWN_PRICE_SEMANTIC`

Only the downstream canonical ingestion contract decides whether a price can populate expected carrier revenue. Vision does not make that decision.

## 9. Identity and duplicate handling

Vision may extract quote/order ID, but it does not create dedup identity.

The normalized ingestion layer must use a stable opportunity identity strategy that can distinguish reused IDs. At minimum, matching should consider:

- provider/platform;
- displayed ID;
- origin;
- destination;
- pickup date/window;
- source timestamp/evidence fingerprint.

If identity is ambiguous, create a separate observation/link candidate rather than destructively merging records.

## 10. Offline-first fallback

Vision is optional network functionality layered on top of an offline-capable PWA.

### Required behavior when offline or extraction service is unavailable

1. User can still capture/select the image.
2. FreightLogic creates a local ingestion item with a generated local ID, capture timestamp, and local image/evidence reference.
3. Status is `PENDING_EXTRACTION_OFFLINE` or equivalent implementation state.
4. Manual load entry remains fully available.
5. Core PWA startup, navigation, decision calculations, existing records, and backup/export behavior continue working.
6. No vision SDK/model dependency is added to the service-worker critical shell.
7. No network exception from extraction can crash or block the app.
8. A later extraction result must not overwrite manual fields already confirmed while offline.

### Retry policy

Initial contract default: user-controlled retry/upload on reconnect. Automatic background upload/retry is not required and must not be introduced without an explicit privacy/product decision.

### Storage implementation

Claude may choose the safest existing local storage mechanism consistent with current FreightLogic architecture. Any new IndexedDB object/store/version migration is core-owned and must satisfy backup/restore compatibility requirements.

Raw image retention duration is intentionally not fixed here; it is an operator product question in `OPEN_QUESTIONS.md`.

## 11. Network / Worker boundary

Preferred architecture:

`PWA client → FreightLogic Worker /extract-compatible boundary → vision provider → strict JSON → client validator`

Requirements:

- no vision-provider secret in client JavaScript;
- explicit timeout and source-health status;
- malformed/non-schema response is treated as extraction failure, not partial truth;
- endpoint may not calculate canonical verdict/grade/True RPM/bid;
- no new provider origin should be added to client CSP if the existing Worker boundary can proxy the request;
- request/response logging must avoid leaking unrelated sensitive image content.

If the existing `/extract` route cannot safely support the contract, Claude must propose the narrowest compatible core change instead of creating a parallel extraction stack.

## 12. Normalized-ingestion handoff

The validated/confirmed vision result feeds the same normalized opportunity-ingestion contract used by:

- manual entry;
- email normalization;
- historical import where appropriate;
- future authorized provider APIs.

Vision-specific fields (`confidence`, `evidence_text`, image reference) remain attached as provenance. They must not force a separate business-object shape.

## 13. Vehicle-fit boundary

Vision may extract freight dimensions/weight/pieces. It does **not** decide fit.

After operator confirmation/threshold acceptance, existing deterministic vehicle-fit logic evaluates the confirmed dimensions against current vehicle truth, including the operator-confirmed hard 121-inch usable cargo-length limit.

A low-confidence or missing dimension must produce UNKNOWN/needs-confirmation, never an automatic fit pass.

## 14. Acceptance criteria for Claude implementation

### Contract / parser

- [ ] Vision success path uses schema-constrained structured output or equivalent strict validation; no prose parsing is required.
- [ ] JSON Schema rejects extra keys, invalid enums, invalid types, and non-finite values.
- [ ] Missing values remain null; no UNKNOWN→0 coercion exists.
- [ ] Every accepted material field has evidence text.
- [ ] Field evidence validator rejects invented numeric/location/date/ID values even at model confidence `1.0`.
- [ ] Relative date text is preserved and not resolved by the model.
- [ ] Price/mileage semantics remain explicit and are never collapsed into generic rate/miles.
- [ ] Multiple-card input cannot merge fields into one opportunity.

### Confidence / confirmation UX

- [ ] `>=0.99` validated fields prefill the editable draft.
- [ ] `0.90–<0.99` fields visibly require confirmation.
- [ ] `<0.90` fields do not populate accepted values.
- [ ] hard-confirm conditions override confidence.
- [ ] entire offer requires explicit `Confirm extracted load` before canonical commit.
- [ ] operator edits are stored as operator-confirmed values and vision output remains provenance, not authority.

### Offline / failure behavior

- [ ] PWA installs/boots/reloads offline with vision endpoint unavailable.
- [ ] image can be saved locally for later/manual handling without blocking normal PWA behavior.
- [ ] manual intake works offline.
- [ ] failed/timed-out/malformed extraction cannot crash startup or load decision flow.
- [ ] late/retried vision result does not overwrite confirmed manual fields.
- [ ] no model SDK/API dependency is added to critical service-worker precache.

### Security / architecture

- [ ] no provider key/secret is shipped to the browser.
- [ ] vision endpoint is intake-only; it does not recalculate canonical verdict, grade, economics, or bid.
- [ ] existing v24 Unified Decision Engine remains the sole canonical decision authority.
- [ ] storage migration, if required, is additive and backup/restore compatible.
- [ ] quote ID alone is never used as destructive dedup identity.

### Regression / evidence fixtures

Use deterministic stubs for CI contract tests and a separate versioned field-fixture certification set for real-model checks.

At minimum cover:

- [ ] clean DispatchLand single-card screenshot;
- [ ] low-resolution/blurred card;
- [ ] cropped quote ID;
- [ ] missing deadhead;
- [ ] target rate + operator bid on same card;
- [ ] no visible rate;
- [ ] relative `TODAY/TOMORROW/ASAP` timing;
- [ ] conflicting visible mileage values;
- [ ] dimensions/weight near vehicle-fit boundary;
- [ ] multi-card screenshot;
- [ ] reused quote ID on a different lane;
- [ ] Warp-like shipper bookable price semantics;
- [ ] hallucinated model response containing a value not present in evidence text.

CI must prove deterministic validator behavior; real-model fixture certification should report field-level outcomes but must not make nondeterministic model calls a flaky required CI dependency.

### Required test gate

Any implementation touching `app.js`, IndexedDB/storage, Worker behavior, service worker, or other shared/core paths follows `/AGENTS.md` locks and runs the full Playwright suite. Existing authority assertions may not be weakened to make vision ingestion pass.

## 15. Explicit non-goals

This contract does **not** authorize:

- freight-provider booking/dispatch automation;
- broad multi-document OCR;
- autonomous acceptance of loads;
- automatic bidding;
- new decision math;
- route-mile inference by the model;
- background photo surveillance;
- unrestricted cloud image retention;
- provider API adapters unrelated to image extraction;
- a broad v24.6 visual/workflow expansion.

## 16. Implementation ownership

GPT owns this specification and evidence semantics. Claude owns runtime/core implementation under the repository lane and lock protocol.

GPT must request the implementation through `/.agents/inbox/` and must not implement the core path itself.
