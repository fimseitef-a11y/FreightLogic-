# FreightLogic Evidence Provenance

Version: 1.0.0
Snapshot date: 2026-08-26
Owner lane: GPT (`docs/`)
Status: canonical evidence-semantics contract

## Purpose

FreightLogic must preserve what a number **actually represents**. A numerically plausible value is unsafe if its semantic meaning is wrong.

This file defines source provenance and the meanings that must never be conflated. It applies to manual entry, screenshots/vision extraction, email intake, historical imports, and future API adapters.

## Evidence precedence

When sources conflict, prefer:

1. current explicit operator correction;
2. primary source evidence: screenshot/order card/rate confirmation/settlement/completion record;
3. operator-confirmed historical data;
4. current canonical FreightLogic doctrine/contracts;
5. verified external provider documentation;
6. derived deterministic math with preserved inputs;
7. AI summaries/handoffs only as discovery aids, never as authority.

No AI inference may silently promote itself above a primary source.

## Required provenance fields

Every externally sourced material field should retain, directly or through a linked evidence record:

- `source_type`
- `source_name`
- `observed_at`
- `source_timestamp` when visible/available
- `raw_evidence_ref` or stable evidence identifier when available
- `price_semantic` for money
- `mileage_semantic` for mileage
- `confirmation_state`
- `field_confidence` when machine-extracted
- `operator_confirmed_at` when manually confirmed

Derived values must point back to their input evidence; they are not new observations.

## Price semantic vocabulary

Use explicit semantics. Do not store an unlabelled number in a generic `rate` field when the meaning is known.

- `CARRIER_PAYOUT` — amount the carrier/operator is contractually paid for the load.
- `OPERATOR_BID` — amount the operator submitted/requested. It is not a win price or payment.
- `BOARD_TARGET_RATE` — board/broker target shown on an opportunity. It is not automatically the winning price or carrier payout.
- `SHIPPER_BOOKABLE_PRICE` — price a shipper can book/buy transportation for. It is not carrier payout.
- `POSTED_RATE` — rate posted on a load board; exact carrier-pay semantics depend on provider/field documentation.
- `MARKET_BENCHMARK` — statistical or modeled market reference. It is not a guaranteed transaction price.
- `CONTRACT_RATE` — contractual benchmark/rate category where the source explicitly says so; not automatically applicable to cargo-van expedite.
- `SETTLED_AMOUNT` — amount actually settled/paid after completion; distinct from initial rate confirmation when adjustments exist.
- `UNKNOWN_PRICE_SEMANTIC` — amount is visible but its meaning cannot be proven. Keep it isolated from canonical revenue.

**Hard rule:** only `CARRIER_PAYOUT`, a user-confirmed expected revenue value, or a lifecycle-appropriate settled amount may populate canonical carrier revenue. Other price semantics may inform evidence/confidence but must not be silently converted into revenue.

## Mileage semantic vocabulary

- `LOADED_MILES` — source-displayed or otherwise verified loaded movement.
- `DEADHEAD_MILES` — empty miles to pickup.
- `DISPLAYED_TOTAL_MILES` — total displayed by a source; do not assume its components unless shown.
- `POST_DELIVERY_REPOSITION_MILES` — empty repositioning after delivery; separate from pre-pickup deadhead.
- `MAP_ESTIMATE` — routing estimate generated outside the source card.
- `UNKNOWN_MILEAGE_SEMANTIC` — numeric mileage visible without a provable label.

Never overwrite source-displayed mileage with a map estimate. Store both with provenance if both are useful.

## Source semantics

### DispatchLand / Dispatch Lane opportunity cards

What they can establish:

- quote/load identifier as displayed;
- origin/destination;
- loaded/deadhead miles if visibly labelled;
- pickup/delivery windows;
- pieces, weight, dimensions, flags/notes when visible;
- target rate when explicitly labelled;
- operator bid when the UI explicitly shows the submitted bid;
- current card state as displayed.

What they must **never** be read as without additional evidence:

- a submitted bid is not a winning rate;
- a target rate is not carrier payout;
- a live quote is not an award;
- `EXPIRED` alone is not lifecycle `LOST`;
- an ID is not globally unique across different lanes/offer instances.

Special operator-confirmed exception: the 2026-08-24 expired screenshot batch was explicitly confirmed by the operator as bids they did not win. The `LOST` interpretation comes from the operator correction, not from `EXPIRED` alone.

### DispatchLand rate confirmations / travel orders

What they can establish:

- an accepted/awarded movement when the document is a genuine rate confirmation;
- contractual lane and shipment facts shown on the document;
- carrier payout if the document explicitly states the amount and pay semantics.

What they must never be read as automatically:

- rate confirmation does not by itself prove pickup, delivery, invoicing, or payment;
- quoted/contracted pay is not the same as settled amount if accessorials/adjustments later change it.

### Completion/delivery records

What they can establish:

- execution completion/delivery when the source explicitly says completed/delivered.

What they must never be read as automatically:

- delivered does not imply invoiced;
- invoiced does not imply paid;
- paid should be represented separately in settlement state.

### Warp cargo-van quote

Current FreightLogic semantic: `SHIPPER_BOOKABLE_PRICE`.

Confirmed examples on 2026-08-24 include Milwaukee-area → Detroit `$575.67`, Detroit → Columbus `$364.38`, Columbus → Chicago `$519.47`, Chicago → Grand Rapids `$335.14`, and Indianapolis → Detroit `$468.41`, each shown with one-day transit in the captured comparison context.

What Warp quote evidence means:

- an all-inclusive/bookable shipper-side transportation price at that time for the quoted request;
- useful live market/replacement-price evidence.

What it must **never** be read as:

- carrier payout;
- operator revenue;
- a DispatchLand winning price;
- a guaranteed future price;
- a universal cargo-van market average.

Current repository policy recognizes public/keyless quote-only access to `POST /api/v1/van/quote` as market evidence; authenticated booking/private operations remain separate. Even if authenticated account/API access exists, booking authorization does not change the quote's price semantic.

### 123Loadboard

Confirmed operator status: a free 123Loadboard account exists.

Current external/API semantics:

- public/developer materials expose load-search and rate/check-rate capabilities through an integration/partner process;
- website/free-account access is not equivalent to API authorization.

Never assume:

- a free account grants API rights;
- a check-rate/market-rate output equals guaranteed carrier payout;
- a posted load rate has a specific pay semantic unless the provider field/documentation establishes it;
- data may be retained, redistributed, or commercialized beyond provider terms.

Exact API eligibility/token/commercial terms remain in `OPEN_QUESTIONS.md` until verified.

### Direct Freight

Confirmed operator status: a free Direct Freight account exists.

Current external/API semantics:

- Direct Freight V1 documentation uses a partner `api-token` and user-scoped `end-user-token` model;
- free website account access is not partner API authorization.

A posted pay/rate field may be useful carrier-side evidence only when the exact endpoint/field semantics and permitted usage are known.

Never assume:

- free account = API access;
- partner token has been issued unless verified;
- posted amount = settled carrier payout;
- provider terms allow unrestricted historical analytics/storage/commercial redistribution.

### DAT RateView

FreightLogic policy: **dormant / non-authoritative for cargo-van expedite** unless the operator explicitly re-authorizes a bounded role.

RateView can represent truckload spot/contract market benchmarks depending on product/field, but FreightLogic must never treat those figures as authoritative cargo-van expedite carrier payout or winning ranges.

`dat-rateview.js` existing in the repository does not grant authority to use its numbers in canonical cargo-van decisions.

### Broker conversation relayed by operator

Semantic: anecdotal/relationship-specific market evidence.

It can inform context and hypothesis generation, but it must never be represented as a statistically validated board-wide average unless a separate dataset supports that claim.

Example: the 2026-06-26 Tulsa/OK-KS rate discussion is preserved as `BROKER_CONVERSATION_RELAY`, not as canonical market truth.

### Screenshot / photo / vision extraction

The **image** is primary evidence. The machine-extracted JSON is a derived representation.

Machine extraction must retain:

- image/evidence reference;
- field-level confidence;
- exact supporting visible text when possible;
- confirmation state.

Never allow a vision model to invent:

- a missing rate;
- a missing mileage value;
- a ZIP/city/state through geocoding inference;
- a date/time from current clock assumptions;
- a price semantic not supported by visible label/provider mapping;
- a quote ID hidden by crop;
- a missing dimension/weight.

The vision-ingest contract is defined in `VISION_LOAD_INGEST_CONTRACT.md`.

### Email alerts / Gmail-derived freight records

Email can be primary documentary evidence when the sender/content is the genuine provider/broker confirmation or completion notice.

Never treat:

- an email alert about an opportunity as live-board state after the message timestamp;
- a rate confirmation as proof of completion/payment unless it says so;
- parsed email fields as more authoritative than the underlying message.

### EIA fuel data

Semantic: external regional/national fuel-price benchmark as documented by the EIA source used by FreightLogic.

Never read it as the operator's actual receipt price. Actual fuel purchase/receipt data is operator-specific evidence and should remain separate.

### NWS weather data

Semantic: weather observation/forecast/hazard evidence from the National Weather Service.

Never read it as a guarantee of route conditions, travel time, road closure status, or safe drivability. It is risk context only.

### FMCSA data

Semantic: authority/registration/safety-related public data as supplied by FMCSA endpoints used by FreightLogic.

Never read it as proof of broker payment reliability, current load availability, or insurance coverage beyond the exact field/source meaning.

### CBP data

Semantic: border-related public operational data when available through the configured source.

Never read it as customs clearance authorization, admissibility determination, or a guarantee of actual crossing time.

## Derived math

Derived math is permitted only when inputs are preserved and semantically valid.

Example:

`True RPM = carrier revenue / (loaded miles + deadhead miles)`

Requirements:

- revenue must have canonical carrier-revenue semantics;
- loaded/deadhead mileage must be known with provenance;
- UNKNOWN input stays UNKNOWN; it must not become zero;
- result must be marked derived and traceable to its inputs.

A source-displayed loaded RPM may be stored as displayed evidence but must not be silently relabelled as True RPM.

## Confidence is not truth

A high model confidence score does not elevate an inferred field above primary evidence. Confidence controls review workflow; provenance controls authority.

## Change control

Any new provider/adapter must add its semantic contract here before its data can influence FreightLogic intelligence. If price or mileage meaning is unclear, use the appropriate `UNKNOWN_*_SEMANTIC` and isolate it from canonical economics until resolved.
