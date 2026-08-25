# FreightLogic Freight-Source Ingestion Contract

Status: implementation contract / docs only.

Purpose: define one provider-independent opportunity/evidence shape that manual intake, pasted text, screenshots, email alerts, and authorized freight APIs can all feed without creating a second decision engine or confusing market prices with carrier revenue.

Last provider-verification date: **2026-08-25**.

## 1. Governing boundaries

1. The v24 Unified Decision Engine remains the only authority for verdict, grade, economics, and bid range.
2. External freight sources provide **facts/evidence**, never an authoritative FreightLogic verdict.
3. An external price must carry an explicit price semantic. FreightLogic must never infer carrier payout merely because a provider returned a dollar amount.
4. Unknown material facts stay unknown. Missing revenue, loaded miles, deadhead miles, weight, dimensions, dates, or identity fields must not be coerced to zero.
5. FreightLogic's own vehicle-fit rules remain authoritative for the operator's configured van. Provider equipment limits are provider booking constraints, not a replacement for the local van-fit gate.
6. No adapter may scrape a board or reuse consumer-login access where the provider requires partner/API authorization.
7. Provider credentials must not be persisted in localStorage or exported in FreightLogic backups.
8. Provider failure must degrade to explicit `UNAVAILABLE`/stale evidence, never to a fabricated market value.

## 2. Normalized ingestion object

Recommended shape:

```js
{
  ingestionId: 'ing_<time>_<random>',
  receivedAt: '2026-08-25T00:00:00.000Z',

  source: {
    platform: 'WARP | 123LOADBOARD | DIRECT_FREIGHT | DISPATCHLAND | EMAIL | MANUAL | SCREENSHOT | OTHER',
    channel: 'API | EMAIL | PASTE | VOICE | PHOTO | MANUAL',
    providerRecordId: '',
    providerQuoteId: '',
    providerUrl: '',
    sourceTimestamp: null,
    fetchedAt: null,
    health: 'HEALTHY | DEGRADED | UNAVAILABLE | UNKNOWN',
    freshness: 'LIVE | FRESH | STALE | UNKNOWN',
    authMode: 'PUBLIC | PARTNER_API | USER_SESSION | MANUAL | UNKNOWN'
  },

  identity: {
    broker: '',
    carrier: '',
    customer: '',
    orderNo: '',
    quoteNo: '',
    lifecycleId: null
  },

  lane: {
    origin: { city: '', state: '', zip: '' },
    destination: { city: '', state: '', zip: '' },
    pickupAt: null,
    deliveryAt: null
  },

  freight: {
    pieces: null,
    pallets: null,
    weightLbs: null,
    lengthIn: null,
    widthIn: null,
    heightIn: null,
    equipment: 'CARGO_VAN | UNKNOWN',
    commodity: ''
  },

  mileage: {
    loaded: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
    platformDisplayed: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
    deadhead: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' },
    repositionAfterDelivery: { value: null, status: 'VERIFIED | ESTIMATED | UNKNOWN', source: '' }
  },

  price: {
    amount: null,
    currency: 'USD',
    semantic: 'CARRIER_PAYOUT | POSTED_CARRIER_RATE | BROKER_TARGET | OPERATOR_BID | SHIPPER_BOOKABLE_PRICE | MARKET_ESTIMATE | UNKNOWN',
    allInclusive: null,
    expiresAt: null,
    bookable: null
  },

  evidence: {
    confidence: 'HIGH | MEDIUM | LOW',
    sampleSize: null,
    notes: [],
    rawTextRef: null,
    rawImageRef: null
  }
}
```

Exact names may be implementation-adjusted, but the separation between source, identity, lane, freight, mileage provenance, and price semantic is mandatory.

## 3. Price semantics

### `CARRIER_PAYOUT`

A confirmed amount FreightLogic expects the operator/carrier to receive for the load. This may enter canonical revenue after normal validation.

### `POSTED_CARRIER_RATE`

A board-displayed amount offered to a carrier, but not yet confirmed as the operator's actual payout. Treat as market evidence until accepted/confirmed.

### `BROKER_TARGET`

A broker/board target or stated budget. Evidence only.

### `OPERATOR_BID`

The operator's submitted bid. Never use as market clearing price merely because it was submitted.

### `SHIPPER_BOOKABLE_PRICE`

A price a shipper can book/pay for transportation. Evidence only. It is **not** the carrier payout and must not populate canonical revenue.

### `MARKET_ESTIMATE`

A model/provider estimate without a directly bookable or posted carrier-side transaction. Evidence only.

### `UNKNOWN`

Any dollar amount whose economic meaning cannot be proven. Keep it visible for review, but exclude it from revenue and calibrated market math.

## 4. Mileage semantics

FreightLogic must preserve these as separate facts:

- **loaded**: origin-to-destination miles used for the load itself;
- **platformDisplayed**: whatever mileage a board/provider displayed, preserved verbatim when available;
- **deadhead**: current/relevant empty reposition miles before pickup;
- **repositionAfterDelivery**: optional post-delivery positioning, never silently added into the primary True RPM denominator unless a later explicit doctrine says so.

Every mileage value carries `VERIFIED | ESTIMATED | UNKNOWN`.

A real `deadhead = 0` is valid and must remain distinguishable from unknown deadhead.

## 5. Identity and deduplication

### Preferred deduplication keys

1. explicit `lifecycleId` after v24.2 linkage;
2. exact `(platform, providerRecordId)`;
3. exact `(platform, providerQuoteId)` for quote evidence;
4. exact normalized broker/order-number pair only when both are explicit and compatible with route/time facts.

### Do not auto-merge from

- city pair alone;
- dollar amount alone;
- approximate timestamp alone;
- ambiguous customer text;
- generic broker/company strings without an explicit label;
- inferred order numbers extracted from unrelated text.

When ambiguous, create a separate ingestion item and flag it for review rather than silently merging two loads.

## 6. Channel adapters

All adapters terminate in the same normalized object before any decision/evidence logic consumes them.

### Manual / paste / voice

- Preserve user-entered values exactly after sanitation.
- Blank fields remain null/unknown.
- Parsed fields must be reviewable before being treated as verified facts.

### Screenshot / photo

- Extract candidate fields, but mark extracted values as unverified until the driver reviews them.
- Preserve the source image reference where the app's storage/privacy contract permits it.
- Never invent cropped/hidden origin, destination, load ID, rate, or mileage text.

### Email

- Treat inbound alert text/attachments as source material, not authoritative structured data until normalized.
- Preserve sender/platform provenance when available.
- Do not assume a ChatGPT/Gmail connector is equivalent to FreightLogic application-level Gmail authorization.
- Do not store Gmail OAuth credentials in the PWA.

### API

- Adapter validates provider response before normalization.
- Provider HTTP/API error maps to source health; it does not manufacture an empty successful record.
- Live calls should be isolated behind a provider client/helper so fixtures can exercise normalization without network calls in CI.

## 7. Provider-specific contract

### Warp cargo-van quote evidence

Current official source references:

- `https://www.wearewarp.com/agents/docs/van`
- `https://www.wearewarp.com/cargo-van-api`
- `https://www.wearewarp.com/freight-api-changelog`

Current verified behavior as of 2026-08-25:

- quote endpoint: `POST https://www.wearewarp.com/api/v1/van/quote`;
- quote-only access is public/keyless according to current Warp self-serve docs;
- booking/private operations require authenticated access;
- response includes a quote identifier, `price_usd`, transit information and expiration/booking metadata depending on endpoint generation;
- current Warp materials describe the quote as an all-inclusive shipper/bookable price.

FreightLogic normalization:

```js
source.platform = 'WARP'
source.channel = 'API'
source.authMode = 'PUBLIC' // quote-only endpoint
price.semantic = 'SHIPPER_BOOKABLE_PRICE'
price.amount = response.price_usd
price.allInclusive = true
price.bookable = true
```

Hard rule: `price.amount` from Warp must **not** populate canonical expected carrier revenue.

Use cases:

- current-lane shipper-side market anchor;
- directional relative pricing signal;
- evidence/confidence support once v24.1 is live;
- future empirical comparison against operator bids/wins only after lifecycle data exists.

Do not create a fixed carrier-payout discount from Warp price in the completion release. A shipper-to-carrier spread must be learned from verified outcomes, not guessed.

Provider-capacity note: current public Warp pages are not perfectly uniform about pallet-count wording. The adapter must therefore validate against the live endpoint response/error contract and must never reuse Warp equipment limits as FreightLogic's own van-fit authority.

### 123Loadboard

Current official source reference:

- `https://www.123loadboard.com/api/`

Current verified behavior as of 2026-08-25:

- developer materials list Search Loads, Check Rates, Bidding, Book Now and other API products;
- API integration is presented as a partner/integrator process with an assigned integration contact.

FreightLogic rule:

- a normal/free board account does not prove partner API authorization;
- do not scrape or automate the consumer website as an API substitute;
- implement only after the actual API access scope/credentials are issued;
- normalize posted carrier-side prices according to the exact returned field semantics instead of assuming every rate field is carrier payout.

### Direct Freight

Current official source references:

- `https://apidocs.directfreight.com/`
- `https://www.directfreight.com/policies/directfreight_api_terms.html`

Current verified behavior as of 2026-08-25:

- Direct Freight V1 requires a partner `api-token` on API calls;
- some user-scoped functionality also uses an `end-user-token`;
- the board API exposes load/truck search and associated freight data under its API terms.

FreightLogic rule:

- a normal/free Direct Freight account does not equal partner API authorization;
- do not persist the partner `api-token` in client-visible settings or backups;
- if integration is approved, place permanent provider secrets server-side and expose only the minimum normalized data needed by FreightLogic;
- preserve returned provider record IDs for deduplication/provenance.

### DAT RateView

Current FreightLogic project rule:

- dormant/non-authoritative for cargo-van expedite pricing;
- `dat-rateview.js` must remain unwired unless the owner later explicitly authorizes a bounded role with confirmed cargo-van semantics.

## 8. Security and secrets

- Public/keyless quote endpoints may be called directly only if CORS, rate-limit, privacy, and abuse implications are acceptable.
- Permanent provider secrets belong in a Worker/server environment, never the PWA source, localStorage, export JSON, sync deltas, or backup payloads.
- User-session tokens must have an explicit retention policy and must never be copied into analytics/history records.
- Logs and diagnostics must redact provider tokens and authorization headers.
- API response bodies may contain broker/contact data; retain only fields required for the load workflow and permitted by provider terms.

## 9. Source health and freshness

Normalize provider/channel health to the vocabulary used by v24.1:

`HEALTHY | DEGRADED | UNAVAILABLE | UNKNOWN`

Freshness is separate:

`LIVE | FRESH | STALE | UNKNOWN`

Examples:

- Warp HTTP 200 quote just fetched -> health `HEALTHY`, freshness `LIVE`.
- Warp rate from a saved expired quote -> health may remain `HEALTHY`, freshness `STALE`.
- 123Loadboard API not authorized -> health `UNAVAILABLE`, not zero rates.
- Manual price with no timestamp -> health `UNKNOWN`, freshness `UNKNOWN` unless user confirms when observed.

## 10. Relationship to v24.1 confidence

The ingestion layer supplies evidence inputs. It does not calculate an alternate verdict.

Confidence may consider:

- source health;
- freshness;
- whether the field was verified vs estimated;
- sample size for historical aggregates;
- agreement/conflict among evidence sources.

Confidence must remain categorical (`HIGH | MEDIUM | LOW`) until sufficient predicted-vs-actual lifecycle data exists for calibrated probability work.

## 11. Relationship to v24.2 lifecycle

An ingestion record may begin before a lifecycle record exists.

Once v24.2 is implemented:

- strong identity evidence may link ingestion to `lifecycleId`;
- an API/board opportunity can create/update the opportunity dimension without overwriting execution/settlement truth;
- repeated provider refreshes update evidence/source facts rather than creating duplicate won/delivered loads;
- EXPIRED provider opportunities remain EXPIRED, not LOST;
- cancellation and expiration semantics must remain provider-aware and explicit.

## 12. Historical/calibration use

Only outcome-backed records may calibrate operator intelligence.

Examples:

- operator bid + later WON -> valid bid/outcome evidence;
- operator bid + later LOST -> valid bid/outcome evidence;
- EXPIRED -> excluded from ordinary win-rate denominator;
- Warp shipper price + no carrier outcome -> market evidence only;
- board screenshot with unknown outcome -> observation only;
- DZ-EXIT win -> separate recovery cohort, excluded from normal-market floor calibration.

## 13. Adapter implementation sequencing

After Milestones 1–4 are green:

1. land pure normalization/validation helpers with fixtures;
2. connect existing manual/paste/photo intake to the normalized shape;
3. connect lifecycle linking/deduplication;
4. add Warp public quote evidence adapter;
5. add source-health/freshness UI and confidence projection;
6. add 123Loadboard adapter only after authorized API access exists;
7. add Direct Freight adapter only after partner token/access exists;
8. add historical import mapping through the same normalization semantics.

No provider adapter should directly write canonical decision fields.

## 14. Required tests

At minimum:

- missing numeric fields remain null/UNKNOWN, never zero;
- a real `deadhead = 0` survives normalization as verified zero;
- price semantic is required before a price can influence revenue/economics;
- `SHIPPER_BOOKABLE_PRICE` cannot populate canonical revenue;
- provider timeout/403/429/5xx maps to source health, not fake empty data;
- expired quotes become stale evidence;
- duplicate `(platform, providerRecordId)` observations do not create duplicate opportunities;
- ambiguous records remain unlinked;
- provider secrets never appear in exports/backups/diagnostics;
- Warp fixture normalization preserves quote ID, price, expiration and shipper-price semantic;
- 123Loadboard/Direct Freight adapters cannot run without their required authorization configuration;
- full existing v24 authority suite remains green.

## 15. Definition of done

The ingestion foundation is complete when every supported intake channel can produce the same normalized opportunity/evidence object with explicit provenance, unknown handling, mileage status, and price semantics, while the Unified Decision Engine remains the only decision authority.

A collection of provider-specific fetch functions that bypass normalization or write directly into revenue/verdict fields does **not** satisfy this contract.
