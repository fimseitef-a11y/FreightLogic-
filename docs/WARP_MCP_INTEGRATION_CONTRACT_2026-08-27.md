# FreightLogic — Warp MCP / API Integration Contract

Date: 2026-08-27
Owner lane: GPT (`docs/`)
Status: evidence/integration contract; does not grant provider access or decision authority

## Purpose

Warp is useful to FreightLogic now as a live shipper-side transportation pricing source. The public Warp MCP/API surface must not be mistaken for a carrier load board or carrier payout feed.

This contract supplements the canonical `docs/EVIDENCE_PROVENANCE.md` Warp section. If there is any conflict, the canonical provenance vocabulary and later explicit operator corrections win.

## Verified public MCP surface

Official Warp material checked 2026-08-27 identifies:

- package: `warp-agent-mcp` v0.18.0;
- hosted MCP endpoint: `https://mcp.wearewarp.com/api/mcp`;
- approximately 31 shipper-side freight tools;
- quote tools including `van_quote`, `box_truck_quote`, `ftl_quote`, `ltl_quote`, `compare_modes`, `batch_quote`, and LTL market options;
- booking/tracking/history/document/account operations including booking, tracking/events, invoices/documents, booking history, quote/lane history, analytics, saved locations, and templates.

Official references:

- `https://www.wearewarp.com/agents/mcp`
- `https://www.wearewarp.com/.well-known/mcp.json`

## Authentication boundary

According to Warp's public MCP documentation at the time checked:

- quote operations are available without authentication;
- booking, tracking/history, document, invoice, and account operations require authenticated Warp access.

Do **not** infer that any particular operator API key automatically has every private permission. The exact key/account type and granted scopes must be tested before implementation relies on them.

## Carrier-side boundary

No public Warp MCP tool was found for:

- available carrier loads;
- loads matched to a specific van;
- carrier bid/counter workflows;
- carrier tender acceptance;
- carrier settlement/payment history as the performing carrier.

Therefore the public MCP/API surface is **not** a DispatchLand/123Loadboard-style carrier opportunity feed.

This does not prove Warp has no freight opportunities for carriers. Warp operates a carrier network and may expose carrier opportunities through onboarding, portal, direct dispatch/tender, partner integrations, or non-public APIs. Those possibilities remain separate from the public MCP/API and require explicit Warp authorization before FreightLogic may model them as a carrier load source.

## Canonical price semantic

Warp cargo-van quote money is:

`SHIPPER_BOOKABLE_PRICE`

It may be used as live external market/replacement-price evidence.

It must never be silently converted into:

- `CARRIER_PAYOUT`;
- operator revenue;
- a DispatchLand winning carrier price;
- a settled amount;
- an available-load offer to the operator;
- a universal cargo-van market average.

A Warp shipper quote can inform evidence/confidence or comparative market context, but it cannot populate canonical carrier revenue unless independent carrier-pay evidence or explicit operator confirmation establishes that semantic.

## Cargo-van capability wording

Warp public pages are not fully uniform about pallet capacity. The MCP documentation checked 2026-08-27 describes cargo-van/Sprinter quoting around 1–3 pallets and roughly 3,500 lb, while other Warp material has described a broader pallet count.

FreightLogic must not use a generic Warp capacity statement to override the operator's actual vehicle-fit constraints. Vehicle fit remains determined from FreightLogic's operator/vehicle evidence (dimensions, payload, door/cargo-space limitations) before rate evidence is considered.

## FreightLogic integration phase

### Allowed now — evidence-only quote adapter

A future Warp adapter may call quote operations and normalize results through the same provider-independent opportunity/evidence contract used elsewhere.

Minimum required provenance:

- `source_type`: external provider API/MCP evidence;
- `source_name`: Warp;
- `observed_at`;
- Warp source timestamp when supplied;
- request/lane identity sufficient to understand what was quoted;
- `price_semantic = SHIPPER_BOOKABLE_PRICE`;
- mileage semantic explicitly labelled from the source/request rather than guessed;
- authentication state only as operational metadata, never as a change to price semantics.

The adapter must remain evidence-only unless a later provider-specific contract explicitly authorizes a carrier opportunity feed.

### Not allowed without new authorization/contract

Do not implement or simulate:

- polling Warp quotes and calling them "available loads";
- deriving carrier payout by subtracting an assumed Warp margin;
- automatically creating lifecycle `WON`, `BOOKED`, or carrier-tender states from shipper quote responses;
- carrier bidding/tender behavior not actually exposed by Warp;
- credential scope claims that have not been tested.

## `compare_modes` use

`compare_modes` may be useful for explaining a shipper-side modal alternative or replacement-cost context. It must not make box/LTL/FTL prices directly comparable to cargo-van carrier payout without explicit semantic translation supported by provider evidence.

## Historical and analytics use

Warp quote/lane history, when authenticated and actually available to the operator account, remains shipper-side price evidence unless the returned field explicitly documents another semantic.

Historical Warp quote data may participate in evidence trends only with preserved observation time. Import/mutation time must not replace the original market-observation age for M6 calibration.

## Future carrier-feed gate

If Warp grants a carrier API/feed or programmatic tender access, FreightLogic must add a provider-specific contract before using it. That contract must define at minimum:

- opportunity identity and reused-ID rules;
- carrier-offer price semantic;
- bid/counter/tender state semantics;
- cancellation/expiration/loss semantics;
- settlement/payment semantics;
- retention/redistribution terms;
- authentication/token handling;
- webhook/polling behavior;
- lifecycle mapping;
- test fixtures proving a shipper price cannot leak into carrier revenue.

Until that gate is satisfied, Warp remains a **shipper-side external quote evidence source**, not a carrier load source.
