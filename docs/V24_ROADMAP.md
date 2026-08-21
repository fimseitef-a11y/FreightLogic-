# FreightLogic v24 Roadmap — Authority & Integrity Rules

Status: adopted after v23.9 Trust & Recovery. This document is the architecture guardrail for v24 work.

## Constitutional rules

1. **Single-file application architecture remains.** Core runtime logic stays in `app.js`; no build step, bundler, transpiler, or module split is introduced. Internal organization may improve without multiplying shipped runtime files.
2. **No new parallel intelligence systems.** New features either feed the canonical decision object or consume it.
3. **Client decision is authoritative.** The future canonical deterministic decision function in `app.js` owns verdict/bid/economics. Worker `/evaluate` may explain, challenge, summarize, or identify risks; it must not independently recalculate the authoritative verdict.
4. **`midwest-stack-authority.js` moves toward adapter status.** Do not add new independent decision math there while v24 is consolidating authority.
5. **Confidence starts categorical.** HIGH/MEDIUM/LOW with provenance, sample size, and recency. Percent probabilities wait until lifecycle predicted-vs-actual data supports calibration.
6. **Every live source has health/provenance.** External API failures may not silently collapse into a value indistinguishable from no data.

## Pre-v24 integrity gate (v23.9.1)

- Align Normal Floor to $1.40 True RPM and Preferred Floor to $1.50.
- Static rate overrides carry freshness: CURRENT <=14 days, AGING 15–30 days, STALE >30 days. STALE static bands cannot relax normal protective pricing. Explicit Dead Zone Exit remains governed by its separate hard gate.
- EIA, NWS, FMCSA, and CBP calls record source health (`OK`, `UNCONFIGURED`, `AUTH_ERROR`, `HTTP_ERROR`, `TIMEOUT`, `NETWORK_ERROR`, `PARSE_ERROR`, `OFFLINE`) and surface it in Diagnostics.
- Broker history normalization/backfill is conservative: explicit broker-labelled evidence only. Never infer broker from ambiguous `trip.customer`. Unresolved rows remain `legacyUnkeyed` and excluded from broker intelligence.
- CI uses a pinned Playwright version and non-deprecated GitHub Action runtimes.

## Delivery sequence

1. **v24.0 Unified Decision Engine** — one deterministic result object inside `app.js`. **In progress:** canonical result contract + grade authority + legacy-render adapter + Worker AI authority separation are complete; Phase B moves the full geography/RPM/long-haul/margin/deadhead/weekly/fatigue/personal hard-gate chain into `deriveUnifiedAuthority()` with boundary tests.
2. **v24.1 Confidence + Evidence** — provenance, sample size, age, HIGH/MEDIUM/LOW.
3. **v24.2 Load Lifecycle** — one accumulating operational identity with additive migration and dual-write transition.
4. **v24.3 Personal Intelligence 2.0** — recency/sample-size weighting and self-calibrating market bands.
5. **v24.4 Next-Move Engine** — evolve F24 into time-aware commands (`STAY`, `REPOSITION NOW`, `WAIT UNTIL … THEN MOVE`, `KEEP BOARD OPEN WHILE MOVING`, `GO HOME`).
6. **v24.5 Driver Mode + visual overhaul** — one combined pass after numbers/data contracts stabilize.
7. **v24.6 Screenshot-first workflow** — promote existing F23/F27 intake rather than create another path.
8. **v25 Live Market Intelligence** — add more feeds only after source-health and internal data contracts are trustworthy.

## v24.2 lifecycle state model

Do not force real operations into one lossy linear enum. Store related dimensions and derive a display stage.

- Opportunity: `SEEN`, `QUOTED`, `BID`, `WON`, `LOST`, `EXPIRED`, `CANCELLED`
- Execution: `NOT_STARTED`, `EN_ROUTE_PICKUP`, `PICKED_UP`, `DELIVERED`, `FELL_THROUGH`
- Settlement: `NOT_INVOICED`, `INVOICED`, `OVERDUE`, `PAID`, `BAD_DEBT`

Rules locked before implementation:

- **EXPIRED is not LOST.** Expired means no known award decision and is excluded from the ordinary win-rate denominator.
- **CANCELLED is not LOST.** Broker/load withdrawal is its own terminal opportunity state.
- **DZ-EXIT outcomes remain operational truth but are a separate calibration cohort.** They may count in raw broker interaction statistics, but they are excluded from normal-market winning-range/floor calibration.
- **Lifecycle requires a DB version bump.** Migration is additive, dual-write is required during transition, and backup/delta/restore/import/export must accept both old and new record shapes until migration is retired.

## Release gate

No v24 feature is release-ready unless full CI is green, version/SW parity is verified, backup/restore parity passes, and changed critical mobile journeys have regression coverage. GitHub branch protection should require the `playwright-suite` check when repository settings permit it.
