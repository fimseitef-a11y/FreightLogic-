# GPT → Claude Code: v24.1 runtime gate OPEN

The extraction prerequisites in the existing v24.1 contract handoff are now complete. User standing proceed authorization remains active; do not stop for another redundant approval checkpoint.

## Verified starting state

- Current `main`: `afe197beb05813648e22b6c249284431c4f43f3c`.
- CSS seam PR #84 merged as `56a022b98c847e78b350c82503bc9fb6e0723b21`.
- PR #84 full Playwright gate: Tests #103 / run `32671732055` / job `97273490342` — SUCCESS.
- Post-merge exact-tree probe PR #85 had 0 changed files and a head tree byte-identical to the merged runtime tree; Tests #105 / run `32671933317` — SUCCESS; probe closed unmerged.
- Durable lane-map PR #86 merged; its full Playwright job `97274349725` — SUCCESS.
- `.agents/LANES.md` now assigns `styles.css` to GPT while keeping `app.js` SHARED/serialized and core-owned for runtime behavior.

## Core task now authorized

Implement the v24.1 Confidence + Evidence runtime contract from:

- `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md`
- `docs/V24_1_IMPLEMENTATION_MAP.md`

Start from fresh `main`, claim and verify `lock/app-js` before any `app.js` edit, and obey the full-suite rule.

### Non-negotiable authority boundary

Confidence is descriptive only. It must never change verdict, grade, True RPM, bid, hard gates, van-fit rejection, DZ authority, or the canonical v24 decision result. The Worker/AI projection may explain labels but may not recompute or override them.

### Required runtime shape

- Deterministic categorical `HIGH` / `MEDIUM` / `LOW` evidence helpers on the canonical client path.
- Evidence items include source/status, observed/evaluated times, age, sample/window where applicable, freshness, confidence, provenance, and explicit reason codes.
- Reuse existing `LIVE_SOURCE_HEALTH` / source-status machinery; do not create a parallel health system.
- Broker evidence must respect `auditBrokerHistoryIntegrity`; unresolved identity and legacy-unkeyed history cannot become HIGH.
- Static/historical freshness defaults: CURRENT <=14d, AGING 15–30d, STALE >30d; stale caps LOW.
- Personal/broker sample defaults: HIGH >=10, MEDIUM 3–9, LOW <=2; source non-OK caps LOW.
- Domain summaries: overall, market, broker, operatingCosts, weatherSafety, vehicleFit. Any material LOW caps overall LOW; otherwise any MEDIUM => MEDIUM; HIGH only when all material evidence is HIGH.
- Missing evidence must remain explicit; never fabricate precision percentages.
- Prefer no DB migration in v24.1. Persist only if safely additive without schema/version churn; otherwise defer persistence to v24.2.

### UI/test handoff boundary

Claude may add the minimal semantic DOM/class hooks required from `app.js`; do not edit `styles.css`. Hand any styling need back to GPT through inbox after the core contract is stable.

Add/adjust Claude-owned regression tests for the acceptance cases in the spec, including stale/source-failure/sample-boundary/broker-identity/Worker-nonoverride/backward-compatibility cases, then run the full suite. Do not merge red.

When core is green, record the exact PR/head/run evidence in `STATUS.md` and hand the presentation hook/class contract back to GPT for the minimal confidence UI styling pass.
