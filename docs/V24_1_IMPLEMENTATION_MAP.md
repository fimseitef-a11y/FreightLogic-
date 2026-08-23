# FreightLogic v24.1 — Current-Source Implementation Map

Status: source-backed companion to `V24_1_CONFIDENCE_EVIDENCE_SPEC.md`. This file identifies integration seams in the current v24.0 runtime; it does not change runtime behavior.

## Gate state at contract integration

Temporary v24.0.1 bank-repair CI machinery was removed by PR #82 before this contract is integrated. The standard PR/push Playwright gate is again the only workflow under `.github/workflows/`; v24.1 must not reintroduce comment-triggered or branch-pushing CI repair paths.

## Core authority seam in `app.js`

The v24.0 regression contract already names the canonical path. v24.1 should extend this path additively rather than create a parallel evaluator.

Current anchors:

- `UNIFIED_DECISION_SCHEMA_VERSION`
- `deriveUnifiedAuthority(facts, policy = UNIFIED_DECISION_POLICY)` — verdict/hard-gate authority; v24.1 must not move confidence logic into this function in a way that changes verdict authority.
- `deriveUnifiedGrade(trueRPM, ...)` — grade authority; confidence must not alter its output.
- `deriveUnifiedEconomics(facts)` — canonical economics; evidence may describe input quality but must not calculate competing economics.
- `deriveUnifiedBid(totalMiles, opts={})` — canonical bid authority; LOW confidence cannot lower the protective result.
- `buildUnifiedDecisionContract(input)` — preferred additive attachment point for the client-owned confidence/evidence projection.
- `unifiedDecisionToLegacy(decision)` — compatibility adapter; add only the minimum compatibility projection needed by current UI.
- `unifiedDecisionForAI(decision)` — compact Worker payload. Any v24.1 projection sent here must carry client-computed labels/evidence summaries, not inputs that invite the Worker to recalculate authoritative confidence.

The current canonical object already groups `market`, `personalIntel`, `risk`, route/economics/authority information. Confidence/evidence should be a sibling additive contract on that canonical object rather than embedded as a second verdict model.

## Existing live-source health seam

v23.9.1 already provides a reusable health substrate in `app.js`:

- `LIVE_SOURCE_HEALTH`
- `LIVE_SOURCE_STATUS`
- `setLiveSourceHealth(source, status, detail={})`
- `_persistLiveSourceHealth()`
- `_liveSourceFailureStatus(...)`

Existing status instrumentation is already present for:

- EIA fuel (`fetchEIAGasPrice()`)
- NWS route alerts (`checkRouteWeather(...)`)
- FMCSA lookup (`lookupFMCSA(...)`)
- CBP border wait (`fetchBorderWaitTime(...)`)

Do not invent a second health registry for v24.1. Evidence items should normalize from the existing status records. Preserve the current failure vocabulary: `OK`, `UNCONFIGURED`, `AUTH_ERROR`, `HTTP_ERROR`, `TIMEOUT`, `NETWORK_ERROR`, `PARSE_ERROR`, `OFFLINE`, with `UNKNOWN` only as the v24.1 normalization fallback when no health record exists.

Important source-specific observations from current runtime:

- EIA has a three-day fetch throttle and records source timestamp/value on success.
- NWS cache freshness is 30 minutes per route point.
- FMCSA cache freshness is 24 hours per DOT number.
- CBP cache freshness is 30 minutes per port.

Therefore v24.1 should support source-specific freshness before applying the generic 14/30-day historical fallback thresholds.

## Broker evidence seam

The existing integrity gate is `auditBrokerHistoryIntegrity()`.

Current rules already enforced by tests/source:

- explicit `brokerDisplay` evidence is valid;
- explicit matched `trip.broker` evidence is valid;
- ambiguous `trip.customer` must not be used to infer broker identity;
- unresolved rows remain `legacyUnkeyed`.

v24.1 broker confidence should consume those resolved/quarantined states rather than introduce a new broker-key heuristic. `legacyUnkeyed` cannot produce HIGH broker confidence.

## Market/static freshness seam

`midwest-stack-authority.js` already owns `RATE_OVERRIDE_FRESHNESS` and protects against stale static bands relaxing pricing. v24.1 can represent that freshness as evidence metadata, but must not move new bid authority into the Midwest adapter.

The existing v24 rule remains:

- USA layer: `authorityRole: 'EVIDENCE_ONLY'`.
- Midwest overlay: `authorityRole: 'ADAPTER_ONLY'`.
- canonical decision in `app.js`: sole authority.

## Minimal v24.1 helper shape

Exact names are implementation-owned, but the smallest clean source change should resemble this responsibility split:

1. Normalize source facts into evidence items.
2. Assign deterministic item confidence from source health + freshness + sample size + provenance.
3. Aggregate only material domains into categorical domain/overall confidence.
4. Attach an immutable confidence/evidence summary to the object built by `buildUnifiedDecisionContract(input)`.
5. Project a compact immutable subset through `unifiedDecisionForAI(decision)`.
6. Render the client-owned result; the Worker may explain it but not replace it.

No helper in this chain may call or modify `deriveUnifiedAuthority`, `deriveUnifiedGrade`, `deriveUnifiedEconomics`, or `deriveUnifiedBid` to make a low-confidence result more permissive.

## Persistence boundary

Prefer no DB migration in v24.1. The current database is `FreightLogic_v18`, DB version 13. If a compact evaluation/history record already accepts additive optional properties, persist only the compact evidence snapshot described by the v24.1 contract.

If persistence would require an object-store/index/key-path migration or DB version change, stop that portion and defer it to the v24.2 lifecycle migration. Do not consume the lifecycle migration budget merely to ship confidence labels.

Any persisted optional fields must survive existing export/backup/restore paths before v24.1 can be considered complete.

## Regression anchors that must remain green

Existing tests that define the authority boundary and should not be weakened:

- `tests/unit/v24-unified-decision.spec.mjs`
  - canonical decision contract + compatibility adapter;
  - centralized grade authority;
  - USA evidence-only / Midwest adapter-only roles;
  - Worker cannot own verdict/grade/bid/True RPM;
  - AI payload carries compact canonical decision.
- `tests/unit/pre-v24-integrity.spec.mjs`
  - protective RPM floors;
  - static freshness guard;
  - EIA/NWS/FMCSA/CBP health instrumentation;
  - conservative broker-history identity rules;
  - reproducible CI toolchain.
- existing v24 authority/economics/bid integration suites must remain unchanged and green.

The v24.1 implementation should add new assertions rather than rewrite these contracts to accommodate the feature.

## Proposed new test responsibilities

Claude-owned test naming is implementation choice, but coverage should independently prove:

- deterministic evidence normalization;
- source-specific cache/freshness boundaries where already defined;
- generic 14/30-day fallback classification for historical/static evidence;
- sample-size boundaries 2/3 and 9/10;
- `legacyUnkeyed` broker evidence stays LOW;
- failed source health is explicitly LOW/unavailable, never neutralized;
- overall confidence cannot average away a material LOW domain;
- confidence cannot relax canonical bid/floor/hard-gate results;
- Worker response projects the client-owned confidence label instead of replacing it;
- absent v24.1 fields remain backward-compatible.

## Integration sequence

1. Restore clean standard CI and remove temporary bank-repair CI residue.
2. Establish/log exact-main green baseline.
3. Complete the approved behavior-preserving UI seam extraction and update physical path ownership.
4. Review/integrate the v24.1 contract.
5. Add confidence/evidence helpers to the canonical client path.
6. Add minimal presentation through the extracted UI seam.
7. Add optional backward-compatible persistence only if no DB migration is needed.
8. Run the complete repository suite and release/parity gates.
