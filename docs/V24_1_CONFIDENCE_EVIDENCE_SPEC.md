# FreightLogic v24.1 — Confidence + Evidence Contract

Status: implementation specification only. This document does not change runtime behavior.

## Purpose

v24.1 adds explicit confidence and evidence metadata to FreightLogic decisions without creating a second decision engine or introducing fake probability estimates.

The v24.0 Unified Decision Engine remains the sole authority for hard gates, verdict, grade, economics, and canonical bid range. v24.1 explains **how trustworthy the supporting inputs are** and **why**.

## Non-negotiable authority rules

1. Confidence is descriptive, not authoritative. It may explain uncertainty but may not independently change verdict, grade, True RPM, or canonical bid range.
2. Hard safety/fit/compliance gates remain hard gates regardless of confidence.
3. Confidence may never weaken a protective price floor because evidence is stale, unavailable, or low quality.
4. Worker `/evaluate` may summarize or challenge confidence/evidence but may not calculate a competing authoritative confidence model or mutate the client-owned decision.
5. No numeric win probability, success probability, or calibrated percentage is introduced in v24.1.
6. `UNKNOWN`, `UNAVAILABLE`, and source failure are not equivalent to zero/no-risk/no-demand. Missing data must remain visibly missing.

## Evidence item contract

Every source-backed fact used or displayed by the decision experience should be representable as an additive evidence item with this logical shape:

```text
EvidenceItem
  key                 stable semantic key for the fact
  category            MARKET | BROKER | FUEL | WEATHER | SAFETY | OPERATIONS | VEHICLE | OTHER
  source              canonical source/provider label
  sourceStatus         OK | UNCONFIGURED | AUTH_ERROR | HTTP_ERROR | TIMEOUT | NETWORK_ERROR | PARSE_ERROR | OFFLINE | UNKNOWN
  observedAt           timestamp of the underlying observation when known
  evaluatedAt          timestamp FreightLogic evaluated the item
  ageSeconds           derived age when observedAt is known
  sampleSize           integer when the evidence is an aggregate; null otherwise
  windowDays           aggregation lookback when applicable; null otherwise
  freshness            CURRENT | AGING | STALE | UNKNOWN
  confidence           HIGH | MEDIUM | LOW
  valueSummary         compact human-readable statement of what the evidence says
  provenance           source-specific trace metadata safe for local storage/display
  reasons[]            deterministic reasons for the assigned confidence
```

Implementation may use different property names if required by the existing code style, but the semantic contract above must remain intact.

## Confidence model

Confidence is categorical and deterministic. It is assigned per evidence item first, then summarized by domain.

### HIGH

Use HIGH only when the evidence is both healthy and materially sufficient for the decision being explained. Typical qualifying conditions:

- live/near-live source reports `OK` and the observation is within the source's intended freshness window;
- historical/personal aggregate has a meaningful sample size and is recent enough to represent the current market;
- broker-specific evidence is keyed to an explicit broker identity rather than an inferred/legacy identity;
- no material source-health or provenance ambiguity is present.

### MEDIUM

Use MEDIUM when the evidence is useful but carries a bounded limitation, such as:

- healthy source but aging observation;
- moderate sample size;
- mixed but still interpretable historical evidence;
- fallback evidence that remains within an approved freshness window;
- a source is healthy but the fact is indirect rather than directly observed.

### LOW

Use LOW whenever the evidence should not be treated as strong operational support, including:

- stale data;
- very small sample sizes;
- unresolved/legacy broker identity;
- static fallback data when fresher evidence is unavailable;
- source status other than `OK` when the item cannot be independently corroborated;
- ambiguous provenance;
- conflicting evidence that cannot be reconciled deterministically.

A source failure must not be converted into a neutral or favorable value merely to keep the UI populated.

## Minimum deterministic thresholds

The implementation should centralize thresholds rather than scatter magic numbers. Unless stronger source-specific rules already exist, use these as the default starting contract:

- static/historical market freshness: CURRENT <= 14 days, AGING 15–30 days, STALE > 30 days;
- personal/broker aggregate sample size: HIGH >= 10, MEDIUM 3–9, LOW <= 2;
- any aggregate with unresolved broker identity: LOW regardless of sample size;
- any STALE item: LOW unless a source-specific rule explicitly requires a different classification for display only;
- any item whose source health is not `OK`: LOW unless its value is independently backed by another healthy source, in which case the corroborating item is scored separately rather than upgrading the failed source.

These thresholds govern confidence labels only. They do not redefine the v24.0 economic floors or Dead Zone rules.

## Domain summaries

The canonical decision may expose additive confidence summaries by domain:

```text
confidence
  overall              HIGH | MEDIUM | LOW
  market               HIGH | MEDIUM | LOW | UNKNOWN
  broker               HIGH | MEDIUM | LOW | UNKNOWN
  operatingCosts       HIGH | MEDIUM | LOW | UNKNOWN
  weatherSafety        HIGH | MEDIUM | LOW | UNKNOWN
  vehicleFit           HIGH | MEDIUM | LOW | UNKNOWN
  reasons[]            compact deterministic explanation
```

`UNKNOWN` is permitted at the domain-summary level when no applicable evidence exists. Evidence items themselves still use HIGH/MEDIUM/LOW and carry explicit source status/freshness.

## Overall-confidence aggregation

Overall confidence must not be a simple average and must not disguise a critical low-confidence dependency.

Recommended deterministic rule:

1. Identify the evidence domains actually material to the displayed decision.
2. If any material domain is LOW because the required source is stale, failed, ambiguous, or based on insufficient sample size, overall confidence cannot exceed LOW.
3. Otherwise, if any material domain is MEDIUM, overall confidence is MEDIUM.
4. Overall confidence is HIGH only when all material domains are HIGH.
5. Domains that are irrelevant to the specific decision are excluded rather than counted as HIGH.

The implementation must document what it considers a material domain for each decision path.

## Evidence provenance requirements

Evidence shown to the driver must preserve enough provenance to answer:

- What source produced this fact?
- Is the source healthy right now?
- How old is the observation?
- If historical, how many observations support it and over what period?
- Is the broker identity explicit and trustworthy?
- Is this live, personal-history, static fallback, or derived evidence?

Provenance must never include credentials, API tokens, bank credentials, or other secrets.

## UI behavior

v24.1 should favor compact driver-facing signals with drill-down detail:

- show the overall label as `Confidence: HIGH`, `MEDIUM`, or `LOW`;
- provide a concise reason such as `HIGH — 18 recent lane observations + live fuel data`;
- expose evidence details on demand rather than flooding the primary bid card;
- visibly distinguish stale/fallback evidence from live evidence;
- visibly distinguish `no data` from `bad data` and from `source unavailable`;
- never display a percentage that implies calibrated odds.

The visual overhaul remains v24.5; v24.1 should add only the minimum UI necessary to make confidence/evidence inspectable.

## Decision-history/audit behavior

When a decision/evaluation is persisted, FreightLogic should preserve a compact evidence snapshot sufficient to explain the decision later:

- confidence labels at evaluation time;
- source/freshness/sample-size summary;
- source-health status;
- identifiers needed to correlate the evidence category, not secrets or full external payloads.

This snapshot must be additive and backward-compatible. If the current storage shape cannot accept additive optional fields without a schema migration, implementation must stop and treat the migration as separate approved scope rather than silently coupling v24.1 to the v24.2 lifecycle migration.

## Source-specific expectations

### Market / personal lane history

- use recency + sample size + provenance;
- Dead Zone Exit outcomes remain a separate calibration cohort and do not upgrade normal-market confidence;
- expired/cancelled opportunities must not be treated as ordinary losses when lifecycle data later becomes available.

### Broker intelligence

- explicit broker-labelled evidence only;
- unresolved `legacyUnkeyed` history remains LOW and excluded from broker-specific confidence claims;
- never infer broker identity from ambiguous customer fields.

### Fuel

- distinguish current configured/observed fuel price from stale corridor/static fallback;
- source failure must be visible rather than converted to zero or an apparently current price.

### Weather / safety

- source health and observation age must be surfaced;
- unavailable weather evidence must never imply safe conditions.

### Vehicle fit

- deterministic fit measurements remain hard facts when known;
- missing dimensions or uncertain cargo measurements should lower fit-evidence confidence but may not override an existing hard rejection.

## Worker boundary

The Worker may:

- explain why confidence is HIGH/MEDIUM/LOW;
- highlight a stale or failed source;
- challenge whether the driver should trust a weak evidence base;
- summarize conflicts between evidence items.

The Worker may not:

- publish a competing confidence score/percentage;
- replace client-owned labels with its own authoritative labels;
- change the canonical verdict/grade/True RPM/bid range because it disagrees with confidence;
- fabricate missing evidence.

## Acceptance contract for implementation

A v24.1 implementation is not complete unless regression coverage demonstrates at least the following:

1. Same inputs produce the same confidence/evidence output deterministically.
2. A stale market item is LOW and cannot relax an existing protective bid floor.
3. A healthy recent item with sufficient sample size can be HIGH.
4. A sample size of 1–2 cannot be HIGH.
5. Unresolved broker identity cannot produce HIGH broker confidence.
6. Source failure is visible as failure/LOW, not converted to a zero or neutral fact.
7. Worker response cannot override canonical confidence labels or decision authority.
8. Missing evidence is represented explicitly and is not conflated with favorable evidence.
9. Persisted historical evaluations remain readable when v24.1 fields are absent.
10. Backup/export/restore paths preserve any new persisted optional evidence snapshot fields if those fields are added.
11. Existing v24.0 verdict/grade/economics/bid assertions remain unchanged and green.
12. Full repository Playwright suite is green on the integrated PR head.

## Out of scope for v24.1

- numeric/calibrated win probabilities;
- new external market feeds;
- lifecycle database migration;
- self-calibrating market bands;
- Next-Move command logic;
- Driver Mode redesign;
- screenshot-first workflow redesign;
- bank-account linking or statement-import expansion;
- changing v24.0 decision authority.

Those remain later roadmap items or separate approved work.

## Implementation sequencing after the extraction gate

1. Land/verify the behavior-preserving UI seam extraction and update physical lane ownership.
2. Implement the smallest additive evidence/confidence data contract in the canonical decision path.
3. Add deterministic confidence helpers and source-health mapping without changing v24.0 economics/verdict math.
4. Add compact UI rendering through the newly extracted presentation lane where possible.
5. Add persistence only if it can remain backward-compatible without a schema migration.
6. Run the full suite and authority-boundary tests.
7. Version/release only after source-side and deployed parity gates are green.
