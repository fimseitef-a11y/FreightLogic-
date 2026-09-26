# GPT → Claude: OMEGA INFINITY money-integrity / release-control repair packet

Date: 2026-09-15 UTC
Baseline audited: `main @ 5df85155221afb402673bfbb327eda715424a370`
Audit mode: OMEGA INFINITY / BLACK CELL, zero-trust against prior reports.

## Why this handoff exists

GPT independently resumed the operator-requested OMEGA INFINITY audit after the external Grok report. The current exact HEAD is materially healthy — GitHub Actions run `34916163712`, job `104214121719`, checked out exact SHA `5df8515` and finished `465 passed, 0 failed across 50 spec files`; live-parity run `34916163598` also passed. The remaining items below are blind spots or release-governance gaps that the current green suite does not close.

Do NOT weaken, quarantine, skip, or rewrite existing assertions to make this pass. `app.js` remains SHARED and requires the lock + full suite under AGENTS.md. `tests/**` and `midwest-stack-authority.js` are Claude-owned under the current lane map.

## P1 — unknown deadhead still becomes a fake zero on secondary operator surfaces

The canonical evaluator is already correct: `knownNum()` + `tripHasKnownDeadhead()` preserve UNKNOWN vs explicit zero. The defect is in secondary/history/UI paths.

### Confirmed exact-head source

1. `exportTripsCSV()` currently does:

```js
const all = (Number(t.loadedMiles||0) + Number(t.emptyMiles||0));
const rpm = all > 0 ? (Number(t.pay||0)/all).toFixed(2) : '0';
```

A trip with `emptyMiles:null` is exported as zero deadhead, a fabricated AllMiles value and a fabricated True RPM.

2. `computeLoadScore()` currently does:

```js
const empty = Number(trip.emptyMiles || 0);
const allMi = loaded + empty;
const trueRpm = allMi > 0 ? pay / allMi : 0;
```

Its baseline construction also uses `Number(t.emptyMiles || 0)` on recent history.

3. `renderLiveScore()` independently does `Number(tripData.emptyMiles || 0)` before invoking `computeLoadScore()`.

4. `tripRow()` computes displayed RPM from `Number(t.emptyMiles||0)` without a direct known-deadhead guard.

5. Several weekly/KPI paths use `Number(t.emptyMiles||0)` but do skip `t.needsReview`; that protects normally sanitized records, so the Grok report overstates this part. Still add direct `tripHasKnownDeadhead(t)` guards where True-RPM/deadhead-derived math is performed so legacy/imported records lacking a correct `needsReview` bit cannot manufacture economics.

6. Additional secondary intelligence paths found during the resumed sweep include deadhead trends, 30-day efficiency/average miles/load score, `rpm7/rpm14`, and the live Intel weekly RPM block. Some have `needsReview` filtering and some do not. Audit every deadhead-derived aggregate rather than patching only the four call sites named by Grok.

### Required invariant

`emptyMiles === null/undefined/blank` means UNKNOWN everywhere. It must never enter a denominator as zero. An explicitly supplied `emptyMiles: 0` remains a real valid zero.

### Required regression coverage

- CSV: unknown deadhead => blank/UNKNOWN deadhead, AllMiles and True RPM; explicit 0 => numeric values.
- load score / live score: unknown deadhead must be unavailable/suppressed, never a confident numeric score.
- trip row / compact row: unknown deadhead must show unavailable RPM/grade, not loaded RPM disguised as True RPM.
- legacy-defense vector: a record with `emptyMiles:null` and stale/missing `needsReview:false` must still be excluded from True-RPM/deadhead-derived KPI/intelligence calculations.
- explicit-zero control in every relevant test.

## P1/P2 — display rounding can change a canonical floor decision

`deriveUnifiedEconomics()` currently computes:

```js
const trueRPM = totalMi > 0 ? roundCents(effectiveRevenue / totalMi) : 0;
```

and that rounded value is passed onward into grade/authority decisions.

Counterexample: `$559.99 / 400 mi = 1.399975`. The real ratio is below the `$1.40` floor, but `roundCents()` produces `1.40`, which can cross the decision boundary.

### Required invariant

Decision authority compares the unrounded ratio. Rounding is presentation only. Preserve compatibility in displayed values if desired, but maintain a raw/precise field for all floor/grade/verdict/bid gating.

### Required regression

- `$559.99 / 400` must remain below the `$1.40` authority floor even if display text renders `$1.40`.
- exact `$560.00 / 400 = 1.40` remains on the floor.
- test the same principle around every other material RPM boundary, not only 1.40.

## P2 hardening — pure economics should fail closed on invalid material inputs

These are lower priority than the two defects above because active callers already partially protect them, but the pure function is an authority boundary and should be internally safe.

### Missing MPG

`deriveUnifiedEconomics()` currently reads `mpg = Number(f.mpg || 0)` and uses fuel `$0` when MPG is absent/zero. The active `mwEvaluateLoad` caller currently supplies the approved ~17.5 MPG fallback and exact-head tests M1-17/M1-18 cover fallback/override, so this is NOT currently proven as a primary live-path blocker. Still, the pure function must not silently turn missing MPG into zero fuel and optimistic profit. Return unavailable cost/profit facts or otherwise fail closed if a material fuel calculation cannot be made.

### Negative mileage

`knownNum(-10)` is finite, then `deriveUnifiedEconomics()` clamps it via `Math.max(0, ...)`. Active `mwEvaluateLoad` also clamps before calling, so this is primarily hardening. Reject/mark invalid negative loaded/deadhead values at the pure economics boundary; do not convert invalid input into a legitimate zero.

Add direct pure-function tests for both.

## P2 — advisory market geography substring collision

`midwest-stack-authority.js` includes `gary` in Tier 1 and its market resolver uses substring-style matching. That makes unrelated names such as `Calgary, AB` capable of matching Gary; `Daytona` can similarly collide with Dayton.

The module is advisory-only and cannot own canonical verdict/grade/bid, so this is not a canonical-money P1, but it can mislead the driver about market quality.

Required repair: boundary-aware city/state matching, while preserving supported abbreviations.

Required tests:
- positives: `Gary, IN`, `Gary IN`, `Dayton, OH`, supported abbreviations.
- negatives: `Calgary, AB`, `Hungary` if parser accepts country text, `Daytona Beach, FL`, and other suffix/prefix collisions.

## P2 release governance — different shipped bytes can share one release identity

The authoritative completion/certification record pins runtime candidate `fb4fe119...`, but current main is `5df8515...` after two shipped UI deltas (`styles.css` at `8ce5fc4...`, `modern-shell.js` at `5df8515...`) while the app/cache generation remained `24.0.10`.

This is NOT a claim that production bytes are currently mismatched: exact-head live parity passed. The defect is identity ambiguity — a shipped runtime asset can change while `APP_VERSION/SW_VERSION/cache generation` stay unchanged, and existing generation tests only verify internal agreement, not runtime-byte continuity.

Add a release-hygiene invariant that fails when declared shipped/runtime bytes change under an unchanged release generation, or introduce a deterministic runtime fingerprint that the certification state and parity gates bind to. Do not merely pin another SHA into a test that goes stale.

## Certification/document drift

Issue #119 and the completion certification documents still contain historical candidate/version references. Do not rewrite history. After fixes merge and exact-head tests/live gates are observed, add a superseding current-state record and update the issue to point to it.

## Mandatory verification after repair

1. Obtain/record SHARED `app.js` lock before edit and keep FL-Lock trailer evidence.
2. Full `node tests/run-all.mjs` — exact new candidate, zero failures.
3. Lane guard.
4. Live Cloudflare parity after deployment settles.
5. Production service-worker gate.
6. Preserve explicit UNKNOWN-vs-zero tests already green.
7. Record exact SHA/run IDs; do not rely on commit-message claims.

## Human-only blockers that remain after code repair

These cannot be truthfully closed by repository automation:

- Physical iPhone A1–A10 against the installed production PWA, especially genuine Airplane Mode reopen/navigation and update identity.
- Authentic M6 five-file operator-history bundle import → reload → export → re-import reconciliation. Do not reconstruct the raw bundle from summaries or screenshots.

Until those are observed, the strongest honest release state remains code-hardened / conditionally ready, not fully certified.
