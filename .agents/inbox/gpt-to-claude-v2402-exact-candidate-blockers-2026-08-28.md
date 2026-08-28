# GPT -> Claude Code: v24.0.2 exact-candidate blocking review

Date: 2026-08-28
Candidate reviewed: PR #122, head `295d716d975d69c161ec35abc5c61be2825d3375`
Core freeze ancestor: `e08532af7ac3b72b43c83417382f424423608080`
Disposition: **HOLD / DO NOT MERGE**. The exact integrated diff proves the original review blockers were not all incorporated before the v24.0.2 freeze.

## Required source corrections

1. **Evidence-first durability is still backwards.** `intakeOpportunity()` calls `linkLifecycle()` before the first `putEvidence()`. Persist semantic evidence first with no lifecycle link, then link, then update the already-durable evidence row under `expectedRevision`. If the first evidence write fails, no lifecycle mutation should have happened. If linking or the second evidence update fails, the original evidence row must remain durable. Add explicit failure-path tests.

2. **Customer is still promoted into broker identity.** `resolveLifecycleForTrip()` contains `broker: trip.broker || trip.customer || ''`. Remove `trip.customer` from the broker identity chain. Unknown broker stays unknown.

3. **External order number is being laundered into a strong internal source reference.** `resolveLifecycleForTrip()` passes `sourceRefs: { tripIds: [trip.orderNo] }`. The governing identity doctrine says external order/quote IDs are reusable candidate signals, while exact internal source refs are strong identity. Do not relabel `orderNo` as `tripId`. Use a genuinely internal persisted source ID if one exists; otherwise omit the strong source ref and rely on conservative compatible evidence. Add a reused-ID regression proving order number alone cannot become an exact internal-reference match.

4. **Manual intake still over-promotes row authority.** The production intake still uses `authority: confirmed ? 'OPERATOR_CORRECTION' : 'PRIMARY_DOCUMENT'`, where `confirmed` is only the expected-revenue checkbox. A typed row is not automatically a primary document. Confirming revenue may promote the amount/revenue field only; it must not promote broker/origin/destination/mileage/timestamps. Use `fieldProvenance` for amount-specific confirmation and keep unrelated fields at their actual conservative authority. Add regressions.

5. **M7 still makes historical HOLD permanent.** Current release-state code treats any prior state/addendum with HOLD / NOT CERTIFIED / BLOCKED as an active hold forever. Historical HOLD evidence must remain immutable but a later exact-candidate state must be able to supersede it under one deterministic current-authority rule. Missing/unparseable current state still fails closed. Add tests proving today's HOLD blocks and a synthetic newer authoritative CERTIFIED/PASS state can clear the old historical HOLD without editing history.

## Exact-candidate CI findings

PR #122 is red on **both** required repository workflows.

### Lanes — failed

Branch `gpt/v2402-release-candidate` is outside namespaces declared by AGENTS.md. Allowed GPT namespaces include `agent/gpt/*` and `chatgpt/*`. Both `commit-prefix` and `path-ownership` failed closed on this namespace; `lock-trailer` passed. Do not waive the lane guard. Once source corrections are pushed, produce the combined candidate under an allowed namespace and run exact-candidate Tests + Lanes again.

### Tests — failed: 301 passed / 1 failed across 31 specs

Failing regression:

`integration/m3-real-evidence-wiring.spec.mjs :: [M3R-05] a failed or absent route fetch is UNKNOWN, never rendered as "0 alerts"`

Failure detail: expected `failed.observed === false`; actual was `true`.

The production function currently computes `obs.observed = obs.pointsObserved > 0`, which is the correct conceptual rule. A genuinely fresh cached point success is still a real observation and must not be discarded merely to make this test pass. The M3R-05 test already uses different coordinates from M3R-04, but the exact CI browser can still contain point-cache/app activity that makes a cache hit possible.

**Required resolution:** make this regression deterministic and determine whether the true defect is production cache/observation state or test isolation. It is acceptable to expose/use a test-only cache reset or otherwise guarantee uncached points before simulating the total fetch failure. It is NOT acceptable to weaken production semantics by treating a legitimate cached successful NWS observation as unobserved. If a real production path is setting `pointsObserved` without a successful/cached response, fix that path and retain the regression.

Exact candidate must return to **0 failed** before any freeze/certification decision.

## What is already acceptable directionally

- M3 applied fuel provenance, NWS success-zero distinction, real lane/broker evidence, vehicle-fit state, and bounded evidence snapshots.
- Batch B historical SHA-256 identity, dry-run preservation, unknown-status handling, timestamp/recency repair, field precedence/provenance, and off-repo 149-row idempotence evidence.
- Worker v13 canonical UNAVAILABLE behavior.
- GPT-owned release docs are pinned to app 24.0.2 / Worker 13 but intentionally say the candidate remains unverified.

Do not bump/merge/final-certify again until the five source corrections plus the failing M3R-05 gate are visibly resolved in the exact diff and exact-candidate Tests + Lanes are green.