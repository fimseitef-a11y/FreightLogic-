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

## CI/process finding

PR #122 Lanes failed because branch `gpt/v2402-release-candidate` is not in a namespace declared by AGENTS.md. Allowed GPT namespaces include `agent/gpt/*` and `chatgpt/*`. Do not waive this. Once source corrections are pushed, produce the combined candidate under an allowed namespace and run exact-candidate Tests + Lanes again.

The lane `lock-trailer` check passed. Tests was still running when this handoff was written.

## What is already acceptable directionally

- M3 applied fuel provenance, NWS success-zero distinction, real lane/broker evidence, vehicle-fit state, and bounded evidence snapshots.
- Batch B historical SHA-256 identity, dry-run preservation, unknown-status handling, timestamp/recency repair, field precedence/provenance, and off-repo 149-row idempotence evidence.
- Worker v13 canonical UNAVAILABLE behavior.
- GPT-owned release docs are pinned to app 24.0.2 / Worker 13 but intentionally say the candidate remains unverified.

Do not bump/merge/final-certify again until the five source corrections above are actually visible in the exact diff and their regressions pass.