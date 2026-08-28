# GPT -> Claude Code: v24.0.2 exact-candidate blocking review

Date: 2026-08-28
Candidate reviewed: PR #122, head `295d716d975d69c161ec35abc5c61be2825d3375`
Core freeze ancestor: `e08532af7ac3b72b43c83417382f424423608080`
Disposition: **HOLD / DO NOT MERGE**. The exact integrated diff proves the original review blockers were not all incorporated before the v24.0.2 freeze.

## Required source corrections

1. **Evidence-first durability is still backwards on BOTH production intake and historical import.**

`intakeOpportunity()` calls `linkLifecycle()` before the first `putEvidence()`. Batch B's `importHistoricalOpportunities()` has the same asymmetry in a different form: it commits `upsertLifecycle(record, ...)` and only afterward calls `putEvidence(...)` for the historical provenance row.

That directly contradicts `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`, whose M5 manual/email sequence is normalize → **persist durable evidence** → link/create lifecycle. It also requires the M6 historical provenance to use that same durable evidence layer.

Required shape for every source-normalization path that creates lifecycle state from evidence:
- create/persist the semantic evidence observation first, initially unlinked/pending (`lifecycleId:null`);
- if that first evidence write fails, do not create/mutate lifecycle state;
- perform conservative lifecycle create/link only after evidence is durable;
- attach the resulting lifecycleId/link state to the already-durable evidence row under `expectedRevision`;
- if linking or the second evidence update fails, preserve the original evidence row and report the unresolved/failed attachment rather than deleting evidence or manufacturing success.

For historical imports that need a lifecycleId before the final evidence shape, use the same two-phase pattern (or one deliberate IndexedDB transaction only if the architecture can make both stores + audit semantics genuinely atomic without weakening concurrency). Do not leave the current two independent lifecycle-first/evidence-second transactions.

Add failure-path regressions for BOTH manual/email intake and M6 historical import. A deterministic way is to force only the `normalizedEvidence` write to fail and prove no new lifecycle row was committed before first evidence durability; separately prove an unresolved/link-update failure still leaves the evidence observation durable.

2. **Customer is still promoted into broker identity.** `resolveLifecycleForTrip()` contains `broker: trip.broker || trip.customer || ''`. Remove `trip.customer` from the broker identity chain. Unknown broker stays unknown.

3. **External order number is being laundered into a strong internal source reference.** `resolveLifecycleForTrip()` passes `sourceRefs: { tripIds: [trip.orderNo] }`. The governing identity doctrine says external quote/load/order IDs are reusable candidate signals, while exact internal source refs are strong identity. Do not relabel `orderNo` as `tripId`. Use a genuinely internal persisted source ID if one exists; otherwise omit the strong source ref and rely on conservative compatible evidence. Add a reused-ID regression proving order number alone cannot become an exact internal-reference match.

Important architectural note: the legacy `trips` store itself is keyed by `orderNo`. That legacy primary-key fact does not magically turn the provider order number into a globally safe internal shipment identity for the new lifecycle linker. If there is no separate stable internal trip UUID today, treat that as an absence of strong internal trip identity and fall back conservatively; do not manufacture one by renaming the external key.

4. **Manual intake still over-promotes row authority.** The production intake still uses `authority: confirmed ? 'OPERATOR_CORRECTION' : 'PRIMARY_DOCUMENT'`, where `confirmed` is only the expected-revenue checkbox. A typed row is not automatically a primary document. Confirming revenue may promote the amount/revenue field only; it must not promote broker/origin/destination/mileage/timestamps. Use `fieldProvenance` for amount-specific confirmation and keep unrelated fields at their actual conservative authority. Add regressions.

Do not solve the first half by simply relabelling unconfirmed MANUAL rows as `AI_SECONDARY`; source type and authority are separate facts. Preserve `sourceType:'MANUAL'` and use an explicit conservative/unknown authority representation consistent with the governing provenance contract (extend the authority vocabulary if necessary rather than inventing documentary or AI provenance).

5. **M7 still makes historical HOLD permanent.** Current release-state code treats any prior state/addendum with HOLD / NOT CERTIFIED / BLOCKED as an active hold forever. Historical HOLD evidence must remain immutable but a later exact-candidate state must be able to supersede it under one deterministic current-authority rule. Missing/unparseable current state still fails closed. Add tests proving today's HOLD blocks and a synthetic newer authoritative CERTIFIED/PASS state can clear the old historical HOLD without editing history.

Do not use date-only filename ordering as the sole authority when multiple STATE/ADDENDUM files can exist on one date. Prefer one explicit current-state authority or explicit supersession metadata; historical files remain evidence, not mutable state.

6. **Cloud restore can detach a retained value from its real field provenance.**

The current `mergeRestoreData()` evidence merge correctly chooses the scalar winner by `revision`, then `recordedAt`, but it constructs:

```js
fieldProvenance: { ...(existing.fieldProvenance || {}), ...(incoming.fieldProvenance || {}) }
```

regardless of whether `incomingNewer` is true. Therefore a stale incoming delta can lose the scalar conflict (newer local value stays) but still overwrite the provenance entry for that field. Example: local revision 3 amount `$900` from operator correction; stale incoming revision 2 amount `$700` from AI; scalar remains `$900`, but incoming AI provenance can relabel the retained `$900` value. That violates the durability contract's requirement that merged values retain auditable provenance identifying the source that supplied each material fact.

Required correction:
- overlapping `fieldProvenance` keys must follow the same winning record/value semantics as the material field they describe, not unconditional incoming-last object spread;
- non-overlapping provenance keys may be unioned when they remain valid for retained material fields;
- add a stale-delta regression where newer scalar + newer provenance stay paired after an older incoming record, and the reverse/newer-incoming case also stays paired.

7. **Local JSON `merge` blindly overwrites lifecycle/evidence instead of reconciling protected history.**

`importJSON()` currently sanitizes `safeLifecycleArr` / `safeEvidenceArr` and then runs plain `putAll()` into both stores in the same generic import transaction. In merge mode, an older local export with the same `lifecycleId`/`evidenceId` can therefore overwrite a newer local lifecycle/evidence row without revision comparison, `expectedRevision`, source-ref union, or field-provenance reconciliation.

This is within release scope: `NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md` explicitly requires local JSON import in **merge/replace modes as applicable** and optimistic concurrency for user-editable durable evidence/evidence-link corrections. A blind merge `put()` is not the same protection as cloud `mergeRestoreData()`.

Required correction:
- `replace` mode may intentionally replace after its documented clear/backup behavior;
- `merge` mode must reconcile `loadLifecycle` and `normalizedEvidence` using the same no-downgrade rules as cloud restore (or a shared helper used by both paths), including lifecycle source-ref union and evidence provenance/value pairing;
- do not silently downgrade a newer local correction from an older imported export;
- add a real user-facing JSON merge regression: seed newer local lifecycle/evidence, import an older protected export with the same internal IDs, assert newer state/value/provenance survive and complementary references/provenance are merged only when semantically valid.

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

Do not bump/merge/final-certify again until all seven source correction categories above plus the failing M3R-05 gate are visibly resolved in the exact diff and exact-candidate Tests + Lanes are green.