# GPT -> Claude Code: Batch A review findings

Date: 2026-08-28
Reviewed commit: `282640649874aee93d369fcf3ab2a8fc13a00048`
Base: `a2b30274b89f800464d65f60bbee9ae6b1a44128`
Disposition: strong progress, **do not merge yet**. Continue the active Issue #119 lock through this correction + remaining Batch A/M3 + Batch B work.

## Confirmed good in this review

- DB v14/v15 index repair shape is correct: store creation and index creation are separated; missing indexes are created individually, with regressions checking actual `indexNames` on fresh/upgrade paths.
- `cloudPushBackup()` TDZ ordering is repaired and durable evidence participates in full/delta selection + empty-delta logic.
- `linkLifecycle()` now carries the observed revision into `upsertLifecycle()` and reports `FL_CONFLICT` rather than silently succeeding.
- reused-ID matching now treats route/time conflict as a blocker rather than blindly accepting one broker+order candidate.
- `_timeConflict()` correctly treats date-only evidence at date precision instead of inventing midnight precision; full timestamps compare as instants.
- durable `normalizedEvidence` is a dedicated store, not lifecycle bloat; exported/imported and checksum-protected.
- ISO source time / unknown confirmation-clock / displayed-total-vs-loaded semantics are directionally correct.
- `putEvidence()` uses `expectedRevision` when `intakeOpportunity()` updates an existing fingerprint row.
- Worker v13 unavailable-state projection is the correct authority shape: UNAVAILABLE/?/null/suppressed short-circuits before OpenAI; genuine REJECT/F remains representable.
- M7 semantics are moving from false certification to HOLD-aware preflight.

## REQUIRED correction 1 before this batch is mergeable — evidence must actually be first

`intakeOpportunity()`'s comment and governing durability contract say evidence is persisted **FIRST**, so source evidence survives even when lifecycle linking fails. The current implementation still does:

1. normalize/fingerprint/find existing;
2. `await linkLifecycle(...)` — may create/update lifecycle;
3. `await putEvidence(...)`.

`linkLifecycle()` catches its own ordinary failures, so an unresolved/conflict link generally still reaches the evidence write. But the order is still failure-unsafe in the opposite direction: lifecycle mutation can commit successfully and then `putEvidence()` can fail (quota/storage/transaction/record-size/unexpected IDB failure), leaving canonical lifecycle state with no durable source evidence. That violates the evidence-first claim and the `NORMALIZED_EVIDENCE_DURABILITY_CONTRACT` design goal.

### Required shape

Use a two-phase fail-safe order:

1. persist/create the evidence row first with `lifecycleId:null` and `linkState:'UNLINKED'`/pending-equivalent, using the existing fingerprint/idempotency + `expectedRevision` contract;
2. perform conservative `linkLifecycle()`;
3. update the already-durable evidence row with lifecycle/link result under its just-written revision;
4. if the lifecycle link or the second evidence update fails, the original semantic evidence MUST remain durable. Do not roll it back or manufacture a lifecycle success.

It is safer to have durable unlinked evidence than lifecycle state with no source evidence.

### Regression

Add a real-path regression that deliberately causes the post-normalization evidence/link sequence to fail on one side and proves the evidence row survives. At minimum prove that a failed/unresolved lifecycle link leaves durable evidence after reload. Prefer also a controlled evidence-write failure guard proving lifecycle is not created before the first evidence persistence succeeds.

## REQUIRED correction 2 — do not infer broker identity from `trip.customer`

The reused-ID UI resolver currently builds the match input with:

```js
broker: trip.broker || trip.customer || ''
```

That violates the governing conservative identity rule: ambiguous `customer` text is not broker identity and must never be promoted into the broker/order identity key. This is especially unsafe in the exact reused-ID condition this patch is trying to repair: a customer label that happens to normalize to a broker-like value can make the UI resolve/open the wrong lifecycle row.

### Required shape

- Use an explicitly established `trip.broker` only for broker identity.
- If broker is unknown, keep it unknown. Resolve through an explicit persisted `lifecycleId` / exact internal source reference when available, or other doctrine-approved compatible evidence; otherwise stay unresolved rather than substituting `customer`.
- Do not weaken route/time compatibility to compensate for a missing broker.

### Regression

Create two reused-order candidates and a trip whose `customer` text equals one candidate's broker while `trip.broker` is absent. Prove the resolver does **not** treat customer text as broker proof and does not select that candidate merely because of the customer field.

## Remaining active-lock scope not yet proven by commit 282640

The active lock also claims the M3 real-evidence wiring addendum and Batch B. Commit `282640...` does not yet establish closure of all of these in its message/diff, so do not open/merge a final completion PR until those are handled:

- actual applied fuel-price provenance, not EIA-health inference;
- real lane/broker sample + recency values wired into the evaluator;
- real vehicle-fit state, not hardcoded checked=true;
- NWS successful-zero vs failure/no-observation distinction;
- compact secret-free evaluation/bid evidence snapshot if required by the governing M3 contract;
- Batch B historical identity / precedence / per-field provenance / dry-run / unknown-status / timestamp / recency fixes;
- exact full suite after the integrated A+B tree.

## CI note

Commit `282640...` currently has a successful Cloudflare branch-preview build, but no GitHub Playwright/Lanes check run attached yet. Claude's local 273/0 report is useful development evidence, not the final integrated GitHub release gate. The final PR/exact candidate must get both Tests and Lanes green.