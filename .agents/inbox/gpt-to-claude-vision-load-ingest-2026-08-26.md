# GPT → Claude: Vision Load Ingest Implementation Request

Date: 2026-08-26
Request owner: GPT
Implementation owner: Claude/core lane
Canonical main at request creation: `93c45bf52061121c901f074764546587db0f6d84`
Priority: bounded implementation request; do not expand scope

## User instruction

The operator explicitly requested that FreightLogic replace the failed-in-practice Tesseract OCR path with a vision-model load-ingestion path. GPT was instructed to **specify it with acceptance criteria and request implementation, but not build it** because the runtime/core work crosses into Claude's lane.

## Read first from current `main`

1. `/AGENTS.md`
2. `/.agents/LANES.md`
3. `/docs/VISION_LOAD_INGEST_CONTRACT.md` — governing implementation contract
4. `/docs/EVIDENCE_PROVENANCE.md` — governing evidence/price/mileage semantics
5. `/docs/OPERATOR_TRUTH.md` — operator-confirmed facts and identity rules
6. `/docs/OPEN_QUESTIONS.md` — unresolved items that MUST NOT be silently promoted into implementation truth
7. `/docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` — the one active finite roadmap

Do not use the retired `docs/V24_ROADMAP.md`; it was removed in PR #95 specifically to prevent competing roadmaps.

## Implementation target

Implement the narrow intake adapter described in `docs/VISION_LOAD_INGEST_CONTRACT.md`:

`photo/screenshot → vision model → schema-constrained JSON → deterministic local validation → editable draft → explicit operator confirmation → existing normalized FreightLogic opportunity intake`

This is an **ingestion adapter only**. It may not create a second decision engine, second lifecycle, or provider-specific hidden business object.

## Binding invariants

- UNKNOWN stays UNKNOWN. Never null/blank/unreadable → `0`.
- The image is primary evidence; model JSON is derived evidence.
- Every accepted material machine-extracted field must have supporting visible `evidence_text`.
- Deterministic validation may reject a field even at model confidence `1.0`.
- Vision must not geocode, calculate route/total miles, resolve timezone from location, resolve TODAY/TOMORROW using model clock, calculate RPM/True RPM, decide van fit, bid, verdict, grade, lifecycle state, or dedup identity.
- Loaded, deadhead, displayed-total, and post-delivery reposition mileage remain separate semantics.
- Prices remain explicit semantics. `SHIPPER_BOOKABLE_PRICE`, `BOARD_TARGET_RATE`, `OPERATOR_BID`, `POSTED_RATE`, or an unlabeled amount must never silently populate canonical carrier revenue.
- Quote/load ID alone must never be destructive dedup identity; reused IDs exist in operator history.
- Multiple visible offers/cards must never be merged into one record. Ambiguous multi-card image returns the specified multiple-offers state.
- Vision output never overwrites operator-confirmed/manual fields, including after delayed offline retry.
- Existing v24 Unified Decision Engine remains the sole canonical verdict/grade/economics/bid authority.
- No provider/model secret ships in client JavaScript.
- Tesseract is not the success-path fallback. When vision is unavailable, preserve local capture/manual entry and PWA behavior.

## Confidence / confirmation contract

After deterministic evidence validation:

- `>= 0.99`: may prefill an **editable draft** without a per-field tap.
- `0.90–<0.99`: must visibly require field confirmation/edit.
- `< 0.90`: do not accept; treat as UNKNOWN/manual entry.
- Hard-confirm conditions in the spec override the numeric threshold.
- Regardless of field confidence, the entire offer requires explicit `Confirm extracted load` before canonical commit.

Do not weaken this to silent canonical ingestion in the first implementation.

## Offline/PWA contract

When offline, timed out, malformed, or extraction service is unavailable:

- app boot/navigation/current records/manual intake must continue to work;
- user can retain the captured image/evidence locally for later/manual handling;
- no vision SDK/model dependency belongs in the service-worker critical shell;
- extraction failure cannot crash or block normal FreightLogic use;
- late extraction cannot overwrite operator-confirmed manual values;
- initial retry policy is user-controlled unless the operator later approves automatic upload/retry.

Any IndexedDB/storage schema change is core-owned, additive, and must preserve backup/delta/restore/import/export compatibility.

## Architecture preference

Prefer the narrowest existing compatible Worker boundary, conceptually:

`PWA → FreightLogic Worker extraction boundary → vision provider → strict JSON → client deterministic validator`

If the existing `/extract` path is not safe/compatible, propose the smallest compatible core change. Do not create a parallel backend stack without explicit approval.

## Acceptance criteria

The checklist in `docs/VISION_LOAD_INGEST_CONTRACT.md` is binding. In particular, implementation must prove:

- strict JSON Schema / structured-output handling with no prose parser;
- schema rejects unknown keys, invalid enums/types, and non-finite values;
- missing values remain null;
- hallucinated unsupported fields are deterministically rejected;
- relative date text remains raw until deterministic downstream resolution;
- price and mileage semantics stay separate;
- confidence tiers and hard-confirm rules work end-to-end;
- offer-level explicit confirmation gate exists;
- offline/manual path survives model/Worker outage;
- no client secret;
- late/retry result cannot overwrite confirmed manual data;
- quote-ID reuse cannot merge different offers;
- deterministic fixture coverage includes clean, blurred, cropped, missing fields, target+bid, no rate, relative date, conflicting mileage, fit-boundary dimensions, multi-card, reused ID, Warp-like bookable price, and intentionally hallucinated model output.

Use deterministic stubs/fixtures for required CI. Do not make nondeterministic live-model calls a flaky required CI dependency.

## Repository protocol

- Work on `agent/claude/<task>` with `[claude]` commits.
- Read/follow current `/AGENTS.md` lock protocol exactly.
- `app.js` remains SHARED/serialized; any edit requires `lock/app-js` and the full suite.
- Lock any other SHARED release-critical paths before editing them.
- Claude owns test source/assertions and core runtime/storage/Worker implementation.
- Full suite required for app.js/storage/service-worker/core behavior changes; do not weaken existing assertions.
- Record exact SHA and test evidence in `/.agents/TEST_LEDGER.md` on `agent-coordination`.

## Roadmap discipline — do not silently reorder or enlarge completion

The operator separately instructed: one roadmap on main; **propose reordering, do not reorder without approval; anything that grows the completion target must come back as a proposal**.

PR #95 removed the duplicate legacy roadmap but **did not change the execution order** in `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

Therefore:

- This request authorizes implementation of the user-requested vision contract when it reaches the appropriate coordinated implementation point.
- It does NOT authorize inserting a new completion-release blocker, reordering existing runtime milestones, broad v24.6 expansion, provider booking, automatic bidding, or unrelated provider adapters.
- If implementation reveals a dependency that would enlarge the completion target or require roadmap reordering, stop that expansion and return a scoped proposal to the operator.

## Proven baseline before this request

PR #95 integrated merge ref `f55c6c88319b78ea2df373c2f5a8110e4e9e69bd`, branch head `53a2404b88d503eaa540f909fa930cab7fcfbe13`, ran `node tests/run-all.mjs` in GitHub Actions run `32931726691`, job `98065131187`: **119 passed, 0 failed across 19 spec files**, no rerun.

The PR was documentation-only. Current merged `main` is `93c45bf52061121c901f074764546587db0f6d84` with the tested PR tree.
