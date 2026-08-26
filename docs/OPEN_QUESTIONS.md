# FreightLogic Open Questions

Version: 1.3.0
Snapshot date: 2026-08-26
Owner lane: GPT (`docs/`)
Status: operator confirmation queue

## Rule

If GPT cannot prove that a carried fact came from an explicit operator statement/correction or primary evidence, it stays here. Nothing in this file may be promoted into `OPERATOR_TRUTH.md` without confirmation or stronger primary evidence.

Use one of these dispositions when resolved:

- `CONFIRMED` — promote to the appropriate canonical document with date/source.
- `REJECTED` — keep the historical question here with the rejection date; do not use it elsewhere.
- `SUPERSEDED` — replace with newer operator-confirmed fact and link the replacement.
- `PRIMARY_EVIDENCE_FOUND` — promote using the primary evidence, not the prior AI claim.

## Equipment / capacity questions

1. **Payload ceiling:** a secondary Claude handoff carried a door-jamb payload figure of **3,598 lb**. GPT does not have operator-confirmed primary evidence for this figure in the current extraction. Confirm from the actual door-jamb label/photo before using it.
2. **Historical heavy-load claim:** GPT context carried that the van has hauled a single pallet around **2,700 lb**. Confirm the exact weight/load and whether this is useful as operational history; it must not be treated as proof that every load at that weight fits payload/axle limits.
3. **Wheel-well/interior dimensions:** generic 2016 Transit reference dimensions such as roughly 54.8 in between wheel wells were carried in context. Confirm which dimensions were actually measured on the operator's van versus copied from manufacturer/reference material.
4. **Maximum practical weight policy:** confirm the operator's desired FreightLogic hard/soft weight thresholds after the actual payload label, axle considerations, and current equipment are verified.

## Operating-cost / economics questions

5. **Cost-per-mile baseline:** GPT context carried approximately `$0.26/mi` fuel + `$0.40/mi` other operating cost = about `$0.66/mi` total. It is unclear whether all three numbers were explicitly confirmed by the operator or partly derived. Confirm current values and date before using them as canonical cost inputs.
6. **Weekly earnings targets:** context carried survival/core/stretch targets around `$3,500–$5,000/week`. Confirm whether these remain active FreightLogic targets and which exact bands should be persisted.
7. **Older market baseline:** context carried approximate operator observations of TX `$0.85–$0.90`, FL `$0.90`, Midwest `$1.00–$1.25`, Canada around `$1.47`. Exact observation dates/source are not preserved here. Confirm or retire these figures rather than treating them as current market truth.
8. **Time-of-day market heuristic:** context carried “after ~6–7 PM thin” and “AM prime 06:00–11:00.” The operator explicitly confirmed poor weekend experience, but GPT cannot prove these exact clock ranges were direct operator statements. Confirm or reject.

## Load-history questions

9. **Adrian, MI → Tulsa, OK (#632684, 2026-06-24):** award is confirmed and 851 loaded + 97 empty / 504 lb are carried. The phrase “award after initial `$1,050`” is ambiguous. Confirm final agreed carrier pay before recording revenue/True RPM.
10. **Fort Wayne, IN → El Paso, TX:** context carried 1,632 mi and `$2,000`, but the exact date and primary record are not present in the current extraction. Confirm/find primary evidence before promotion.
11. **Lake Zurich, IL → Toledo, OH (#27973, 2026-08-21):** `$450` award is operator-confirmed. Confirm whether the load was completed/delivered and later paid.
12. **Warren, MI → Louisville, KY (#27990, 2026-08-23):** rate confirmation exists. Confirm completion, carrier pay, and settlement status.
13. **West Allis, WI → Le Roy, NY (rate confirmation 2026-07-30):** confirm completion and settlement status.
14. **125-row master ledger location:** operator confirmed the consolidated master as 125 rows (124 unique orders + 1 quote) and instructed not to re-audit supplied values. Identify the exact canonical CSV/file that should become the durable row-level import source so no future AI must reconstruct those rows from chat summaries.
15. **Remaining row-level history:** several completed lanes are known from primary completion evidence, but exact order IDs/pay/miles are absent from the current extraction. Reconcile from the operator-verified master/primary records rather than guessing.

## Quote-board / DispatchLand questions

16. **2026-08-24 lost-bid batch completeness:** three exact lost bids are preserved in `OPERATOR_TRUTH.md`, but the operator stated the screenshots represented all loads bid that day. Reconcile the full screenshot batch into a durable row-level file so every lost bid is represented, not only the rows still present in context.
17. **56-quote board batch:** counts and dedup rules are confirmed, but the full 56-row dataset is not reproduced in the current extraction. Identify/import the exact primary dataset or screenshots.
18. **Same-day “winning range” evidence source:** the operator requires same-day winning range + recommended bid + strategic minimum. Confirm which observable outcomes qualify as winning-price evidence when DispatchLand does not expose the actual award price.

## Warp questions

19. **Warp authenticated account/API status:** context contains evidence that Warp account/quote access was active and a prior email/context record referred to an API key. Current official quote-only documentation is public/keyless while booking/private actions require authentication. Confirm what authenticated production/sandbox credentials are actually active now; do not expose secrets in this file.
20. **Warp booking intent:** confirm whether FreightLogic should ever progress beyond quote-only market evidence into authenticated booking/tracking, or whether that remains explicitly deferred.

## 123Loadboard questions

21. **`$200` API/integration offer:** context carried that 123Loadboard offered a `$200` key/integration and that work was paused pending MC/DOT status. Confirm the exact offer, whether it is one-time or recurring, current validity, and whether MC/DOT activation is actually a prerequisite.
22. **API authorization:** confirm whether an integration/partner application has been submitted/approved. A free account is confirmed but is not API authorization.
23. **Permitted retention/analytics:** verify the exact terms for storing load/search/rate data inside a commercial FreightLogic product before implementing persistent ingestion.

## Direct Freight questions

24. **Partner token status:** free account is confirmed; verify whether any partner `api-token` has been requested or issued.
25. **End-user token model:** verify the intended user-scoped authorization flow and whether a single-operator FreightLogic deployment can use it under Direct Freight terms.
26. **Permitted retention/redistribution:** verify what Direct Freight data may be stored historically and used for commercial analytics before adapter implementation.

## Vision-ingest product questions

27. **Raw image retention:** after a load image is successfully confirmed, should FreightLogic retain the original image indefinitely, retain it for a limited audit period, or allow immediate deletion while keeping the structured record/evidence hash? The vision contract leaves this as a product decision.
28. **Automatic retry privacy:** when a photo is captured offline, should extraction retry automatically on reconnect or only after an explicit user action? The contract defaults to explicit/user-controlled upload unless the operator approves a different policy.
29. **Multi-card screenshots:** should the first implementation require the user to crop/select one load card before extraction, or support selecting among multiple detected cards? The contract takes the safer one-offer-per-extraction path for acceptance, but UI behavior remains to be confirmed.

## Resolved roadmap decisions

30. **CONFIRMED — 2026-08-26 — Gate 0.** The operator approved the proposal to make `OPERATOR_TRUTH.md` + `EVIDENCE_PROVENANCE.md` + `OPEN_QUESTIONS.md` formal Gate 0 of the one canonical completion roadmap. Gate 0 is already complete because all three files are durable on `main`. This adds no runtime milestone work.
31. **CONFIRMED — 2026-08-26 — Vision is not a completion blocker.** The operator approved the proposal that vision ingestion may be implemented but must **not** enlarge the named completion-release definition. The release may freeze without successful vision-model extraction once the required provider-independent normalized/manual-email ingestion foundation and all other release gates are complete.
32. **CONFIRMED — 2026-08-26 — Ingestion order.** Inside Milestone 5, the approved order is `normalized contract → manual/email → vision → provider adapters`. Provider adapters may not leapfrog vision. If vision is deferred, provider-adapter expansion is deferred too; neither is required to freeze the completion release.
33. **CONFIRMED — 2026-08-26 — Milestone 1 MPG fallback parity.** The operator explicitly approved reconciling the stale `MW.mpg: 16.5` fallback/source label with the operator-confirmed approximately **17.5 MPG loaded baseline** already recorded in `OPERATOR_TRUTH.md`. This is authorized as a narrowly bounded Milestone-1 source-of-truth parity repair, not a new feature. Required implementation behavior: the fallback/comment must no longer contradict Gate 0, while an explicit user vehicle-MPG setting remains higher priority and must continue to override the fallback. Claude/core lane owns the runtime/test implementation under the normal `app.js` lock and full-suite rules.

These resolved items remain here as an audit trail rather than being deleted.

## Resolution discipline

When the operator answers any item, update this file and the appropriate canonical document in the same PR/commit where practical. Do not delete the question in a way that erases why a prior assumption was rejected.
