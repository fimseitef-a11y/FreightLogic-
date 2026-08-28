# FreightLogic Completion Release — Certification State

Date: 2026-08-27
Current-main review baseline: `62a305904507965644a8ac396aba66d833c94c30` (PR #108 runtime/import work plus PR #114 docs)
Status: **HOLD — NOT CERTIFIED FOR COMPLETION RELEASE**

This is a certification-state record, **not a second roadmap**. Milestone order and release scope remain governed by `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

Green CI proves the tested assertions passed. It does **not** certify a release when exact-current-source review demonstrates an uncovered correctness defect.

## Current implementation state

The repository contains substantial implementation for:

- Gate 0 operator-truth / evidence-provenance governance;
- Milestone 1 doctrine and money-integrity repairs;
- Milestone 2 expense/fuel optimistic concurrency;
- Milestone 3 Confidence + Evidence helpers/UI integration;
- Milestone 4 load lifecycle schema/state/UI/analytics foundation;
- Milestone 5A normalized-opportunity helper and helper-level local intake machinery;
- Milestone 6 historical-import and calibration machinery;
- a local JSON-import repair that now includes `loadLifecycle` (merged in PR #108);
- a file-specific M6 historical bundle adapter (merged in PR #108), which remains **reconciliation-unsafe and is not certified**;
- the finite M7 field/deployment checklist in `FIELD_TEST_CHECKLIST.md`.

**M5B distinction:** current source still does not prove a production driver-facing manual/email-compatible caller through `intakeOpportunity()`. Helper existence and helper-level tests are not production wiring.

## Current release-blocking source defects

### 1. IndexedDB v14 lifecycle indexes

The catch-all DB upgrade path creates `loadLifecycle` before the v14 block that creates its indexes. The `updatedAt`, `orderNo`, and `broker` indexes are therefore not guaranteed to exist after the intended upgrade path.

Certification requires a migration repair plus assertions against actual resulting `indexNames` for both fresh and v13→v14 databases.

### 2. Cloud delta-sync lifecycle initialization

`cloudPushBackup()` checks lifecycle delta state in its empty-delta guard before the lifecycle variable is safely initialized. A valid empty-delta path can fail before upload/no-op completion.

Certification requires the code repair and a real empty-delta regression.

### 3. Lifecycle / durable-evidence export integrity

Local JSON export includes lifecycle data, but the protected checksum contract still does not prove integrity coverage for lifecycle plus all newly durable normalized evidence.

Every protected durable data class must participate in export integrity, and a mutation to lifecycle/evidence must change the checksum. Untouched exports must validate and intentionally corrupted protected payloads must fail validation.

### 4. Reused-identifier lifecycle ambiguity and timestamp loss

External quote/order IDs are reused in real operator history. A unique broker+order match is not sufficient when supplied route/time facts conflict. Lifecycle stage chips/editor lookup keyed by order number alone can display or edit the wrong shipment.

Pickup/delivery/source timestamps must preserve available clock precision instead of being truncated to `YYYY-MM-DD`. Ambiguous identity must fail safe rather than choose a record.

### 5. Lifecycle background-link concurrency

`linkLifecycle()` can read a matched base row and persist a merged object without proving that the same revision is still current. Normal intake/background callers must honor the compare-and-abort boundary rather than overwrite a newer lifecycle mutation.

A real stale background-link race regression is required.

### 6. Worker canonical-absence compatibility

The Worker remains incompatible with the canonical client's legitimate incomplete state unless repaired end to end. Client-owned `UNAVAILABLE`, grade `?`, `trueRPM=null`, and suppressed/null bid must remain unavailable/unknown; the Worker must not manufacture `REJECT`, `F`, `$0.00`, numeric True RPM, or a substitute canonical answer.

Client-owned confidence/evidence labels may be explained or challenged but not replaced by model-authored competing labels.

### 7. Confidence/evidence real-path wiring

Post-M3 review remains open for:

- fuel provenance at the actual write/apply point — EIA health is not proof that the active fuel price came from EIA;
- NWS successful-zero versus no-observation/failure semantics;
- persisted compact secret-free evaluation-history evidence snapshots;
- actual lane/broker sample and recency wiring from real evaluator inputs;
- excluding irrelevant broker materiality when no broker was supplied;
- vehicle-fit evidence derived from real supplied measurements/profile state, never hardcoded `checked=true`.

Confidence remains descriptive-only. Repairs must not change decision authority.

### 8. Normalized opportunity evidence is not yet proven durable and M5B production path is absent

`normalizeOpportunity()` carries semantic/provenance data, but release certification requires those material fields to survive reload, backup/full+delta restore, local export/import, and integrity checking through a durable evidence contract.

Current-source issues that remain in the certification queue include:

- `DISPLAYED_TOTAL_MILES` must not occupy a field named `loadedMi`;
- unknown historical `operatorConfirmedAt` must stay unknown rather than default to current time;
- valid ISO source timestamps must survive normalization/persistence;
- price/mileage vocabulary must match `docs/EVIDENCE_PROVENANCE.md`;
- a real shipped manual/email-compatible surface must call normalize → durable evidence persistence → conservative lifecycle link.

Tests that invoke `intakeOpportunity()` only through `window.__FL_TESTS` do not satisfy M5B production wiring.

The governing persistence contract is `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`.

### 9. PR #108 merged useful fixes together with unresolved M6 reconciliation defects

PR #108 merged as `6b06ce9cad38853f3a200da95895fec8adb962f7`. Its local `importJSON()` repair is valid and should be preserved: `loadLifecycle` now participates in the local JSON-import transaction.

However, the historical adapter/fingerprint portion is **not certified** and requires corrective core work:

1. `_historicalRowFingerprint()` uses 32-bit DJB2 plus raw length. This fixes the 120-character truncation defect but remains collision-unsafe; a same-length collision was already demonstrated during pre-merge review.
2. `scripts/m6-import.mjs` explicitly reconciles completed orders in `new Map()` keyed by order number alone. Reused external IDs can therefore collapse distinct shipments.
3. Adapter rows set `stableId: orderNo`; core `_orderStableKey()` trusts explicit `stableId` first, laundering the unsafe external ID into internal identity.
4. `upsertOrder()` is first-source/fill-blanks. A later explicit operator correction cannot supersede an earlier populated lower-authority value.
5. Material per-field provenance is not retained. `_sources` is accumulated and then deleted, while row-level `sourceName/rawEvidenceRef` can misdescribe where merged material values came from.
6. `text 2.csv` maps source field `Carrier` directly to canonical `broker` without proven source semantics.
7. `dry_run` rows are withheld from import instead of being durably preserved as a distinct operational-history class excluded from normal economics.
8. RECOVERED rows set `awarded:true` for every non-dry status, including unrecognized statuses mapped to `opportunity:SEEN`; unknown status must not manufacture award evidence.
9. Adapter date normalization slices valid timestamps to date-only precision, weakening reused-ID disambiguation.

The post-merge corrective packet is on `agent-coordination` at `.agents/inbox/gpt-to-claude-post108-corrective-core-2026-08-27.md`.

### 10. M6 real-import outcome is provisional until reconciliation is repaired

PR #108 reported a real-bundle outcome of 136 reconciled order records + 6 quote observations = 142 lifecycle rows, with 132/136 missing deadhead and no fabricated calibration range. Those are useful observations from that adapter version, **not final authoritative ledger counts** while identity/precedence/provenance/status handling is unsafe.

After correction, the real bundle must be rerun off-repo and the old-vs-new row/status reconciliation reported without committing raw personal/financial source files.

### 11. M6 recency provenance

Calibration must use durable source observation time. Unknown observation age must not receive full-current weight, and lifecycle/import/correction `updatedAt` must not substitute for market-observation time.

Importing or correcting an old record today must not make its market evidence look newly observed.

### 12. Release-generation parity

`app.js` still advertises an older generation while later milestone functionality exists, and Worker generation markers remain behind the intended corrected runtime. Final app/PWA/service-worker/cache-buster/manifest/Worker versions must be selected and aligned only after the corrective runtime is stable.

Do not use a version bump to hide unresolved correctness work.

## Warp MCP/API integration disposition

Current contract: `docs/WARP_MCP_INTEGRATION_CONTRACT_2026-08-27.md`.

Warp public MCP is a shipper-side quote/booking surface. Cargo-van quote money remains `SHIPPER_BOOKABLE_PRICE` evidence, never carrier payout/operator revenue or carrier load availability. No public carrier available-load/bid/counter/tender tool has been verified. A future carrier feed requires explicit provider authorization and a new provider-specific semantic/lifecycle contract before it may influence carrier opportunity state.

Warp/provider expansion remains non-blocking and must not leapfrog the correctness gates above.

## Test-suite certification gaps

Existing green CI still misses real-path defects. Required regressions include, at minimum:

- actual lifecycle index names after fresh/v13→v14 migration;
- empty cloud delta path;
- stale background lifecycle-link race;
- reused order number with conflicting route/time remaining distinct/unresolved;
- full timestamp survival;
- local export/import plus checksum coverage for lifecycle/durable normalized evidence;
- production M5B intake followed by reload proving semantic evidence survives;
- Worker incomplete-canonical projection preserving all unknown/UNAVAILABLE fields;
- real M3 evidence assembly/provenance/history path;
- same-length historical-fingerprint collision;
- reused order ID across distinct historical shipments;
- later operator correction precedence over lower-authority populated data;
- dry-run durable preservation/exclusion;
- unknown RECOVERED status non-promotion;
- field-level provenance preservation after multi-source reconciliation;
- M6 unknown-age conservative weighting.

A test encoding an unsafe assumption must be corrected to the governing contract rather than preserved merely because it previously passed.

## Certification gates still required

Before a named completion release can be frozen:

1. Close every proof-backed current-source defect above with real-path regressions.
2. Keep existing Level X+ authority and money-integrity tests green.
3. Implement and prove the real M5B production manual/email-compatible intake path.
4. Prove normalized evidence remains semantically traceable after reload; missing deadhead remains unknown and cannot become zero.
5. Prove full backup + delta + restore parity with all current durable stores/evidence.
6. Prove local export/import parity and integrity checking for every protected durable data class.
7. Repair M6 adapter identity/precedence/provenance/status semantics; rerun the real import off-repo and report non-sensitive reconciliation outcomes.
8. Run the full automated suite and lane checks on the exact candidate SHA.
9. Complete the finite physical iPhone Safari/offline/GPS checks in `FIELD_TEST_CHECKLIST.md` against that exact candidate.
10. Verify live Cloudflare Pages/Worker generation, `/health`, auth-denial behavior, and non-sensitive `/evaluate` + `/extract` boundary smoke tests.
11. Record an executable rollback point.
12. Only then mark the completion release certified/frozen.

Long-horizon iOS storage/DST observations in the checklist remain post-release resilience evidence and must not be falsely marked PASS before their observation window exists.

## Current integration disposition

- `main` contains M1–M6 implementation machinery plus PR #108's local lifecycle-import fix, but **no release certification is implied**.
- PR #108 is merged; its historical reconciliation/fingerprint portion now requires a corrective core PR rather than further draft review.
- M5B production intake remains open; helper-level tests do not satisfy it.
- M3/M4/Worker/durability/recency blockers remain open until exact-current source and regressions prove otherwise.
- Vision intake and provider adapters remain non-blocking/deferred behind provider-independent correctness.
- M7 is finite and explicit in `FIELD_TEST_CHECKLIST.md`; operator/device-only checks cannot be invented by an agent.

The controlling rule remains: **EVIDENCE → TEST → CHALLENGE → RECONCILE → CERTIFY → ADOPT**.
