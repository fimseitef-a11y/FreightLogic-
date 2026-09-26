# GPT → Claude: current repair gate after PR #110

Date: 2026-08-27
Current `main`: `2c75582548cc3a5d0b3fa6cbcad47f8ad668fd7f`
Open draft PR #108 head: `9cd624edcb60cbfb740e97f94d43cf0497ab367f`

## Priority

Do not advance release/freeze or M7 certification from the current runtime. The next core pass is a corrective M3–M6 re-certification pass.

PR #110 merged `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`; treat it as the implementation contract for the already-required M5/M6 durable semantic evidence path.

## Recommended core sequence

### A. Repair current-main M3/M4 integrity first

Preserve existing M1/M2 authority/concurrency behavior. Repair, with regressions:

1. Worker canonical absence: `UNAVAILABLE`, unknown grade, null True RPM, and suppressed/null bid must survive `/evaluate`; Worker remains explanation-only and consumes client-owned confidence.
2. M3 evidence wiring: explicit fuel write-point provenance; successful NWS zero vs no observation/failure; actual lane/broker intel; actual vehicle-fit measurement state; compact evaluation-history confidence/evidence snapshot; non-applicable domains remain non-material/UNKNOWN.
3. DB-v14 lifecycle indexes: ensure `updatedAt`, `orderNo`, and `broker` indexes exist on fresh and upgrade paths even when the store was created by a catch-all.
4. Cloud delta: initialize lifecycle delta before any `lc.length` no-change check.
5. Export integrity: protected lifecycle/durable evidence included in local export must be covered by integrity verification.
6. Reused-ID lifecycle safety: no orderNo-only UI selection; no broker+order auto-link unless route/time/internal-source compatibility is proven; competing candidates surface unresolved.
7. Preserve full pickup/delivery timestamp precision required for route/time compatibility.
8. Re-check lifecycle background optimistic concurrency and legacy backfill on the actual implementation path.

Do not version/release until this corrected runtime shape is final.

### B. Implement M5/M6 durable normalized evidence

Follow merged `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`.

Key requirement: `normalizeOpportunity()` may not return a rich evidence object that disappears after reload. Persist a bounded semantic evidence record linked conservatively to lifecycle, without turning `loadLifecycle` into a second trip/accounting ledger.

Required durable semantics include price semantic, mileage semantic, source type/name, observed/source timestamps, raw evidence reference, confirmation/confidence/health where applicable, explicit broker/carrier/company roles, and unknown-vs-zero preservation.

Wire a real manual/email-compatible intake path through normalize → persist evidence → conservative lifecycle link.

Add backup full/delta/restore/local export/import/checksum/concurrency parity for the new durable evidence class.

### C. Reconcile PR #108; do not merge it wholesale yet

Keep the valid local `importJSON()` lifecycle fix.

The existing bounded fingerprint fix solves truncation but uses a 32-bit DJB2 identity. Replace it with a collision-resistant bounded deterministic digest. Keep both regressions:

- long-provenance identical re-import adds zero rows;
- two distinct rows engineered to collide under the old 32-bit hash remain distinct under the replacement.

Repair `scripts/m6-import.mjs` before merge:

- no orderNo-only reconciliation;
- later higher-authority operator corrections supersede lower-authority values;
- retain auditable per-field provenance when merging sources;
- DRY RUN remains separately represented rather than discarded;
- unknown/secondary statuses never set `awarded:true` or WON without evidence;
- do not guess `Carrier` → `broker` semantics if the source meaning is unresolved;
- raw operator financial/history CSVs stay out of the public repo.

Re-run the real bundle after repair and report only non-sensitive aggregate results and any changed row/status counts.

## Gate before GPT re-review

Return one exact core head SHA after A+B+C are implemented or clearly separated into reviewable stacked PRs. Full local suite must be green. GitHub Tests + Lanes + Worker build must be green. Do not mark the completion release certified or PR #108 ready merely because existing tests pass.
