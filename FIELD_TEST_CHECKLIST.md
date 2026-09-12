# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`.

Current candidate: **FreightLogic v24.0.5 / IndexedDB v15 / Worker v13**. The automated/source gate is already green at **372 passed / 0 failed across 40 spec files** with lane/path/lock enforcement green. Do not convert automated evidence into a physical-device PASS.

Before testing, record the exact production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open the exact production candidate in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify the candidate generation.
5. If updating from an older installed generation, use the normal non-destructive service-worker/PWA update path.

PASS requires v24.0.5 to become the active app generation without blank shell, reload loop, startup error, lost local data, or destructive website-data clearing. Prior evidence that the installed app was v23.7.0 remains an unresolved A1 observation until this exact check passes.

## A2. Full Evaluate + Quick Evaluate UNKNOWN versus explicit zero

Use one harmless synthetic load.

- With complete facts and explicit deadhead, full Evaluate and Quick Evaluate should produce coherent canonical economics/grade/verdict.
- Repeat with deadhead blank/unstated in both paths.
- Repeat with deadhead explicitly `0`.

PASS requires missing deadhead to remain UNKNOWN/UNAVAILABLE with no invented numeric True RPM, grade, verdict, or bid; explicit `0` remains a real known zero. Quick Evaluate must not score a load that full Evaluate correctly refuses because deadhead is unknown.

## A3. Production opportunity intake durability

Create one synthetic manual/email-compatible opportunity through the shipped UI, including provenance and a clearly non-carrier amount semantic where available. Close the app, reopen, and inspect it.

PASS requires the evidence and provenance to survive reload, non-carrier money not to become canonical revenue, unknown mileage/deadhead to stay unknown, and lifecycle state to remain conservative unless evidence supports progression.

## A4. Offline round trip

1. Load the exact candidate online.
2. Enable Airplane Mode.
3. Create/edit representative synthetic local data.
4. Close/reopen while offline.
5. Reconnect and reopen again.

PASS requires offline launch, durable offline saves, no reconnect duplication/loss, and no static JavaScript/asset failure being masked by HTML-shell fallback.

## A5. Local export/import + secret exclusion

Using synthetic data, export the shipped portability payload and restore/import it through the supported path.

PASS requires trips/expense-or-fuel/lifecycle/evidence/provenance to round-trip; UNKNOWN deadhead stays unknown; credentials, backup tokens, PIN material, and device-local lockout state are absent; an untouched protected export validates and a deliberately corrupted synthetic payload is rejected where the integrity check is exposed.

## A6. Real-device GPS background resilience

Start a test GPS trip, move a representative distance, background/lock the iPhone for at least 10 minutes, return, and stop/save.

PASS requires the session to survive or recover through the intended path and mileage to remain plausible or explicitly labelled degraded/incomplete rather than falsely precise.

## A7. GPS permission loss mid-trip

Start a test trip, revoke location permission in iOS Settings, return to FreightLogic, and stop/review the trip.

PASS requires visible degraded/paused tracking, preserved salvageable trip state, and no suspect precise mileage flowing forward as verified data.

## A8. Stale-edit conflict on real browser/device

Open the same synthetic trip/expense/fuel record in two Safari tabs. Save Tab 1, then save the stale Tab 2 form.

PASS requires the stale write to be rejected or refreshed to the newer record. Tab 1's change must not be silently overwritten.

## A9. Candidate-specific doctrine / geography / cargo-fit / profit sanity

Use synthetic values only.

1. Blank, one-character, and two-character location text must not manufacture a favorable market.
2. **Gary, IN** must resolve as the intended U.S. Tier-1 Chicago/Gary-belt market, never Calgary/Canada.
3. A **121 in** cargo length should respect the confirmed default usable-length boundary; **122 in** must not silently fit without an explicit provenance-bearing larger override.
4. With a defensible operating-cost-per-mile input, inspect True Profit; then remove the input/denominator needed to defend that cost.

PASS requires blank/underspecified markets to fail closed, Gary to retain U.S. Tier-1 doctrine, 122-inch freight not to fit by default, and precise True Profit to become unavailable/explicitly estimated when cost-per-mile is not defensible.

# B. Live deployment blockers

Run these against the same production candidate used for A1-A9. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed live procedure.

## B1. Exact production generation

PASS requires production app/PWA/service-worker/manifest assets to identify v24.0.5 and be tied to the intended GitHub `main` candidate. A preview deployment is not production parity.

## B2. Worker health + auth boundary

PASS requires `/health` to report Worker `13`, unauthorized admin/driver requests to be denied, and no secret/token exposure.

## B3. Live `/evaluate` authority smoke

PASS requires a complete canonical decision to remain client-owned and an incomplete/`UNAVAILABLE` decision to stay unavailable—no Worker/overlay fabrication of `REJECT`, `F`, zero True RPM, or `$0` bid.

## B4. Live `/extract` / backup authority smoke

Where deployed/enabled, use synthetic data. Extraction must return bounded evidence only; authenticated backup/full-delta/restore must preserve data/authority semantics. A failed/unavailable source must remain explicit.

## B5. Rollback evidence

Record the approved rollback SHA and verify the rollback procedure is executable, not merely described.

# C. Private-history reconciliation blocker

Run the current M6 importer/reconciliation machinery against the real private operator bundle outside the public repository.

PASS requires no invented broker identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source timestamps/semantics, and no collapse of distinct shipments sharing external IDs. Record only non-sensitive reconciliation results publicly.

# D. Non-blocking resilience watch list

These observations are valuable after the finite release gate and must not be claimed if their observation window has not elapsed:

- 7-8 day cold-storage reopen;
- deliberate storage-pressure save failure handling;
- real DST/year-boundary observation.

Failures should become follow-up defects, but these long-horizon observations do not expand the finite completion gate.

# Certification record

For every blocking item use exactly one of:

- `PASS` — actually observed on the exact candidate;
- `FAIL` — observed defect, with reproduction evidence;
- `NOT RUN` — not performed; never infer PASS;
- `NOT APPLICABLE` — only when the canonical completion plan explicitly makes the feature non-blocking/not shipped.

For a failure record the checklist ID, exact candidate SHA/version, device/iOS/browser or PWA context, reproduction steps, screenshot when useful, whether local data changed/lost, and whether a safe export/backup existed.

The release remains **HOLD** until the private-history, live-production, and all applicable finite physical-iPhone blockers are PASS and a later certification-state document explicitly supersedes `COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`.