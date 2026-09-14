# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`.

Current runtime synchronization point: exact Git SHA `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`, **FreightLogic v24.0.10 / IndexedDB v15 / Worker v17**, merged PR #193. Exact main suite [34884711942](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884711942) passed **457/0 across 49 specs**. Live parity [34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070) passed for the expected generations and all 23 declared runtime assets. Authenticated run [34884786623](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884786623) recorded **5 authority passes / 3 NOT RUN**, plus **21 synthetic backup passes / 0 failures**. The existing six-width browser spec passed **2/0**; its mobile-coverage follow-ups remain open. Paid authority probes, token rotation, installed-app restore, real private-history reconciliation, standalone recovery evidence, and physical-device checks are not certified by these runs. Source, network, desktop, and older-generation evidence never substitutes for a physical-device PASS.

Before testing, record the exact frozen production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify **24.0.10** is active on exact candidate SHA `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`.
5. If updating from an older installed generation, use the normal non-destructive service-worker/PWA update path.
6. Confirm the primary shell is **Today / Loads / Evaluate / Trips / Money** and More still exposes the secondary surfaces.

PASS requires the named final candidate to become active without blank shell, reload loop, startup error, lost local data, or destructive website-data clearing. Loads must render the canonical load inbox, Evaluate must still resolve to the canonical evaluator, and prior evidence from older installed generations never substitutes for this exact check.

## A2. Full Evaluate + Quick Evaluate UNKNOWN versus explicit zero

Use one harmless synthetic load.

- With complete facts and explicit deadhead, full Evaluate and Quick Evaluate should produce coherent canonical economics/grade/verdict.
- Repeat with deadhead blank/unstated in both paths.
- Repeat with deadhead explicitly `0`.

PASS requires missing deadhead to remain UNKNOWN/UNAVAILABLE with no invented numeric True RPM, grade, verdict, or bid; explicit `0` remains a real known zero. Quick Evaluate must not score a load that full Evaluate correctly refuses because deadhead is unknown.

## A3. Production opportunity intake durability

Create one synthetic manual/email/notification-compatible opportunity through the shipped UI, including provenance and a clearly non-carrier amount semantic where available. Close the app, reopen, and inspect it.

PASS requires evidence and provenance to survive reload, non-carrier money not to become canonical revenue, unknown mileage/deadhead to stay unknown, and lifecycle state to remain conservative unless evidence supports progression.

## A4. Offline round trip

1. Load the exact candidate online.
2. Enable Airplane Mode.
3. Create/edit representative synthetic local data.
4. Close/reopen while offline.
5. Navigate through Today, Loads, Evaluate, Trips, and Money while offline.
6. Reconnect and reopen again.

PASS requires offline launch, durable offline saves, working structural navigation, no reconnect duplication/loss, and no static JavaScript/asset failure being masked by HTML-shell fallback. `admin-driver-ui.js` must also be available after the normal online prime; the old v24.0.8 production 404 may not be treated as current evidence.

## A5. Local export/import + secret exclusion

Using synthetic data, export the shipped portability payload and restore/import it through the supported path.

PASS requires trips/expense-or-fuel/lifecycle/evidence/provenance to round-trip; UNKNOWN deadhead stays unknown; credentials, backup tokens, PIN material, and device-local lockout state are absent; an untouched protected export validates and a deliberately corrupted synthetic payload is rejected where the integrity check is exposed. If `planningAvgMph` is explicitly set, it may round-trip as a durable setting; if absent/cleared, import/restore must not invent or clamp one.

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
4. A pallet at the floor-level wheel-well pinch must respect the operator-measured **54.8 in** width; **54.9 in** must not silently fit by default.
5. Cargo at the practical payload boundary must respect **3,000 lb**; **3,001 lb** must not silently fit by default.
6. With a defensible operating-cost-per-mile input, inspect True Profit; then remove the input/denominator needed to defend that cost.

PASS requires blank/underspecified markets to fail closed, Gary to retain U.S. Tier-1 doctrine, the length/wheel-well/payload boundaries to fail closed by default, and precise True Profit to become unavailable/explicitly estimated when cost-per-mile is not defensible.

## A10. v24.0.9 pickup-feasibility gate

Use a synthetic load with an optional pickup cutoff.

1. Leave Trip Planning average speed unset and create an obviously impossible pickup window.
2. Confirm the app does **not** invent a speed or a reachability verdict; ordinary economics remain unchanged by the new gate when speed is unset.
3. Set an explicit realistic planning average speed in Settings.
4. With known deadhead and an unreachable cutoff, Evaluate must show **CAN'T TAKE** before economics.
5. Move the cutoff to a comfortably reachable time and confirm normal economics return.
6. Clear deadhead entirely and verify UNKNOWN deadhead does not become zero or a false reachable result.
7. Enter explicit deadhead `0` and verify it is treated as real zero distance.
8. Create a reachable but under-30-minute-slack case and verify it is advisory/tight only; it must not independently alter grade/verdict/bid authority.

PASS requires the v24.0.9 pickup-feasibility behavior above to remain intact on the named v24.0.10 candidate. A guessed/clamped/default planning speed is a failure.

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A10. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

## B1. Exact production app generation

Current verifier evidence: **PASS** for **v24.0.10 / Worker v17** at `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`, [run 34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070). All 23 declared assets loaded and no static request returned an HTML shell. The earlier immediate push run 34884711957 failed before this successful post-deploy observation.

For a subsequent runtime candidate, open **Actions → Verify Live Parity → Run workflow** on `main`, leave both origin inputs blank, and preserve the checked-out SHA and explicit PASS / FAILURE / UNOBSERVED verdict. The workflow also runs automatically on pushes to main; it does not deploy.

The verifier's result is generation/delivery/content evidence, not a cryptographic comparison of all live bytes. It does not prove the installed service worker has updated, preserved local data, or launched offline; those remain A1/A4 observations.

## B2. Worker health + auth boundary

Current evidence: **Worker v17 DEPLOYED AND OBSERVED**. Deployment run 34884719806 observed health version 17, followed by parity PASS in run 34885000070. Authenticated run 34884786623 verified the model-free authority and synthetic backup checks listed in the certification record.

Final certification still requires the applicable unrun authority/rotation/restore checks with a dedicated non-published test identity. Overall workflow SUCCESS does not certify skipped probes.

## B3. Live `/evaluate` authority smoke

PASS requires a complete canonical decision to remain client-owned and an incomplete/`UNAVAILABLE` decision to stay unavailable—no Worker/overlay fabrication of `REJECT`, `F`, zero True RPM, or `$0` bid.

Status: **MODEL-FREE PROBES PASS (5/0); PAID COMPLETE-DECISION AND REJECT/F PROBES NOT RUN** in run 34884786623.

## B4. Live `/extract` / backup / rotation authority smoke

Where deployed/enabled, use synthetic data. Extraction must return bounded evidence only; authenticated full/delta backup and restore must preserve data/authority semantics. In-place token rotation must keep user identity and history while invalidating the old token.

Status: **SYNTHETIC SNAPSHOT/DELTA CONTRACTS PASS (21/0)** in run 34884786623. **Paid extraction, token rotation, and installed-app restore are NOT RUN in that evidence.** The 21 passes prove byte-exact snapshot/delta retrieval, ordering, counters, scoped listing, auth boundaries, and cleanup; they are not a device restoration or rotation test.

## B5. Rollback / fix-forward evidence

Status: **TOOLING REPAIRED; STANDALONE FINAL EVIDENCE NOT RUN IN THIS DOCUMENTATION PASS**.

PR #193 made `scripts/verify-rollback.mjs` derive HEAD, app/Worker generation and previous app generation instead of pinning stale literals. Its six regressions passed in exact main run 34884711942.

Run the read-only verifier with repository history available and record its candidate SHA/output and the final recovery procedure. Default policy remains **FIX FORWARD**; regression success or a verifier PASS never approves an older known-regression release as a safe rollback.

# C. Private-history reconciliation blocker

The original August 27 five-file M6 bundle was recovered privately in prior evidence. Preflight reports 216 source rows and the unchanged adapter deterministically produces 149 candidate records. Raw rows remain outside the public repository.

Status: **BUNDLE PREVIOUSLY RECOVERED / APPLICATION ROUND TRIP + IDEMPOTENCE + CONFLICT REVIEW STILL UNVERIFIED**.

This documentation pass did not access or reconcile the original private files. Earlier recovery/preflight evidence alone does not prove application round-trip success. Do not reconstruct the bundle from summaries.

Do not reconstruct the separate unavailable 125-row master from summaries. Once the actual raw M6 files are regained, run the isolated import/re-export and reconciliation machinery outside the public repository, then record only non-sensitive results publicly.

PASS requires no invented broker identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source timestamps/semantics, no collapse of distinct shipments sharing external IDs, deterministic re-import/idempotence, and reviewed conflicts before adoption.

# D. Six-width browser-layout gate

Observed: **EXISTING BROWSER SPEC PASS, 2/0**, in main run 34884711942 at the named v24.0.10 candidate. It covers 320/375/390/393/430/440, both theme states, five surfaces, navigation/control geometry, a long-content probe, reduced motion, and a 320px modal.

The implementation uses the default desktop `launchApp()` context. The handoff in `claude-to-gpt-v24010-merge-reconcile-2026-09-14.md` records remaining coarse-pointer, clipped-overflow and expanded-evaluator-field coverage issues. Keep those follow-ups open; the current PASS does not certify coverage the test does not exercise.

The existing acceptance requirements remain: no page-level horizontal overflow, 44×44 primary touch targets, 16px visible mobile form controls, long-string/modal containment, and reduced-motion behavior across the six widths. iOS safe-area, software-keyboard and Home Screen PWA behavior remain physical-iPhone observations.

# E. Non-blocking resilience watch list

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

The release remains **HOLD**. Current CI, live parity and bounded synthetic checks are recorded in `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`; applicable unrun authority/rotation/app-restore checks, real private-history reconciliation, complete mobile acceptance, standalone recovery evidence and physical-iPhone blockers must still be observed on the same final candidate. Only a later certification record may clear HOLD.
