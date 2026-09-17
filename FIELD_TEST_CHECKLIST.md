# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`, `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md`, and `docs/CERTIFICATION_DEFERRAL_2026-09-16.md`.

Current runtime synchronization point: **production serves FreightLogic v24.0.14 / IndexedDB v16 / Worker v19, and current `main` carries the same runtime generations.** Production was observed 2026-09-16 by live all-asset parity run `35087770010`, `workflow_dispatch` on `main` @ `8f90725`, whose `EXPECTED` block is exactly those generations. `main` has advanced since then through documentation/coordination commits without changing the shipped runtime generation. Test against what the device actually reports only when the deferral below lifts; any generation disagreement at that time is itself a finding and requires a superseding certification-state document before recording a PASS.

**Not a live test queue.** A1-A12 and the section C private-history reconciliation are **deferred by the operator's 2026-09-16 decision** to the final post-v24.5 candidate and run **once** against that candidate. **24.0.14 is not the certification candidate.** See `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before running any row below. The instrument is ready and remains open; it is deliberately not being run yet, and a partial A-section against a superseded generation is not evidence.

**The exact candidate SHA lives in the certification document, not here.** This file has gone stale across prior generations, so do not copy a candidate SHA into this checklist. When the deferral lifts, read the exact candidate out of the then-current superseding certification-state document and confirm the displayed app generation, service-worker/cache generation, and Worker `/health` generation on the device itself before testing. If any disagree, stop — the disagreement is the finding.

All of section B and section D are closed by observed live evidence for the recorded production baseline. What remains open is exactly what a headless runner cannot close: **A1-A12 on a physical iPhone** and **section C private-history reconciliation**. Their schedule is governed by the deferral decision above.

Do not convert source, deployment-build, preview, desktop, or older-generation evidence into a physical-device PASS.

Before testing, record the exact frozen production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify the **exact final post-v24.5 candidate named in the current certification document** is active.
5. If updating from an older installed generation, use the normal non-destructive service-worker/PWA update path.
6. Confirm the primary shell and More/secondary-surface reachability match the final redesigned shell documented for that candidate.

PASS requires the named final candidate to become active without blank shell, reload loop, startup error, lost local data, or destructive website-data clearing. Loads must render the canonical load inbox, Evaluate must still resolve to the canonical evaluator, Unified Load Intake must remain reachable through its approved final entry point, and prior evidence from older installed generations never substitutes for this exact check.

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

PASS requires offline launch, durable offline saves, working structural navigation, no reconnect duplication/loss, and no static JavaScript/asset failure being masked by HTML-shell fallback. `admin-driver-ui.js` must also be available after the normal online prime; the old v24.0.8 production 404 may not be treated as current evidence. (B6 proves the deployed service-worker path from a headless runner, but the device is where the *installed PWA's* offline navigation is confirmed, which B6 explicitly does not observe.)

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

## A10. Pickup-feasibility gate

Use a synthetic load with an optional pickup cutoff.

1. Leave Trip Planning average speed unset and create an obviously impossible pickup window.
2. Confirm the app does **not** invent a speed or a reachability verdict; ordinary economics remain unchanged by the new gate when speed is unset.
3. Set an explicit realistic planning average speed in Settings.
4. With known deadhead and an unreachable cutoff, Evaluate must show **CAN'T TAKE** before economics.
5. Move the cutoff to a comfortably reachable time and confirm normal economics return.
6. Clear deadhead entirely and verify UNKNOWN deadhead does not become zero or a false reachable result.
7. Enter explicit deadhead `0` and verify it is treated as real zero distance.
8. Create a reachable but under-30-minute-slack case and verify it is advisory/tight only; it must not independently alter grade/verdict/bid authority.

PASS requires the exact fail-closed behavior above. A guessed/clamped/default planning speed is a failure.

## A11. iOS 27 / Safari 27 regression pass (added 2026-09-15)

**Run this only if the device is on iOS 27 or later; record the iOS version either way.** This is a physical rendering/interaction gate that automated geometry and service-worker checks cannot replace. See `docs/IOS27_SAFARI27_ASSESSMENT_2026-09-15.md`.

1. **F31 Earnings Trends chart.** With 4+ weeks of data, open the final Money trends surface and inspect the chart in both week and month views. Confirm bars align to their baseline and axis, the overlay line tracks the bar tops, labels are not clipped or overlapping, and the values shown match the Money card's own figures.
2. **Driver tab bar icons.** Confirm every final primary-nav icon renders at the right weight and size, the center action is not clipped, and the active tab is visibly distinguishable in both dark and light.
3. **Selects.** Open the evaluator with More Details expanded and tap through every select — currency, mode, day of week, strategic reason — plus Settings' vehicle class and the Load Intake selects. Confirm the native picker opens, option text is readable, and the viewport does not zoom on focus. Tapping a select must not scroll the driver out of the load being priced.
4. **Scroll anchoring.** Paste into the Smart Load Inbox and confirm existing rows do not jump as any recent-paste/status bar renders above them. Record visual behavior; do not infer from desktop automation.
5. **Persistent storage actually granted.** In Diagnostics, confirm storage is reported as persisted for the installed Home Screen app.
6. **Background sync remains non-authoritative.** Close the app fully, reopen later, and confirm the cloud-backup paused/reconnect mitigation behaves as specified rather than assuming background delivery.

PASS requires no visual regression in the final SVG/icon/select surfaces, no zoom-on-focus, persisted storage granted, and the cloud-backup paused/reconnect behavior working as specified. Record the iOS and Safari versions with the result.

## A12. Zero-token driver onboarding — **the storage-partition question**

**Prerequisite for the current production baseline is satisfied:** production app 24.0.14 / Worker v19 carries the invite/claim contract and B7 has live evidence against Worker v19. When the final post-v24.5 candidate is deployed, re-confirm its app and Worker generations before running this gate.

This gate exists because of one question no headless runner can answer, and the answer determines whether a real driver is stranded.

1. **Owner setup.** On the owner's device, with App Lock enabled, open Settings → Cloud Backup → Admin. Paste the admin token once and save. Confirm it asks for the PIN, confirms configured status, clears the field, and never shows the value again. Deliberately try a wrong token first and confirm it stores nothing.
2. **Invite.** Tap Invite driver, enter a name, and confirm the share sheet carries a link and states an expiry. Confirm nothing on this screen exposes the permanent bearer token or raw claim code.
3. **Delivery by iMessage and by Mail.** Send the same invite both ways to the driver's phone. Both must open the app directly. Note whether either client rewrites or truncates the URL fragment.
4. **Claim in Safari.** On the driver's iPhone, open the link in Safari. Confirm the claim wizard appears, the address bar no longer shows the code once the wizard is up, and completing the claim connects cloud backup.
5. **THE QUESTION: Add to Home Screen.** Install the app to the Home Screen and open it from there. Record explicitly whether the claimed credential is present or the installed app uses a separate storage partition. If storage is separate, re-claim using the same invite path and confirm the owner still sees **one** driver with backup history intact, not a second account.
6. **Invite exhaustion/expiry.** Confirm claims beyond the allowed count or expiry are refused rather than silently creating anything.
7. **Revoke.** Remove the driver and confirm their app stops backing up and the old invite cannot reactivate them.

PASS requires the answer to step 5 recorded explicitly, one driver account surviving the whole sequence with its backup count intact, and no permanent bearer token exposed to either person.

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A12. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

## B1. Exact production app generation — **PASS on recorded baseline**

**Observed 2026-09-16.** Live all-asset parity run `35087770010`, `workflow_dispatch` on `main` @ `8f90725`, returned PASS against production for app/service-worker 24.0.14 and Worker v19. Re-observe on the final post-v24.5 candidate before certification.

## B2. Worker health + auth boundary — **PASS on recorded baseline / re-observe on final candidate**

Current certification authority records Worker v19 live. Re-run the authenticated/live Worker gates after the final candidate Worker deploy and record the exact run ID; do not carry a source-only result forward as a new observation.

## B3. Live `/evaluate` authority smoke — **PASS historically / re-observe on final candidate**

The authenticated authority smoke has previously observed complete canonical decisions staying client-owned and incomplete/UNAVAILABLE decisions staying unavailable. Re-run against the final candidate Worker before certification.

## B4. Live `/extract` / backup / rotation authority smoke — **PASS historically / re-observe on final candidate**

The authenticated backup/delta/list/status/rotation contract has previously passed with synthetic identities and cleanup. Re-run against the final candidate Worker before certification.

## B5. Rollback / fix-forward evidence — **PASS instrument**

`scripts/verify-rollback.mjs` derives candidate generations from the tree/history and is deliberately incapable of declaring an older generation safe. The standing policy is **fix forward**. Run it against the final frozen candidate and record its output.

## B6. Production service-worker / offline behaviour — **PASS historically / re-observe on final candidate**

The production service-worker verifier proves installation/control, declared precache assets, real script fetchability, offline subresource semantics, and drifted-version self-healing. It does not replace A4 installed-PWA offline navigation on the real device. Re-observe B6 on the final candidate.

## B7. Live invite/claim contract — **PASS on Worker v19 baseline / re-observe on final candidate if Worker changes**

Observed 2026-09-16 against Worker v19 in run `35049144080`. The live verifier proves the invite auth boundary, malformed/unknown claim handling, successful seeded claim whose minted token actually authenticates, same-user re-claim with old-token revocation, and claim exhaustion while cleaning synthetic records. If the final candidate changes the Worker or invite/claim path, re-run B7; otherwise carry the v19 observation forward explicitly as unchanged evidence rather than pretending it is a new observation.

# C. Private-history reconciliation blocker

The original August 27 five-file M6 bundle was recovered privately in prior evidence. Preflight reports 216 source rows and the unchanged adapter deterministically produces 149 candidate records. Raw rows remain outside the public repository.

Status: **BUNDLE PREVIOUSLY RECOVERED / RAW FILES NOT AVAILABLE IN CURRENT SESSION / APPLICATION ROUND TRIP + IDEMPOTENCE + CONFLICT REVIEW NOT RUN / DEFERRED TO FINAL POST-v24.5 CANDIDATE**.

Do not reconstruct the bundle or the separate unavailable master from summaries merely to make this gate pass. Once the actual raw M6 files are regained, run the isolated import/re-export and reconciliation machinery against the final candidate, then record only non-sensitive results publicly.

PASS requires no invented broker identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source timestamps/semantics, no collapse of distinct shipments sharing external IDs, deterministic re-import/idempotence, and reviewed conflicts before adoption.

# D. Six-width browser-layout gate — **PASS instrument / rerun for final redesigned shell**

This is separate from the physical iPhone gate. `tests/integration/six-width-layout.spec.mjs` observes 320, 375, 390, 393, 430 and 440 CSS-px across the primary surfaces and guards against page-level horizontal overflow, undersized primary navigation targets, and narrow-width modal failures. The final redesigned shell must run the current version of this gate before certification.

This is still **not** a substitute for iOS safe-area, software-keyboard, visual SVG/select rendering, or Home Screen PWA evidence. Those are A1-A12.

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

The release remains **HOLD**, but this HOLD is **deferred by operator decision**, not a live testing queue for 24.0.14. A1-A12 and M6 run once against the final post-v24.5 candidate after its certification-state document names the exact deployed generation and this checklist has been re-verified against the redesigned shell. A deferred gate remains open; nothing in this file converts it to PASS.