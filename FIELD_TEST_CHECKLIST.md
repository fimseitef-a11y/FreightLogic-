# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md`.

Current runtime synchronization point: exact Git SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`, **FreightLogic v24.0.9 / IndexedDB v15 / Worker v15**. PR #175 integrated the pickup-feasibility gate and its exact runtime suite passed **431 tests / 0 failures across 45 spec files**. GitHub's Cloudflare check attached to this exact merge SHA succeeded for `freightlogic-v2` (check `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`). Read-only verifier/docs work subsequently raised the merged repository suite to **442/0 across 46 spec files** in run `34800434526` without changing shipped runtime files. The source deployment inventory covers every declared runtime asset and no longer excludes `admin-driver-ui.js`. A manual/read-only **Verify Live Parity** GitHub Actions workflow is now merged; it must actually be dispatched before exact live all-asset parity can be marked PASS. Authenticated Worker smokes, six-width browser geometry, private-history reconciliation, and physical-device evidence remain open. Do not convert source, deployment-build, preview, desktop, or older-generation evidence into a physical-device PASS.

Before testing, record the exact frozen production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify **24.0.9** is active on exact candidate SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`.
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

PASS requires the exact v24.0.9 fail-closed behavior above. A guessed/clamped/default planning speed is a failure.

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A10. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

## B1. Exact production app generation

Current evidence for **v24.0.9**: **PRODUCTION BUILD SUCCEEDED / LIVE RUNNER MERGED / EXACT LIVE ALL-ASSET PARITY NOT RUN**. GitHub's Cloudflare check attached to exact runtime SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` succeeded as check `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`. Source-side deployment coverage derives 23 runtime assets and confirms none is excluded from deploy, including `admin-driver-ui.js`.

A read-only manual workflow now exists to make the previously blocked network observation:

1. In GitHub, open **FreightLogic- → Actions → Verify Live Parity**.
2. Tap **Run workflow** on `main`.
3. Leave **App origin** and **Worker origin** blank so production defaults are used.
4. Tap **Run workflow**.
5. Record the run ID, checked-out SHA, and explicit `PASS`, `FAILURE`, or `UNOBSERVED` verdict.

Only a green `PASS` run may close live all-asset parity. `FAILURE` means production was observed and a real mismatch exists. `UNOBSERVED` means the runner made no HTTP observation and is neither PASS nor a product failure. An actual HTTP 4xx/5xx is observed evidence, not UNOBSERVED.

PASS still requires the live production origin to match the exact final generation across every derived runtime asset, app/PWA/service worker/manifest/static assets, `modern-shell.js`, and security policy. A Cloudflare build success does not prove byte/content parity by itself.

## B2. Worker health + auth boundary

Current evidence: **Worker v15 LIVE FREE CHECKS PASSED ON 2026-09-13 / AUTHENTICATED CHECKS NOT RUN**. Worker source did not change in v24.0.9.

Observed free checks: `/health` HTTP 200/version 15; production-origin CORS exact; backup OPTIONS HTTP 204; unauthorized admin denied HTTP 401.

PASS for final certification additionally requires authenticated authority/backup boundaries with a dedicated non-published test identity and no secret exposure.

## B3. Live `/evaluate` authority smoke

PASS requires a complete canonical decision to remain client-owned and an incomplete/`UNAVAILABLE` decision to stay unavailable—no Worker/overlay fabrication of `REJECT`, `F`, zero True RPM, or `$0` bid.

Status: **NOT RUN authenticated**.

## B4. Live `/extract` / backup / rotation authority smoke

Where deployed/enabled, use synthetic data. Extraction must return bounded evidence only; authenticated backup/full-delta/restore must preserve data/authority semantics. In-place token rotation must keep the same user identity and existing backup history while invalidating the old token. A failed/unavailable source must remain explicit.

Status: **NOT RUN authenticated**.

## B5. Rollback / fix-forward evidence

Status: **NOT RUN / VERIFIER TOOLING STALE**.

The current `scripts/verify-rollback.mjs` still names an older production candidate and expects Worker v14 even though the current release source/live Worker is v15. Do **not** treat a failure from that stale expectation as release evidence. A bounded Claude-owned correction has been requested.

After the verifier is reconciled to the v24.0.9 / Worker-v15 state, run it and record the exact source SHA and named regressions. Existing evidence supports a default **fix-forward** policy because older app/Worker generations contain known regressions. This is not proof of an actual deployment rollback or operator approval to accept a regression; record those distinctions explicitly. Never label an older known-regression build safe merely because it resolves.

# C. Private-history reconciliation blocker

The original August 27 five-file M6 bundle was recovered privately in prior evidence. Preflight reports 216 source rows and the unchanged adapter deterministically produces 149 candidate records. Raw rows remain outside the public repository.

Status: **BUNDLE PREVIOUSLY RECOVERED / RAW FILES NOT AVAILABLE IN CURRENT SESSION / APPLICATION ROUND TRIP + IDEMPOTENCE + CONFLICT REVIEW NOT RUN**.

The current execution session does not have the five raw files mounted, and filename searches across the accessible File Library, Dropbox, and Google Drive found no copy. Do not reconstruct the bundle from chat summaries merely to make this gate pass.

Do not reconstruct the separate unavailable 125-row master from summaries. Once the actual raw M6 files are regained, run the isolated import/re-export and reconciliation machinery outside the public repository, then record only non-sensitive results publicly.

PASS requires no invented broker identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source timestamps/semantics, no collapse of distinct shipments sharing external IDs, deterministic re-import/idempotence, and reviewed conflicts before adoption.

# D. Six-width browser-layout gate

This is separate from the physical iPhone gate. The v24.0.9 source already contains the known source repairs: 16px mobile form controls, 44×44 small-screen theme target, broad reduced-motion handling, and tertiary-label contrast above 4.5:1 in both themes.

Still required:

- observe 320, 375, 390, 393, 430, and 440 CSS-px widths in dark/light themes;
- prove no page-level horizontal overflow on Today, Loads, Evaluate, Trips, or Money;
- prove primary bottom-nav interactive geometry meets the 44×44 target;
- prove representative long strings and a narrow-width modal/bottom sheet do not force horizontal overflow;
- preserve reduced-motion behavior.

A Claude-owned Playwright geometry gate has been requested so these browser checks become repeatable. It must not be presented as a substitute for iOS safe-area/software-keyboard/Home Screen PWA evidence.

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

The release remains **HOLD** until exact v24.0.9 live production all-asset parity is observed, authenticated Worker authority/backup smokes pass, the real private-history bundle is reconciled, six-width browser-layout acceptance passes, truthful rollback/fix-forward evidence is recorded, and all applicable physical-iPhone blockers are PASS. Any later certification-state document must explicitly supersede `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md` before the release is frozen.
