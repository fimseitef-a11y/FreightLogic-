# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`.

Current runtime synchronization point: **FreightLogic v24.0.10 / IndexedDB v15 / Worker v17**.

**The exact candidate SHA lives in the certification document, not here.** This file went two generations stale (it read `24.0.9` / Worker `v15` while production served `24.0.10` / `v17`), which would have had a tester confirming the wrong build and recording a PASS for a candidate that is not the one being certified. Read the SHA out of `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md` immediately before testing, and confirm the generation strings above against Diagnostics and Worker `/health` on the device itself. If any of the three disagree, stop — the disagreement is the finding.

All of section B and section D are now closed by observed live evidence, recorded in that certification document. What remains open is exactly what a headless runner cannot reach: **A1-A10 on a physical iPhone**, and **section C private-history reconciliation**, which needs raw files that are not in this repository.

Do not convert source, deployment-build, preview, desktop, or older-generation evidence into a physical-device PASS.

Before testing, record the exact frozen production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify **24.0.10** is active, on the exact candidate SHA named in the certification document.
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

PASS requires offline launch, durable offline saves, working structural navigation, no reconnect duplication/loss, and no static JavaScript/asset failure being masked by HTML-shell fallback. `admin-driver-ui.js` must also be available after the normal online prime; the old v24.0.8 production 404 may not be treated as current evidence. (B6 now proves this from a headless runner on every push — but the device is where the *installed PWA's* offline navigation is confirmed, which B6 explicitly does not observe.)

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

## A10. Pickup-feasibility gate (shipped v24.0.9, current in v24.0.10)

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

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A10. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

## B1. Exact production app generation — **PASS**

**Observed 2026-09-14.** `Verify Live Parity` run `34885000070` (`workflow_dispatch` on `main`) returned **VERDICT: PASS** against the production origin: all **23** declared runtime assets load, none is served as HTML for a static request, and the deployed Worker reports its current generation.

Worth keeping in the record: the **push**-triggered run on the same SHA failed, because it fires seconds after a merge and races the Cloudflare deploy. That FAILURE was real evidence about the origin *at that instant* and is not evidence about the release. Re-dispatch and record the later run; do not dismiss the first one, and do not cite it either.

To re-observe at any time:

1. GitHub → **FreightLogic- → Actions → Verify Live Parity**.
2. **Run workflow** on `main`, leaving **App origin** and **Worker origin** blank.
3. Record the run ID, checked-out SHA, and the explicit `PASS` / `FAILURE` / `UNOBSERVED` verdict.

Only a green `PASS` closes live all-asset parity. `UNOBSERVED` means the runner made no HTTP observation — neither a pass nor a product failure. An actual HTTP 4xx/5xx **is** observed evidence.

## B2. Worker health + auth boundary — **PASS**

**Observed 2026-09-14.** Worker **v17** was deployed by run `34884719806` (`DEPLOY`-confirmed dispatch) and verified three independent ways: the deploy workflow's own post-deploy checks, the auto-triggered authenticated smoke, and the live parity re-dispatch reporting `Worker reports v17 — {"ok":true,"version":"17"}`.

Free checks observed: `/health` HTTP 200 / version 17; production-origin CORS exact rather than `*`; unauthenticated `/admin/users` and `/evaluate` both denied HTTP 401.

## B3. Live `/evaluate` authority smoke — **PASS**

**Observed 2026-09-14**, run `34884786623`, against the deployed Worker using an expiring synthetic identity seeded in production KV and cleaned up afterwards. No operator data and no real driver credential was involved.

PASS required — and observed — a complete canonical decision staying client-owned, and an incomplete/`UNAVAILABLE` decision staying unavailable: no Worker or overlay fabrication of `REJECT`, `F`, zero True RPM, or a `$0` bid.

## B4. Live `/extract` / backup / rotation authority smoke — **PASS**

**Observed 2026-09-14**, same run (`34884786623`), **21 passed / 0 failed**: full backup, delta write, `GET /backup/delta` retention/ordering/gap counters, `GET /list` device scoping, `GET /status`, malformed-token and tokenless denial, and in-place token rotation preserving the user identity and existing backup history while invalidating the old token. Synthetic records only; cleanup verified.

## B5. Rollback / fix-forward evidence — **PASS**

The verifier that was stale here is repaired. `scripts/verify-rollback.mjs` no longer names any candidate: it derives the candidate from `HEAD`, the app and Worker generations from the tree, and the previous generation from git history, so it cannot go stale between releases and needs no per-release edit. Run it and record its output against the final frozen candidate.

Its verdict is deliberately incapable of naming a safe rollback target. Older generations carry known regressions, so the approved policy is **fix forward**. Absence of a proven safety-gate regression in the immediately previous generation is reported as exactly that — *not proven unsafe* — and is explicitly **not** an approval. Never label an older known-regression build safe merely because it resolves.

## B6. Production service-worker / offline behaviour — **PASS**

**Observed 2026-09-14.** `Verify Production Service Worker` drives a real headless Chromium against the production origin and proves, in order: the worker installs and activates; the page is controlled after one reload; `admin-driver-ui.js` and `midwest-stack-authority.js` are injected **and actually fetchable** (a tag pointing at a 404 was the 2026-09-13 defect); all 23 declared assets are present in the precache under the current generation; the driver shell renders; and — with the network verifiably down — a subresource miss returns `504 text/plain` rather than the HTML shell, while a drifted `?v=` on a known asset self-heals to the real file.

It states its own limit rather than implying otherwise: **the offline navigation itself is not observed there.** A navigation restarts the service worker outside the network emulation that covered it, which was tested, not assumed. That is precisely what **A4** on a real device is for, and why B6 does not replace it.

# C. Private-history reconciliation blocker

The original August 27 five-file M6 bundle was recovered privately in prior evidence. Preflight reports 216 source rows and the unchanged adapter deterministically produces 149 candidate records. Raw rows remain outside the public repository.

Status: **BUNDLE PREVIOUSLY RECOVERED / RAW FILES NOT AVAILABLE IN CURRENT SESSION / APPLICATION ROUND TRIP + IDEMPOTENCE + CONFLICT REVIEW NOT RUN**.

The current execution session does not have the five raw files mounted, and filename searches across the accessible File Library, Dropbox, and Google Drive found no copy. Do not reconstruct the bundle from chat summaries merely to make this gate pass.

Do not reconstruct the separate unavailable 125-row master from summaries. Once the actual raw M6 files are regained, run the isolated import/re-export and reconciliation machinery outside the public repository, then record only non-sensitive results publicly.

PASS requires no invented broker identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source timestamps/semantics, no collapse of distinct shipments sharing external IDs, deterministic re-import/idempotence, and reviewed conflicts before adoption.

# D. Six-width browser-layout gate — **PASS**

This is separate from the physical iPhone gate. The source repairs are in: 16px mobile form controls (v24.0.10 removed the two inline `font-size:13px` values that were the root cause, so the `!important` safety net is no longer load-bearing), the 44×44 small-screen target, broad reduced-motion handling, and tertiary-label contrast above 4.5:1 in both themes.

The requested geometry gate exists and runs in the suite on every PR and push: `tests/integration/six-width-layout.spec.mjs` observes 320, 375, 390, 393, 430 and 440 CSS-px in both theme states, proves no page-level horizontal overflow across the five surfaces, checks bottom-nav interactive geometry, and covers a narrow-width modal under reduced motion.

Two measurement traps are worth knowing, because the first version of this gate was green while measuring nothing:

- `document.documentElement.scrollWidth` **cannot** detect overflow in this app — `styles.css` sets `body { overflow-x: hidden }`, so the page never reports a scrollWidth wider than the viewport however far content spills. Injecting `min-width: 900px` left a scrollWidth assertion green.
- Under mobile emulation the layout viewport **expands** to fit content wider than the device (`innerWidth` read 900 at a 320px device), so geometry compared against `innerWidth` is compared against a viewport that already grew to accommodate the overflow. Measure against the device width the test set.

This is still **not** a substitute for iOS safe-area, software-keyboard, or Home Screen PWA evidence. Those are A1-A10.

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
