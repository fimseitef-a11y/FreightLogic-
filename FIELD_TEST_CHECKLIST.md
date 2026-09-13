# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md`.

Current source synchronization point: exact Git SHA `03c97b64af354fa83fcb15881b320bfdfbf1e20a`, **FreightLogic v24.0.7 / IndexedDB v15 / Worker v15 source**. The last exact-byte production app/PWA PASS was for v24.0.5 on 2026-09-12; v24.0.7 production parity has not yet been re-observed. Worker v14 was the last confirmed deployed backup/API generation; the first v15 deployment attempt stopped safely before deploy because of a stale preflight pin, now fixed by PR #163. Do not convert source, preview-build, or desktop evidence into a physical-device PASS.

A further operator-approved structural UI pass is pending in the Claude/source lane. **Do not spend final physical-iPhone certification on an intermediate UI candidate.** Run the blocking A-section only after the structural pass is merged and the exact final production SHA/generation is named.

Before testing, record the exact production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify the exact named final candidate generation.
5. If updating from an older installed generation, use the normal non-destructive service-worker/PWA update path.

PASS requires the named final candidate generation (currently source v24.0.7, subject to the pending structural pass) to become active without blank shell, reload loop, startup error, lost local data, or destructive website-data clearing. Prior evidence from older installed generations never substitutes for this exact check.

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
4. A pallet at the floor-level wheel-well pinch must respect the operator-measured **54.8 in** width; **54.9 in** must not silently fit by default.
5. Cargo at the practical payload boundary must respect **3,000 lb**; **3,001 lb** must not silently fit by default.
6. With a defensible operating-cost-per-mile input, inspect True Profit; then remove the input/denominator needed to defend that cost.

PASS requires blank/underspecified markets to fail closed, Gary to retain U.S. Tier-1 doctrine, the length/wheel-well/payload boundaries to fail closed by default, and precise True Profit to become unavailable/explicitly estimated when cost-per-mile is not defensible.

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A9. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

## B1. Exact production app generation

Current evidence for **v24.0.7**: **NOT RUN / UNOBSERVED**. The last exact production app/PWA byte-parity PASS was v24.0.5 on 2026-09-12. Source has since advanced and the visual system changed, so that old PASS cannot be carried forward.

PASS requires the exact final production SHA/generation, app/PWA/service worker/manifest/static assets, and security policy to match the named source candidate.

## B2. Worker health + auth boundary

Current evidence: **v15 source is merged but v15 deployment is not yet observed**. Worker v14 was the last confirmed deployed generation. A v15 deploy run stopped before `wrangler deploy` because of a stale v14 preflight literal; PR #163 fixed that deploy-path defect and merged.

PASS requires `/health` to return 200 and report Worker `15`, production-origin CORS to target `https://freightlogic-v2.fimseitef.workers.dev`, unauthorized admin/driver requests to be denied, and no secret/token exposure.

## B3. Live `/evaluate` authority smoke

After Worker v15 is deployed, PASS requires a complete canonical decision to remain client-owned and an incomplete/`UNAVAILABLE` decision to stay unavailable—no Worker/overlay fabrication of `REJECT`, `F`, zero True RPM, or `$0` bid.

## B4. Live `/extract` / backup / rotation authority smoke

Where deployed/enabled, use synthetic data. Extraction must return bounded evidence only; authenticated backup/full-delta/restore must preserve data/authority semantics. In-place token rotation must keep the same user identity and existing backup history while invalidating the old token. A failed/unavailable source must remain explicit.

## B5. Rollback / fix-forward evidence

Run `node scripts/verify-rollback.mjs` and record the exact source SHA and named regressions. Existing evidence supports a fix-forward policy because older app/Worker generations contain known regressions. This is not proof of an actual deployment rollback or operator approval to accept a regression; record those distinctions explicitly.

# C. Private-history reconciliation blocker

The raw row-level private master dataset is not currently available in the accessible repository/File Library. Do not reconstruct it from summaries.

When the real source bundle is available, first run `node scripts/verify-history-bundle.mjs <private-bundle-dir>`, then the current M6 importer/reconciliation machinery outside the public repository. The exact five-file contract and review steps are in `docs/COMPLETION_HANDOFF_2026-09-12_PR158.md`. Structural preflight alone does not close this gate.

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

The release remains **HOLD** until the approved structural UI pass is integrated and re-tested, Worker v15 is deployed and live-verified, the exact final app/PWA generation is production-verified, the real private-history reconciliation is run, and all applicable physical-iPhone blockers are PASS. A later certification-state document must explicitly supersede `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md` before the release is frozen.
