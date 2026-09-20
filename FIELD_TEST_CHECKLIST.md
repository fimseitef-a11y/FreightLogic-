# FreightLogic Field Test Checklist

Purpose: finite **Milestone 7 physical-device certification gate** for the FreightLogic completion release.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`, `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-18.md`, and `docs/CERTIFICATION_DEFERRAL_2026-09-16.md`.

Current runtime synchronization point: **production serves FreightLogic v24.0.24 / IndexedDB v16 / Worker v21, and BOTH generations are OBSERVED** — re-dispatched live parity `35434716935` (job `105875325854`) and production service worker `35434719454` (job `105875332085`), both `VERDICT: PASS` on `f75f9cc`. Worker `/health` reports v21, all 22 declared runtime assets load with none served as HTML, 20 repository-only paths stay non-public, and the precache is `freightlogic-24.0.24`. **A13's Worker-v21 prerequisite is therefore discharged** — that row is OPEN like the rest of the A section rather than BLOCKED. The push-triggered parity on the same merge FAILED eleven seconds in (`35434651294`, ninth recorded occurrence of the Cloudflare race) and is not evidence about the release. **This line is a lookup, not a record:** re-read `APP_VERSION` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-19.md` every session. It has gone stale by three generations once already — which is the failure this file exists to prevent, a tester confirming the wrong build and recording a PASS for a candidate that is not the one being certified.

**Voice Load was deliberately REMOVED in v24.0.17 by operator decision (Issue #230).** The
evaluator microphone, the Load Intake and Smart Load Inbox voice buttons, the voice status
region and the module itself are all gone on purpose. On any generation from 24.0.17
onward, their absence is the intended end state — **not** a regression, **not** a missing
asset, and **not** a failed deploy. Declared runtime assets are **22** from 24.0.17 (23
before), and a parity or asset-coverage reading of "`voice-load.js` absent" is correct.
Load intake is paste and type only; do not test for or report a voice path.

**Not a live test queue.** A1-A13 is **deferred by the operator's 2026-09-16 decision** to the final post-v24.5 candidate and runs **once** against it. *(Section C is no longer part of that wait: the five raw files were supplied on 2026-09-18, the reconciliation ran, and all six PASS criteria are recorded in section C. Its deferral was conditioned on the files being missing, and they are not.)* **Production now serves 24.0.24 / DB16 / Worker v21 and both generations are OBSERVED, but that is still not the certification candidate** — the deferral names the final post-v24.5 candidate, and deploying a generation does not promote it into one. See `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before running any row below. The instrument is ready and remains open; it is deliberately not being run yet, and a partial A-section against a superseded generation is not evidence.

**Candidate-specific row text below is intentionally not being rewritten in this documentation-only handoff.** Per the deferral decision, A1, A3, A9, A10 and A11 must be re-verified against the final redesigned shell before the device gate runs. Until then, do not execute stale generation-specific instructions as though they describe the final candidate.

**The exact candidate SHA lives in the certification document, not here.** This file went two generations stale once (it read `24.0.9` / Worker `v15` while production served `24.0.10` / `v17`), which would have had a tester confirming the wrong build and recording a PASS for a candidate that is not the one being certified. It went one generation stale again at v24.0.11, and the certification document it defers to then went **two** generations stale at v24.0.12 — which is worth understanding, because it is the same drift one level up: removing the SHA from this file relocated the staleness into the document this file points at rather than removing it. The fix is keeping that document current on the day a shipped file changes, not copying the SHA back here where the two can disagree. When the deferral lifts, read the SHA out of the then-current superseding certification document immediately before testing and confirm the generation strings against Diagnostics and Worker `/health` on the device itself. If any disagree, stop — the disagreement is the finding.

All of section B and section D are now closed by observed live evidence recorded in the current certification authority. What remains open is exactly what a headless runner cannot reach: **A1-A13 on a physical iPhone**, deferred as stated above. **Section C has now run** — see that section for the structural result, and for the two things it deliberately does not cover: the separate 125-row 2026-08-24 master, and conflict review before adoption.

Do not convert source, deployment-build, preview, desktop, or older-generation evidence into a physical-device PASS.

Before testing, record the exact frozen production Git SHA/origin, displayed app generation, Diagnostics/service-worker identity, Worker `/health` generation, iPhone model, iOS version, and whether the test is in Safari or the installed Home Screen PWA.

Use synthetic/non-sensitive records where practical. Do **not** delete the installed PWA or clear Safari website data merely to make an update test pass; those actions can erase local IndexedDB evidence.

## A1. Safe install / update / launch identity

1. Record Diagnostics/install identity before changing anything.
2. Open `https://freightlogic-v2.fimseitef.workers.dev` in Safari.
3. Launch the existing Home Screen app, or install only if it is not already present.
4. Close/reopen online and verify **the frozen candidate's declared app generation** is active, on the exact candidate SHA named in the certification document. Read both out of that document immediately before testing — this step named `24.0.12` for five generations, which is the drift the rule two sections above exists to prevent, sitting inside the row that enforces it.
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

## A10. Pickup-feasibility gate (shipped v24.0.9; run against the frozen candidate)

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

**Run this only if the device is on iOS 27 or later; record the iOS version either way.** iOS 27 and Safari 27 shipped 2026-09-14 with 525 fixes, the largest count in a recent Safari release, and WebKit describes the release as existing features *behaving differently — more correctly — than before*. Thirty of those are SVG fixes. A correctness fix is still a rendering change, and **no automated gate in this repository can see it**: the six-width spec asserts no horizontal overflow and interactive geometry, not that a chart looks right, and the production service-worker gate asserts delivery and offline semantics, not pixels. See `docs/IOS27_SAFARI27_ASSESSMENT_2026-09-15.md`.

1. **F31 Earnings Trends chart.** With 4+ weeks of data, open Home → Money and inspect the trends chart in **both** week and month views. It is hand-built SVG — `<rect>` bars, a `<polyline>` net-overlay line, `<text>` labels. Confirm bars align to their baseline and axis, the overlay line tracks the bar tops, labels are not clipped or overlapping, and the values shown match the Money card's own figures. A chart that renders but reads *wrong* is the failure mode here, not a blank chart.
2. **Driver tab bar icons.** The five tabs carry inline SVG with explicit `stroke-width`, sized by CSS. Confirm every icon renders at the right weight and size, the centre Evaluate tab is not clipped, and the active tab is visibly distinguishable in both dark and light.
3. **Selects.** Open the evaluator with **More Details** expanded and tap through every select — currency, mode, day of week, strategic reason — plus Settings' vehicle class and the Load Intake selects. Confirm the native picker opens, option text is readable, and **the viewport does not zoom on focus** (v24.0.10: iOS zooms on any control under 16px computed size). Tapping a select must not scroll the driver out of the load being priced.
4. **Scroll anchoring.** FreightLogic opts out nowhere, so Safari 27 supplies this automatically. Paste into the Smart Load Inbox and confirm existing rows do **not** jump as the recent-paste bar renders above them. This is a "should now be better than before" check, not a pass/fail on a shipped fix.
5. **Persistent storage actually granted.** In Diagnostics, confirm storage is reported as persisted for the installed Home Screen app. Safari applies a seven-day cap to script-writable storage including IndexedDB; `requestPersistentStorage()` runs at boot, and this is the check that it was *granted* rather than merely requested. For a bookkeeping app this is the difference between believing the data is durable and knowing it.
6. **Background sync is still absent — confirm nothing depends on it.** iOS 27 does **not** add Background Sync, despite secondary coverage claiming otherwise. Close the app fully, reopen the next day, and confirm the cloud-backup paused banner appears with a working one-tap Resume. That banner is the mitigation and it must not have regressed.

PASS requires no visual regression in the SVG surfaces, no zoom-on-focus, persisted storage granted, and the cloud-backup paused banner behaving as specified. Record the iOS and Safari versions with the result — an A11 PASS on iOS 26 certifies nothing about iOS 27.

## A12. Zero-token driver onboarding (added v24.0.13) — **the storage-partition question**

**Prerequisite: the frozen candidate's declared app AND Worker generations must both be
deployed before this runs**, with the Worker first — the app calls `POST /admin/invites` and
`POST /claim`, and a Worker generation that predates them cannot answer. The historical minimum
this row was written against (Worker v18 / app 24.0.13) is met and long exceeded; production has
served **24.0.19 / Worker v20** since 2026-09-18. Do not treat that minimum as the bar. Read both
generations out of the certification document, confirm them against Diagnostics and Worker
`/health` on the device itself, and record both with the result — an A12 run against generations
other than the candidate's certifies nothing.

This gate exists because of one question no headless runner can answer, and the answer
determines whether a real driver is stranded.

1. **Owner setup.** On the owner's device, with App Lock enabled, open Settings →
   Cloud Backup → Admin. Paste the admin token once and save. Confirm it asks for the
   PIN, confirms "Admin access configured ✓", **clears the field**, and never shows the
   value again. Deliberately try a wrong token first and confirm it says so and stores
   nothing. Close the browser completely, reopen, open the panel: it must still say
   configured, and the first action must ask for the PIN rather than the token.
2. **Invite.** Tap Invite driver, enter a name, and confirm the share sheet carries a
   link and states an expiry ("link works until …"). Confirm nothing on this screen,
   including the modal, uses the word "token" or shows the raw code.
3. **Delivery by iMessage and by Mail.** Send the same invite both ways to the driver's
   phone. Both must open the app directly. Note whether either client rewrites or
   truncates the URL — a fragment is the part most likely to be mangled by a link
   preview or a redirect wrapper.
4. **Claim in Safari.** On the driver's iPhone, open the link in Safari. Confirm the
   claim wizard appears with no app chrome, that Continue stays disabled until the
   passphrase is 10+ characters, confirmed, and the checkbox ticked, and that the
   address bar no longer shows the code once the wizard is up. Complete the claim and
   confirm cloud backup is connected.
5. **THE QUESTION: Add to Home Screen.** Install the app to the Home Screen and open it
   from there. **Is the claimed token present, or is that a separate storage
   partition?** Record the answer explicitly — this is the whole reason A12 exists.
   - If the token is present: note it, and the flow is finished.
   - If storage is separate: the installed app will have nothing. Open the SAME invite
     link again from the Home Screen app and walk the re-claim end to end. It must
     succeed, and the Drivers list on the owner's device must still show **one** driver
     with their backup count intact — not a second account. A second `userId` would
     orphan every backup made before the install, which is the failure this path exists
     to prevent. Record the result either way.
6. **Invite expiry and single use.** Confirm a fourth claim of the same link is refused
   with "already been used" rather than silently creating anything.
7. **Revoke.** From the owner's device, Remove the driver. Confirm the driver's app
   stops backing up, and that opening their old invite link again is refused rather
   than reactivating them.

PASS requires the answer to step 5 recorded explicitly, one driver account surviving
the whole sequence with its backup count intact, and no token or code visible to
either person at any point.

## A13. Screenshot intake on a real iPhone (added v24.0.21, Issue #252)

**Requires Worker v21 deployed — SATISFIED.** The screenshot path calls `POST /extract-image`,
which does not exist on Worker v20; against a v20 Worker every attempt fails and this row would be
BLOCKED, not FAIL. Worker v21 is deployed and live-observed (`/health` reporting `21` in live
parity `35424880453`), so the prerequisite is met and this row is OPEN. Confirm `/health` still
reports **21** before starting anyway: the prerequisite is a live fact, not a permanent one, and a
Worker redeploy can move it.

This row exists because the three ways an image can reach the app behave differently in an
**installed** Home Screen PWA than in a Safari tab, and no headless environment can tell you
which ones actually deliver a file. The picker is the designed-guaranteed path; the other two
are additions.

1. **Photos / Files picker.** More → Load Intake → **Photos / Files**. Choose a real
   DispatchLand (or comparable) screenshot. Confirm an extraction returns and the review step
   opens with values in it.
2. **Screenshot / camera capture.** Repeat through the **📷 Screenshot** control. Record
   whether iOS offers the share/photo sheet and whether the chosen image arrives.
3. **Clipboard paste.** Copy a screenshot, long-press the text box, Paste. Record whether an
   image is delivered or whether iOS pastes nothing — **either answer is a valid result**, and
   a "nothing" here is the reason the picker exists. Do not record this as a failure of the row.
4. **UNKNOWN deadhead survives to the evaluator.** Use a posting that does **not** state a
   deadhead. Confirm the Deadhead box is **blank**, that the review note says blank means
   unknown rather than zero, and that scoring it asks for the figure instead of grading on an
   invented zero. This is the assertion that matters most on a device: a fabricated `0`
   overstates True RPM invisibly.
5. **Explicit zero survives.** Use a posting stating zero deadhead (or type `0`). Confirm the
   evaluator receives `0` and grades, rather than asking again.
6. **Review beats the model.** Change one extracted value by hand before scoring. Confirm the
   canonical result reflects **your** value, not the extracted one.
7. **No second evaluator.** Confirm the decision card is the ordinary canonical result —
   verdict, grade, True RPM, bid range — and that nothing on screen is an AI-authored grade,
   rate-per-mile or recommendation.
8. **Failure falls back.** Turn Airplane Mode on and try a screenshot. Confirm a plain error
   that points at pasting/typing, that the text path still works, and that no empty review
   form opens.

PASS requires step 1 working, steps 4 and 5 both correct, step 6 correct, and steps 2/3
**recorded with whatever they actually did** rather than marked PASS by assumption.

**The certification runner now carries this row.** This paragraph previously read *"the
certification runner does not carry this row yet"* and instructed recording A13 manually; that
was accurate when written and has since been satisfied. A13 was added to this checklist — the
instrument of record — and requested through `/.agents/inbox/` rather than edited across lanes,
because `field-certification.js` and `tests/integration/field-certification-runner.spec.mjs` are
both GPT-owned under `.agents/LANES.md`. The GPT lane landed it: the companion now exposes
`A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13` and `FC-01`/`FC-12` assert that exact identity and
order, `FC-12` requires A13 to carry its own camera, clipboard and UNKNOWN-deadhead evidence
controls rather than a bare PASS button, and `FC-15` asserts A13 BLOCKS below Worker v21 and
accepts a recorded iOS non-delivery without accepting a fabricated deadhead zero.

The reason the old wording mattered still holds and is why this correction is recorded rather
than quietly overwritten: **a runner that has never heard of A13 cannot report it missing**, so
A1-A12 complete was never A13 evidence. That gap is now closed in the instrument itself.

# B. Live deployment blockers

Run these against the same final production candidate used for A1-A13. See `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the detailed procedure.

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

# C. Private-history reconciliation — **RECONCILIATION RUN, criteria PASS**

The five raw 2026-08-27 files were supplied by the operator on 2026-09-18 and the
reconciliation was run. **Raw rows stay outside the public repository** — nothing below
is a cell value; this is the non-sensitive structural result the gate asks to be recorded
publicly.

**The bundle is the authentic recovered source, not a reconstruction**, and that is
asserted on independent evidence rather than on the supplier's manifest. This section
already recorded, from the earlier private recovery, that preflight reports **216 source
rows** and that the unchanged adapter deterministically produces **149 candidate
records**. Both numbers reproduced exactly, on a run that had no access to the previous
one. The two documented per-file row counts (`text 2.csv` 58, `RECOVERED_…` 26) also
matched independently, and the supplied manifest's SHA-256 for all five files matched the
bytes actually present.

`node scripts/verify-history-bundle.mjs <bundle>` → **0 blocking problems, 0 warnings**,
5 of 5 required files, 216 data rows. `node scripts/m6-import.mjs` → 149 records.

PASS criteria, each verified against the produced records rather than assumed:

| Criterion | Result |
|---|---|
| No invented broker identity | **PASS** — `broker` is set only from `COMPLETE-UNIFIED-DATA.csv` (50) and `All_Trips_App_Import_v1.csv` (32), never from `text 2.csv`'s `Carrier`, which stays in its own `carrierLabel` field on 58 records. 67 records keep broker deliberately empty rather than inferred. |
| No unsupported WON/completed promotion | **PASS** — `dry_run` → `awarded:false` (2), `live_quote` → `awarded:false` (4), `chat_captured` → `awarded:null` (2, tri-state preserved, no award invented), unrecognized statuses 0. The 116 rows with no status column are all `kind: ORDER` / `opportunity: WON`, 114 of them `execution: DELIVERED`, from the three historical-trip files — the award is inherent to the record class, not a promotion. |
| No UNKNOWN-to-zero coercion | **PASS, exactly** — `deadMi` is null on 141 and positive on 8, with **zero zeros**: not one unknown became 0. `trueRpmDefensible` false on 139 = the reported `missingDeadhead` and `withheldFromTrueRpm` counts, and 139 + 4 true + 6 null = 149. |
| Preserved source timestamps/semantics | **PASS** — 138 timestamps retained as 13-digit epoch ms; 11 records carry no timestamp and are left **null** rather than defaulted to import time. All 138 are midnight UTC because **the source files are date-only**; nothing was truncated, there was no clock precision to lose. |
| No collapse of distinct shipments sharing an external ID | **PASS** — 5 external order numbers appear on more than one record, retaining 5 extra records, matching the adapter's own `reusedIdKeptSeparate: 5`. `withheld.json` carries the withheld row with its `reason`. |
| Deterministic re-import / idempotence | **PASS** — a second import into a clean directory produced **byte-identical** `import-report.json`, `records-for-import.json` and `withheld.json`. |

**One judgement call for the operator, flagged rather than absorbed:** a single
`in_progress` row carries `awarded: true`. That is defensible — *awarded* means the bid
was won, not that delivery finished, and its `execution` is `NOT_STARTED` rather than
`DELIVERED` — but it is the one award in the set that rests on reading the status that
way, so confirm it before adoption.

**Still open, and not covered by this bundle.** The separate **125-row 2026-08-24 master
CSV** is not in it; the supplied README says so explicitly and this run neither contains
nor substitutes for it. Do not reconstruct that master from summaries. Adoption also
still requires the conflict review before records are imported into a live database —
this run produced the candidate set and its evidence; it did not adopt them.

Re-run this gate against the final post-v24.5 candidate if the adapter changes, since the
result is a statement about that adapter. What is no longer true is the previous status:
the source files are no longer missing and the reconciliation is no longer un-run.

# D. Six-width browser-layout gate — **PASS**

This is separate from the physical iPhone gate. The source repairs are in: 16px mobile form controls (v24.0.10 removed the two inline `font-size:13px` values that were the root cause, so the `!important` safety net is no longer load-bearing), the 44×44 small-screen target, broad reduced-motion handling, and tertiary-label contrast above 4.5:1 in both themes.

The requested geometry gate exists and runs in the suite on every PR and push: `tests/integration/six-width-layout.spec.mjs` observes 320, 375, 390, 393, 430 and 440 CSS-px in both theme states, proves no page-level horizontal overflow across the five surfaces, checks bottom-nav interactive geometry, and covers a narrow-width modal under reduced motion.

Two measurement traps are worth knowing, because the first version of this gate was green while measuring nothing:

- `document.documentElement.scrollWidth` **cannot** detect overflow in this app — `styles.css` sets `body { overflow-x: hidden }`, so the page never reports a scrollWidth wider than the viewport however far content spills. Injecting `min-width: 900px` left a scrollWidth assertion green.
- Under mobile emulation the layout viewport **expands** to fit content wider than the device (`innerWidth` read 900 at a 320px device), so geometry compared against `innerWidth` is compared against a viewport that already grew to accommodate the overflow. Measure against the device width the test set.

This is still **not** a substitute for iOS safe-area, software-keyboard, or Home Screen PWA evidence. Those are A1-A13.

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

The release remains **HOLD**. Every gate in the list this paragraph used to enumerate is now closed by observation on the current candidate — live production all-asset parity, authenticated Worker authority/backup smokes, six-width browser-layout acceptance, and truthful rollback/fix-forward evidence — and they were first recorded with their run IDs in `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-15.md`. **That document is no longer the authority and must not be cited as one** — the chain has since resolved forward to `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-19.md`, which `scripts/m7-certify.mjs` resolves by explicit supersession rather than by date order. Read the authority out of that runner, not out of this sentence.

What holds the release is now exactly **one** thing: the applicable physical-iPhone blockers in this file (**A1-A13**) are not PASS. This paragraph previously said *"exactly two things"* and named the unreconciled private-history bundle as the second. That was accurate when written and is now superseded: the operator supplied the five raw 2026-08-27 files on 2026-09-18, the reconciliation ran, and all six PASS criteria are recorded in section C. The current authority's own status line names A1-A13 as the only remaining gate. Two caveats from section C survive and are **not** release blockers: adoption still requires the conflict review, and the separate 125-row master CSV remains unavailable and must not be reconstructed from summaries.

Any later certification-state document must explicitly supersede `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-19.md` before the release is frozen.
