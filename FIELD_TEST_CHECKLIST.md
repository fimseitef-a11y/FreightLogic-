# FreightLogic Field Test Checklist

Purpose: the finite **Milestone 7 physical-device certification gate** for the named FreightLogic completion release, plus a separate long-horizon resilience watch list.

Authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md`.

The automated suite must already be green on the exact release-candidate SHA before the blocking device checks below are treated as certification evidence. Do not mark a field check passed from an emulator, desktop browser, AI description, or an old app generation.

## Record before testing

For the candidate being tested, record:

- candidate Git SHA;
- live FreightLogic URL;
- app/PWA version displayed by the candidate;
- Worker `/health` version reported by the candidate deployment;
- iPhone model;
- iOS version;
- whether testing from Safari tab or installed Home Screen PWA.

Use non-sensitive synthetic/test entries where possible. Do not put private financial/history source files into screenshots or issue comments.

---

# A. Completion-release blocking device checks

These are the representative iPhone/offline/GPS checks required by Milestone 7. They are intentionally finite; the week-long observations later in this file are useful resilience evidence but are not a reason to hold a technically ready release candidate for eight days.

## A1. Install, launch, reload, and update path

**Steps**

1. Open the exact release-candidate deployment in iPhone Safari.
2. Add FreightLogic to the Home Screen if it is not already installed.
3. Launch from the Home Screen.
4. Reload/reopen once while online.
5. Close the app fully, reopen it, and verify the same candidate generation is active.
6. If this candidate is replacing an older installed generation, verify the normal update flow reaches the new generation rather than serving stale cached `app.js`/service-worker assets.

**Pass**

- app opens without startup error;
- no blank/stuck shell;
- expected candidate version is visible/diagnosable;
- existing local data remains present;
- installed PWA does not remain on an older cache generation after the update flow.

**Fail**

- old generation remains active after the documented update path;
- blank shell, repeated reload loop, startup error, or missing existing local data.

---

## A2. One-handed decision journey + UNKNOWN-vs-zero integrity

Use a harmless synthetic cargo-van load.

**Steps**

1. Enter a normal candidate with all required material facts, including an explicit deadhead value.
2. Run the normal driver-facing evaluation journey one-handed on the phone.
3. Confirm the displayed verdict, grade, True RPM, and bid range are readable and internally coherent.
4. Repeat with the deadhead/material required field **blank**.
5. Repeat with the same field explicitly entered as **0**.

**Pass**

- complete input yields the expected canonical decision surface;
- blank/unknown material input produces `UNAVAILABLE`/unknown behavior and does not manufacture a numeric True RPM, grade, or bid;
- explicit `0` remains a known zero and is not treated as blank;
- Confidence/Evidence remains descriptive and does not replace the canonical verdict/grade/economics/bid.

**Fail**

- blank becomes zero;
- unknown load shows fabricated `REJECT`, `F`, `$0.00`, numeric True RPM, or a bid range;
- AI/Worker output replaces the client-owned canonical fields.

---

## A3. Production manual/email-compatible intake survives reload

Run this only after M5B is production-wired on the candidate. A helper exposed only through tests does not qualify.

**Steps**

1. From the shipped driver-facing intake surface, create one synthetic opportunity manually (or through the shipped email-compatible intake path).
2. Include an external amount whose semantic is **not carrier payout** (for example a clearly labelled shipper/bookable or target price if the UI supports that semantic).
3. Save/confirm through the real production path.
4. Close the app completely and reopen it.
5. Reopen the opportunity/evidence details.

**Pass**

- opportunity still exists after reload;
- source/provenance and price/mileage semantics still exist;
- a non-carrier price has **not** become canonical carrier revenue;
- unknown deadhead/mileage stays unknown rather than becoming zero;
- lifecycle state is conservative (normally `SEEN`/equivalent unless explicit evidence justified a later state).

**Fail**

- evidence exists only until reload;
- source timestamp/provenance disappears;
- shipper/target/bid money becomes operator revenue;
- missing mileage becomes zero;
- intake silently creates `WON`, `DELIVERED`, or `PAID` without evidence.

---

## A4. Offline full-use round trip

**Steps**

1. While online, confirm the PWA is fully loaded.
2. Enable Airplane Mode.
3. Create/edit representative local data: one trip/opportunity, one expense or fuel entry, and one lifecycle/status action available in the shipped UI.
4. Close and reopen FreightLogic while still offline.
5. Confirm the offline entries remain.
6. Disable Airplane Mode and reopen once more.

**Pass**

- installed app launches offline;
- offline saves persist across close/reopen;
- reconnect does not duplicate, erase, or mutate the offline records;
- no permanent reconnect/error spinner remains.

**Fail**

- app cannot launch offline after prior installation;
- data disappears on offline reopen or reconnect;
- duplicates appear after reconnect;
- unknown values are silently filled during reconnect.

---

## A5. Local export/import round trip on the candidate

Use synthetic/non-sensitive records.

**Steps**

1. Create or identify a small test set containing at least a trip, expense/fuel item, lifecycle row, and normalized opportunity evidence if M5B is present.
2. Run the shipped local export/backup action.
3. Preserve the exported test file.
4. Use the shipped import/restore path on a disposable test profile/state or after otherwise making the test safe to restore.
5. Reopen the restored records.

**Pass**

- protected data classes round-trip intact;
- lifecycle/evidence semantics and provenance survive;
- missing deadhead stays missing;
- integrity/checksum validation accepts the untouched export and rejects a deliberately corrupted test payload when the UI/tooling exposes that check;
- no duplicate lifecycle/evidence rows are created by an idempotent re-import where the contract says they should dedupe.

**Fail**

- lifecycle/evidence is absent after restore;
- provenance/semantic fields disappear;
- unknown mileage becomes zero;
- export says success but imported protected data differs materially.

---

## A6. Real-device GPS background resilience

**Steps**

1. Start GPS trip tracking.
2. Drive/move a representative distance.
3. Background the app or lock the iPhone for at least 10 minutes during the trip.
4. Return to FreightLogic.
5. Complete/stop the test trip.

**Pass**

- trip remains active or resumes through the intended recovery path;
- mileage is plausible for the movement actually made;
- any degraded/incomplete tracking state is explicitly labelled rather than shown as confidently precise.

**Fail**

- tracking silently stops with no recovery state;
- mileage resets to zero or is wildly wrong without warning;
- orphaned trip cannot be recovered through the shipped path.

---

## A7. GPS permission loss mid-trip

**Steps**

1. Start a test GPS trip.
2. Revoke location permission in iOS Settings while the trip is active.
3. Return to FreightLogic and then stop/review the trip.

**Pass**

- FreightLogic clearly reports location loss/degraded tracking;
- mileage is limited to known tracked distance or marked incomplete/estimated;
- an unreliable figure is not presented as verified precise mileage.

**Fail**

- permission loss is silent;
- a suspect precise mileage flows into the trip/tax surface with no provenance warning.

---

## A8. Stale-edit conflict on a real browser/device

This confirms optimistic concurrency behavior outside the test harness.

**Steps**

1. Open FreightLogic in two Safari tabs/windows using the same local profile.
2. In Tab 1, open the same existing trip (or the supported expense/fuel record) and save a change.
3. Without refreshing Tab 2, save a conflicting edit to that same record.

**Pass**

- stale save is rejected/refreshes to the latest version with a clear conflict message;
- Tab 1's newer value is not silently overwritten.

**Fail**

- both saves appear successful and the later stale form silently destroys the first edit.

---

# B. Live deployment checks

These are release blockers too, but Claude/automation can perform most of them. Record their result against the same exact candidate SHA used for the iPhone tests.

## B1. Cloudflare generation parity

**Pass requires**

- live Pages/Worker deployment resolves to the expected candidate generation;
- app/PWA/service-worker/manifest/cache-buster/Worker markers agree with the final selected release generation;
- no stale preview/branch deployment is mistaken for production.

## B2. Worker health and auth boundary

**Pass requires**

- `/health` reachable and reports the expected Worker generation/bindings;
- unauthorized admin request returns the expected denial;
- no secret/token is exposed in response/logging surfaced to the client.

## B3. Live `/evaluate` authority-boundary smoke test

With a non-sensitive fixture:

**Pass requires**

- complete canonical decision can be explained without Worker recomputing/replacing verdict, grade, True RPM, or bid;
- incomplete canonical decision preserves `UNAVAILABLE`, unknown grade, `trueRPM=null`, and suppressed/null bid rather than manufacturing `REJECT/F/$0.00`.

## B4. Live `/extract` smoke test

If `/extract` is part of the deployed candidate, use a non-sensitive synthetic fixture.

**Pass requires**

- extraction returns only the bounded evidence shape it is authorized to return;
- no hidden bid/verdict/lifecycle inference;
- extraction failure/no-data remains explicit rather than fabricated.

## B5. Rollback point

**Pass requires**

- exact rollback SHA/release is recorded;
- documented rollback procedure is executable, not merely descriptive.

---

# C. Non-blocking long-horizon resilience watch list

These checks are valuable after the finite completion gate. Record failures as follow-up defects, but do not claim they were performed if the observation window has not elapsed.

## C1. 7–8 day cold-storage observation

1. Record current test trip/expense counts.
2. Leave the installed app unused for 8+ days.
3. Reopen the Home Screen PWA.

**Watch for:** local data loss, startup failure, stale cache generation, or storage-warning behavior that is misleading on the actual iOS version.

## C2. Storage-pressure save failure

With device storage under deliberate pressure, save a test trip with receipt images.

**Pass expectation:** explicit storage/error handling; no silently half-written operational record.

## C3. DST / clock-boundary observation

Around an actual DST or year boundary, record a trip near the local transition.

**Pass expectation:** intended local calendar date agrees across trip list, money/week buckets, and tax export; lifecycle source timestamps retain their real clock/time-zone meaning where captured.

---

# Certification record

For the named completion release, record each blocking item as one of:

- `PASS` — personally/actually observed on the exact candidate;
- `FAIL` — observed defect, include reproduction evidence;
- `NOT RUN` — never convert this to PASS from inference;
- `NOT APPLICABLE` — only if the canonical completion plan says the feature is non-blocking/not shipped in this release.

Minimum report for a failure:

- checklist ID (`A1`, `A2`, etc.);
- exact candidate SHA/version;
- iPhone model + iOS version + Safari/Home Screen context;
- reproduction steps;
- screenshot when useful;
- whether local data was lost/changed;
- whether an export/backup existed before the failure.

The completion release is not certified until all Milestone 7 blocking automated, deployment, and physical-device checks applicable to the candidate are PASS and the current certification-state document has no remaining proof-backed runtime blocker.
