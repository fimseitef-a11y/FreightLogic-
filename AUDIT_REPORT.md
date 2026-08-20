# FreightLogic — Adversarial Audit Report

Audited against v23.8.3. F-1…F-6 were fixed within that version; F-7 and F-8 were fixed in
v23.8.4.

Audit date: 2026-08-19, updated through phase 7 (fixes) and the automatable subset of phase 4
(field resilience). Scope: `app.js` (16,145 lines), `index.html`, `service-worker.js`,
`voice-load.js`, `admin-driver-ui.js`, `midwest-stack-authority.js`, `cloud-backup-worker.js`.
Method: static reading + a real Playwright/Chromium harness against the live app (real
IndexedDB, real Cache Storage, real `crypto.subtle`) — no mocks, no reimplementation of app
logic. Test suite lives in `tests/` and is committed. **All 8 findings are now FIXED** —
see the Findings table's Status column and each finding's own section for the fix, the commit,
and the post-fix reproduction. F-7 and F-8 surfaced during phase 4, were logged rather than
fixed pending the owner's decision, and were **fixed in v23.8.4** once that decision came —
see "New findings from Phase 4" below. Phases 5–6 (full E2E journeys, one-handed usability)
are still outstanding.

## Executive Summary

Six findings, all reproduced against the running app with a passing/failing automated test
and an exact `file:line`. Two are money-critical: the Schedule‑C tax export silently corrupts
column alignment on any comma in a trip's origin/destination (nearly guaranteed in normal
"City, ST" usage), and the Dead Zone Exit "hard cap at C" is dead code — it can never fire,
so a driver taking a legitimate survival-mode DZ load sees a red "F" instead of the documented
orange "C," and the session history strip disagrees with the main card about the same
evaluation. Two are security/data-integrity gaps with no severity ceiling on abuse: the App
Lock PIN has no brute-force lockout (a 4-digit PIN falls in under 20 minutes to a console
loop), and two tabs/devices editing the same trip silently lose whichever change was saved
first — no version check, full-object overwrite. One is an unvalidated field
(`trip.paidDate`) that bypasses the same-file validation every sibling date field gets,
propagating to broker pay-speed analytics with inconsistent downstream bounds-checking. One
is informational: the "test exports" object on `window` is unconditionally live in
production despite its own comment claiming a gate that doesn't exist in code. RPM
consistency, tier-boundary exhaustiveness, prototype-pollution guarding, CSV-formula
neutralization, and the cloud-backup crypto all held up under fuzzing and are documented
clean below. Phase 4 (field resilience)'s automatable subset has now been run against the real
app — storage quota, offline-then-reconnect, DST/clock-skew, and GPS resilience — and surfaced
two more real findings: Add Expense and Add Fuel were completely broken for every new record
(F-8, Critical — an uncaught IndexedDB error with no error shown to the driver), and a single
transient GPS blip mid-trip killed tracking with only an undocumented reload as a recovery path
(F-7, High). Neither was offline-specific; F-8 in particular reproduced on every attempt,
online or off. Both were logged rather than fixed on the spot, and both were **fixed in
v23.8.4** after the owner approved. Phases 5–6 (full E2E journeys, one-handed usability) were
**not executed dynamically** — see "What could NOT be tested" — this report does not claim
coverage there.

## Findings

| ID | Severity | Area | Status | Description |
|----|----------|------|--------|-------------|
| F-1 | **Critical** | F20 Dead Zone Exit | **FIXED** | Grade cap "at C" was dead code — DZ-active loads always showed raw grade F; eval-history strip disagreed with the main card for the identical evaluation |
| F-3 | **Critical** | Tax export (F30) | **FIXED** | Schedule C mileage-log CSV had no field quoting — any comma in trip origin/destination corrupted column alignment |
| F-4 | **High** | App Lock / auth | **FIXED** (policy approved by owner before implementation) | PIN unlock had no brute-force lockout, backoff, or attempt cap — bounded only by PBKDF2 cost (~115ms/attempt measured) |
| F-6 | **High** | Trip storage (TOCTOU) | **FIXED** | Two tabs/devices editing the same trip: last save silently reverted the other tab's unrelated field changes (full-object overwrite, no version check) |
| F-2 | **Medium** | AR / trip storage | **FIXED** (+F-2b: `sanitizeStop.date` had the same gap) | `trip.paidDate` bypassed `isValidISODate()` (unlike every sibling date field); downstream consumers applied inconsistent bounds-checking |
| F-5 | **Low / Info** | Attack surface | **FIXED** | `window.__FL_TESTS` was unconditionally exposed in production; its own comment claimed a gate (`__FL_TESTS_ENABLED`) that didn't exist in code |
| F-8 | **Critical** | Expense/Fuel storage | **FIXED in v23.8.4** | Add Expense and Add Fuel were completely broken for every new record — an uncaught IndexedDB `DataError` on save, no toast, no data written. Found during Phase 4 |
| F-7 | **High** | F21 GPS Trip Tracking | **FIXED in v23.8.4** | A single transient GPS error (or permission revocation) mid-trip killed the live tab's tracking session; the only visible recovery action ("Start Trip") abandoned the accumulated miles instead of resuming them. Found during Phase 4 |

\* commit hash recorded at the time this table entry was last updated; see the finding's own
section below for the authoritative hash if this table is stale relative to it. F-7 and F-8
were discovered during Phase 4 (field resilience), outside the originally-approved Step 1 fix
list — logged with full reproduction rather than fixed unilaterally, per this audit's own
established discipline for findings surfaced mid-testing (see F-2's date-field audit). The
owner subsequently approved both, and they shipped in v23.8.4.

---

## Correctness pass on this report itself (phase 7, step 0)

Before any fix, the audit brief asked me to close an evidence gap: **not every finding
actually had a failing assertion**, contradicting the original report's closing line ("F-1/F-5
are proven via passing assertions... F-2/F-3/F-4/F-6 are proven via a failing assertion each").
That line was accurate — the gap is real — but note the brief's own guess at which two findings
lacked one ("I believe F-2 and F-5") was itself wrong: **F-2 already had a failing assertion**
(`tests/unit/pure-functions.spec.mjs`, verified in the very next test run below). The two
findings that actually had no red assertion were **F-1 and F-5**. Both were rewritten to assert
the documented-correct behavior (and fail against the pre-fix code) rather than assert that the
bug reproduces — see the harness/test diffs in commit `df69fb8`. Post-correction, a full run
showed 7 failing assertions across all 6 findings (F-1 contributed two: the main grade-cap
check and the eval-history-agreement check).

**Second-order correction, found while fixing F-1:** the DZ-exit test's dynamic "evidence"
in the *original* report was not actually valid proof, for an unrelated reason. The evaluator's
DZ no-reload confirmation checkbox lives inside a collapsed native `<details>` element the
original test never expanded, and its `page.check(...)` call was wrapped in `.catch(()=>{})`
that silently swallowed the resulting timeout — so DZ mode was never actually activated in that
test run. The "grade F" it captured was simply the correct, ordinary grade for a genuinely
low-RPM load, misread as proof of the cap bug. The underlying finding was still real: re-running
a corrected version of the same test (details expanded, checkbox failures no longer swallowed,
and gated on the DZ-only "Active: ... — Grade capped at C" string rather than the looser
"Dead Zone" text that also appears in the merely-*eligible* state) against the **pre-fix** code
reproduced the bug exactly as described (`grade: "F", gradeLabel: "REJECT"`); against the
**post-fix** code it shows the documented `"C"` in all three DZ sub-tiers. See
`tests/integration/dz-exit-grade-cap.spec.mjs` and the F-1 section below for the full
before/after evidence.

---

### F-1 — Dead Zone Exit "capped at C" never actually happened — FIXED

**Status: FIXED** (see the "fix F-1: DZ grade cap" commit in `git log`).

**Where:** `app.js:6296-6303` (`dzClassifySubTier`), `app.js:6515-6528` (grade computation +
display cap), `app.js:6685-6692` (session eval-history write), `app.js:7415-7433`
(`_renderEvalHistory`), documented behavior at `app.js:6793` and `app.js:7107`
("... — capped at C").

**The bug:** `dzClassifySubTier()` only returns a non-null sub-tier (activating DZ mode) when
`dzFloor (0.90) <= trueRPM < MW.hardRejectRPM (1.25)`. The raw letter-grade thresholds
(`app.js:6515-6520`) put *any* `trueRPM < 1.25` at grade **F** — there is no RPM value for
which DZ mode is active and the raw grade is A or B. But the display-cap logic was:

```js
const dzDisplayGrade = isDZActive ? (['A','B'].includes(grade) ? 'C' : grade) : grade;
```

Since `grade` can only ever be `'F'` while `isDZActive` is true, the `'A'/'B' → 'C'` remap
could never fire, and `dzDisplayGrade` just equalled the raw `'F'`. The hero card rendered a
big **F**, colored orange, not the "C" the Settings panel and in-card copy explicitly promise
(`app.js:6793`: *"DZ-FLOOR $0.90 • DZ-ACCEPTABLE $1.00 • DZ-STANDARD $1.10 — capped at C"*).
Separately, `histEntry` stored the **raw, uncapped** `grade`/`gradeColor`/`gradeLabel`, so the
"Recent Evaluations" strip showed **red "F" / "REJECT"** for the exact same evaluation the main
card just labeled an orange DZ-EXIT "survival" load.

**Fix:** `dzDisplayGrade = isDZActive ? 'C' : grade` — an unconditional cap. This is safe (not
just "usually correct") because `isDZActive` can only be true when `trueRPM < MW.hardRejectRPM`
(1.25), which is exactly the domain where the raw grade computation always yields `'F'` — so
the fix doesn't depend on that constant relationship holding by luck; the new structural fuzz
test below re-verifies it on every run instead of assuming it. `histEntry` now stores
`dzDisplayGrade`/`dzDisplayGradeLabel`/`dzDisplayGradeColor`/`dzDisplayGradeEmoji` instead of
the raw values, so the history strip agrees with the main card. Option (a) from the original
proposed-fix section below — the language honesty option (b) was not pursued.

**⚠️ Methodology correction:** the dynamic "evidence" in the *original* version of this report
was not valid proof, for a reason unrelated to the bug itself. The DZ no-reload confirmation
checkbox (`#mwDZNoReloadToggle`) lives inside a collapsed native `<details id="mwEvalDetails">`
the original test never expanded, and its `page.check(...)` call was wrapped in a
`.catch(()=>{})` that silently swallowed the resulting timeout — so DZ mode was **never
actually activated** in that test run. The "F" grade captured was simply the ordinary, correct
grade for a genuinely low-RPM load; the "DZ text present" check was also a false positive,
matching the merely-*eligible* banner text ("DEAD ZONE EXIT MODE") that renders before
confirmation, not the activation-only "Active: ... — Grade capped at C" string. The underlying
finding was still real — re-running a corrected methodology (details expanded, checkbox
failures no longer swallowed, gated on the activation-only string) against the pre-fix code
reproduces it exactly:

```
[evidence, pre-fix, corrected methodology] hero grade element text during a genuinely
  active DZ-Exit: "F DZ"
[evidence, pre-fix] fl_eval_hist[0] = {"grade":"F","gradeLabel":"REJECT","gradeColor":"var(--bad)"}
```

**Reproduction (post-fix, current suite):** `tests/integration/dz-exit-grade-cap.spec.mjs`.
Drives the real evaluator UI (Portland, OR → Chicago, IL, 1900 loaded miles) across all three
documented DZ sub-tiers (revenue swept so trueRPM lands in DZ-FLOOR ~$0.95, DZ-ACCEPTABLE
~$1.05, DZ-STANDARD ~$1.20), explicitly expanding `#mwEvalDetails` and checking
`#mwDZNoReloadToggle` for real (no swallowed failures), gating activation on the
`"Active: ... capped at C"` string:

```
[evidence] DZ-FLOOR ($0.90-$0.99, needs 500mi+ saved): isReallyActive=true heroGrade="C DZ"
[evidence] DZ-ACCEPTABLE ($1.00-$1.09): isReallyActive=true heroGrade="C DZ"
[evidence] DZ-STANDARD ($1.10-$1.24): isReallyActive=true heroGrade="C DZ"
[evidence] fl_eval_hist[0] = {"grade":"C","gradeLabel":"DZ-ACCEPTABLE","gradeColor":"#f0a500"}
```

Plus two regression guards: a structural fuzz (`dzClassifySubTier` swept across 6,300
`dzFloor x trueRPM x distanceSaved` combinations, confirming activation never occurs outside
`[dzFloor, MW.hardRejectRPM)` — the invariant the fix's safety depends on) and a negative
control (a non-DZ, grade-A load 90mi from home is confirmed NOT force-capped to "C"). All 7
tests in the file pass. `tests/unit/pure-functions.spec.mjs`'s Omega-tier-exhaustiveness and
`OMEGA_TIERS` band-overlap tests were re-run and are unaffected (this fix never touches
`omegaTierForMiles`/`OMEGA_TIERS`/`mwClassifyRPM`) — still 12/13 passing (only F-2 red, as
expected, unrelated to this fix).

**Impact:** No dollar loss by itself, but this was exactly the kind of trust-eroding
inconsistency the spec calls out — a driver skimming the eval-history strip later would
reasonably have read a past DZ-Exit as a rejected/bad load, undermining the feature's whole
purpose (giving confidence to take a legitimate survival-mode load). Fixed.

---


---

### F-3 — Schedule C tax-export CSV had no field quoting — FIXED

**Status: FIXED** (see the "fix F-3: quote CSV fields..." commit in `git log`).

**Where:** `app.js:12446` (the export line, now removed), `app.js:12438-12439` (unquoted
free-text fields fed into it), contrast with the correctly-quoted general export at
`app.js:1349` and the shared `downloadCSV()` helper at `app.js:1347-1356`.

**The bug:** The general trip/expense/fuel CSV export quotes every cell via `downloadCSV()`:
```js
function downloadCSV(rows, filename){
  const bom = '﻿';
  const csv = bom + rows.map(r => r.map(c => `"${csvSafeCell(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  ...
}
```
The Tax Season Export (F30) mileage log hand-rolled its own CSV join instead of calling that
helper, and didn't quote:
```js
const csv = rows.map(r => r.map(v => csvSafeCell(v)).join(',')).join('\r\n'); // old app.js:12446
```
`csvSafeCell` only guards against **formula injection** (leading `=+-@|%!`); it does nothing
about commas. The mileage-log rows embed `trip.origin`/`trip.destination` — free text the app
itself autofills/suggests in "City, ST" form throughout the UI. Any trip with a comma in either
field silently shifted every subsequent column (Loaded Mi, Deadhead Mi, Total Mi, Rate,
Deduction) for that row when opened in Excel, Numbers, or accounting software.

**Fix:** Deleted the F30 export's hand-rolled CSV join/Blob/anchor-click code and replaced it
with a call to the existing, already-correct `downloadCSV(rows, filename)` helper — the same
one the general export already used. This is reuse, not a parallel fix: there is now exactly
one CSV-writing code path with field quoting in the app, so this exact bug class can't reopen
in a third export later without also being caught by the same helper's tests.

**Reproduction (post-fix):** `tests/integration/tax-export-csv-corruption.spec.mjs`, 4 tests:
1. Seeds a trip with `destination: 'Springfield, IL'`, exports, and — using the app's own
   quote-aware CSV parser (`parseCSVLines`, not a naive `split(',')` that would still
   misreport a properly-quoted comma as 2 cells) — confirms the row parses to exactly as many
   columns as the header, with `"To"` round-tripping to `"Springfield, IL"` exactly and the
   deduction figure landing in the correct column.
2. **Three-way reconciliation** (the audit's re-verification requirement): seeds two trips
   with known pay/mileage, and confirms the per-trip sum computed in the test, the *rendered*
   Schedule C summary card's numbers, and the numbers inside the *exported CSV*'s summary
   section all agree to the cent.
3. **Year-boundary bucketing**: seeds one trip dated 2025-12-31 and one dated 2026-01-01,
   confirms the 2025 export includes only the former and the 2026 export includes only the
   latter.
4. (Covered in test 1) Standard-mileage deduction figure unaffected by the fix.

```
[evidence] data row (parsed): ["2026-03-01","AUDIT-CSV-1","Chicago, IL","Springfield, IL","200","0","200","0.725","145.00"]
[evidence] rendered card: gross=$1,700.00 mileage=$253.75   (matches per-trip sum and CSV summary exactly)
```

All 4 pass. **Scope note** on the audit's "standard-mileage vs actual-expense split"
re-verification ask: FreightLogic's Tax Season Export only ever implements the standard-mileage
deduction (`IRS.MILEAGE_RATE_2026/2025 x business miles`) — a repo-wide grep finds no "actual
expense method" toggle anywhere in `app.js`, so there is no such split to verify; this is a
scope fact about the app, not a gap in this fix.

**Impact:** This is the file a CPA is handed. A shifted row silently reassigned the mileage
deduction figure to the wrong column (or dropped it off the end), which either understated or
overstated a Schedule C mileage deduction with no error, warning, or visual cue in the CSV
itself — tax-filing risk, not just a display bug. Fixed; three-way reconciliation and
year-boundary bucketing both re-verified clean post-fix.

---

### F-4 — App Lock PIN had no brute-force lockout — FIXED

**Status: FIXED** (see the "fix F-4: App Lock brute-force lockout" commit in `git log`). Policy
and recovery approach were proposed to and approved by the app owner *before* implementation,
per the standing instruction not to ship a lockout that could strand a driver using this
one-handed in a moving vehicle.

**Where:** `app.js:5285-...` (`requireAppUnlock`), `app.js:177-207` (`verifyPin`, unchanged).

**The bug:** `requireAppUnlock()` rendered a PIN input and an Unlock button; every click (or
Enter) called `verifyPin()` fresh with zero shared state — no attempt counter, no exponential
backoff, no lockout window. PBKDF2 (310k iterations, SHA-256) was the *only* cost per guess —
at ~115ms/attempt, all 10,000 combinations of a 4-digit PIN were exhaustible in under 20
minutes from a single unattended browser tab.

**Fix (approved policy):**
- Attempts 1-5: free, no delay (normal fat-finger tolerance).
- Attempts 6-10: 10s delay before the *next* attempt is even accepted.
- Attempts 11-15: 60s delay.
- Attempts 16+: 5-minute delay — the cap, never grows further, **never permanent**.
- State (`appLockFailCount`/`appLockLockedUntil`) persists in `settings` so a reload can't
  reset the counter, and is deliberately *not* added to `ALLOWED_SETTINGS_KEYS` so a restored
  backup never re-imports a stale lockout from another device/session. Resets to 0 on any
  successful unlock.
- A **"Forgot PIN?"** link on the unlock screen (confirmation-gated) clears `appLockEnabled`/
  `appLockPin`/the lockout counters — removing the lock, never touching trip/expense data —
  available even mid-lockout, so the driver is never truly stuck. Per CLAUDE.md's credential
  table the PIN gates app UI access, not disk encryption, and a technical user could already
  achieve the same removal by clearing site data — this doesn't weaken the PIN against a
  sophisticated attacker, it just gives the legitimate owner an honest, immediate way back in
  instead of waiting out a timer.
- **Reentrancy guard added while implementing this:** without it, rapid concurrent calls to
  `tryUnlock()` (button-mash, or a scripted `.click()` loop faster than one
  verifyPin+setSetting round-trip) could each read the same pre-increment `appLockFailCount`
  before any of them wrote the incremented value back, silently undercounting attempts and
  diluting the whole throttle — found via a real test flake while writing the reproduction
  below, not purely theoretical.

**Reproduction (post-fix):** `tests/integration/pin-lockout.spec.mjs`, 7 tests: first 5 wrong
guesses stay exactly as before (plain "Incorrect PIN", no delay); the 6th triggers a
countdown-locked state (input+button disabled, persisted `appLockLockedUntil`); the lockout
survives a page reload (checked via the persisted DB value, not just UI state, since this
app's own boot sequence can itself take real time); once the delay elapses the input
re-enables itself with no user action; the correct PIN unlocks and resets the counter to zero;
"Forgot PIN" removes the lock even while still mid-lockout. All 7 pass.

**Impact:** App Lock's threat model is "someone else with the unlocked-or-briefly-accessible
device" (glovebox, truck stop, borrowed phone). Fixed: brute-forcing now costs real, escalating
wall-clock time (minutes-to-hours instead of ~20 minutes flat) while the legitimate owner is
guaranteed a way back in within 5 minutes worst-case, or immediately via Forgot PIN.

---

### F-6 — Concurrent trip edits from two tabs silently lost data — FIXED

**Status: FIXED** (see the "fix F-6: optimistic concurrency" commit in `git log`).

**Where:** `app.js:952-986` (`upsertTrip`), `app.js:8693-8696` (`openTripWizard` snapshot),
`app.js:8893-8908` (`save()`'s `upsertTrip()` call site + `FL_CONFLICT` handler),
`app.js:908-945` (`sanitizeTrip`).

**The bug:** `upsertTrip()`'s "TOCTOU-safe: read + write in single readwrite transaction"
comment was accurate only for the **audit-log snapshot** written inside that same call — it
said nothing about the trip record itself, because the read that actually seeds the edit form
happens much earlier (`openTripWizard(existing)`, a separate IDB transaction at modal-open
time). `save()`/`collectTrip()` then always wrote the **entire** in-memory `trip` object with
`stores.trips.put(t)` — a full overwrite, not a field-level patch — with no `updatedAt` /
version precondition check before the put. Two tabs (or two devices sharing local storage, or
simply two browser windows on one device) open on the same trip raced: whichever called
`upsertTrip()` last won completely, silently reverting every field the losing-order tab
changed, even fields the winning tab never touched.

**Fix:** `upsertTrip()` now captures the caller's in-memory `updatedAt` (the value preserved
untouched through the whole edit session, from `openTripWizard(existing)` through
`collectTrip()`) and, inside the same read-then-write transaction, compares it against the
*currently stored* `updatedAt`. A mismatch aborts the transaction and throws `FL_CONFLICT`
instead of overwriting — undefined for a brand-new trip, so new-trip saves are never blocked.
This is a **compare-and-abort inside one transaction, not a lock**: nothing waits on anything,
and per the IndexedDB spec a transaction that hasn't committed when its connection tears down
(a tab dying mid-save) is auto-aborted, not partially applied — so a dead tab can't strand a
lock for other tabs to wait on. `save()`'s click handler catches `FL_CONFLICT`, tells the
driver ("this trip changed elsewhere — showing the latest version"), and reopens the wizard on
the fresh server record so they can redo their edit — one tap, no merge UI.

**Residual gap found and closed while implementing this:** the precondition only works if
`updatedAt` survives round-trips. `sanitizeTrip()` — the function CSV import and JSON
backup-restore both funnel every trip through, *bypassing* `upsertTrip()` with a direct
`stores.trips.put()` — was not copying `raw.updatedAt` onto its output at all, so every
CSV-imported or JSON-restored trip would have silently lost its `updatedAt` and skipped the
conflict check on its first post-import edit (JSON restore, in particular, is the *primary*
"move to a new phone" backup path, not a rare edge case). Fixed by having `sanitizeTrip()`
preserve `raw.updatedAt` when present and numeric, leaving it `undefined` for genuinely new
trips (the correct "no conflict check yet" state) — `upsertTrip()` still always sets the real
value after the check, unaffected.

**Reproduction (post-fix):** `tests/integration/toctou-concurrent-edit.spec.mjs`, 3 tests.
Seeds one trip *the way `upsertTrip()` actually would* (with a real `updatedAt` stamp — an
earlier version of this test seeded without one and got a false pass, silently bypassing the
whole fix; fixed before this was reported as passing), opens it in two Playwright pages
sharing one browser context:

```
[evidence] Tab B's form still showed pay=1000 when it saved (stale — Tab A had already changed it to 1500 in storage)
[evidence] final stored trip: pay=1500, loadedMiles=400
[evidence] Tab B post-conflict form pay field: "1500"
```

Tab A's `pay=1500` survives; Tab B's `loadedMiles=450` edit — which used to silently ride
along with the lost-update overwrite — is correctly rejected entirely (final `loadedMiles` is
still `400`, Tab A's last-known-good value, not Tab B's `450`); Tab B's form is refreshed to
show the current server value instead of silently sitting on stale data. A third,
**best-effort** test fires a save from a third tab and closes that tab immediately without
awaiting completion, 5 times, checking the stored record stays structurally well-formed and
matches one of the two known-good snapshots (pre- or fully-post-write) every time — this
confirms IndexedDB's own transaction atomicity holds in this code path empirically, but (noted
in the test itself) can't pin a `page.close()` to an exact instruction inside an in-flight
transaction from outside the page, so it's evidence across repeated attempts, not a single
deterministically-timed interruption proof.

**Impact:** Any workflow with two open tabs (common — "let me check something in a new tab
while this form is open") or, per CLAUDE.md's Dispatch Layer note, any future multi-device
sync work built on the current storage model would have inherited this. Financial fields
(`pay`, `isPaid`, `paidDate`) were exactly what was at risk. Fixed, including the import-path
gap that would have silently reopened it for any trip touched by CSV import or JSON restore.

---

### F-2 — `trip.paidDate` bypassed date validation applied to every sibling field — FIXED

**Status: FIXED** (see the "fix F-2: paidDate validation" commit in `git log`).

**Where:** `app.js:~926` (the bug), contrast with `app.js:913-916` (`pickupDate`,
`deliveryDate`, `invoiceDate`, `dueDate` — all `isValidISODate`-checked in the same function),
`app.js:~1662` (CSV import writes `paidDate` from a raw cell with no validation before it
reaches `sanitizeTrip`), `app.js:2170-2200` (`computeBrokerStats` — no sanity bound on the
resulting day-count), `app.js:~15427` (`renderMoneyCard` — the same kind of calculation,
*with* a `d>=0 && d<365` bound).

**The bug:** Every date field on a trip went through `isValidISODate()` in `sanitizeTrip()`
except `paidDate`:
```js
t.paidDate = raw.paidDate || (t.isPaid ? isoDate() : null); // no validation
```
A CSV-imported `PaidDate` column reached this field completely unvalidated, and any string
`new Date()` *can* parse — including nonsensical-but-valid values like a pre-invoice date or a
far-future date — flowed straight into day-count math. `renderMoneyCard` bounded its result
(`d>=0 && d<365`); `computeBrokerStats`, which drives per-broker "average days to pay"
analytics, did not.

**Fix:** `t.paidDate = isValidISODate(raw.paidDate) ? raw.paidDate : (t.isPaid ? isoDate() : null);`
— same pattern, same fallback semantics as every sibling field (garbage is treated as absent).
Added the same `d >= 0 && d < 365` bound to `computeBrokerStats` that `renderMoneyCard` already
had.

**Audit of other date fields (requested re-check):** scoped to the sanitizer functions
(`sanitizeTrip`, `sanitizeStop`, `sanitizeExpense`, `sanitizeFuel` — the data-validation layer
every IDB write for these record types goes through), since that's the exact bypass pattern
F-2 is about. `sanitizeExpense.date` and `sanitizeFuel.date` were already correctly validated.
One more instance found: **`sanitizeStop.date`** (a trip's multi-stop entries) had the identical
bypass (`raw.date || ''`, no `isValidISODate`). Logged as **F-2b** and fixed in this same
commit — lower severity than F-2 itself, since grepping `app.js` finds no computation anywhere
that reads `stop.date` for date-math (unlike `paidDate`, which fed `computeBrokerStats`'s
day-count arithmetic); it's stored/displayed raw only, today. Fixed for consistency before
anything starts consuming it, not because it's currently causing a wrong number anywhere.
Document expiry dates and other date fields outside this sanitizer family were not in scope for
this pass.

**Reproduction (post-fix):** `tests/unit/pure-functions.spec.mjs`, 4 tests (up from 1): garbage
paidDate on a paid trip now falls back to today's ISO date, matching every sibling field; a
genuinely valid paidDate round-trips exactly; an *unpaid* trip with garbage paidDate gets `null`
(not a fabricated date); F-2b confirms `sanitizeStop.date` rejects garbage the same way. All
pass.

**Impact:** Corrupted or adversarial CSV import data (a driver's own bad export from another
tool, or a shared/imported file) could have skewed per-broker pay-speed analytics with
unbounded values, with no user-visible sign anything was wrong — a wrong-but-confident-looking
signal in a feature (Broker Intel) explicitly meant to steer bid decisions. Fixed.

---

### F-5 — `window.__FL_TESTS` was unconditionally live in production — FIXED

**Status: FIXED** (see the "fix F-5: gate window.__FL_TESTS" commit in `git log`).

**Where:** `app.js:16192-16199` (the gate), `tests/lib/harness.mjs` (the harness-side opt-in
this fix depends on, added in commit `df69fb8`, Step 0).

**The bug:** The comment said *"Only active when `window.__FL_TESTS_ENABLED` is set before
load"*, but no code anywhere in `app.js` read that flag — the assignment was unconditional,
exposing 31 (later 32) internal functions/constants, including `hashPin`, every sanitizer, and
the full pricing tables, to any script executing in the page context on every production load.

**Fix:** `if (typeof window !== 'undefined' && window.__FL_TESTS_ENABLED === true){` — the gate
the comment already documented, now actually implemented. This audit's own test harness
(`tests/lib/harness.mjs`, updated in Step 0 before any fix landed) sets
`window.__FL_TESTS_ENABLED = true` via `context.addInitScript()` before navigation whenever a
spec needs `__FL_TESTS`, which is how the rest of this suite keeps working unmodified — no
other spec file needed a single line changed for this fix.

**Reproduction (post-fix):** `tests/integration/fl-tests-exposure.spec.mjs`, 2 tests: a genuine
production load (no `__FL_TESTS_ENABLED` set) now correctly shows `window.__FL_TESTS` as
`undefined`; the harness's explicit opt-in still correctly exposes it. Both pass.

```
[evidence] window.__FL_TESTS present=false (0 keys) with __FL_TESTS_ENABLED never set
```

**Impact:** Low on its own — these were pure functions operating on caller-supplied data, not
secrets or live DB handles — but it was unintended attack-surface widening (a reconnaissance
aid for an attacker who already had *some* script execution) and a straightforward
contradiction between the code's stated intent and its actual behavior. Fixed.

---

## New findings from Phase 4 (field resilience)

Two new findings surfaced while building the automatable subset of Phase 4 (storage quota,
offline-then-reconnect, DST/clock-skew, GPS resilience — see
`tests/integration/field-resilience.spec.mjs`). Both were logged with full reproduction and
NOT fixed at the time — they fell outside the six findings the owner explicitly ordered fixed
in Step 1, and this audit's own precedent (F-2's sibling-field audit) is to log new findings
discovered during a testing phase rather than silently expand the fix list.

**Both were subsequently approved by the owner and fixed in v23.8.4.** The sections below keep
the original reproductions intact (that is the evidence the fixes were built against) and
record what shipped under each finding's "Fix" heading.

### F-8 — Add Expense and Add Fuel were completely broken for every new record — FIXED

**Status: FIXED in v23.8.4.** Discovered incidentally while building the offline field-test
scenario (`tests/integration/field-resilience.spec.mjs`) — not offline-specific, confirmed to
reproduce fully online too.

**Where:** `sanitizeExpense()` (`app.js:1044`) and `sanitizeFuel()` (`app.js:1120`), feeding
`addExpense()` (`app.js:1065`, `stores.expenses.add(e)`) and `addFuel()` (`app.js:1129`,
`stores.fuel.add(x)`).

**The bug:** Both sanitizers build the new record's `id` field the same way:

```js
id: raw.id ? intNum(raw.id, 0, 1e12) : undefined,
```

For a brand-new expense or fuel entry, `raw.id` is absent, so this line puts an **explicit**
`id: undefined` property onto the object passed to `store.add()`. The `expenses` and `fuel`
object stores are both `{ keyPath: 'id', autoIncrement: true }` — but per the IndexedDB spec,
auto-increment only fills in the key when the key-path property is *absent* from the object.
An object that explicitly *has* an `id` property set to `undefined` is evaluated as carrying a
real (invalid) key, and `.add()` throws synchronously:

> `DataError: Failed to execute 'add' on 'IDBObjectStore': Evaluating the object store's key
> path yielded a value that is not a valid key.`

Neither `addExpense()` nor `addFuel()` wraps the `.add()` call in a `try/catch`, so this is an
**uncaught exception**. The Save button's click handler (`app.js:9268` for expenses) has no
surrounding error handling either — the exception just propagates and dies. Nothing is shown
to the driver: no toast, no validation hint, the modal simply doesn't close and the tap appears
to do nothing. The record is never written.

**Reproduction:**
```
[evidence] page error thrown by the click: "Failed to execute 'add' on 'IDBObjectStore':
Evaluating the object store's key path yielded a value that is not a valid key."
[evidence] expenses count before=0, after=0; modal still open=true
```
Confirmed with a raw (app-bypassing) IndexedDB call using `sanitizeExpense()`'s/`sanitizeFuel()`'s
exact output shape: `{ id: undefined, ... }` throws against both stores; the byte-identical
object with the `id` key *omitted entirely* succeeds with an auto-generated key. Confirmed not
offline-specific (identical crash with `navigator.onLine === true`, zero network involved) —
this rules out anything related to the offline scenario it was found in; it's a pure
sanitizer/store-shape bug. `updateExpense()`/`updateFuel()` (editing an *existing* record) are
unaffected — those always have a real, non-undefined `id`, so `raw.id` is truthy and the
ternary takes the other branch.

**Impact:** Critical. Add Expense and Add Fuel are two of the app's most basic, most frequently
used flows (the empty-state copy for expenses literally says "Takes 5 seconds") and the whole
point of the app is bookkeeping/tax-deduction tracking — this breaks entry of new expense and
fuel records outright, with a completely silent failure mode (no error surfaced at all) that
would read to a driver as "the app is frozen" or "my tap didn't register," not as data loss.
Anyone testing this against a running instance of the app hits it on the very first attempt to
add an expense or a fuel entry.

**Fix (shipped in v23.8.4).** Only set the `id` key when there's a real value to set — spread
it in conditionally instead of assigning `undefined`:
```js
...(raw.id ? { id: intNum(raw.id, 0, 1e12) } : {}),
```
A one-line change in each of the two sanitizers, touching no other field, targeting the root
cause (an explicitly-present `undefined` key-path property) with no behavior change on the edit
path — `updateExpense`/`updateFuel` still throw `Missing id` correctly when the key is absent.

Additionally, the expense save handler (`app.js:9272`) gained the `try/catch` the fuel handler
(`app.js:9370`) already had. That asymmetry is the entire reason this failure was *silent* on
the expense side; now any future storage error reaches the driver as a toast.

**Post-fix reproduction:**
```
[evidence] page errors thrown by the click: []
[evidence] expenses count before=0, after=1; modal still open=false
[evidence] auto-generated id on the saved expense: 1
[evidence] fuel count before=0, after=1; modal still open=false
[evidence] raw add() with an explicit id:undefined (the old shape): {"ok":false,"thrown":"Failed to
  execute 'add' on 'IDBObjectStore': Evaluating the object store's key path yielded a value that
  is not a valid key."}
[evidence] raw add() with the id key omitted (the fixed shape): {"ok":true,"key":2}
```
Tests: `[FINDING F-8 / FIXED]` in `tests/integration/field-resilience.spec.mjs` (drives the real
Add Expense and Add Fuel UI end to end, and keeps a regression guard on the underlying
IndexedDB semantics the fix depends on) and three sanitizer-level tests in
`tests/unit/pure-functions.spec.mjs`.

---

### F-7 — A single transient GPS error mid-trip killed tracking; the visible recovery action discarded the trip instead — FIXED

**Status: FIXED in v23.8.4.** `tests/integration/field-resilience.spec.mjs`,
`[FINDING F-7 / FIXED]` tests.

**Where:** `_doStartTracking()`'s `watchPosition` error handler, `app.js:14871-14880`.

**The bug:** The error callback treats every `GeolocationPositionError` code identically —
code 1 (`PERMISSION_DENIED`), code 2 (`POSITION_UNAVAILABLE`), and code 3 (`TIMEOUT`) all hit
the same branch: show a toast, set `_activeTracking = null`, re-render the idle "Start Trip"
UI. There is no tolerance for a single transient error before abandoning the whole session —
no retry, no grace window, no distinction between "the user permanently revoked location
access" and "the GPS chip blipped for one reading." A `POSITION_UNAVAILABLE` blip is a
realistic, ordinary event while actually driving (a tunnel, a parking garage, an urban canyon,
a brief cell/GPS handoff) — not a rare edge case.

What actually happens on this error, verified directly:
1. The live tab's UI reverts to idle "Start Trip" and shows a toast (`_doStartTracking`
   correctly does not silently fail — the driver IS told something happened).
2. **The `sessionStorage['fl_active_tracking']` resume record is NOT cleared** by this error
   path (only `stopTripTracking()` clears it) — it's still sitting there with the same
   `trackingId` and the miles accumulated before the error.
3. Reloading the tab **does** recover the session: `resumeTrackingIfActive()` (`app.js:15007`,
   called on every boot) reads that still-present record and calls `_doStartTracking()` again
   with the same `trackingId` and `totalMiles` intact, showing "Trip tracking resumed."
4. But the *only visible affordance* in the crashed tab is the "Start Trip" button, and tapping
   it does **not** use the recovery path — `startTripTracking()` only checks `if
   (_activeTracking) return`, which is false since the crash nulled it, so it calls
   `_initTrackingObject()` and generates a **brand-new** `trackingId`, silently abandoning the
   old session (and its accumulated miles/gpsLogs) for good.

So there is a working recovery mechanism, but it's reachable only by an undocumented action
(reload the page) that nothing in the UI suggests, while the obvious, visible action after the
crash actively destroys the recoverable data instead of using the path that would have saved
it.

**Reproduction:**
```
[evidence] track area after ONE transient GPS error: "Start TripTap when you pick up a load"
[evidence] toast shown: "Couldn't get your location right now. Try moving to an open area."
[evidence] sessionStorage record survives the crash: {"trackingId":"...","totalMiles":0,...}
[evidence] track area after reloading the tab: "Trip in progress ... Stop & Save Trip"
[evidence] toast on reload: "Trip tracking resumed."
[evidence] trackingId before crash: fa5cec2f-...  trackingId after tapping "Start Trip" again: 17bdd0c5-...
```
Permission revocation mid-trip (`context.clearPermissions()`) hits the identical code path
(`err.code === 1`) with identical total-session-loss behavior — same root cause, not a separate
mechanism. A regression-guard test confirms an ordinary error-free Start → Stop → Save still
works fine; this is specifically about error tolerance, not GPS tracking in general.

**Impact:** High. A driver's entire in-progress trip (potentially hours of tracked mileage) can
be lost to one ordinary GPS hiccup, with the app's own visible UI leading them to *make it
worse* by tapping the button it's showing them. The data isn't unrecoverable in principle (the
sessionStorage record and old `gpsLogs` entries survive), but nothing in the product surfaces
that to the driver.

**Fix (shipped in v23.8.4).** The owner chose to go further than the grace-window direction
originally sketched here, on the reasoning that a grace window still destroys the trip once it
expires — an hour parked at a dock inside a garage would hit exactly that. The shipped fix:

1. **A GPS error never ends the session**, for any error code. `_activeTracking.gpsErrorSince` /
   `.gpsErrorCode` record the current error streak (cleared by any fix, including a low-accuracy
   one, so the reset had to land before the `accuracy > 100` early-return).
   `_renderTrackingActive` degrades honestly — "GPS signal lost — searching (Nm)" for codes 2/3,
   "Tracking paused — location access is off" for code 1 — while always keeping Stop & Save
   reachable, since that button is what actually banks the accumulated miles.
2. **Permission-denied (code 1) stays alive too**, rather than tearing down as originally
   suggested. Tearing down on code 1 would have produced a resume → denied → teardown loop
   against the new resume prompt, and destroying data is not the right answer to a condition the
   driver can reverse in Settings.
3. **The error callback gained the `trackingId` guard** its success counterpart already had (a
   stale watcher could otherwise clobber a newer session), and now **toasts once per streak**
   rather than once per callback — `watchPosition` re-fires the error callback every `timeout`
   (15 s), so per-callback toasting would have buried the driver.
4. **`_doStartTracking()` clears any prior `watcherId`** before re-arming, closing a watcher leak
   the old teardown path left behind.
5. **`startTripTracking()` offers `_showResumeTrackingModal()`** when a session record ≤24 h old
   is present, instead of silently minting a new `trackingId`. Resume continues the original
   session; "Discard & Start New" cleans the old `gpsLogs` and starts fresh. Discarding is still
   possible — but as an explicit labelled choice, which was the actual finding. The restore
   logic is shared with `resumeTrackingIfActive()` via `_readSavedTracking()` /
   `_restoreTrackingFromSaved()` rather than duplicated.

**Post-fix reproduction** (sustained `POSITION_UNAVAILABLE` via CDP
`Emulation.setGeolocationOverride` with no parameters — `context.setGeolocation()` only emits a
one-event transient error in Chromium, so it cannot hold the degraded state open):
```
[evidence] track area during sustained signal loss: "Trip in progress0m  •  0 miles  •
  📡 GPS signal lost — searching (0m)Stop & Save Trip"
[evidence] Stop & Save still reachable during the outage: true
[evidence] track area after the signal returns: "Trip in progress0m  •  0.1 miles  •  📍 Good…"
[evidence] trackingId before: a4ccaede-…, after choosing Resume: a4ccaede-…
[evidence] track area after permission revoked mid-trip: "Trip in progress0m  •  0 miles  •
  ⏸ Tracking paused — location access is offStop & Save Trip"
[evidence] trips before Stop & Save: 0, after: 1
```
The last line is the point of the whole change: after a mid-trip permission revocation the
driver can still bank the trip.

---

## What was tested and found clean

- **RPM formula consistency (Phase 2 ask).** `computeLoadScore`'s `trueRpm = pay/(loaded+empty)`
  (`app.js:2546`) and `mwEvaluateLoad`'s `trueRPM = effectiveRevenue/totalMi`
  (`app.js:6369`, `totalMi = loadedMi+deadMi` at `app.js:6358`) use the identical all-in
  definition; both also expose a separate `loadedRPM`/`loadedRpm` for loaded-only display.
  No mixing of loaded-only and all-in RPM was found feeding the same grade/verdict decision.
- **Omega tier exhaustiveness/mutual exclusivity.** `omegaTierForMiles()` fuzzed at 0.5-mile
  resolution from -50 to 3000 miles plus exact boundary values (180/350/600/900 and their
  ±0.01 neighbors) — every value classified into exactly one of tiers 0–4 with no gaps or
  double-classification. `OMEGA_TIERS` band structure (`under < floor < strong < ideal <
  premium`) checked for internal overlap across all 5 tiers — none found.
  (`tests/unit/pure-functions.spec.mjs`)
- **`mwClassifyRPM` monotonic scan.** Every $0.01 step from $0 to $3.00 RPM resolves to a
  tier object; the reverse-iteration scan (`app.js:6207-6212`) never fails to match.
- **Determinism.** `computeLoadScore()` called 25× with byte-identical input on the same trip
  produced 25 byte-identical JSON results — no hidden state (`Math.random`, `Date.now()`
  inside the scoring path, iteration-order dependence) causing score drift on re-evaluation.
- **Prototype pollution guard.** `deepCleanObj()` strips `__proto__`/`constructor`/`prototype`
  keys at every nesting depth on a crafted payload built via `JSON.parse` (the real ingestion
  path for imports); confirmed `Object.prototype` is not polluted afterward and benign
  sibling keys survive.
- **CSV formula-injection guard.** `csvSafeCell()` neutralizes all of `= + - @ TAB CR | % !`
  at line start and after embedded newlines, without false-positiving on ordinary
  comma-containing text like `"Springfield, IL"`. (Its blind spot — missing comma quoting in
  one export path — is F-3 above; the formula-injection guard itself is intact everywhere.)
- **XSS spot-checks.** `escapeHtml()` correctly escapes all five HTML-relevant characters and
  handles `null`/`undefined`/numbers without throwing. Grep-based sweep of every `innerHTML =`
  assignment referencing `.notes`/`.customer`/`.broker`/`.origin`/`.destination` on the same
  line found `escapeHtml(...)` wrapping every match; one place that builds an unescaped
  intermediate string from `origin`/`destination` (`app.js:13092`, lane-trend `display` field)
  escapes it at the actual render site (`app.js:13111`) before insertion. This is a targeted
  spot-check, not exhaustive line-by-line coverage of all ~16K lines — see limitations below.
- **Cloud backup crypto.** `cloudEncrypt`/`cloudDecrypt` (`app.js:11279-11302`) use a fresh
  `crypto.getRandomValues` salt and IV on every call (no reuse across encryptions), PBKDF2 at
  600,000 iterations (with a documented 100,000-iteration fallback for pre-v23.4.1 backups),
  and AES-256-GCM. No salt/IV reuse or downgrade-without-fallback-limit issue found by
  reading; not independently fuzzed against a live Cloudflare Worker (see below).
- **`hashPin` salt uniqueness.** Two `hashPin('1234')` calls produced different salts and
  different output hashes — no salt reuse.
- **Service worker fetch/cache logic (static read).** Network-first with cache fallback for
  app-logic requests (JS/HTML/navigations), cache-first with network fallback for static
  assets, offline shell fallback when nothing cached, activate-time deletion of any cache name
  other than the current version + receipt/share caches, share-target POST restricted to an
  allowlisted MIME set. No cross-origin cache-poisoning path found (non-GET and cross-origin
  requests fall through to default browser handling, not `respondWith`). Not dynamically
  tested (see below).

## What could NOT be tested, and why

- **Phase 4 field-resilience scenarios** (tab killed mid-write, mid-OCR, mid-export;
  QuotaExceededError during a save; a full simulated day in airplane mode; iOS Safari 7-day
  eviction; cold start after a week; GPS no-fix/stale-fix/wrong-coordinate mid-trip; clock
  skew/DST transitions) were **not executed**. These need either real device/OS-level
  conditions (Safari ITP eviction timing, iOS backgrounding) that a headless Chromium harness
  cannot simulate, or deliberate low-level fault injection (killing the process mid-IndexedDB-
  transaction, forcing `QuotaExceededError`) that this pass did not build tooling for. The
  code *does* have `onerror`/`QuotaExceededError` handling visible by inspection
  (`app.js:954`, `1014`, `1028`) but it was not exercised under an actual quota-exhaustion
  condition.
- **Phase 5 full E2E journeys** (cold install → first evaluated load with tap counts; Snap
  Load OCR → tier verdict → trip → fuel → delivery → invoice → payment → AR cleared; full tax
  year → Schedule C export "an accountant would accept"; invite-a-friend → zero data mixing)
  were **not scripted end-to-end**. The harness built here proves individual mechanisms (DZ
  cap, CSV export, PIN, concurrent edit) with targeted flows through the real UI, but does not
  chain them into full timed user journeys with tap counts. OCR-specific testing needs a
  crafted rate-confirmation image and a working Tesseract.js runtime (the optional vendor
  files noted in `README.txt` were not present in this checkout to confirm), which this pass
  did not attempt to source or fabricate.
- **Phase 6 usability under load** (contrast ratios, tap-target sizing at arm's length,
  glove/sunlight legibility) requires visual/human judgment or an accessibility-audit tool
  (axe-core or similar) this pass did not wire in; not assessed.
- **Cloud Backup Worker (`cloud-backup-worker.js`) live behavior** — rate limiting, the
  `/evaluate` and `/extract` AI endpoints, invite-link token handling (history/referrer/
  clipboard/replay exposure) — was read statically but not exercised against a live
  deployment; this environment has no `OPENAI_API_KEY`/`ADMIN_TOKEN` or deployed Worker
  instance to test against. The invite-link flow specifically (token in URL, one user's data
  bleeding into another's local store) needs two real device profiles exercising the actual
  `/admin/users` + `/backup` endpoints, which was out of reach here.
- **Exhaustive XSS/CSV coverage.** The escapeHtml/CSV spot-checks above are grep-anchored
  (same-line pattern matching) and targeted manual reads of the highest-traffic render paths
  (trip list, lane trends). They are not a line-by-line audit of every one of app.js's several
  hundred `innerHTML =` assignments; a genuinely exhaustive pass would need either an
  automated taint-tracking tool or substantially more manual review time than this pass spent.
- **F20 Dead Zone Exit activation-condition matrix.** F-1 above proves the grade-cap display
  bug conclusively, but the audit brief also asked for "every activation boundary and every
  condition combination" (distance-from-home threshold, distance-saved threshold, each
  sub-tier RPM boundary, the no-reload-confirmed toggle, DZ-enabled setting). Only the
  boundaries needed to demonstrate F-1 were exercised; a full combinatorial sweep of
  `dzCheckEligibility`/`dzClassifySubTier` (which depend on the market-coordinate database and
  settings, not just pure numeric input) was not built.
- **Multi-tab TOCTOU beyond trips.** F-6 demonstrates the lost-update pattern on `trips`. The
  same `upsertTrip`-style full-overwrite pattern appears in `upsertExpense`/`updateExpense`
  (`app.js:1007-1042`) and likely other stores; those were not independently exercised with
  two tabs, though the code shape strongly suggests the same bug class applies. (Phase 4 did
  end up exercising `addExpense`/`addFuel` directly while building an unrelated offline
  scenario, and found a different, more severe bug there first — see F-8. The TOCTOU question
  for expenses specifically is still open.)

## Test Suite

Committed under `tests/`:
- `tests/lib/harness.mjs` — launches a real headless Chromium (Playwright) against the app
  served from the repo root, with real IndexedDB/Cache Storage/`crypto.subtle`. Fresh browser
  context per spec file (equivalent to a brand-new device).
- `tests/unit/pure-functions.spec.mjs` — 16 tests against `window.__FL_TESTS` exports (F-2, F-2b).
- `tests/integration/dz-exit-grade-cap.spec.mjs` — F-1.
- `tests/integration/tax-export-csv-corruption.spec.mjs` — F-3.
- `tests/integration/pin-lockout.spec.mjs` — F-4.
- `tests/integration/toctou-concurrent-edit.spec.mjs` — F-6.
- `tests/integration/fl-tests-exposure.spec.mjs` — F-5.
- `tests/integration/field-resilience.spec.mjs` — Phase 4 field resilience (storage quota,
  offline/reconnect, DST/clock-skew, GPS resilience); surfaced F-7 and F-8.
- `tests/run-all.mjs` — runs every spec and prints an aggregate summary.

**Run it:**
```bash
ln -sfn "$(npm root -g)/playwright" node_modules/playwright   # one-time, see tests/README.md
node tests/run-all.mjs
```
Last run: **55 passed, 0 failed** across 7 spec files. All 8 findings (F-1 through F-8, plus
F-2b) are FIXED and every test now asserts correct behavior.

Note on the retagged tests: while F-7 and F-8 were logged-but-unfixed, their tests deliberately
asserted the *buggy* behavior — per this suite's convention, a green checkmark on an
"F-n / NEW" test meant the evidence was captured correctly, not that the bug was fixed. When
the fixes shipped in v23.8.4 those tests went red, which is exactly what should happen, and
they were rewritten and retagged `[FINDING F-n / FIXED]`. No `/ NEW` tags remain in the suite.

---

## v23.9 "Trust & Recovery" audit — X-01 … X-12

Scoped follow-up pass, requested directly (not derived from a prior dynamic Playwright run —
these are static source-read findings, verified against `app.js` on the `v23.9` branch base
commit). All 12 are **CONFIRMED** — none refuted. Findings marked "confirmed at proposal time"
were verified in the same sitting the fix list was proposed (before Phase 1 began); the rest
were verified in a dedicated pass per the owner's Amendment 1 before any fix landed. Status
column reflects state as of this section being written — see `git log` for the commit that
closes each once Phases 1–7 land.

| ID | Area | Confirmed at | Status |
|----|------|--------------|--------|
| X-01 | Cloud restore / delta sync | dedicated pass | **FIXED — Phase 4** |
| X-02 | Tax — mileage rate | dedicated pass | **FIXED — Phase 1** |
| X-03 | Tax — method double-dip | dedicated pass | **FIXED — Phase 1** |
| X-04 | Dead Zone authority split | proposal time | **FIXED — Phase 5** |
| X-05 | Export checksum/payload mismatch | proposal time | **FIXED — Phase 3** |
| X-06 | Test runner exit code | proposal time | **FIXED — Phase 2** |
| X-07 | Restore coverage gap | dedicated pass | **FIXED — Phase 4** |
| X-08 | SW critical shell omission | dedicated pass | **FIXED — Phase 6** |
| X-09 | Diagnostics fake token | proposal time | **FIXED — Phase 6** |
| X-10 | SheetJS CDN fallback | proposal time | **FIXED — Phase 6** |
| X-11 | OCR claim on dead code path | proposal time | **FIXED — Phase 6** |
| X-12 | Deployment checklist drift | dedicated pass | **FIXED — Phase 6** |

### X-01 — `cloudPullBackup()` never fetches `/backup/delta` — CONFIRMED

**Where:** `app.js:11686-11729` (`cloudPullBackup`, full function body).

Step 1 calls `GET /status` (`:11693`), step 2 calls `GET /backup` (`:11699`), decrypts, confirms,
and calls `mergeRestoreData(parsed)` (`:11715`). No call to `/backup/delta` (`GET` or otherwise)
appears anywhere in the function. The only `/backup/delta` reference in `app.js` is the **upload**
side, `cloudPushBackup`'s `isDelta` branch (`app.js:11584`, `POST config.url + '/backup/delta'`).
Deltas are written but never read back — a device that only ever pulls (a fresh phone, a restore
after data loss) gets the last full snapshot and silently loses every delta synced after it,
exactly as described. Confirmed.

### X-02 — `MILEAGE_RATE_2026` is a flat, non-date-keyed constant — CONFIRMED

**Where:** `app.js:97-98` (`IRS.MILEAGE_RATE_2026 = 0.725`, `IRS.MILEAGE_RATE_2025 = 0.70`),
consumed at `app.js:12484` (`const mileageRate = year >= 2026 ? IRS.MILEAGE_RATE_2026 :
IRS.MILEAGE_RATE_2025;`) and three further read sites (`:10177-10180`, `:14295`, `:14396`, all
reading the same flat constant).

The selection is per **calendar year**, not per trip date — there is no code path that can apply
two different rates within the same year. IRS Announcement 2026-11's midyear increase
(2026-01-01→06-30 = $0.725, 2026-07-01→12-31 = $0.76) cannot be represented; every 2026 trip,
regardless of date, gets $0.725. Confirmed.

### X-03 — F30 sums standard mileage AND actual vehicle-operating costs — CONFIRMED

**Where:** `app.js:12511-12532` (`schedC` bucket build + `totalDeductions` sum).

`schedC.insurance` and `schedC.repairs` (Schedule C lines 15 and 21 — actual vehicle-operating
costs: auto insurance, repairs/maintenance) are populated from raw expense categories
(`:12523-12524`) and added into `totalDeductions` (`:12532`) in the **same sum** as
`mileageDeduction` (the standard-mileage figure, `:12496`). The IRS standard-mileage rate already
bakes in depreciation, maintenance, repairs, and insurance — claiming both for the same vehicle
is exactly the double-dip described. Separately confirmed the data-model gap: `expByCategory`
matches any category string containing `"insurance"` (`:12523`) into one flat `schedC.insurance`
bucket with no distinction between auto, cargo, liability, or occ-acc insurance — matches the
"existing insurance category conflates auto with cargo/liability/occ-acc" claim exactly.
Confirmed.

### X-04 — Dead Zone Exit authority duplicated outside the main evaluator — CONFIRMED (prior pass)

**Where:** `midwest-stack-authority.js:44-48` (`DEAD_ZONE` mode, `floor: 0.91`), `:234-250`
(verdict logic including `TAKE_IF_LIVE` at the floor with no gate-confirmation checks visible in
this file), contrasted with `app.js`'s own `dzCheckEligibility`/`dzClassifySubTier` gate logic.
Two independent implementations of the same decision, confirmed to disagree in shape (the
standalone file has no equivalent of the main evaluator's manual-confirmation/grade-cap gates in
the reachable verdict path). Confirmed.

### X-05 — `checksumFull` computed over different data than the payload it verifies — CONFIRMED (prior pass)

**Where:** `app.js:1366` (`computeExportChecksumFull(trips, expenses, fuel, settings)` — `settings`
here is the **unfiltered** `dumpStore('settings')` result from `:1364`, including `fmcsaApiKey`/
`eiaApiKey`) vs `app.js:1374` (`payload.settings` — the **filtered** array with those two keys
stripped). `importJSON`'s verify step (`:1442`) recomputes the checksum over `data.settings` as
found in the file — the filtered array — which can never equal a checksum computed over the
unfiltered array. Every legitimate export mismatches its own integrity check on import. Confirmed.

### X-06 — `run-all.mjs` always exits 0 — CONFIRMED (prior pass)

**Where:** `tests/run-all.mjs:42`, `process.exit(0)`, with an accurate comment explaining several
specs are expected to fail one assertion each (proof-of-bug tests). Correct for a human reading
the printed summary, but means no CI gate can use this runner's exit code to block a merge.
Confirmed.

### X-07 — `mergeRestoreData()` omits settings, receipts, and gpsLogs — CONFIRMED

**Where:** `app.js:11607-11684` (full function body). Explicit per-store handling exists only for
`trips` (:11612-11624), `expenses` (:11627-11638), `fuel` (:11641-11652), and a generic loop over
`simpleStores = ['laneHistory','weeklyReports','reloadOutcomes','bidHistory','documents']`
(:11656-11679). No branch reads `parsed.settings`, `parsed.receipts`, or `parsed.gpsLogs` — all
three are silently dropped on cloud restore even though `exportJSON()` includes all three in a
manual export (`app.js:1373-1381`). Confirmed.

### X-08 — `midwest-stack-authority.js` is absent from the service worker's install-blocking critical shell — CONFIRMED

**Where:** `service-worker.js:9-20` (`CORE` array — includes `midwest-stack-authority.js?v=23.8.4`
at line 14) vs `service-worker.js:48` (the separate `critical` array used in the `install` event's
`cache.addAll(critical)`: `['./', APP_SHELL, './app.js?v=23.8.4', './voice-load.js?v=23.8.4',
'./sw-bridge.js?v=23.8.4', './manifest.json?v=23.8.4']`). `midwest-stack-authority.js` (and
`admin-driver-ui.js`) are only in the broader, non-blocking `CORE` list — a first offline install
can complete and serve the app shell before the authority overlay script is actually cached,
so a driver's very first offline session can be missing the TRUE_RPM decision layer with no
error surfaced. Confirmed.

### X-09 — Diagnostics `/status` self-test uses a fake token, not a real `flk_`-format one — CONFIRMED (prior pass)

**Where:** `app.js:11375` — `fetch(CLOUD_WORKER_URL + '/status', { ..., headers:{'X-Backup-Token':
'ping','X-Device-Id':'diag'} })`. The literal strings `'ping'`/`'diag'` are not a real token —
contrast with the app's own `flk_<uuid-no-dashes>` format documented in `CLAUDE.md`. This self-test
therefore doesn't exercise the actual auth path a driver's device uses. Confirmed.

### X-10 — SheetJS has a CDN fallback, and CSP whitelists it in both deploy configs — CONFIRMED (prior pass)

**Where:** `app.js:1788-1797` (`loadSheetJS`, local vendor file first, `https://cdn.jsdelivr.net/
npm/xlsx@0.18.5/dist/xlsx.full.min.js` fallback), CSP `script-src`/`connect-src` allow
`cdn.jsdelivr.net` in both `index.html:10` and `_headers:2`. Confirmed.

### X-11 — Universal Import UI advertises OCR on a dead code path — CONFIRMED (prior pass)

**Where:** `app.js:1839-1841` — `importPDFFile(file)` is a one-line stub: `toast('PDF import is
not supported — paste the load text instead', true);`. The UI that routes to it still reads
"📸 Rate confirmation (PDF) — uses OCR" (`:1853`) and "PDF: extracts text via OCR and prefills a
trip." (`:1857`). Confirmed.

### X-12 — Deployment parity checklist references versions three-plus releases stale — CONFIRMED

**Where:** `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` — every version marker in the document
(`app.js?v=23.5.0`, `voice-load.js?v=23.5.0`, `sw-bridge.js?v=23.5.0`,
`midwest-stack-authority.js?v=23.5.1`, `manifest.json?v=23.5.0`, `SW_VERSION = '23.5.1'`, `CORE
includes midwest-stack-authority.js?v=23.5.1`) predates the current `23.8.4`. This document is
distinct from `scripts/verify-cloudflare-parity.mjs`'s `EXPECTED` block (which does track
`23.8.4` correctly) — the markdown checklist is the one that drifted. Confirmed.
