# FreightLogic v23.8.3 — Adversarial Audit Report

Audit date: 2026-08-19. Scope: `app.js` (16,145 lines), `index.html`, `service-worker.js`,
`voice-load.js`, `admin-driver-ui.js`, `midwest-stack-authority.js`, `cloud-backup-worker.js`.
Method: static reading + a real Playwright/Chromium harness against the live app (real
IndexedDB, real Cache Storage, real `crypto.subtle`) — no mocks, no reimplementation of app
logic. Test suite lives in `tests/` and is committed; no fixes are included in this branch.

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
clean below. Phases 4–6 (field resilience, full E2E journeys, one-handed usability) were
**not executed dynamically** — see "What could NOT be tested" — this report does not claim
coverage there.

## Findings

| ID | Severity | Area | Description |
|----|----------|------|-------------|
| F-1 | **Critical** | F20 Dead Zone Exit | Grade cap "at C" is dead code — DZ-active loads always show raw grade F; eval-history strip disagrees with the main card for the identical evaluation |
| F-3 | **Critical** | Tax export (F30) | Schedule C mileage-log CSV has no field quoting — any comma in trip origin/destination corrupts column alignment |
| F-4 | **High** | App Lock / auth | PIN unlock has no brute-force lockout, backoff, or attempt cap — bounded only by PBKDF2 cost (~115ms/attempt measured) |
| F-6 | **High** | Trip storage (TOCTOU) | Two tabs/devices editing the same trip: last save silently reverts the other tab's unrelated field changes (full-object overwrite, no version check) |
| F-2 | **Medium** | AR / trip storage | `trip.paidDate` bypasses `isValidISODate()` (unlike every sibling date field); downstream consumers apply inconsistent bounds-checking |
| F-5 | **Low / Info** | Attack surface | `window.__FL_TESTS` is unconditionally exposed in production; its own comment claims a gate (`__FL_TESTS_ENABLED`) that does not exist anywhere in code |

---

### F-1 — Dead Zone Exit "capped at C" never actually happens (Critical)

**Where:** `app.js:6296-6303` (`dzClassifySubTier`), `app.js:6515-6526` (grade computation +
display cap), `app.js:6679-6690` (session eval-history write), `app.js:7415-7433`
(`_renderEvalHistory`), documented behavior at `app.js:6793` and `app.js:7107`
("... — capped at C").

**The bug:** `dzClassifySubTier()` only returns a non-null sub-tier (activating DZ mode) when
`dzFloor (0.90) <= trueRPM < MW.hardRejectRPM (1.25)`. The raw letter-grade thresholds
(`app.js:6515-6520`) put *any* `trueRPM < 1.25` at grade **F** — there is no RPM value for
which DZ mode is active and the raw grade is A or B. But the display-cap logic is:

```js
const dzDisplayGrade = isDZActive ? (['A','B'].includes(grade) ? 'C' : grade) : grade;
```

Since `grade` can only ever be `'F'` while `isDZActive` is true, the `'A'/'B' → 'C'` remap
can never fire, and `dzDisplayGrade` just equals the raw `'F'`. The hero card
(`app.js:6743`, `6784`) renders `${dispGrade}` — a big **F**, colored orange via
`dzDisplayGradeColor`, not the "C" the Settings panel and in-card copy explicitly promise
(`app.js:6793`: *"DZ-FLOOR $0.90 • DZ-ACCEPTABLE $1.00 • DZ-STANDARD $1.10 — capped at C"*).

Separately, `histEntry` (`app.js:6679-6690`, written to `sessionStorage['fl_eval_hist']`)
stores the **raw, uncapped** `grade`/`gradeColor`/`gradeLabel` — not the DZ-adjusted display
values — and `_renderEvalHistory()` renders that raw entry verbatim. So the "Recent
Evaluations" strip shows **red "F" / "REJECT"** for the exact same evaluation the main card
just labeled an orange DZ-EXIT "survival" load.

**Reproduction:** `tests/integration/dz-exit-grade-cap.spec.mjs`. Fills the real evaluator UI
with Portland, OR → Chicago, IL, 1900 loaded miles, $2000 revenue (trueRPM ≈ $1.05, DZ-eligible
from the default home base at ~1500+ mi, >200mi saved toward home), confirms the DZ-EXIT
banner fires, then reads the DOM and `sessionStorage` the app itself produced.

```
[evidence] hero grade element text during DZ-Exit: "F"
[evidence] fl_eval_hist[0] = {"grade":"F","gradeLabel":"REJECT","gradeColor":"var(--bad)"}
```

**Impact:** No dollar loss by itself, but this is exactly the kind of trust-eroding
inconsistency the spec calls out — a driver skimming the eval-history strip later would
reasonably read a past DZ-Exit as a rejected/bad load, undermining the feature's whole
purpose (giving confidence to take a legitimate survival-mode load).

**Proposed fix (tradeoff noted):** Either (a) make the cap real — force `dzDisplayGrade = 'C'`
whenever `isDZActive` regardless of the raw letter, and persist `dzDisplayGrade`/
`dzDisplayGradeColor`/`dzDisplayGradeLabel` into `histEntry` instead of the raw values; or
(b) drop the "capped at C" language entirely and lean fully on the `DZ-FLOOR`/`DZ-ACCEPTABLE`/
`DZ-STANDARD` sub-tier labels, which are already accurate. (a) matches the documented design
intent with a small diff; (b) is more honest about what the number actually measures but
requires updating two in-app copy strings and any driver training material.

---

### F-3 — Schedule C tax-export CSV has no field quoting (Critical)

**Where:** `app.js:12446` (the export line), `app.js:12438-12439` (unquoted free-text fields
fed into it), contrast with the correctly-quoted general export at `app.js:1349`.

**The bug:** The general trip/expense/fuel CSV export quotes every cell:
```js
const csv = bom + rows.map(r => r.map(c => `"${csvSafeCell(c).replace(/"/g, '""')}"`).join(',')).join('\n'); // app.js:1349
```
The Tax Season Export (F30) mileage log does not:
```js
const csv = rows.map(r => r.map(v => csvSafeCell(v)).join(',')).join('\r\n'); // app.js:12446
```
`csvSafeCell` only guards against **formula injection** (leading `=+-@|%!`); it does nothing
about commas, and the row builder never wraps fields in quotes. The mileage-log rows embed
`trip.origin`/`trip.destination` (`app.js:12438-12439`) — free text the app itself
autofills/suggests in "City, ST" form throughout the UI. Any trip with a comma in either field
silently shifts every subsequent column (Loaded Mi, Deadhead Mi, Total Mi, Rate, Deduction)
for that row when opened in Excel, Numbers, or accounting software.

**Reproduction:** `tests/integration/tax-export-csv-corruption.spec.mjs`. Seeds one trip via
the real `sanitizeTrip()` shape with `destination: 'Springfield, IL'`, opens Tax Season Export
through the real More → Tax Season Export UI flow, intercepts the CSV Blob the app itself
builds (no hand-crafted CSV), and counts columns against the row's own header.

```
[evidence] header: Date,Trip #,From,To,Loaded Mi,Deadhead Mi,Total Mi,Rate ($/mi),Deduction ($)
[evidence] data row: 2026-03-01,AUDIT-CSV-1,Chicago, IL,Springfield, IL,200,0,200,0.725,145.00
[evidence] expected 9 columns, row has 11 (unquoted "Springfield, IL" splits into 2 fields)
```

**Impact:** This is the file a CPA is handed. A shifted row silently reassigns the mileage
deduction figure to the wrong column (or drops it off the end), which either understates or
overstates a Schedule C mileage deduction with no error, warning, or visual cue in the CSV
itself — tax-filing risk, not just a display bug. Nearly guaranteed to trigger given the app's
own "City, ST" convention for city fields throughout the evaluator and trip form.

**Proposed fix (tradeoff noted):** Reuse the exact quoting pattern already correct at
`app.js:1349` (`"${csvSafeCell(v).replace(/"/g,'""')}"` per cell) in the F30 export at
`app.js:12446`. No behavioral tradeoff — this is a straight bug fix; the only reason to
hesitate is that it changes the byte-for-byte output of a file users may already have on disk
from prior exports (immaterial for correctness, but worth a changelog note since some
drivers may diff exports year-over-year).

---

### F-4 — App Lock PIN has no brute-force lockout (High)

**Where:** `app.js:5251-5277` (`requireAppUnlock`), `app.js:177-207` (`verifyPin`).

**The bug:** `requireAppUnlock()` renders a PIN input and an Unlock button; every click (or
Enter) calls `verifyPin()` fresh with zero shared state — no attempt counter, no exponential
backoff, no lockout window, no CAPTCHA-equivalent. PBKDF2 (310k iterations, SHA-256,
`app.js:167-174`/`app.js:185-186`) is the *only* cost per guess. `verifyPin`'s final
comparison for the modern hash format is also a plain JS `===` on the derived hash string
(`app.js:188`) — not inherently constant-time, though this is a secondary concern relative to
the missing lockout.

**Reproduction:** `tests/integration/pin-lockout.spec.mjs`. Sets a real 4-digit PIN through
the app's own `hashPin()` + settings store, reloads to trigger the real unlock modal, and
scripts 15 consecutive wrong guesses through the actual `#unlockPin` input and `#unlockNow`
button — exactly what a DevTools console loop would do.

```
[evidence] 15/15 attempts: hint stayed "Incorrect PIN" every time, input never disabled,
           per-attempt latency ~97–122ms flat (no growing backoff)
```

At ~115ms/attempt, all 10,000 combinations of a 4-digit PIN are exhaustible in under 20
minutes from a single unattended browser tab; a 6-digit PIN in under 32 hours (or minutes,
parallelized across multiple tabs — nothing here serializes attempts either).

**Impact:** App Lock's threat model is "someone else with the unlocked-or-briefly-accessible
device" (per CLAUDE.md's credential table, the PIN gates *app* access, not disk encryption).
Under that model, an unattended device (glovebox, truck stop, borrowed phone) is fully
exposed to trip/expense/fuel financial data within the time it takes to eat lunch.

**Proposed fix (tradeoff noted):** Add a persisted failed-attempt counter (in `settings`,
alongside `appLockPin`) with escalating delay (e.g. 5 free attempts, then 30s/2min/10min
lockout windows) and a hard reset only via full app data wipe or a recovery flow. Tradeoff:
this is a local-only PIN with no server backing, so a "forgot PIN" story needs a
deliberately painful reset (e.g., requires the JSON export passphrase or a full data-clear
acknowledgment) or the lockout becomes a self-inflicted denial-of-service for the driver.

---

### F-6 — Concurrent trip edits from two tabs silently lose data (High)

**Where:** `app.js:943-955` (`upsertTrip`), `app.js:8650-8653` (`openTripWizard` snapshot),
`app.js:8809-8852` (`collectTrip`/`save`).

**The bug:** `upsertTrip()`'s "TOCTOU-safe: read + write in single readwrite transaction"
comment is accurate only for the **audit-log snapshot** written inside that same call — it
says nothing about the trip record itself, because the read that actually seeds the edit form
happens much earlier (`openTripWizard(existing)`, a separate IDB transaction at modal-open
time). `save()`/`collectTrip()` then always writes the **entire** in-memory `trip` object with
`stores.trips.put(t)` — a full overwrite, not a field-level patch — with no `updatedAt` /
version precondition check before the put. Two tabs (or two devices sharing local storage,
or simply two browser windows on one device) open on the same trip race: whichever calls
`upsertTrip()` last wins completely, silently reverting every field the losing-order tab
changed, even fields the winning tab never touched (because its in-memory copy still holds
the old value for those fields too).

**Reproduction:** `tests/integration/toctou-concurrent-edit.spec.mjs`. Seeds one trip, opens
its real Edit view in two independent Playwright pages sharing one browser context (same as
two tabs on one device), changes `pay` 1000→1500 in Tab A and saves, then — using Tab B's
form which still holds the pre-Tab-A value because it loaded first — changes an unrelated
field (`loadedMiles`) in Tab B and saves.

```
[evidence] Tab B's form still showed pay=1000 when it saved (stale)
[evidence] final stored trip: pay=1000, loadedMiles=450
```

Tab A's `pay` change is gone. No error, no conflict warning, no merge — just silent loss.

**Impact:** Any workflow with two open tabs (common — "let me check something in a new tab
while this form is open") or, per CLAUDE.md's Dispatch Layer note, any future multi-device
sync work built on the current storage model inherits this. Financial fields (`pay`,
`isPaid`, `paidDate`) are exactly what's at risk.

**Proposed fix (tradeoff noted):** Store `updatedAt` (already present) as an optimistic lock:
before `put`, re-read the current record inside the same transaction and reject/merge if its
`updatedAt` doesn't match what the form started from, surfacing a "this trip changed since you
opened it — reload?" prompt. Tradeoff: added complexity in every edit path and a new failure
mode (conflict prompt) the driver has to resolve one-handed; a cheaper partial mitigation is
to warn the driver in-app when a second tab of FreightLogic is detected open (`BroadcastChannel`
or `storage` event), which doesn't fix the race but makes it visible.

---

### F-2 — `trip.paidDate` bypasses date validation applied to every sibling field (Medium)

**Where:** `app.js:926` (the bug), contrast with `app.js:913-916` (`pickupDate`,
`deliveryDate`, `invoiceDate`, `dueDate` — all `isValidISODate`-checked in the same function),
`app.js:1637` (CSV import writes `paidDate` from a raw cell with no validation before it
reaches `sanitizeTrip`), `app.js:2152-2155` (`computeBrokerStats` — no sanity bound on the
resulting day-count), `app.js:15427-15429` (`renderMoneyCard` — the same kind of calculation,
*with* a `d>=0 && d<365` bound).

**The bug:** Every date field on a trip goes through `isValidISODate()` in `sanitizeTrip()`
except `paidDate`:
```js
t.paidDate = raw.paidDate || (t.isPaid ? isoDate() : null); // app.js:926 — no validation
```
`daysBetweenISO()` (`app.js:2111-2116`) does return `null` for genuinely unparseable strings,
so garbage that `new Date()` can't parse at all is filtered out downstream. But a
CSV-imported `PaidDate` column (`app.js:1637`) reaches this field completely unvalidated, and
any string `new Date()` *can* parse — including nonsensical-but-valid values like a
pre-invoice date or a far-future date — flows straight into day-count math. `renderMoneyCard`
bounds its result (`d>=0 && d<365`); `computeBrokerStats`, which drives per-broker "average
days to pay" analytics, does not.

**Reproduction:** `tests/unit/pure-functions.spec.mjs` — calls the real, exported
`sanitizeTrip()` with garbage in every date field. `pickupDate`/`deliveryDate`/`invoiceDate`
all fall back to a valid ISO date as designed; `paidDate` is stored verbatim.

**Impact:** Corrupted or adversarial CSV import data (a driver's own bad export from another
tool, or a shared/imported file) can skew per-broker pay-speed analytics with unbounded values,
with no user-visible sign anything is wrong — a wrong-but-confident-looking signal in a
feature (Broker Intel) explicitly meant to steer bid decisions.

**Proposed fix (tradeoff noted):** Add `isValidISODate(raw.paidDate) ? raw.paidDate : null` at
`app.js:926`, matching every sibling field, and add the same `d>=0 && d<365` bound to
`computeBrokerStats` that `renderMoneyCard` already has. No real tradeoff — this brings
`paidDate` in line with the pattern the rest of the function already uses.

---

### F-5 — `window.__FL_TESTS` is unconditionally live in production (Low / Informational)

**Where:** `app.js:16021-16038`.

**The bug:** The comment says *"Only active when `window.__FL_TESTS_ENABLED` is set before
load"*. No code anywhere in `app.js` (or any other shipped file) reads
`window.__FL_TESTS_ENABLED`. The assignment is unconditional:
```js
if (typeof window !== 'undefined'){
  window.__FL_TESTS = { escapeHtml, csvSafeCell, ..., hashPin, sanitizeTrip, ... };
}
```
Every production page load exposes 31 internal functions/constants — including `hashPin`,
every sanitizer, and the full pricing tables — to any script executing in the page context: a
same-origin XSS payload, a malicious browser extension, or anything pasted into DevTools.

**Reproduction:** `tests/integration/fl-tests-exposure.spec.mjs`. Loads the app with *no* init
script at all (the opposite of what the comment says is required) and confirms
`window.__FL_TESTS` and `window.__FL_TESTS.hashPin` are present anyway.

**Impact:** Low on its own — these are pure functions operating on caller-supplied data, not
secrets or live DB handles — but it's unintended attack-surface widening (a reconnaissance aid
for an attacker who already has *some* script execution) and a straightforward contradiction
between the code's stated intent and its actual behavior, exactly the kind of drift this audit
was asked to catch.

**Proposed fix (tradeoff noted):** Either gate the assignment on `window.__FL_TESTS_ENABLED`
as documented (breaks this test suite's current approach of testing the production bundle
directly — the harness would need to set the flag before navigation, which is a one-line
change in `tests/lib/harness.mjs`), or drop the comment's claim and accept the exposure as
intentional. Given this audit's own harness leans on `__FL_TESTS` for fast, accurate coverage
of pure functions, the honest fix is probably to gate it AND update the harness to set the
flag — not to remove the export entirely.

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
  two tabs, though the code shape strongly suggests the same bug class applies.

## Test Suite

Committed under `tests/`:
- `tests/lib/harness.mjs` — launches a real headless Chromium (Playwright) against the app
  served from the repo root, with real IndexedDB/Cache Storage/`crypto.subtle`. Fresh browser
  context per spec file (equivalent to a brand-new device).
- `tests/unit/pure-functions.spec.mjs` — 13 tests against `window.__FL_TESTS` exports.
- `tests/integration/dz-exit-grade-cap.spec.mjs` — F-1.
- `tests/integration/tax-export-csv-corruption.spec.mjs` — F-3.
- `tests/integration/pin-lockout.spec.mjs` — F-4.
- `tests/integration/toctou-concurrent-edit.spec.mjs` — F-6.
- `tests/integration/fl-tests-exposure.spec.mjs` — F-5.
- `tests/run-all.mjs` — runs every spec and prints an aggregate summary.

**Run it:**
```bash
ln -sfn "$(npm root -g)/playwright" node_modules/playwright   # one-time, see tests/README.md
node tests/run-all.mjs
```
Last run: **19 passed, 4 failed** across 6 spec files (F-1/F-5 are proven via passing
assertions plus logged evidence; F-2/F-3/F-4/F-6 are proven via a failing assertion each — the
failures are the point, they are read-outs of real app behavior, not broken tests).
