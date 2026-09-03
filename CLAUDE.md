# FreightLogic — Claude Code Guide

## Project Overview

**FreightLogic v24.0.3** is a production-ready PWA (Progressive Web App) built for expedited cargo van operators. It provides freight decision intelligence: load scoring, bid recommendations, trap detection, market positioning, proactive positioning briefs, and full business bookkeeping — all running locally in the browser with optional cloud backup and OpenAI-backed load evaluation.

**Stack:** Vanilla JS (IIFE, `'use strict'`), HTML5, CSS custom properties, IndexedDB, Service Worker, Cloudflare Worker (cloud backup + AI evaluate).

**No build system.** No npm, no bundler, no transpiler. Everything ships as flat files.

**v24.0 authority rule:** `app.js` is the sole deterministic owner of load verdict, grade, economics, and bid range. USA scoring and `midwest-stack-authority.js` are evidence/advisory layers. Cloud Worker `/evaluate` may explain or challenge assumptions, but it must project—not recalculate—the canonical decision.

---

## File Structure

```
index.html                 — Single-page app shell + all CSS (Design System v3.0 "Command",
                             with v4.0 "Command" component extensions)
app.js                     — Core application (~830KB, all logic in one IIFE)
voice-load.js              — Voice input enhancement module (spoken numbers, interim results)
admin-driver-ui.js         — Admin driver management UI (injected via service worker)
midwest-stack-authority.js — Midwest Stack v2 authority overlay; TRUE_RPM decision layer
                             (injected via service worker, not referenced from index.html)
sw-bridge.js               — Service worker auto-update bridge (SKIP_WAITING + reload)
service-worker.js          — PWA offline caching; injects admin-driver-ui.js and
                             midwest-stack-authority.js into HTML responses
cloud-backup-worker.js     — Cloudflare Worker: multi-user backup + AI load evaluation + AI field extraction
manifest.json              — PWA manifest
midwest-stack-config.json  — Midwest Stack tuning config (precached, offline-available)
_headers                   — Cloudflare Pages security headers (CSP, X-Frame-Options, Permissions-Policy)
wrangler.jsonc             — Wrangler config for the Pages/Worker deploy (`freightlogic-v2`)
favicon*.png / icon*.png   — App icons
README.txt                 — Notes on optional offline vendor files (Tesseract OCR only, v23.9)
vendor/                    — Bundled third-party scripts committed to the repo (v23.9, X-10):
                             `xlsx.full.min.js` (SheetJS v0.18.5) + its Apache-2.0
                             `xlsx.full.min.js.LICENSE`. Precached by the service worker's
                             critical shell — see PWA / Service Worker below.
docs/                      — Deployment parity checklist, source authority, release notes,
                             `BACKUP_CONTRACT.md`, `DEFERRED.md` (v23.9)
schemas/                   — JSON schemas (broker memory, positioning memory, screenshot intake)
scripts/                   — `verify-cloudflare-parity.mjs` deploy-parity checker
tests/                     — Playwright suite (real headless Chromium, real IndexedDB).
                             `run-all.mjs` runs everything; see `tests/README.md`
AUDIT_REPORT.md            — Adversarial audit findings F-1…F-8 (v23.8.x) and X-01…X-12 (v23.9)
                             with reproductions
FIELD_TEST_CHECKLIST.md    — Device-only tests a headless harness cannot cover
```

### Bundled vs. optional offline vendor files
- `vendor/xlsx.full.min.js` — SheetJS v0.18.5 (Excel import). **Bundled, not optional**
  as of v23.9 (X-10) — no CDN fallback exists; `loadSheetJS()` (`app.js`) loads only this
  file, and the service worker precaches it in the install-blocking critical shell.
- `tesseract.min.js` + `worker.min.js` + `tesseract-core-simd-lstm.wasm.js` — Tesseract.js
  v5.1.1 (OCR receipts). Still **optional** — drop these in the repo root to avoid the
  `cdn.jsdelivr.net` fallback `loadTesseract()` (`app.js`) otherwise uses. This is why
  `cdn.jsdelivr.net` is still in the CSP's `script-src`/`connect-src` (`index.html`,
  `_headers`) even though SheetJS no longer needs it.

---

## Architecture

### app.js structure (in order)
1. **Constants & config** — `APP_VERSION`, `DB_NAME`, `LIMITS`, `IRS` tax constants
2. **Security utilities** — `escapeHtml`, `deepCleanObj`, `csvSafeCell`, `sanitizeImportValue`
3. **Numeric hardening** — `finiteNum`, `posNum`, `intNum`, `validateRecordSize`
4. **Storage** — `requestPersistentStorage`, `checkStorageQuota`, ITP/Safari detection
5. **Navigation** — `openTripNavigation` (Apple Maps on iOS, Google Maps otherwise)
6. **UI utilities** — `toast`, `openModal`, `closeModal`, `haptic`, autocomplete
7. **IndexedDB layer** — `initDB` (v12 schema), `migrateFromLegacyDB`, `ensureLocalUserId`, `tx`, `idbReq`, CRUD for all stores
8. **Data stores:** `trips`, `expenses`, `fuel`, `receipts`, `receiptBlobs`, `settings`, `auditLog`, `marketBoard`, `laneHistory`, `weeklyReports`, `reloadOutcomes`, `bidHistory`, `documents`, `gpsLogs`
9. **Export/Import** — JSON, CSV, XLSX (trips/expenses/fuel), receipt blobs
10. **Freight evaluator** — Market Feed, Tomorrow Signal, Strategic Floor A–E scoring; auto-triggers OpenAI analysis via `/evaluate`
11. **Cloud backup** — encrypt/decrypt, push/pull, user identity, AI evaluate call
12. **UI rendering** — Trip list, expense list, fuel log, dashboard, settings panel
13. **F21 GPS Trip Tracking** — `startTripTracking`, `stopTripTracking`, `nearestMarketCity`, `renderTripTrackingUI`, `resumeTrackingIfActive`
14. **F22 Money Dashboard** — `renderMoneyCard` with weekly P&L, unpaid summary, goal progress, quarterly tax estimate
15. **F23 Smart Load Inbox** — `parseLoadTextForInbox`, `renderLoadInbox`, auto-fills evaluator fields
16. **F24 Proactive Positioning Engine** — `getPositioningBrief`, `renderPositioningCard`, `_triggerPostDeliveryBrief`
17. **F25 Vehicle Maintenance Tracker** — `openMaintenanceTracker`, `checkMaintenanceDue`, `_getMaintenanceSchedule`
18. **F26 First-Time Setup Wizard** — `checkFirstRunSetup`, `openSetupWizard`, `_saveSetupWizardResults`
19. **F27 Unified Load Intake** — `openLoadIntake`; paste/voice/photo → parsed draft review → score or save as trip
20. **F28 Diagnostics Panel** — `openDiagnosticsPanel`; SW, cache, IDB counts, voice, cloud, AI endpoint self-test
21. **F29 Post-Trip Lane & Broker Review** — `openPostTripReview`, `_savePostTripReview`; 6-question chip UI after delivery

### IndexedDB schema (`DB_VERSION = 15`, `DB_NAME = 'FreightLogic_v18'`)
- `trips` — keyPath: `orderNo`
- `expenses` — keyPath: `id`
- `fuel` — keyPath: `id`
- `receipts` — keyPath: `tripOrderNo`
- `receiptBlobs` — keyPath: `id`
- `settings` — keyPath: `key`
- `auditLog` — keyPath: `id`
- `marketBoard` — keyPath: `id`
- `laneHistory` — keyPath: `id`
- `weeklyReports` — keyPath: `weekId`
- `reloadOutcomes` — keyPath: `id`
- `bidHistory` — keyPath: `id`
- `documents` — keyPath: `id`
- `gpsLogs` — keyPath: `id`, autoIncrement
- `loadLifecycle` — keyPath: `lifecycleId` (v14; indexes `updatedAt`, `orderNo`, `broker`)
- `normalizedEvidence` — keyPath: `evidenceId` (v15; indexes `recordedAt`, `lifecycleId`,
  `fingerprint`, `observedAt`) — the durable normalized-evidence store

### DB migration
On first boot after upgrade from any prior version, `migrateFromLegacyDB()` opens
`XpediteOps_v1` read-only, copies all stores into `FreightLogic_v18`, records
`legacyMigrated` in settings, and never runs again. The old DB is not deleted.

### User namespace
`ensureLocalUserId()` generates a stable `usr_<16hex>` on first boot, stored in
`settings['localUserId']`. Foundation for multi-user import/restore isolation.

---

## Key Constants

```js
const APP_VERSION = '24.0.3';
const DB_VERSION = 15;
const DB_NAME = 'FreightLogic_v18';
const DB_NAME_LEGACY = 'XpediteOps_v1';
const PAGE_SIZE = 50;

// IRS tax data (2026)
// X-02 (v23.9): mileage rate is date-keyed, not a flat per-year constant —
// getMileageRate(date) reads the MILEAGE_RATES table (app.js, near the IRS
// const). 2026 has two bands: 0.725/mi Jan 1–Jun 30, 0.76/mi Jul 1–Dec 31
// (IRS Announcement 2026-11 midyear increase). Adding a future year, or a
// future midyear correction, is a MILEAGE_RATES table edit only.
IRS.PER_DIEM_CONUS = 80          // $/day
IRS.SE_RATE = 0.153              // 15.3% self-employment tax

// Import/receipt limits
LIMITS.MAX_IMPORT_BYTES = 30MB
LIMITS.MAX_RECEIPT_BYTES = 6MB
LIMITS.MAX_RECEIPTS_PER_TRIP = 20
```

---

## Security Requirements

This app handles financial data. All security mitigations are intentional and must not be removed:

- **XSS:** Always use `escapeHtml(s)` before inserting user content into `innerHTML`.
- **CSV injection:** Always wrap exported cells with `csvSafeCell(val)`.
- **Prototype pollution:** Use `deepCleanObj(obj)` when ingesting untrusted objects.
- **Import sanitization:** All imported trips/expenses/fuel pass through `sanitizeTrip/Expense/Fuel`.
- **Record size limit:** `validateRecordSize(obj, label)` — max 1MB per record.
- **Allowed settings keys:** Whitelist enforced on import (`ALLOWED_SETTINGS_KEYS`).
- **CSP:** Defined in `index.html` — do not loosen without review.

---

## Credential Storage Rules

| Credential | Storage | Scope |
|---|---|---|
| Backup token (`flk_…`) | IndexedDB (`settings`) | Persists across sessions — non-secret identifier |
| Encryption passphrase | `sessionStorage` (`fl_cloud_pass`) | Cleared on tab/browser close — never written to disk |
| Admin token | `sessionStorage` (`fl_admin_tok`) | Cleared on tab/browser close |
| Device ID | `localStorage` (`fl_device_id`) | Persists — non-secret identifier |

Do not move the passphrase or admin token back to persistent storage.

The admin token grants create/list/revoke over **every** driver account, so it is the most
sensitive credential in the app. Both writers must keep it session-scoped:
`app.js` (`cloudAdminSaveToken`) and `admin-driver-ui.js` (`saveTok`/`loadTok`).
`admin-driver-ui.js` also runs `purgeLegacyTok()` on every load, which migrates any token
left in `localStorage` by a pre-23.8.0 build into `sessionStorage` and deletes the on-disk
copy. Do not remove that purge until enough releases have passed that no stale copies remain.

---

## Coding Conventions

- **No external frameworks** — pure DOM APIs only.
- **`$` / `$$`** — shorthand for `querySelector` / `querySelectorAll`.
- **`fmtMoney(n)`** — format as USD currency string.
- **`roundCents(n)`** — IEEE-754-safe cent rounding.
- **`isoDate(d)`** — local ISO date string `YYYY-MM-DD`.
- **`clampStr(s, max)`** — trim + limit string length (default 120).
- **Event listeners:** Use `addManagedListener(el, evt, handler)` — automatically cleaned up on `beforeunload`.
- **All async DB ops** return Promises via `idbReq(req)`.
- **Transactions:** Use `tx(storeNames, mode)` helper — returns `{ t, stores }`.

---

## Cloud Backup Worker (Cloudflare Worker)

**File:** `cloud-backup-worker.js`
**KV binding:** `BACKUPS`
**Endpoint:** `https://freightlogic-backup.fimseitef.workers.dev`

### Environment

| Type | Name | Purpose |
|---|---|---|
| Secret | `ADMIN_TOKEN` | Admin endpoint auth |
| Secret | `OPENAI_API_KEY` | AI load evaluation |
| Var | `ALLOWED_ORIGIN` | Exact app origin for CORS (falls back to `*` if unset) |
| Var | `OPENAI_MODEL` | OpenAI model ID (default: `gpt-4.1-mini`) |

### Key endpoints:
- `POST /admin/users` — create user (returns `userId`, `token`)
- `GET /admin/users` — list users
- `DELETE /admin/users/:id` — deactivate user
- `POST /backup` — store encrypted backup (`X-Device-Id`, `X-Backup-Token` headers)
- `GET /backup` — retrieve latest backup
- `DELETE /backup` — delete all backups for this user+device
- `GET /list` — list backup keys
- `GET /status` — backup count + user name
- `POST /evaluate` — AI load evaluation (OpenAI); rate limited 100 req/hr per user (hourly window); returns `{ ok, ai: { verdict, grade, summary, trueRpmBand, bidAdvice, primaryReason, risks, positives, nextMove }, model, user }`
- `POST /extract` — AI field extraction from raw load text; rate limited 50 req/hr per user (hourly window); returns `{ ok, fields: { orderNo, customer, broker, origin, destination, pay, loadedMiles, deadheadMiles, pickupDate, deliveryDate, weight, commodity, notes }, model, user }`
- `POST /backup/delta` — store delta (partial sync payload); max 2MB; expires after 7 days; keeps last 20 deltas
- `GET /backup/delta` — (v11, X-01) retrieve every currently-retained delta for this user+device, chronological oldest-first, plus `retainedCount`/`totalCreated` so the client can detect pruning; returns `{ ok, deltas: [{key, ts, payload}], retainedCount, totalCreated }`

Token format: `flk_<uuid-no-dashes>`

---

## IRS / Tax Data

Update annually. Sources:
- Per diem: IRS Notice 2025-54
- Mileage: IRS Notice 2026-10
- SE tax: IRS Pub 463 / Schedule SE

Current rates are in the `IRS` constant at the top of `app.js`.

---

## PWA / Service Worker

- `manifest.json` references `v=24.0.3` cache-busting query on the manifest link.
- `service-worker.js` handles offline caching; version `24.0.3`; caches `sw-bridge.js`; injects both the `admin-driver-ui.js` and `midwest-stack-authority.js` script tags into HTML responses via `injectEnhancementScripts()` (each guarded by an `injectBeforeBodyClose()` idempotency check); broadcasts `SW_ACTIVATED` message to all open clients on activate. The `install` event's critical (install-blocking) shell includes `midwest-stack-authority.js` and `vendor/xlsx.full.min.js` (X-08/X-10, v23.9) — see "Cloud Backup Worker" and the v23.9 changelog section below.
- Share-target POSTs are staged in the `freightlogic-share-v2` cache (`SHARE_CACHE`) and expire after 5 minutes.
- `sw-bridge.js` detects waiting workers, sends `SKIP_WAITING`, and reloads once — no user prompt required.
- Receipt blobs are cached in the Cache API under `__receipt__/<id>` URLs.
- `enforceReceiptCacheLimit()` keeps cache bounded (max `LIMITS.MAX_RECEIPT_CACHE = 40`).

---

## Development Notes

- **No build step** — edit files directly and reload in browser.
- **Test locally** with any static file server (e.g., `python3 -m http.server 8080`).
- **IndexedDB migrations** — increment `DB_VERSION` and add `if (old < N)` block in `initDB()`.
- **Version bumps** — every release must update all of these. Items 1, 3, 8, and 10 have
  all silently drifted in past releases, so verify them explicitly:
  1. `APP_VERSION` in `app.js` (plus the header comment block at the top). The header
     block's top entry is a *changelog entry*, not just a version string: give the new
     release its own line describing what it shipped, and leave the prior release's text
     under its own version. v24.0.0 shipped with v23.9's entry merely relabelled — it
     still read `v24.0.0 "Trust & Recovery" (X-01..X-12, in progress)` — which is how a
     finished release ends up claiming someone else's work and its own incompleteness.
  2. `SW_VERSION` in `service-worker.js` (plus its header comment)
  3. `?v=` cache-busters in `service-worker.js` — `ADMIN_UI_TAG`, `MIDWEST_STACK_TAG`, and
     every entry in the `CORE` array. These are easy to miss and stale values ship stale assets.
  4. `manifest.json` `name` field
  5. `?v=` query on `<link rel="manifest">` in `index.html`
  6. `?v=` queries on `app.js`, `voice-load.js`, and `sw-bridge.js` script tags in `index.html`
  7. Design-system header comment. This **moved to `styles.css`** when the CSS was
     extracted; there is no design-system comment in `index.html` any more. `styles.css`
     is **gpt**-owned under `/.agents/LANES.md`, so the core lane must request this bump
     through `/.agents/inbox/` rather than editing it. Found stale at `24.0.0` during the
     v24.0.3 recon — it had silently missed 24.0.1, 24.0.2 and 24.0.3.
  8. `VERSION` const and header comment in `midwest-stack-authority.js`
  9. Header comments in `voice-load.js` and `sw-bridge.js`
  10. Version references in `CLAUDE.md` — Project Overview, Key Constants, and PWA sections
  11. `EXPECTED` block in `scripts/verify-cloudflare-parity.mjs` (`serviceWorkerVersion`,
      `manifestName`, `overlayScript`) plus the inline `?v=` / version strings in its
      assertions. Added to this list in v23.8.3 — it was an 11th location that the
      "ten locations" audit never covered, and it fails the deploy check when stale.
  12. **Not a version string, but checked by the same script** (Amendment 5, v23.9):
      `scripts/verify-cloudflare-parity.mjs` also asserts `index.html`'s CSP `<meta>`
      tag and `_headers`' `Content-Security-Policy` line are byte-identical — a real
      drift between them (missing Google Fonts origins in `_headers`) was found and
      fixed while adding this check. If you edit the CSP, edit both files together.
  13. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` — the *manual* checklist quotes
      concrete `?v=` markers, `SW_VERSION`, the manifest `name`, and the expected Worker
      version. Added to this list after the v24.0.0 close-out shipped with this file still
      reading `23.9.0` / Worker `v11`: the close-out fixed every code-side marker and the
      verify script, but nothing pointed at this doc, so it drifted a full release behind
      the thing it exists to verify.
  14. Also verify `service-worker.js`'s `critical` array (the install-blocking shell,
      distinct from the broader `CORE` list) still contains `midwest-stack-authority.js`
      and `vendor/xlsx.full.min.js` (X-08/X-10, v23.9) — a stale/reverted `critical`
      array is a silent regression this checklist wouldn't otherwise catch, since the
      version-string grep below doesn't inspect array contents.
  15. `midwest-stack-config.json` `appTarget`. Added in v24.0.3 — the recon found it
      reading `FreightLogic v24.0.0`, two releases behind, because the quick-audit grep
      below never listed the file. It is now in that grep.
  16. **`SW_VERSION` must equal `APP_VERSION`.** This is not cosmetic, and it is the
      reason v24.0.3 exists. A browser installs a new service worker only when the
      worker script's own BYTES differ; changing `app.js` does not change
      `service-worker.js`. PR #134 (bridge repair) and PR #136 (install identity) both
      shipped under an unchanged `24.0.2` `SW_VERSION`, so `CACHE_NAME`
      (`freightlogic-${SW_VERSION}`) never moved and an existing client had no new cache
      identity to fetch on any axis — it could keep serving the broken bridge
      indefinitely. `tests/unit/cache-generation.spec.mjs` now enforces this invariant,
      along with items 3–6, 11, 12, 14 and 15, so most of this list is machine-checked
      rather than remembered.

  Quick audit — every shipped file should report the new version:
  ```bash
  grep -rno "2[0-9]\.[0-9]\+\.[0-9]\+" app.js index.html manifest.json service-worker.js \
    midwest-stack-authority.js sw-bridge.js voice-load.js styles.css midwest-stack-config.json \
    | awk -F: '{print $1" -> "$3}' | sort -u
  ```
  Historical changelog comments in `app.js` legitimately name older versions — leave those alone.

---

## v22–v23.8 Features (F21–F32)

### F21 — GPS Trip Tracking
- `renderTripTrackingUI()` — populates `#homeTripTrackCard` on Home with Start/Stop button
- `startTripTracking()` → `_showLocationPermissionModal()` (first use) → `_initTrackingObject()` → `_doStartTracking()`
- `stopTripTracking()` — clears watcher, shows review modal, calls `upsertTrip()`
- `resumeTrackingIfActive()` — called on boot; reads `sessionStorage('fl_active_tracking')`
- `nearestMarketCity(lat, lng)` — returns nearest market city within 100 mi, e.g. "Indianapolis, IN"
- `_cleanGpsLogs(trackingId)` — removes `gpsLogs` IDB entries after save or discard
- Settings keys: `f21OnboardingSeen` (bool), `f21PermissionSeen` (bool)
- sessionStorage key: `fl_active_tracking` (JSON: trackingId, startTime, startPos, totalMiles)
- **Error resilience (v23.8.4, F-7):** a `GeolocationPositionError` never ends the session.
  `_activeTracking.gpsErrorSince` / `.gpsErrorCode` track the current error streak (cleared by
  any fix, including a low-accuracy one); `_renderTrackingActive` degrades to "GPS signal lost —
  searching (Nm)" for codes 2/3 or "Tracking paused — location access is off" for code 1, always
  keeping Stop & Save reachable. The error toast fires once per streak, not once per callback.
- `_readSavedTracking()` / `_restoreTrackingFromSaved(saved)` — shared by `resumeTrackingIfActive()`
  and `_showResumeTrackingModal()`. `_readSavedTracking` applies no age policy; each caller
  decides (boot auto-stops a >24 h record, the resume prompt ignores one).
- `_showResumeTrackingModal(saved)` — `startTripTracking()` opens this instead of minting a new
  `trackingId` when a session record ≤24 h old is still present. Resume keeps the original
  session; "Discard & Start New" cleans the old `gpsLogs` and starts fresh.

### F22 — Money Dashboard
- `renderMoneyCard()` — populates `#homeMoneyCard` after `renderHome()` computes KPIs
- Shows: this-week gross/spent/net, unpaid count + amount, collection %, avg days-to-pay,
  weekly goal progress bar, collapsible quarterly tax estimate
- Hides when 0 valid trips; simplified (1-line) view for 1–2 trips; full card at 3+
- Tax estimate uses `IRS.PER_DIEM_CONUS`, `IRS.PER_DIEM_PCT_NON_DOT`, `IRS.SE_NET_FACTOR`, `IRS.SE_RATE`
- Settings keys: `f22OnboardingSeen` (bool)

### F23 — Smart Load Inbox
- `renderLoadInbox()` — populates `#loadInboxCard` at top of Evaluate tab (one-time init via `data-inboxInit`)
- `parseLoadTextForInbox(rawText)` — wraps `parseLoadTextEnhanced()`, adds confidence score (0–100)
- "Score Load →" fills `#mwRevenue`, `#mwLoadedMi`, `#mwDeadMi`, `#mwOrigin`, `#mwDest` and dispatches `input` event
- Recent pastes stored in `sessionStorage('fl_inbox_recent')` (last 5, cleared on session end)
- Settings keys: `f23OnboardingSeen` (bool)

### F24 — Proactive Positioning Engine (v23.0.0)
- `getPositioningBrief(city)` — core intelligence function; combines reload scores, outbound lane history, nearby market anchors, NWS weather alerts, and day-of-week trip patterns into a structured brief with HOLD/REPOSITION/HUNT command + HIGH/MEDIUM/LOW confidence; 5-min cache via `_positioningCache`
- `renderPositioningCard(overrideCity?, isExploring?)` — populates `#homePositioningCard` on Home; auto-detects city from GPS, last trip destination, or override; shows command badge, outbound lane rows (tap → `openLaneBreakdown`), weather alerts, collapsible nearby markets; `isExploring` flag prevents infinite drill-down; F24 onboarding card on first display
- `_triggerPostDeliveryBrief(city)` — fires ~1s after trip save when `saved.deliveryDate && saved.destination`; shows modal with command badge + quick stats; opt-out checkbox after 3rd view; suppressed by `f24AutoBriefDisabled` setting
- GPS stationary detection: `_doStartTracking` setInterval refreshes positioning card after 10+ min stationary; resets `_f24Shown` when moving again
- `_positioningCache` cleared on every trip save (`upsertTrip` call site)
- Settings keys: `f24PostDeliveryCount` (int), `f24AutoBriefDisabled` (bool), `f24OnboardingSeen` (bool)

### F25 — Vehicle Maintenance Tracker (v23.1.0)
- `checkMaintenanceDue()` — non-blocking; called in `renderHome()`; populates `#homeMaintenanceAlert` if any item is overdue or due within 14 days
- `openMaintenanceTracker()` — Intel tile modal; shows all service items with status badge (OK/warn/overdue), "Log Service" per item, and "Add Item" form for custom services
- `_logMaintenanceService(items, idx, onDone)` — sub-modal (date, cost, notes); saves updated `lastDate`/`lastCost` to schedule; auto-creates an expense record (category: `Maintenance`) when cost > 0
- `_getMaintenanceSchedule()` / `_saveMaintenanceSchedule(items)` — load/save `settings['maintenanceSchedule']`; first-run seeds four default items (Oil & Filter, Tire Rotation, Vehicle Inspection, Registration)
- `_maintenanceStatus(item)` — returns `{ label, daysUntil, state }` where state is `ok` / `warn` / `overdue`
- `MAINTENANCE_DEFAULTS` — four preset items with `id`, `label`, `intervalDays`, `icon`
- Intel tile: `🔧 Maintenance` in `INTEL_TILES`; accessible via More page tile handler
- No new IDB store — schedule persists in `settings['maintenanceSchedule']`; service cost events stored as ordinary expenses
- Settings keys: `maintenanceSchedule` (array), `lastMaintenanceNotify` (timestamp, reserved)

### F26 — First-Time Setup Wizard (v23.4.0)
- `checkFirstRunSetup()` — called on boot; skips if `f26SetupComplete` or user already has trips (migration-safe)
- `openSetupWizard()` — 5-step modal: home base, vehicle info, weekly goal + fuel cost, monthly fixed expenses, operating preferences
- `_saveSetupWizardResults(vals)` — persists all wizard values to settings; builds `monthlyExpensesConfig` array (non-zero items only); keeps legacy individual monthly cost keys in sync; saves `vehicleYear` and `vehicleMake`
- Driver Command Strip wired in `renderHome()` (idempotent): `#dcEvaluate`, `#dcAddTrip`, `#dcAddExpense`, `#dcMoney`, `#dcBestMove`
- Monthly Expense Manager (F26 companion) — `openMonthlyExpenseManager()` accessible from Settings
- Settings keys: `f26SetupComplete` (bool), `monthlyExpensesConfig` (array), `homeLocation`, `vehicleClass`, `vehicleMpg`, `fuelPrice`, `weeklyGoal`, `preferredRegion`, `payloadLimitLbs`, `vehicleYear`, `vehicleMake`, `autoRecurringExpenses` (bool)

### F27 — Unified Load Intake (v23.4.0)
- `openLoadIntake()` — replaces the ad-hoc parse-then-fill flow; two-stage modal (text input → parsed draft review)
- Stage 1: paste area + voice button + Parse action; voice uses `SpeechRecognition` (same as voice-load.js)
- Stage 2: editable draft grid (revenue, miles, deadhead, weight, origin, dest, order#, broker, notes) with parse-confidence indicator; "Score This Load" fills evaluator fields and navigates to Evaluate tab; "Save as Trip Draft" saves to `settings['tripDraft']` and opens `openQuickAddSheet()`
- Parse confidence color-coded: ≥70% green, ≥40% amber, <40% red
- Accessible via Driver Command Strip (`#dcEvaluate`) and F23 Load Inbox

### F28 — Built-in Diagnostics / Self-Test (v23.4.0)
- `openDiagnosticsPanel()` — accessible via More → Advanced → Diagnostics Intel tile
- Auto-runs on open; "Run Tests Again" button for manual re-run
- Tests: SW registration state, Cache API keys, IDB record counts (trips/expenses/fuel/receipts/laneHistory), voice input support, File API, offline/SW readiness, cloud backup config, AI endpoint ping (6s timeout)
- Color-coded pass/fail per row (green/red/neutral)

### F29 — Post-Trip Lane & Broker Review (v23.4.0)
- `openPostTripReview(trip)` — fires ~1.2s after trip save when trip has `deliveryDate`, `origin`, `destination` and review not yet done
- 6 chip-tap questions: lane rating (1–5), broker payment speed, reload ease from destination, destination market strength, rate vs. strategy, would-run-again
- `_savePostTripReview(trip, answers)` — merges review into existing `laneHistory` record (running avg rating, would-run %, last broker pay/reload/dest fields) or creates a new minimal record; stores broker feedback in `bidHistory` for broker grading
- One-time-per-trip guard: `laneReviewDone_<orderNo>` settings key; review prompt suppressed on re-save of same trip
- Settings keys: `laneReviewDone_<orderNo>` (bool per trip), `laneReviewEnabled` (global opt-out, reserved)

### F30 — Tax Season Export (v23.4.0)
- `openTaxSeasonExport()` — Intel tile modal; year selector (prior 3 years); Schedule C summary with gross income, expense line items by IRS category, total deductions, net profit, mileage deduction, per diem deduction, and SE tax estimate
- "Export CSV" downloads IRS-ready Schedule C summary + full mileage log as a two-sheet CSV
- "Print / Save PDF" opens a `window.print()`-friendly formatted view
- Accessible via More → Tax & Finance Intel tile
- Settings keys: `f30LastExportYear` (int)

### F31 — Earnings Trends (v23.4.0)
- `renderEarningsTrends()` — appended to `#homeMoneyCard` when 4+ weeks of data exist; pure SVG bar chart (no canvas)
- Week view: last 8 weeks, gross revenue bars with net overlay line; tap bar to see week detail
- Month toggle: last 6 calendar months; same bar/line treatment
- `_buildWeeklyBuckets(trips, exps, n)` / `_buildMonthlyBuckets(trips, exps, n)` — aggregate helpers
- Hidden at < 4 weeks of data to avoid noisy single-bar charts
- Settings keys: `f31TrendView` (`'week'`|`'month'`, persists toggle state)

### F32 — Smart Insight Card (v23.7.0)
- `renderSmartTip(state)` — non-blocking; injects one data-driven insight into the "What's Next" card on Home
- Checks (in priority order): broker concentration ≥50%, RPM trend decline ≥8%, deadhead trend rise ≥5pp, AR 45+ days outstanding ≥2 invoices, personal weekly gross record
- Positive insight (record week) shown when no warnings are present
- Dismisses silently if no insight qualifies; re-evaluated on every home render
- No settings keys — purely reactive to live data

---

## v23.8.0 — Live-Data Corrections

Not a new feature tier; a correctness pass over the live-data inputs that feed scoring.

### EIA fuel price feed
- Requires a user-supplied EIA API key stored in `settings['eiaApiKey']` — the feed is inert without one and returns `null` early.
- Queries the EIA v2 weekly series `petroleum/pri/gnd`, faceted to Midwest PADD 2 (`duoarea=R20`), product `EPMR` (regular gasoline).
- Falls back to product `EPM0` (all grades) when the primary series returns no usable record; returns `null` if both miss.
- Throttled to one fetch per 3 days via `settings['eiaLastFetchTs']`; 8s request timeout.
- On success writes `eiaLastPrice`, `eiaLastDate`, `eiaLastFetchTs` and surfaces an "Apply" link in Settings that writes the price into `fuelPrice`.
- Settings keys: `eiaApiKey`, `eiaLastPrice`, `eiaLastDate`, `eiaLastFetchTs`

### Other v23.8.0 changes
- July 2026 market override table added as `rate-overrides-2026-07.json` (renamed from
  `rate-overrides-2026-05.json` — filename now matches content). **Superseded in
  v23.8.3:** that JSON was never read by any code path, so its bands never took
  effect; they now live in `midwest-stack-authority.js` and the file is deleted.
- Refreshed fuel baseline — this lives in `MW.fuelBaseline` (`app.js:5961`,
  currently `3.55`), *not* in the rate-overrides JSON, which has no fuel field.
- `midwest-stack-authority.js` version aligned to the app version (`VERSION` const + header).

---

## v23.8.1 — Audit Cleanup

Not a feature release; a verify-then-fix pass over items that had drifted or were
left unmerged from prior audits.

- Confirmed the admin token (`fl_admin_tok`) is sessionStorage-only in both `app.js`
  and `admin-driver-ui.js`, with `purgeLegacyTok()` migrating any stale on-disk copy
  at boot (this had shipped in PR #65 ahead of this pass — verified, not re-applied).
- Confirmed `rate-overrides-2026-07.json` is the correctly named file and that no
  active code, docs, or checklist reference the pre-rename filename (historical
  dated docs under `docs/` intentionally still name the file as it was at the time,
  same convention as `app.js` changelog comments — left alone). *(This audit checked
  the filename but not whether anything read the file — v23.8.3 found nothing did,
  and deleted it.)*
- Resolved comment-header version drift in `voice-load.js`, `sw-bridge.js`, and the
  `VERSION` constant in `midwest-stack-authority.js`.
- Full version-string bump to 23.8.1 across all ten checklist locations.

---

## v23.8.2 — Broker Identity Chain

`bidHistory` recorded outcomes and reviews from three separate flows (F29 broker-pay
reviews, Counter-Offer Memory, and the bid win/loss log via `logBid`) but never
captured *who* or *where* consistently — `omegaSaveToBidHistory` wrote `broker: ''`
and `lane: ''` on every save, and `logBid` had zero call sites. This pass wires the
identity chain end-to-end so `bidHistory` finally records real broker/lane keys.

- Reused the existing `#mwBroker` field (added ahead of this pass as part of the
  v24.0.0 slice, already autocompleted at all four load-intake entry points) instead
  of introducing a duplicate `#mwBrokerName` field. Backed it with a `<datalist
  id="mwBrokerList">`, filled by the new `populateBrokerList()` (distinct broker
  names from `bidHistory`/`laneHistory`, refreshed every time the Evaluate view is
  shown via `renderOmega()`).
- New shared helper `normBroker(s)` — trims, lowercases, collapses whitespace — is
  now the single source of truth for broker identity across the app.
- `openBrokerNotes` / `normalizeBrokerKey` rekeyed off `#mwBroker` (via `normBroker`)
  instead of `#mwDest || origin`. No fallback key: the Broker Notes button is hidden
  whenever `#mwBroker` is empty and reappears on its `input` event.
- `omegaSaveToBidHistory` now writes real `broker` (normalized) + `brokerDisplay`
  (trimmed original) + `lane` (via `normalizeLane()`, the same format `laneHistory`
  uses) instead of hardcoded empty strings, pulled from the shared `#mwBroker` /
  `#mwOrigin` / `#mwDest` fields (which stay mounted in the DOM even while the Omega
  tab is active).
- `logBid()` is now wired to a Won / Lost / Expired pill control on the evaluator's
  result card (below Bid Range); outcome values map directly to `logBid`'s existing
  `'won' | 'rejected' | 'expired'` set — no signature change needed. Clicking a pill
  disables the group and highlights the chosen outcome.
- DB `v12 → v13`: migration flags any existing `bidHistory` row with an empty/missing
  `broker` as `legacyUnkeyed: true` (nothing is deleted). `getBrokerIntel()` (the
  bidHistory-backed per-broker aggregator) and Counter-Offer Memory's history view
  now exclude `legacyUnkeyed` rows so old blank-broker rows don't pollute stats.
- ~~Known gap: `getBrokerIntel()`'s index query still reads the raw,
  un-normalized `#mwBroker` value.~~ **Closed in the v23.8.3 correctness pass** —
  see below; both sides of the `bidHistory` broker index now agree.

---

## Intelligence Bridge — first v24 slice (landed ahead of v24.0.0)

The first v24 slice, shipped before the v24.0.0 release and now folded into the
Unified Decision Engine (see the v24.0.0 section at the end of this file) — its
STEP 7 Personal Intelligence downgrade is one of the authority boundaries that
release locked down. Historically `laneHistory`,
`bidHistory`, and `reloadOutcomes` were recorded (F29 reviews, Counter-Offer
Memory, bid win/loss log) and *displayed* (Lane Intel panel, USA Engine panel,
counter-offer negotiation intel) but never touched the evaluator's ACCEPT /
REJECT / STRATEGIC verdict — a driver could see "Trap lane, 4 Dead Zone exits"
right next to a green ACCEPT banner with no reconciliation between the two.

- `usaScoreLoad(opts)` now separates `personalScore` / `personalBullets` out of
  its blended `score` — the portion of the USA Engine score driven specifically
  by *your* trip history (lane RPM-vs-average, DZ trap pattern, destination
  reload difficulty, broker pay speed, broker counter-offer/win acceptance),
  as opposed to market-structure factors (corridor, zone, economics) that are
  already covered by the evaluator's own Geography/RPM steps.
- `getBrokerIntel(broker)` — new aggregator; unifies the three `bidHistory`
  record shapes (F29 `brev_` broker-pay reviews, Counter-Offer Memory `outcome`
  records, bid win/loss log `outcome`) into one per-broker signal:
  `fastPayPct` / `slowPayPct` (from reviews) and `acceptedPct` (accepted +
  partial + won, pooled across both outcome-logging flows).
- `mwEvaluateLoad()` STEP 7 "Personal Intelligence" — reads
  `usaResult.personalScore/personalBullets` and can downgrade an already-ACCEPT
  verdict to STRATEGIC when history disagrees strongly (`personalScore <= -6`);
  informational-only otherwise. **Downgrade-only**: never touches REJECT or
  DZ-EXIT — those stay pure hard-floor / survival-mode outcomes so personal
  history can never soften a rate-floor or profit-margin rejection.
- New optional evaluator field `#mwBroker` (Broker / Customer), persisted in
  `settings['mwLastInputs']`. Auto-filled from `parsed.customer` at all four
  load-intake entry points (Smart Load Inbox modal + Home card, F27 Load
  Intake, OCR quick-scan) when the parser found a broker/company name.
- ~~Known gap: `openBrokerNotes` still keys off `dest || origin`.~~ **Stale — this
  bullet was already untrue when written.** v23.8.2 rekeyed Broker Notes off
  `#mwBroker` via `normBroker()` with no destination/origin fallback
  (`app.js:7169-7191`, `normalizeBrokerKey` at `app.js:14303`). Verified in the
  v23.8.3 correctness pass; the v23.8.2 section above is the accurate one.
- Not yet done: `reloadOutcomes` city-level reload scoring (`getCityReloadScore`)
  was already wired into `usaScoreLoad` pre-existing and is now correctly
  included in `personalScore` — no new work needed there.

---

## v23.8.3 — Correctness Pass

Scoped correctness pass. No new features. Closes the broker-identity read/write
mismatch left open by v23.8.2, fixes a function-shadowing bug found while
auditing the call sites, and puts the July 2026 rate bands into actual effect.

**`bidHistory` broker index — both sides now use `normBroker()`:**

| Direction | Site | File:line | Before |
|---|---|---|---|
| Read | `getBrokerIntel()` | `app.js:12013` | `(broker||'').trim()` — raw case |
| Read | Trip-detail counter intel | `app.js:2904` | `getAll(trip.customer)` — raw case |
| Write | F29 `_savePostTripReview` | `app.js:12182` | `clampStr(trip.customer,60)` — raw case |
| Write | Counter-Offer Memory `comSave` | `app.js:13993` | `clampStr(broker,80)` — raw case |
| Write | Import sanitizer | `app.js:1476` | `clampStr(r.broker,80)` — raw case |
| Write | `logBid()` | `app.js:12199` | caller-normalized only; now also normalizes internally |

Already correct and unchanged: `omegaSaveToBidHistory` (`app.js:8083`).

- Every writer now also stores `brokerDisplay` (trimmed original) so UI keeps
  real casing while the index key stays normalized. `populateBrokerList()` and
  Counter-Offer Memory's broker cards read `brokerDisplay || broker`.
- Counter-Offer Memory's aggregation groups on `normBroker(r.broker)` via an
  `Object.create(null)` map, so pre- and post-normalization rows collapse into one
  card and a literal `__proto__` broker name cannot drop a bucket.
- No existing rows migrated or rewritten. `legacyUnkeyed` handling is unchanged;
  the trip-detail counter-intel reader now also filters `legacyUnkeyed` rows, matching
  `getBrokerIntel()` and Counter-Offer Memory.

**Function-shadowing bug (pre-existing, unrelated to the key mismatch):**
Two top-level `getBrokerIntel()` declarations lived in the same IIFE scope —
the F3 trips-based one and the v24.0.0 bidHistory aggregator declared ~174 lines
later. Hoisting meant the v24 one won at *every* call site, so F3's
`attachBrokerIntelToField` → `renderBrokerAlert` received the bidHistory record
shape and threw on `avgRPM.toFixed(2)`, killing the broker alert under the trip
form's Customer field. The F3 function is renamed `getBrokerTripIntel()`
(`app.js:11834`, caller at `app.js:11895`); the bidHistory aggregator keeps the
original name. Confirmed no other duplicate top-level function declarations in `app.js`.

**Rate bands — July 2026 override put into effect:**
`midwest-stack-authority.js` hardcoded `RATE_OVERRIDE_2026_05` (effectiveDate
`2026-05-25`), and `rate-overrides-2026-07.json` — precached in the service-worker
`CORE` array — was never read by any code path. The May *compression* bands had
therefore stayed in force through a market that inverted to *tightening* in July,
bidding roughly $0.15–0.25/mi low across the middle bands.

- Const renamed `RATE_OVERRIDE_2026_07`, `effectiveDate` → `2026-07-09`, band values
  transcribed verbatim from the July JSON. All three consumers updated
  (`bandForMiles`, the `override` block in `assessLoad`, and the
  `window.FreightLogicMidwestStack` export).
- All five bands had a one-to-one July counterpart on matching mile ranges
  (`longRecovery` ↔ `midLengthRecovery`); no May value was carried forward.
- `extremeLongLock` source reads `1800+` / `1.50-1.90+`; the numeric array shape
  cannot carry an open upper bound, so `9999` keeps the existing sentinel and `1.90`
  is recorded as the stated premium floor, not a cap.
- Inner keys (`compressedBands`, `realisticWin`, band names) intentionally unchanged
  — renaming them touches `assessLoad` for no behavioural gain.
- `rate-overrides-2026-07.json` **deleted**, removed from service-worker `CORE`, and
  the `scripts/verify-cloudflare-parity.mjs` assertion that required it inverted to
  assert it stays gone. Historical `docs/` references left alone per existing convention.
- Evaluator scoring logic, hard floor, and DZ unlock floor untouched — bands only.

**Also fixed:** `app.js:12780` fell back to a hardcoded `3.50` fuel price that had
drifted from `MW.fuelBaseline` (`3.55`); it now reads the const.

---

## Adversarial Audit (shipped inside v23.8.3)

A full adversarial audit ran against the app with a Playwright harness driving real
headless Chromium (real IndexedDB, Cache Storage, `crypto.subtle`). It produced
`AUDIT_REPORT.md`, the `tests/` suite, and `FIELD_TEST_CHECKLIST.md`.

Six findings were fixed in that pass. **These shipped without a version bump** — the
audit's fixes went out still labelled `23.8.3`, which is exactly the drift the release
checklist above exists to prevent. Backfilled here in v23.8.4 for the record:

| Finding | Severity | Fix |
|---|---|---|
| F-1 | High | F20 Dead Zone Exit grade cap was dead code — the cap never applied to the displayed grade |
| F-2 | Medium | `sanitizeTrip` did not validate `paidDate` like its sibling date fields; **F-2b** — `sanitizeStop.date` had the same gap |
| F-3 | Medium | Tax Season Export (Schedule C) did not quote CSV fields — a comma in any value shifted every downstream column |
| F-4 | Medium | App Lock had no brute-force lockout on the PIN |
| F-5 | Medium | `window.__FL_TESTS` was assigned unconditionally on every load, exposing 32 internals (including `hashPin`) to any same-origin script; now gated behind `window.__FL_TESTS_ENABLED` |
| F-6 | Medium | Trip saves were TOCTOU-vulnerable — two tabs editing one trip silently lost the first write; now optimistic-concurrency checked |

Two further findings (F-7, F-8) surfaced during the audit's Phase 4 and were logged
rather than fixed, pending the owner's decision. Both are fixed in v23.8.4 below.

---

## v23.8.4 — Field Resilience (F-7, F-8)

Closes the two findings `AUDIT_REPORT.md` logged but left unfixed. No new features.

**F-8 (Critical) — new expense and fuel records could never be saved.**
`sanitizeExpense()` (`app.js:1047`) and `sanitizeFuel()` (`app.js:1123`) both built the
key as `id: raw.id ? intNum(raw.id, 0, 1e12) : undefined`. For a brand-new record
`raw.id` is absent, so that placed an **explicit** `id: undefined` on the object handed
to `store.add()`. IndexedDB auto-increment only fills the key when the key-path property
is *absent* — an explicitly-present `undefined` counts as a real (invalid) key, and
`add()` throws `DataError` synchronously. The expense save handler had no `try/catch`, so
it was an uncaught exception: no toast, no hint, the modal simply never closed and nothing
was written. Add Expense and Add Fuel were broken for **every** new record.

- Both sanitizers now omit the key entirely for new records:
  `...(raw.id ? { id: intNum(raw.id, 0, 1e12) } : {})`. The edit path is untouched —
  `updateExpense`/`updateFuel` still throw `Missing id` correctly when the key is absent.
- The expense save handler (`app.js:9272`) gained the same `try/catch` the fuel handler
  (`app.js:9370`) already had, so any future storage error surfaces instead of vanishing.

**F-7 (High) — a GPS error destroyed the in-progress trip.**
`_doStartTracking()`'s error callback treated every `GeolocationPositionError` code
identically: toast, `_activeTracking = null`, re-render idle. It never cleared
`sessionStorage['fl_active_tracking']` (only `stopTripTracking()` does), so the trip
*looked* lost but wasn't — a reload fully recovered it. The only visible affordance left,
"Start Trip", took the `_initTrackingObject()` path and minted a fresh `trackingId`,
orphaning the old session's miles and `gpsLogs` for good.

- **A GPS error never ends the session now** — transient (codes 2/3) *or* permission-denied
  (code 1). The session degrades in place and Stop & Save keeps working, which is what
  actually salvages the miles. This goes further than the audit's suggested grace window,
  which would still have destroyed the trip once it expired.
- The error callback gained the `trackingId` guard its success counterpart already had, and
  toasts once per error streak rather than once per callback (`watchPosition` re-fires the
  error callback every `timeout`, 15 s).
- `_doStartTracking()` now clears any prior `watcherId` before re-arming, so a repeat call
  cannot leave two live watchers burning GPS.
- `startTripTracking()` offers `_showResumeTrackingModal()` when a session record ≤24 h old
  is present. Discarding is still possible — but as an explicit labelled choice, which was
  the actual finding.
- See the F21 section above for the helper-level detail.

**Tests.** The F-7/F-8 tests in `tests/integration/field-resilience.spec.mjs` previously
asserted the *buggy* behavior (suite convention: a green `[FINDING F-n / NEW]` test means
the evidence was captured, not that the bug is fixed). They are retagged `/ FIXED` and now
assert correct behavior, plus new sanitizer-level tests in
`tests/unit/pure-functions.spec.mjs`. Full suite: **55 passed, 0 failed** across 7 specs.

---

## v23.9 "Trust & Recovery" (in progress)

Scope = 12 audit findings (X-01…X-12, documented in `AUDIT_REPORT.md`) + 4 Phase 7
additions. Tracked here phase by phase as they land; see `AUDIT_REPORT.md` for the
source-level evidence behind each finding and `docs/DEFERRED.md` for anything raised
during this pass but explicitly out of scope.

### Phase 1 — Tax correctness (X-02, X-03)

**X-02 — date-keyed mileage rate.** `IRS.MILEAGE_RATE_2026`/`MILEAGE_RATE_2025` (flat
per-year constants) are gone. `MILEAGE_RATES` (a table of `{ effectiveFrom, effectiveTo,
businessRate }`) + `getMileageRate(date)` replace them everywhere in `app.js` — F30 (Tax
Season Export), the CPA Package, and the Accountant Package export all now sum a
per-trip, per-trip-date rate instead of applying one flat rate to a period total. 2026
has two bands (`0.725` Jan–Jun, `0.76` Jul–Dec, per IRS Announcement 2026-11's midyear
increase). Adding a future year, or a future midyear correction, is a table edit only.

**X-03 — standard mileage vs. actual expense, no more double-dip.** F30 previously
summed the standard-mileage deduction and actual vehicle-operating costs
(insurance/repairs) into the same `totalDeductions` — disallowed by the IRS. Fixed via:
- A category→method-sensitivity map (`classifyExpenseTaxBucket()`): bucket **A**
  (vehicle-operating: fuel, repairs/maintenance, auto insurance, oil, tires,
  registration, lease) is suppressed from Schedule C totals when the elected method is
  Standard Mileage; bucket **B** (parking, tolls, cargo/liability/occ-acc insurance,
  loan interest, personal property tax, lumper fees, scale tickets, load board subs,
  phone, permits, MC authority fees, and any category this map doesn't recognize) is
  always deductible regardless of method; bucket **C** (an insurance-category expense
  with no resolved auto/cargo/liability/occ-acc sub-type) is excluded from every total
  and flagged in the F30 UI for manual reclassification.
- The old flat `"Insurance"` category is split at the data-model level: the `expenses`
  store gained an explicit `insuranceBucket` field (`'A'|'B'|'C'|undefined`), derived
  automatically from specific category text (`Auto Insurance`, `Cargo Insurance`,
  `Liability Insurance`, `Occupational Accident Insurance` — added to the category
  datalist in `index.html`) or left `'C'` for bare/legacy `"Insurance"`.
  `migrateInsuranceCategorySplit()` is a one-time, idempotent, reversible migration
  that tags existing bare-"Insurance" expense records `insuranceBucket: 'C'` — it
  writes a retained pre-mutation backup (`insuranceMigrationBackup_<timestamp>` in
  `settings`) before touching anything, and is gated behind a blocking confirm()
  prompt (`checkInsuranceSplitMigration()`, boot-time) asking the owner to take a
  manual JSON export first. `revertInsuranceCategorySplit(key)` undoes a pass from its
  backup. See `tests/integration/insurance-migration.spec.mjs` for the
  run-twice-produces-identical-state proof.
- Per-vehicle tax-method election: `settings['vehicleProfiles']` (array of
  `{ id, label, vehicleTaxMethod, firstYearElection, createdAt }`) +
  `settings['activeVehicleId']` — kept in the existing `settings` store (no new IDB
  object store, no `DB_VERSION` bump; a full multi-vehicle fleet schema is out of scope
  for this release, see `docs/DEFERRED.md`). `vehicleTaxMethod` ∈ `UNSET |
  STANDARD_MILEAGE | ACTUAL_EXPENSE` (default `UNSET`); `firstYearElection` ∈ `UNKNOWN |
  ACTUAL_EXPENSE | STANDARD_MILEAGE` (default `UNKNOWN`). Setting `firstYearElection` to
  `ACTUAL_EXPENSE` permanently hard-locks that vehicle's `vehicleTaxMethod` to
  `ACTUAL_EXPENSE` (`saveActiveVehicleProfile()`), with a one-time explanation shown to
  the driver.
- F30 export is **blocked** (no CSV/print buttons, no computed totals) while
  `vehicleTaxMethod = UNSET`. Once a method is set but `firstYearElection = UNKNOWN`,
  export is allowed but every export (CSV, print/PDF view, and the on-screen summary)
  carries a `DRAFT — vehicle method unverified. Not for filing.` header/banner.
  Selecting Standard Mileage while `firstYearElection = UNKNOWN` also shows a persistent
  inline warning in the method picker itself.
- Settings gained a "Verify vehicle tax method" row (`#vehicleTaxMethodRow` in
  `index.html`, wired in `renderInsights()`) that stays visible until the active
  vehicle's `firstYearElection` is resolved.

Files touched: `app.js`, `index.html`, `CLAUDE.md`, `docs/BACKUP_CONTRACT.md` (new —
Amendment 2: every new persisted field this phase added is documented there),
`tests/unit/pure-functions.spec.mjs`, `tests/integration/insurance-migration.spec.mjs`
(new), `tests/integration/tax-export-csv-corruption.spec.mjs` (updated — F30 export is
now gated on a vehicle tax method being set, which predates that spec).

### Phase 2 — Release gate (X-06)

`tests/run-all.mjs` now exits non-zero if any spec's assertions fail
(`process.exit(totalFail ? 1 : 0)`) instead of unconditionally exiting 0. New
`.github/workflows/tests.yml` runs the full suite on every PR to `main` — set it as a
required status check under branch protection for it to actually block merge. See
`tests/README.md`'s "Exit code" section for why the old unconditional-0 behavior was
correct at the time it was written and why it no longer is.

Files touched: `tests/run-all.mjs`, `tests/README.md`, `.github/workflows/tests.yml`
(new).

### Phase 3 — Export integrity (X-05)

`exportJSON()`'s `checksumFull` was computed over the **unfiltered** settings dump
(including `fmcsaApiKey`/`eiaApiKey`) but the payload's `settings` field was the
**filtered** array with those two keys already stripped — so a genuine, untampered
export never matched its own checksum on import, and every normal import showed a
false "this file has been tampered with" warning. Fixed by building
`exportableSettings` once (secret keys already stripped) and using that exact array as
both the `checksumFull` input and the payload's `settings` field — one array, one
source of truth, computed once.

Files touched: `app.js`, `tests/integration/export-checksum-integrity.spec.mjs` (new —
round-trip proof: export with both secret keys present → checksum is self-consistent →
import shows no integrity warning → both keys are genuinely absent from the export).

### Phase 4 — Disaster recovery (X-01, X-07)

**X-01 — delta sync is now readable.** `cloud-backup-worker.js` (bumped to v11) gained
`GET /backup/delta`, returning every currently-retained delta payload for the user+
device, chronological oldest-first, plus a lifetime `totalCreated` counter alongside
the currently-retained count so the client can detect pruning (the 20-key cap or the
7-day TTL). `cloudPullBackup()` now fetches the base snapshot AND every retained delta,
applies them in order via `mergeRestoreData()`, and distinguishes a **confirmed gap**
(`totalCreated > retainedCount` — provably lost data) from **unverifiable** (the
endpoint failed or a delta couldn't be decrypted — coverage unknown). Both surface a
visible `⚠️ Partial restore — …` toast; there is no code path left where a delta-backed
restore can silently report "Cloud backup restored!" while actually missing data.

**X-07 — `mergeRestoreData()` now covers every pushed store.** Previously only
`trips`/`expenses`/`fuel` plus a generic `laneHistory`/`weeklyReports`/
`reloadOutcomes`/`bidHistory`/`documents` loop were restorable; `settings`, `receipts`,
and `gpsLogs` were pushed by `cloudPushBackup()` but silently dropped on restore. Fixed,
with per-store merge semantics chosen for what each store actually is (see
`docs/BACKUP_CONTRACT.md` for the full rationale):
- `settings` — **add-only**: a key already present locally is never overwritten (no
  revision timestamp exists to compare against), so this is safe for both the
  disaster-recovery case (everything restores, since nothing local exists yet) and a
  routine top-up merge (never clobbers a live local change).
- `receipts` (keyPath `tripOrderNo`) — file-list **union by file `id`**; blob bytes
  still aren't part of the contract, only the metadata pointer (same as manual
  JSON export/import always worked).
- `gpsLogs` (keyPath `id`, autoIncrement) — the incoming numeric `id` is device-local
  and never used as a write key (it could collide with an unrelated local record);
  dedup on `(tripTrackingId, timestamp)` instead, via `add()`.

Also closed while touching this code: `cloudPushBackup()` now strips `fmcsaApiKey`/
`eiaApiKey` from its `settings` payload (the same filter `exportJSON()`'s
`exportableSettings` already applies, X-05) — previously only the manual JSON export
path did this. `cloudGetConfig()` now actually reads the `cloudBackupUrl` setting
(previously written by `cloudSaveConfig()` but never read back — every request silently
used the hardcoded `CLOUD_WORKER_URL` regardless) — this is also what makes the E2E
test below possible without touching the production endpoint.

New `docs/BACKUP_CONTRACT.md` is the authoritative store-by-store table (which stores
are pushed, which are restored, and why each merge strategy is what it is) — kept in
sync in the same commit as any future field/store addition, per Amendment 2.

Files touched: `app.js`, `cloud-backup-worker.js` (v10 → v11), `docs/BACKUP_CONTRACT.md`,
`docs/DEFERRED.md`, `scripts/verify-cloudflare-parity.mjs` (`workerVersion` bumped to
match), `tests/lib/mock-worker.mjs` (new — local stand-in for the Worker's KV-backed
endpoints, since this environment has no live Cloudflare Worker to test against; see its
header comment), `tests/integration/backup-restore-parity.spec.mjs` (new — E2E: full
backup → 3 delta syncs → wipe local → restore → parity of every contracted store, plus
a confirmed-gap warning test). Full suite: 70 passed, 0 failed across 10 spec files.

### Phase 5 — Decision authority (X-04)

The standalone `midwest-stack-authority.js` overlay had **no gate at all** on its
DEAD_ZONE mode: `trueRpm >= 0.91 && (destRole.role === 'tier1' || 'tier2')` alone could
produce `TAKE_IF_LIVE` at the $0.91/mi survival floor, with none of the main
evaluator's distance-from-home, distance-saved, or manual-confirmation checks. The
file's own `DEAD_ZONE` mode description had always *claimed* "Requires 1000+ miles from
home, no reloads above $1.25 nearby, and meaningful move toward density" — the code
never actually enforced it.

Fixed by extracting one canonical gate function, `isDeadZoneEligible()` (`app.js`),
which both the main evaluator (`mwEvaluateLoad`) and the standalone overlay now call —
exposed on `window` since both scripts run in the same page/global scope (no bundler,
no modules; `midwest-stack-authority.js` is injected into the same document as
`app.js`). All four gates must pass:
1. `distanceFromHome >= MW.dzActivationDistanceMi` — **changed from 1500mi to 1000mi**
   to match the canonical figure the standalone file's own mode description had always
   claimed (this was the actual drift — not a new number invented for this fix).
2. `distanceSaved >= MW.dzMinDistanceSaved` (200mi) — "meaningful movement toward
   stronger freight."
3. `dzFloor <= trueRPM < MW.hardRejectRPM` (1.25) — "no viable reload above the
   standard floor nearby": a load already clearing 1.25 doesn't need survival mode.
4. `noReloadConfirmed === true` — manual; DZ mode never self-activates.

Returns `{ eligible, gradeCap: 'C', reasons }` — `gradeCap` is structural, not just
documentation, so a caller activating DZ mode from this result carries the F-1 grade-cap
requirement with it rather than needing to remember it separately.

Two supporting pieces so the standalone file — which has no geo/settings model of its
own — can call the gate meaningfully:
- `window.flDzGeoCheck(origin, dest)` — a **synchronous** twin of the main evaluator's
  `dzCheckEligibility()` (which is `async`, awaiting `getSetting()`), reading settings
  from the synchronous `SETTINGS_CACHE` instead. Both share one pure geo-computation
  core (`_dzGeoEligibility()`) — one distance calculation, two settings-resolution paths.
- The standalone overlay reads the **same** `#mwDZNoReloadToggle` checkbox the main
  evaluator renders (shared DOM, not a second control) for gate 4 — "manually
  validated" means the same physical checkbox state in both panels.

`midwest-stack-authority.js`'s fix is surgical: when the gate fails, DEAD_ZONE mode
simply does **not** lower `floorRpm`/`winRpm`/`askRpm` to survival-mode levels — they
keep the generic, band-derived values already computed above that block. This means a
load that's actually fine on its own economics still gets an honest verdict; only the
artificially-low $0.91 floor privilege is withheld. `posted.grade` is hard-capped to
`'C'` (via `gradeCap`) whenever the gate genuinely passes, mirroring the main
evaluator's F-1 fix.

This is scoped narrowly per the release brief — one shared gate-check function, not a
rewrite of either file's scoring/verdict logic.

Files touched: `app.js` (`isDeadZoneEligible`, `_dzGeoEligibility`,
`dzCheckEligibilitySync`, `MW.dzActivationDistanceMi` 1500→1000, new
`MW.dzMinDistanceSaved`), `midwest-stack-authority.js`,
`tests/integration/dz-gate-parity.spec.mjs` (new — 5 fixtures spanning all three DZ
sub-tier RPM bands, an unconfirmed case, and an above-hard-reject case; asserts the
main evaluator and the standalone engine agree on every one, driving the real
unmodified standalone file via `page.addScriptTag`). Full suite: 76 passed, 0 failed
across 11 spec files.

### Phase 6 — Remaining findings (X-08 through X-12)

**X-08 — service worker critical shell.** `midwest-stack-authority.js` was only in the
broader, non-blocking `CORE` precache list; the `install` event's actual install-blocking
`critical` array didn't include it. A first offline install could complete and serve the
app shell before the TRUE_RPM decision layer was cached at all, with no error surfaced.
Added it (and, from X-10, the bundled SheetJS vendor file) to `critical`.

**X-09 — diagnostics self-test used a fake token.** The Diagnostics panel's Worker-
reachability self-test sent the literal string `'ping'` as `X-Backup-Token` — not a valid
`flk_`-format token — so the Worker's `/status` auth middleware always rejected it with
403, and the self-test reported "HTTP 403" regardless of whether the Worker was actually
reachable. Now uses the real configured `cloudBackupToken` when one exists, and reports
"Not configured" (not a guaranteed-fail ping) when it doesn't.

**X-10 — SheetJS is now bundled, no CDN fallback.** `vendor/xlsx.full.min.js` (SheetJS
v0.18.5, Apache-2.0, `vendor/xlsx.full.min.js.LICENSE`) is committed to the repo —
previously this was one of the "optional offline vendor files" a driver could choose to
drop in themselves, with a `cdn.jsdelivr.net` fallback if they didn't. `loadSheetJS()`
now loads only the bundled file; Excel import works fully offline from the very first
install, with no live network dependency at all for this feature. `cdn.jsdelivr.net`
stays whitelisted in CSP **only** for the still-optional Tesseract.js OCR fallback
(untouched, out of scope for this pass) — see the "Bundled vs. optional offline vendor
files" note near the top of this doc.

While adding Amendment 5's index.html/`_headers` CSP-parity assertion (below), found and
fixed a **real, pre-existing drift**: `_headers` (the actual HTTP response Cloudflare
Pages serves) was missing the Google Fonts origins (`fonts.gstatic.com`,
`fonts.googleapis.com`) that `index.html`'s own `<link>` tags require and that the meta
tag's copy of the CSP already allowed — meaning the live site had, in effect, been
blocking its own fonts stylesheet independently of what the meta tag permitted. Fixed by
making `_headers` byte-identical to `index.html`'s CSP.

**X-11 — dead OCR claim removed.** The Universal Import UI's dedicated PDF button claimed
"uses OCR" / "extracts text via OCR and prefills a trip," but `importPDFFile()` has always
been an unconditional stub that just toasts "PDF import is not supported." Removed the
button and the OCR claim text; PDF is still accepted via the "Any file — auto-detect"
catch-all, which degrades to the same honest not-supported toast rather than silently
rejecting the file type.

**X-12 — deployment checklist modernized.** `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`
referenced `v23.5.0`/`v23.5.1`/Worker `v10` — three-plus releases stale. Updated to
`v23.9.1`/Worker `v11`, and added checklist items for the X-08 critical-shell contents,
the X-10 bundled-vendor/offline-Excel-import check, the X-01 `GET /backup/delta`
endpoint, the X-04 Dead Zone gate parity, and the Amendment 5 CSP-parity check.

**Full v23.9.1 version-marker bump** (all 13 checklist locations, including the two new
ones added this phase) landed in this same pass — see the "Version bumps" checklist
above. `scripts/verify-cloudflare-parity.mjs`'s `EXPECTED` block and inline assertions
now target `23.9.1`/Worker `v11`, and it gained: a local (no-network) CSP-parity check
(Amendment 5) and a live check that the deployed Worker's `critical` shell includes both
X-08/X-10 files.

Files touched: `app.js`, `service-worker.js`, `midwest-stack-authority.js` (version bump
only), `index.html`, `_headers`, `manifest.json`, `sw-bridge.js`, `voice-load.js`,
`scripts/verify-cloudflare-parity.mjs`, `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`,
`vendor/xlsx.full.min.js` (new, bundled) + `vendor/xlsx.full.min.js.LICENSE` (new),
`tests/unit/service-worker-shell.spec.mjs` (new — X-08/X-10 static checks),
`tests/unit/release-hygiene.spec.mjs` (new — X-09/X-11 static checks),
`tests/integration/xlsx-bundled-vendor.spec.mjs` (new — proves the bundled vendor file
works with all external network blocked). Full suite: 82 passed, 0 failed across 14 spec
files. (One F-7 GPS test flaked once mid-phase on an unrelated CDP-geolocation timing
issue — re-run confirmed 13/13 clean; no code change was needed or made for it.)

## v23.9 Phase 7 — additions

All 12 X-01…X-12 findings are fixed as of Phase 6. Phase 7 adds four things the release
brief specified beyond the audit findings themselves. 7B/7C/7D are self-contained;
**7A requires a printed inventory + explicit approval before any editing begins**
(Amendment 5) — tracked separately below once that inventory is presented.

### 7D — Dimensional/payload pre-check

Configurable van profile (Settings → Van Profile, `settings['vanProfile']`, defaults to
published 2016 Ford Transit T250 148" cargo-van figures — `VAN_PROFILE_DEFAULT` in
`app.js`, explicitly labeled as needing verification against the driver's own spec
sheet/door sticker, not treated as ground truth). New optional evaluator fields
(`#mwLoadLengthIn`/`#mwLoadWidthIn`/`#mwLoadHeightIn`/`#mwLoadWeightLbs`, "More
Details") feed `checkVanFit()`, called at the very start of `mwEvaluateLoad()` — before
any RPM/scoring/verdict computation. A load exceeding any configured limit renders
"CAN'T TAKE — dimensional/payload conflict" in place of the normal result card and
returns immediately; economics are never computed for it.

Since Smart Load Inbox (F23), F27 Load Intake, and OCR quick-scan all funnel their
parsed values into these same evaluator fields before scoring, gating inside
`mwEvaluateLoad()` itself covers every intake path (including manual entry) from one
place — no per-path duplication. A load with no dimension data entered at all (the
common case — most postings don't include cargo dimensions) is not blocked; this is a
safety net for when dimensions ARE known, not a requirement that every load specify
them. Width/height are checked against both the cargo box and the (typically narrower/
shorter) rear door opening — a load can fit inside the box but be too tall or wide to
physically load through the door, and the violation message names whichever constraint
actually binds.

New `settings['vanProfile']` field: documented in `docs/BACKUP_CONTRACT.md` per
Amendment 2. No additional push/restore code was needed — `cloudPushBackup()`'s
`settings` dump and X-07's add-only settings merge in `mergeRestoreData()` both handle
any settings key generically.

Files touched: `app.js`, `index.html` (new evaluator fields + Settings → Van Profile
section), `docs/BACKUP_CONTRACT.md`. New tests:
`tests/unit/pure-functions.spec.mjs` (5 `checkVanFit()` cases — no dims entered, over
length, over payload alone, fits-the-box-but-not-the-door, comfortably within every
limit) and `tests/integration/van-fit-precheck.spec.mjs` (drives the real evaluator UI —
over-payload blocks and shows no grade at all, clearing the field un-blocks it, and a
custom tighter profile is actually respected, not just the defaults). Full suite: 91
passed, 0 failed across 15 spec files.

---

## Dispatch Layer (Planned)

A Dispatch upgrade is planned for a future release. Driver-only features are the current development focus. No dispatch UI, multi-driver management, or load assignment logic should be added until that phase begins.

---

## Accessibility

- Touch targets minimum 44×44px (WCAG 2.1 AA).
- Focus management on modal open/close (`openModal` / `closeModal`).
- `haptic(ms)` provides tactile feedback on supported devices.
- Dark-first design; light theme available via `[data-theme="light"]`.


## v23.9.1 — Pre-v24 Integrity Gate

- Normal/preferred True RPM floors aligned to $1.40/$1.50.
- Static July rate bands now expire through CURRENT/AGING/STALE freshness states; stale bands cannot relax protective pricing outside the explicit Dead Zone gate.
- EIA/NWS/FMCSA/CBP use a shared live-source health contract surfaced in Diagnostics.
- Conservative broker-history integrity pass normalizes proven broker keys and keeps unresolved legacy rows quarantined; it never infers broker identity from ambiguous `trip.customer`.
- CI pins Playwright 1.62.1 and uses Node24-capable GitHub Action runtimes.
- `docs/V24_ROADMAP.md` is the authoritative v24 sequencing/authority contract.

---

## v24.0.0 — Unified Decision Engine

The first roadmap milestone in `docs/V24_ROADMAP.md`, and the release that makes
the "v24.0 authority rule" at the top of this file structural rather than
aspirational. Before it, the evaluator, the USA Engine, `midwest-stack-authority.js`,
and the Worker's `/evaluate` response could each arrive at a verdict, and nothing
reconciled them.

**One canonical decision object.** A single deterministic, client-owned result
object inside `app.js` now owns hard-gate verdict, grade, economics, and bid
range. Every other layer is demoted to input or commentary:

| Layer | Role after v24.0.0 |
|---|---|
| `app.js` canonical decision | **Authoritative** — verdict, grade, economics, bid range |
| USA scoring | Evidence only |
| `midwest-stack-authority.js` | Advisory overlay |
| Worker `/evaluate` | Review only — *projects* canonical verdict/grade/True RPM/bid, never recalculates |

The AI payload carries a compact canonical decision rather than a second
calculation request, which is what keeps `/evaluate` from re-deriving an answer
of its own.

**Authority boundaries locked by regression tests.** These are exact thresholds,
asserted on both sides of each boundary:
- Normal floor — `1.39` rejects, `1.40` survives.
- Out-of-density threshold — `1.59` rejects, `1.60` survives.
- An explicit strategic band cannot rescue an out-of-density weak load.
- Long-haul floor and the home/replace exception preserve legacy behavior.
- True-cost and fuel-only margin reject thresholds are exact.
- Deadhead hard gate is exact around 35% / strong RPM.
- Mid-week stabilization downgrade is deterministic.
- Fatigue safety veto overrides otherwise-valid economics *and* DZ survival.
- Personal Intelligence may downgrade an ACCEPT but can never revive a hard
  reject (the v24 restatement of the downgrade-only rule).
- Valid DZ conditions activate DZ-EXIT *before* later safety gates.
- Identical inputs always produce an identical canonical decision.

**Economics and bid authority.** Economics uses the supplied driver/live MPG and
fuel price exactly; fixed `MW` defaults cannot override it. Operating and border
costs reconcile to true profit and break-even. The canonical bid minimum starts
at `$1.40`/true-mile; urgency and border premiums are deterministic with urgency
capped, and an invalid or negative urgency can never reduce the protective bid
floor.

**Worker.** `cloud-backup-worker.js` bumped v11 → v12 to carry the authority
projection contract.

**Test coverage added:** `tests/unit/v24-unified-decision.spec.mjs` (5),
`tests/integration/v24-authority-boundaries.spec.mjs` (11),
`tests/integration/v24-economics-bid.spec.mjs` (7), all wired into
`tests/run-all.mjs`. Full suite: **119 passed, 0 failed across 19 spec files.**

**Release gate status.** Full Playwright suite green (119/0, re-verified at
close-out). Source-side version/SW parity verified across all 13 checklist
locations, including the `critical` install-blocking shell and the
`index.html`/`_headers` CSP byte-identity check. The *live* half of
`scripts/verify-cloudflare-parity.mjs` (deployed Pages origin + Worker `/health`)
must still be run from a network that can reach those origins before the deploy
is considered parity-verified.

*Correction (later pass):* the "all 13 checklist locations" claim above covered the 13
locations the checklist listed **at the time** — which did not include the manual
`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` itself. That file was still reading
`23.9.0` / Worker `v11` when v24.0.0 closed out, and was corrected afterwards; it is now
location 13 in the version-bump checklist above (the `critical`-array item moved to 14).

---

## v24.1 "Confidence + Evidence" — specified, NOT implemented

Roadmap item 2 in `docs/V24_ROADMAP.md`. As of this writing v24.1 exists **only as a
contract**; there is zero runtime code for it, and no version marker moved (every shipped
file is still `24.0.0`).

Two documents landed in PR #80 and are the authoritative spec:

- `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md` — the behavior contract: the `EvidenceItem`
  shape, categorical HIGH/MEDIUM/LOW confidence rules, deterministic thresholds
  (static/historical freshness CURRENT ≤14d / AGING 15–30d / STALE >30d; aggregate sample
  size HIGH ≥10 / MEDIUM 3–9 / LOW ≤2), domain summaries, the overall-confidence
  aggregation rule (a material LOW domain caps overall at LOW — never averaged away), the
  Worker boundary, and a 12-point acceptance contract.
- `docs/V24_1_IMPLEMENTATION_MAP.md` — where it attaches in the current source:
  `buildUnifiedDecisionContract()` is the additive attachment point,
  `unifiedDecisionForAI()` the compact Worker projection, and the existing
  `LIVE_SOURCE_HEALTH` / `LIVE_SOURCE_STATUS` substrate (v23.9.1) is the source-health
  registry to normalize from — **do not create a second one**.

Authority rules this release must not break (they are the v24.0 rules restated):
confidence is descriptive only; it may never change verdict, grade, True RPM, or the
canonical bid range, and may never relax a protective floor because evidence is stale or
a source failed. `UNKNOWN` / `UNAVAILABLE` / source failure must stay visibly distinct
from "no risk" or a favorable value. No numeric win probability in v24.1 — percentages
wait for lifecycle calibration data (v24.2+).

**Prerequisite gate, not yet met:** the spec's own sequencing puts a behavior-preserving
UI seam extraction *before* any v24.1 code. That extraction has not landed. Persistence
is also gated — if the evidence snapshot cannot be stored as additive optional fields on
the existing shapes, that portion defers to the v24.2 lifecycle migration rather than
spending its migration budget here (`DB_VERSION` stays 13).

Out of scope for v24.1 (per the spec): calibrated probabilities, new external feeds,
lifecycle DB migration, self-calibrating bands, Next-Move logic, Driver Mode redesign,
screenshot-first rework, bank-account/statement import, and any change to v24.0 decision
authority.

### Related repo state at the time of the spec landing

- The temporary v24.0.1 bank-repair CI machinery is gone (PR #82). `.github/workflows/`
  contains only `tests.yml` again. v24.1 must not reintroduce comment-triggered or
  branch-pushing CI repair paths.
- PR #76 ("v24.0.1: Bank statement expense import foundation") was closed **unmerged** —
  bank/statement import is not in the tree and is explicitly out of v24.1 scope.
- `README.txt` was rewritten (PR #81) to match actual behavior: SheetJS is bundled and
  install-critical with **no** CDN fallback, and the Tesseract OCR files are described as
  historical notes rather than a supported optional drop-in, since they are not in
  `vendor/`.
- Baseline re-verified for this pass: full Playwright suite **119 passed, 0 failed across
  19 spec files**.

---

## v24.0.1 — Doctrine & Money Integrity (completion-plan Milestone 1)

Milestone 1 of `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`, the single canonical
roadmap. No new features; this is the money-integrity certification gate that must
close before v24.1 Confidence + Evidence can land.

**UNKNOWN is no longer a silent zero.** `knownNum(v)` (`app.js`, beside `finiteNum`)
is the single rule: `null`, `undefined`, blank/whitespace strings, `NaN` and
`Infinity` all return `null`. An explicit `0` the operator actually supplied returns
`0` and stays a **verified** zero. Before this, the canonical layer read every
material fact through `Number(x || 0)`, so a load with no revenue or no deadhead
figure still produced a precise True RPM, a real letter grade, a verdict, and a bid
range — all derived from inputs that were never there.

- `deriveUnifiedEconomics()` returns `{ available: false, unknownFacts: [...] }` with
  **every** money field `null` (not `0`) when `loadedMi`, `deadMi`, or revenue is
  unknown. Valid input behaves exactly as before.
- `deriveUnifiedGrade()` returns grade `?` / `known: false` for an unknown True RPM
  instead of coercing to `0` and falling through to grade **F** — a REJECT that
  looked calculated but was only a missing input. A genuinely low RPM is still a real F.
- `deriveUnifiedAuthority()` returns verdict `UNAVAILABLE` when `trueRPM`, `totalMi`,
  `deadheadPct`, or `effectiveRevenue` is unknown, and names the missing facts.
- `buildUnifiedDecisionContract()` carries `factsComplete` / `unknownFacts` and
  **suppresses the bid range** (`suppressed: true`) when facts are incomplete.
- The evaluator treats a **blank deadhead field as UNKNOWN**, not zero, and asks for
  the figure — entering `0` records a verified zero. This is a deliberate UX change:
  blank-means-zero silently overstated True RPM on every load where deadhead was
  omitted.

**Mileage provenance is explicit.** `MILEAGE_PROVENANCE` = `VERIFIED | ESTIMATED |
UNKNOWN`; economics carries `mileageProvenance` with `loaded`, `deadhead`,
`platformDisplayedMi` and `repositionMi` kept as four distinct numbers. A
platform-displayed figure never overwrites loaded miles.

**Doctrine parity.**
- Cincinnati and Toledo are **Tier 1** in canonical `MW.tier1`, in
  `midwest-stack-authority.js`, and in `midwest-stack-config.json`.
- Level X+ taxonomy is exact everywhere: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`,
  D `1.40–1.49`, E `1.25–1.39`, Reject `<1.25`. The stale `MW.rpmTiers` band
  `1.35–1.49 "Minimum Standard" / ACCEPT` and the rendered ladder row
  `D $1.35–$1.49` both contradicted `deriveUnifiedGrade()` and the $1.40 normal
  floor; both are corrected.
- The F20/DZ absolute floor is exactly **`0.90`**. `midwest-stack-authority.js`
  carried `DEAD_ZONE.floor: 0.91` while its own `hardStops.absoluteTrueRpmReject`
  was already `0.90` — two survival floors in one file.
- The overlay's `finite(value, fallback)` returned `fallback || 0` for a missing
  material fact. Material facts now read through `knownNum()`; `assessLoad()` returns
  `available: false` rather than an advisory built on invented zeros. `finite()`
  survives for presentation helpers only.
- `midwest-stack-config.json`: `appTarget` `v23.5.x` → `v24.0.1`, `authorityName`
  `Midwest Stack v2` → `Midwest Stack v11 / Level X+`, `effectiveDate` refreshed.

**Approved MPG parity.** `MW.mpg` `16.5` → **`17.5`**, matching the operator-confirmed
loaded baseline in `docs/OPERATOR_TRUTH.md` (Gate 0). This is a **fallback only** — an
explicit `vehicleMpg` setting still overrides it and canonical economics uses the
explicit value exactly. Authorized by `docs/OPEN_QUESTIONS.md` item 33 (CONFIRMED
2026-08-26); deliberately not a broader fuel-model redesign.

**Why this shipped as a version bump.** All cache-busters were `?v=24.0.0` and
`CACHE_NAME` is `freightlogic-${SW_VERSION}`. Landing M1 without bumping would leave
every installed PWA serving the pre-M1 `app.js` and overlay from cache — the fix
would never reach a driver. The bump is what makes the repair deliverable.

**Tests:** `tests/integration/m1-doctrine-integrity.spec.mjs` (new) covers the packet's
full regression matrix. Three existing evaluator specs
(`dz-exit-grade-cap`, `dz-gate-parity`, `van-fit-precheck`) had their **fixtures**
updated to enter deadhead `0` explicitly — they always meant a zero-deadhead load and
were relying on blank-means-zero. No assertion was changed, skipped, or weakened.

**Still open at M1 close:** `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` is
GPT-owned under `/.agents/LANES.md` and still reads `24.0.0`; a bump was requested
through `/.agents/inbox/` rather than edited across lanes.


---

## v24.0.2 "Release Integrity" — Issue #119 Batch A + Batch B

A correctness pass over the completion-release blockers, driven by two exact-source
audits (`.agents/inbox/gpt-to-claude-batch-a-source-audit-2026-08-28.md` and
`…-batch-b-…`). No new features. Every fix carries a regression that drives the
REAL runtime path the defect lived on — the previous coverage exercised helpers and
store existence, which is exactly why these shipped green.

### Batch A — release integrity

- **DB indexes are created independently of the store.** The catch-all `ensureStore`
  in `initDB()` runs BEFORE the versioned migration blocks, so `loadLifecycle`
  already existed when the `old < 14` block tested `objectStoreNames` — and the whole
  index body was skipped, on a fresh database as much as on an upgrade. A new
  `ensureIndexes(store, specs)` helper runs unconditionally and guards each index
  with `indexNames.contains`, which repairs a database that reached v14 index-less.
- **`cloudPushBackup()` empty-delta TDZ.** `loadLifecycle` was dumped and filtered
  AFTER the empty-delta guard that reads it — a temporal-dead-zone `ReferenceError`
  on every delta push, invisible because the function's own `try/catch` turned it
  into a generic "Backup failed" retry. It is now dumped with every other store.
- **`linkLifecycle()` compare-and-abort.** It read the base record and then called
  `upsertLifecycle()` without the revision it had just observed, so a background
  link merged a stale base over a user correction that landed in between.
  `FL_CONFLICT` is now reported as a conflict, never swallowed into a success.
- **Reused external identifiers.** A broker + order-number pair is a CANDIDATE
  signal, not identity. `lifecycleMatchCandidate()` links only when the supplied
  route/time facts do not conflict and nothing competes; source clock precision is
  preserved rather than truncated. `renderLifecycleChips()` and
  `openLifecycleEditor()` resolve through the same doctrine (`resolveLifecycleForTrip`)
  instead of a `Map` keyed on order number that let duplicates overwrite each other.
- **Durable normalized evidence (`normalizedEvidence`, DB v15).** `intakeOpportunity()`
  returned the normalized object and persisted only lifecycle identity/state, so price
  and mileage semantics, provenance, confirmation state and source references did not
  survive a reload. They now live in a dedicated bounded store that participates in
  local export/import, full and delta cloud backup, and restore. `loadLifecycle`
  stays a lifecycle state/linking structure — the durability contract's architectural
  boundary. Evidence with an UNRESOLVED lifecycle link is still fully preserved.
  - Full `EVIDENCE_PROVENANCE.md` price vocabulary (`BOARD_TARGET_RATE`,
    `POSTED_RATE`, `MARKET_BENCHMARK` added); the revenue gate is unchanged.
  - Mileage slots are semantic: a `DISPLAYED_TOTAL_MILES` value can never occupy
    canonical `loadedMi`. `POST_DELIVERY_REPOSITION_MILES` and `MAP_ESTIMATE` have
    their own slots.
  - A valid ISO source timestamp is preserved (it was being nulled by `knownNum()`),
    and an unknown operator-confirmation clock stays `null` instead of defaulting to
    the import time. A live user action may stamp `now` via `stampConfirmationNow`.
  - `evidenceFingerprint()` is a bounded SHA-256 digest (`fp:sha256:<40 hex>`).
  - `reconcileEvidenceFields()` is authority-aware with per-field provenance.
- **`computeExportChecksumProtected()`** covers lifecycle and evidence. Older exports
  still verify through `checksumFull`.
- **Real M5B production intake:** More → Intel → **Opportunity Intake**
  (`openOpportunityIntake()`). Offline, no provider authorization, makes the operator
  state the price semantic explicitly, and persists durable evidence before linking.
- **Worker v12 → v13.** `UNAVAILABLE` / grade `?` / null True RPM / a suppressed bid
  project verbatim instead of being coerced to `REJECT` / `F` / `$0.00`, and an
  unavailable decision short-circuits before any OpenAI call. A real `REJECT` and a
  real `F` still project unchanged.
- **Evaluation evidence reads the real inputs.** Fuel provenance
  (`settings['fuelPriceProvenance']`, written at all three real write points), the
  real per-route NWS observation (a successful zero-alert fetch is a real zero; no
  fetch / offline / timeout / HTTP error is an absence and never reads as "0 alerts"),
  the real `laneHistory` and `bidHistory` records, and the real van-fit measurement
  state (`vanFitChecked: true` was hardcoded). With no broker entered the broker
  domain is inapplicable and omitted, rather than a synthetic LOW that capped overall
  confidence. `sessionStorage['fl_eval_hist']` entries carry a bounded
  confidence/evidence snapshot; legacy entries lacking it read as not-recorded.
- **`scripts/m7-certify.mjs`** — the default run is a release PREFLIGHT, a skipped
  suite is `SKIP` not `PASS`, and while the canonical certification state is HOLD it
  prints `NOT CERTIFIABLE` and never tells the operator to freeze.

### Batch B — M6 reconciliation

- `_historicalRowFingerprint()` is SHA-256-based and async, and its input keeps the
  full ISO source instant. The 32-bit DJB2 token it replaces has a demonstrated
  same-length collision pair.
- `_orderStableKey()` ignores a bare external `stableId`; only an explicit
  `internalStableId` is honoured. `scripts/m6-import.mjs` no longer sets one.
- The adapter groups by order number as a CANDIDATE and merges only compatible rows;
  merging is authority-aware and per-field provenance survives it. A source column
  named `Carrier` stays `carrierLabel`. DRY RUN is imported as its own class
  (`cohort.dryRun` clears `normalMarketEligible`) rather than discarded. An
  unrecognized status sets no award (`awarded` is tri-state). Full timestamps keep
  their clock precision.
- Places are compared as TOKEN SEQUENCES, with exactly one extra trailing two-letter
  state token allowed as a qualification of a less specific value — normalization,
  not fuzzy matching. `Chicago` vs `Chicago Heights IL`, and `Chicago IL` vs
  `Chicago MO`, both still conflict.
- `calibrateWinningRange()` no longer gives an undated observation weight `1.0`;
  undated evidence stays counted but leaves the recency-weighted cohort, and
  `unknownAgeCount` / `weightedSampleSize` are reported. `calibrateFromLifecycle()`
  no longer substitutes lifecycle `updatedAt` for a market-observation time.

### Test coverage

Full suite: **318 passed, 0 failed across 32 spec files** (was 241/26 at v24.0.1).
New: `tests/integration/batch-a-release-integrity.spec.mjs` (21),
`tests/integration/m3-real-evidence-wiring.spec.mjs` (15),
`tests/integration/batch-b-m6-reconciliation.spec.mjs` (14),
`tests/unit/worker-canonical-absence.spec.mjs` (5),
`tests/unit/m7-runner-semantics.spec.mjs` (8),
`tests/integration/blockers-exact-candidate.spec.mjs` (12), plus
`tests/fixtures/blank.html` and `launchBlank()` in the harness for tests that must
establish database state before the app boots.

Five existing assertions changed, each because it encoded a defect this release
fixes: two `DB_VERSION` literals, the fabricated operator-confirmation timestamp,
the displayed-total-in-`loadedMi` acceptance, the Worker's grade-`F` coercion, and
the now-async fingerprint call. None was skipped or weakened.

### Exact-candidate blocker corrections (post-freeze review)

The v24.0.2 freeze was reviewed against exact source and held. Eight contract
defects were corrected before the candidate could stand
(`.agents/inbox/gpt-to-claude-v2402-exact-candidate-blockers-2026-08-28.md`):

1. **Evidence-first durability, on BOTH source-normalization paths.**
   `intakeOpportunity()` linked lifecycle before persisting evidence, and
   `importHistoricalOpportunities()` committed the lifecycle row before writing
   its provenance evidence. Either could leave lifecycle state standing for an
   observation that was never recorded. Both now run three phases — persist the
   observation UNLINKED, link/create lifecycle, attach the link under
   `expectedRevision`. A first-phase failure touches no lifecycle state; a link
   or attachment failure preserves the evidence and reports the failure.
2. **`trip.customer` is out of the broker identity chain**, read side and write
   side. The `trips` store has no `broker` field at all, so a trip-sourced
   lifecycle row now carries no broker — the app does not know it and stops
   inferring it. Linking is unaffected because of (3).
3. **`trip.orderNo` is no longer laundered into `sourceRefs.tripIds`.** Trips
   already mint an internal UUID (`newTripTemplate`), so the exact-internal-
   reference signal carries real internal identity; a caller with no trip
   record offers none rather than fabricating one.
4. **Confirmation is field-scoped.** New authority `OPERATOR_ENTERED_UNVERIFIED`
   describes a typed, unconfirmed value honestly (`sourceType` stays `MANUAL` —
   source and authority are separate facts). Confirming revenue promotes
   `amount`/`canonicalRevenue` through `fieldProvenance` alone, never broker,
   route, mileage or timestamps.
5. **A historical HOLD is immutable evidence, not a permanent state.**
   Supersession in `scripts/m7-certify.mjs` is explicit (`Supersedes: <file>`),
   never date ordering. Missing, unreadable or `Status:`-less state fails
   closed, and a superseding document that itself holds still holds.
6. **Restore keeps a retained value paired with its own provenance.**
   `fieldProvenance` was spread incoming-last regardless of who won the scalar
   conflict, so a stale delta could relabel a retained newer value. A loser's
   entry now survives only where the winner has none AND the loser's value is
   the value actually retained.
7. **Local JSON `merge` reconciles protected history.** `importJSON()` ran a
   plain `putAll()` into `loadLifecycle` and `normalizedEvidence`. Both now use
   `reconcileLifecycleRecord()` / `reconcileEvidenceRecord()`, shared with
   cloud restore so the paths cannot drift. `replace` still replaces.
8. **An identical re-import is a true no-op** — the stored record is returned
   untouched rather than re-written with a new `revision`/`recordedAt`. A
   previously UNRESOLVED row is excluded: it may now be linkable, which is a
   real mutation.

`_resetRouteWeatherStateForTests()` makes the NWS regression deterministic by
clearing the point cache; production's `observed = pointsObserved > 0` is
unchanged, because a cached success is a real observation.

**Raised, not changed:** `sanitizeTrip()` defaults `invoiceDate` to
`deliveryDate`, so every saved delivered trip reads as INVOICED for settlement
and AR. That is long-standing trips-schema behaviour outside this release's
scope; M4-24 now documents it rather than masking it with a fixture that
bypassed sanitization.

### Docs handoff — closed by PR #125

`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` carried
`<FINAL_APP_VERSION>` / `<FINAL_WORKER_VERSION>` placeholders and
`docs/BACKUP_CONTRACT.md` was missing the `normalizedEvidence` store required by
its Amendment 2. Both are `docs/` (gpt) under `/.agents/LANES.md`, so the landed
values (`24.0.2`, DB `v15`, Worker `13`) went through `/.agents/inbox/` rather
than a cross-lane edit. The GPT lane delivered them in PR #125, reviewed and
merged from this lane on 2026-09-02; the checklist now reads `24.0.2` throughout
and the backup contract records `normalizedEvidence` with its protected-checksum
and revision-aware restore semantics.

---

## v24.0.3 "Cache Generation" — release-identity freeze

No behaviour change and no new features. This release exists so that the two
repairs already merged under `24.0.2` can actually reach an installed client.
Driven by `.agents/inbox/gpt-to-claude-v2403-cache-generation-bump-2026-09-03.md`
(RELEASE BLOCKER, Issue #119).

**The defect.** PR #134 repaired the service-worker update handshake and PR #136
added the Diagnostics install-identity readout. Both changed `app.js` (and #134
changed `sw-bridge.js`), and both shipped with every version marker still reading
`24.0.2` — including `SW_VERSION`. Three separate cache identities therefore stood
still at once:

- A browser installs a new service worker only when **the worker script's own
  bytes** differ from the installed copy. Neither PR touched `service-worker.js`,
  so there was nothing to install.
- `CACHE_NAME` is `freightlogic-${SW_VERSION}`, so the precached shell kept its
  name and was reused wholesale.
- The `?v=` query strings are the only other cache identity the child assets
  carry, and they were unchanged too.

A client already holding the pre-repair `24.0.2` shell thus had no new identity to
fetch on any axis, and could keep serving the broken bridge indefinitely. This is
distinct from the observed iPhone `v23.7.0` wrong-origin investigation — it is a
release-generation correctness problem for **any** earlier `24.0.2` client.

**The fix.** Every governed marker moves atomically to `24.0.3`: `APP_VERSION`,
`SW_VERSION` (and therefore `CACHE_NAME`), `ADMIN_UI_TAG`, `MIDWEST_STACK_TAG`,
the `CORE` and install-blocking `critical` arrays, the `index.html` manifest and
script `?v=` queries, the `manifest.json` name, the `midwest-stack-authority.js`
`VERSION` const, every module header comment, and the `EXPECTED` block plus inline
assertions in `scripts/verify-cloudflare-parity.mjs`.

`DB_VERSION` stays **15** and the Worker stays **v13** — no source semantics
changed, so neither is touched.

**Two markers the checklist never covered**, both found by the read-only recon in
`RECON_24_0_2.md` and both stale by more than one release:

- `midwest-stack-config.json` `appTarget` read `FreightLogic v24.0.0`. Fixed here
  and added to the checklist as item 15.
- `styles.css`'s design-system header reads `24.0.0`. That file is **gpt**-owned
  under `/.agents/LANES.md`, so it is **not** fixed here — it is requested through
  `/.agents/inbox/`. Checklist item 7 is rewritten to say so, since it still
  pointed at `index.html`, where that comment has not lived since the CSS
  extraction.

**Regression.** `tests/unit/cache-generation.spec.mjs` (new, 10 assertions) makes
the invariant machine-checked instead of remembered: `SW_VERSION == APP_VERSION`,
`CACHE_NAME` derived rather than hardcoded, every `?v=` in both `service-worker.js`
and `index.html` at the current generation, the exact URLs `index.html` requests
present verbatim in the SW precache, the `critical` shell current and still
carrying the X-08/X-10 files, manifest/overlay/header agreement, parity-script
expectations, `DB_VERSION`/Worker unchanged, and CSP byte-identity across the bump.

Each assertion derives from `APP_VERSION` rather than a pinned literal, so the spec
keeps working at `24.0.4` without edits. Both invariants were verified by negative
control — reverting `SW_VERSION` to `24.0.2` fails CG-01, and drifting a single
`index.html` query string fails CG-04 and CG-05 — so these do not pass vacuously.

**CG-05 is the one worth understanding.** The app-logic branch of the fetch handler
looks up `cache.match(req)` **without** `{ ignoreSearch: true }`
(`service-worker.js:139`), while the `isStatic` branch does pass it. So a
query-string mismatch on a `.js` request is a hard cache miss, and the handler then
falls back to `cache.match(APP_SHELL)` — returning `index.html`, `Content-Type:
text/html`, `HTTP 200`, in response to a `<script src>`. The browser refuses to
execute it and the script silently vanishes, with no 404 and no console error. The
recon demonstrated this against the shipped worker by killing the origin. Nothing
is wrong at `24.0.3` because every marker agrees; CG-05 is what keeps it that way.

**Not certified.** Per
`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md`, live Cloudflare
verification and the physical iPhone checks remain the open gates and are not
satisfiable from an automated environment. This release does not change that
status, and nothing here should be read as instructing the operator to reinstall
the PWA or clear website data — doing so destroys the local IndexedDB evidence the
installed-origin investigation still needs.
