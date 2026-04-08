# FreightLogic — Claude Code Guide

## Project Overview

**FreightLogic v22.0.1** is a production-ready PWA (Progressive Web App) built for expedited cargo van operators. It provides freight decision intelligence: load scoring, bid recommendations, trap detection, market positioning, and full business bookkeeping — all running locally in the browser with optional cloud backup and OpenAI-backed load evaluation.

**Stack:** Vanilla JS (IIFE, `'use strict'`), HTML5, CSS custom properties, IndexedDB, Service Worker, Cloudflare Worker (cloud backup + AI evaluate).

**No build system.** No npm, no bundler, no transpiler. Everything ships as flat files.

---

## File Structure

```
index.html              — Single-page app shell + all CSS (Design System v3.0 "Command")
app.js                  — Core application (~448KB, all logic in one IIFE)
sw-bridge.js            — Service worker auto-update bridge (SKIP_WAITING + reload)
service-worker.js       — PWA offline caching
cloud-backup-worker.js  — Cloudflare Worker: multi-user backup + AI load evaluation
manifest.json           — PWA manifest
favicon*.png / icon*.png — App icons
README.txt              — Notes on optional offline vendor files
```

### Optional offline vendor files (drop in root to avoid CDN):
- `xlsx.full.min.js` — SheetJS v0.18.5 (Excel import)
- `tesseract.min.js` + `worker.min.js` + `tesseract-core-simd-lstm.wasm.js` — Tesseract.js v5.1.1 (OCR receipts)

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

### IndexedDB schema (`DB_VERSION = 12`, `DB_NAME = 'FreightLogic_v18'`)
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
const APP_VERSION = '22.0.1';
const DB_VERSION = 12;
const DB_NAME = 'FreightLogic_v18';
const DB_NAME_LEGACY = 'XpediteOps_v1';
const PAGE_SIZE = 50;

// IRS tax data (2026)
IRS.MILEAGE_RATE_2026 = 0.725   // $0.725/mile
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
| Admin token | `sessionStorage` (`fl_admin_token`) | Cleared on tab/browser close |
| Device ID | `localStorage` (`fl_device_id`) | Persists — non-secret identifier |

Do not move the passphrase or admin token back to persistent storage.

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
- `POST /evaluate` — AI load evaluation (OpenAI); rate limited 20 req/min per user; returns `{ ok, ai: { verdict, grade, summary, trueRpmBand, bidAdvice, primaryReason, risks, positives, nextMove }, model, user }`

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

- `manifest.json` references `v=18.2.0` cache-busting query on the manifest link.
- `service-worker.js` handles offline caching; version `18.2.0`; caches `sw-bridge.js`.
- `sw-bridge.js` detects waiting workers, sends `SKIP_WAITING`, and reloads once — no user prompt required.
- Receipt blobs are cached in the Cache API under `__receipt__/<id>` URLs.
- `enforceReceiptCacheLimit()` keeps cache bounded (max `LIMITS.MAX_RECEIPT_CACHE = 40`).

---

## Development Notes

- **No build step** — edit files directly and reload in browser.
- **Test locally** with any static file server (e.g., `python3 -m http.server 8080`).
- **IndexedDB migrations** — increment `DB_VERSION` and add `if (old < N)` block in `initDB()`.
- **Version bumps** — keep these five in sync every release:
  1. `APP_VERSION` in `app.js`
  2. `SW_VERSION` in `service-worker.js`
  3. `manifest.json` `name` field
  4. `?v=` query on `<link rel="manifest">` in `index.html`
  5. `?v=` queries on `app.js` and `sw-bridge.js` script tags in `index.html`
- **Master source asset** — `MIDWEST_STACK_FREIGHTLOGIC_MASTER_APP_SOURCE_v5.md` is referenced by `openMasterSourceCenter()` but not included in repo.

---

## v22 Features (F21–F23)

### F21 — GPS Trip Tracking
- `renderTripTrackingUI()` — populates `#homeTripTrackCard` on Home with Start/Stop button
- `startTripTracking()` → `_showLocationPermissionModal()` (first use) → `_initTrackingObject()` → `_doStartTracking()`
- `stopTripTracking()` — clears watcher, shows review modal, calls `upsertTrip()`
- `resumeTrackingIfActive()` — called on boot; reads `sessionStorage('fl_active_tracking')`
- `nearestMarketCity(lat, lng)` — returns nearest market city within 100 mi, e.g. "Indianapolis, IN"
- `_cleanGpsLogs(trackingId)` — removes `gpsLogs` IDB entries after save or discard
- Settings keys: `f21OnboardingSeen` (bool), `f21PermissionSeen` (bool)
- sessionStorage key: `fl_active_tracking` (JSON: trackingId, startTime, startPos, totalMiles)

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

---

## Accessibility

- Touch targets minimum 44×44px (WCAG 2.1 AA).
- Focus management on modal open/close (`openModal` / `closeModal`).
- `haptic(ms)` provides tactile feedback on supported devices.
- Dark-first design; light theme available via `[data-theme="light"]`.
