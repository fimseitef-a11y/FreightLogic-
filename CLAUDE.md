# FreightLogic — Claude Code Guide

## Project Overview

**FreightLogic v17.0.0** is a production-ready PWA (Progressive Web App) built for expedited cargo van operators. It provides freight decision intelligence: load scoring, bid recommendations, trap detection, market positioning, and full business bookkeeping — all running locally in the browser with optional cloud backup.

**Stack:** Vanilla JS (IIFE, `'use strict'`), HTML5, CSS custom properties, IndexedDB, Service Worker, Cloudflare Worker (cloud backup).

**No build system.** No npm, no bundler, no transpiler. Everything ships as flat files.

---

## File Structure

```
index.html              — Single-page app shell + all CSS (Design System v3.0 "Command")
app.js                  — Core application (~448KB, all logic in one IIFE)
service-worker.js       — PWA offline caching
cloud-backup-worker.js  — Cloudflare Worker for multi-user cloud backup (KV-backed)
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
7. **IndexedDB layer** — `initDB` (v9 schema), `tx`, `idbReq`, CRUD for all stores
8. **Data stores:** `trips`, `expenses`, `fuel`, `receipts`, `settings`, `auditLog`, `marketBoard`
9. **Export/Import** — JSON, CSV, XLSX (trips/expenses/fuel), receipt blobs
10. **Freight evaluator** — Market Feed, Tomorrow Signal, Strategic Floor A–E scoring
11. **UI rendering** — Trip list, expense list, fuel log, dashboard, settings panel

### IndexedDB schema (`DB_VERSION = 9`, `DB_NAME = 'XpediteOps_v1'`)
- `trips` — keyPath: `orderNo`
- `expenses` — keyPath: `id`
- `fuel` — keyPath: `id`
- `receipts` — keyPath: `tripOrderNo`
- `settings` — keyPath: `key`
- `auditLog` — keyPath: `id`
- `marketBoard` — keyPath: `id`

---

## Key Constants

```js
const APP_VERSION = '17.0.0';
const DB_VERSION = 9;
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

## Coding Conventions

- **No external frameworks** — pure DOM APIs only.
- **`$` / `$$`** — shorthand for `querySelector` / `querySelectorAll`.
- **`fmtMoney(n)`** — format as USD currency string.
- **`roundCents(n)`** — IEEE-754-safe cent rounding.
- **`isoDate(d)`** — local ISO date string `YYYY-MM-DD`.
- **`clampStr(s, max)`** — trim + limit string length (default 120).
- **Event listeners:** Use `addManagedListener(el, evt, handler)` — automatically cleaned up on `beforeunload`.
- **All async DB ops** return Promises via `idbReq(req)`.
- **Transactions:** Use `tx(storeNames, mode)` helper — returns `{ txn, stores }`.

---

## Cloud Backup Worker (Cloudflare Worker)

**File:** `cloud-backup-worker.js`
**KV binding:** `BACKUPS`
**Secret:** `ADMIN_TOKEN`
**Endpoint:** `https://freightlogic-backup.fimseitef.workers.dev`

### Key endpoints:
- `POST /admin/users` — create user (returns `userId`, `token`)
- `GET /admin/users` — list users
- `DELETE /admin/users/:id` — deactivate user
- `POST /backup` — store backup (`X-Device-Id`, `X-Backup-Token` headers)
- `GET /backup` — retrieve backup
- `DELETE /backup` — delete backup

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

- `manifest.json` references `v=17.0.0` cache-busting query on the manifest link.
- `service-worker.js` handles offline caching.
- Receipt blobs are cached in the Cache API under `__receipt__/<id>` URLs.
- `enforceReceiptCacheLimit()` keeps cache bounded (max `LIMITS.MAX_RECEIPT_CACHE = 40`).

---

## Development Notes

- **No build step** — edit files directly and reload in browser.
- **Test locally** with any static file server (e.g., `python3 -m http.server 8080`).
- **IndexedDB migrations** — increment `DB_VERSION` and add upgrade logic in `initDB()`.
- **Version bumps** — update `APP_VERSION` in `app.js`, `version` in `manifest.json`, and cache-bust query in `index.html`.
- **Master source asset** — `MIDWEST_STACK_FREIGHTLOGIC_MASTER_APP_SOURCE_v5.md` is referenced by `openMasterSourceCenter()` but not included in repo.

---

## Accessibility

- Touch targets minimum 44×44px (WCAG 2.1 AA).
- Focus management on modal open/close (`openModal` / `closeModal`).
- `haptic(ms)` provides tactile feedback on supported devices.
- Dark-first design; light theme available via `[data-theme="light"]`.
