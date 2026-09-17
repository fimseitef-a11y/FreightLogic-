# FreightLogic — Claude Code Guide

## Project Overview

**FreightLogic v24.0.18** is a production-ready PWA (Progressive Web App) built for expedited cargo van operators. It provides freight decision intelligence: load scoring, bid recommendations, trap detection, market positioning, proactive positioning briefs, and full business bookkeeping — all running locally in the browser with optional cloud backup and OpenAI-backed load evaluation.

**v24.0.17 source candidate:** Voice Load removed completely by operator decision
(#230), the import ceiling enforced before materialization (#232), and internal
audit/certification documents withheld from the public asset origin (#228). App
**24.0.16 → 24.0.17**; DB stays **16**; Worker stays **v20 source**. **Source-only: not
deployed and not live-observed.** It STACKS ON an undeployed v24.0.16 — Worker v20 still
must deploy before the app generation, exactly as the v24.0.16 section requires. Issue
**#224 remains OPEN** (the `db === null` race did not reproduce), so `main` must not be
described as having all automatable gates green.

**v24.0.16 source candidate:** three trust-boundary security issues (#219 untrusted
import installing credentials, #221 the token index outranking the account record plus
raw `token=` setup links, #220 the jsDelivr executable fallback) and the #224 readiness
/ diagnostics work. Worker **v19 → v20**; DB stays **16**. **Source-only: not deployed
and not live-observed.** Issue **#224 is OPEN** — the `db === null` race did not
reproduce — so `main` must not be described as having all automatable gates green.

**Production serves 24.0.15 / DB16 / Worker v19, and that is OBSERVED.** Live parity job
`105095664502` on `ee07297` reports `index.html` referencing app/voice/SW-bridge
**24.0.15**, service worker **24.0.15**, manifest name `FreightLogic v24.0.15`, all
**23/23** declared runtime assets loading from the production app origin with none served
as an HTML fallback, and Worker `/health` at **v19** — `VERDICT: PASS`. The production
service-worker gate passed on the same SHA. Physical iPhone A1-A12 and authentic M6
remain open, deferred by operator decision to the final post-v24.5 candidate.

**Stack:** Vanilla JS (IIFE, `'use strict'`), HTML5, CSS custom properties, IndexedDB, Service Worker, Cloudflare Worker (cloud backup + AI evaluate).

**Current cloud identities:** app/assets service `freightlogic-v2` serves `https://freightlogic-v2.fimseitef.workers.dev`; backup/API is `https://freightlogic-backup.fimseitef.workers.dev`. **Production serves app v24.0.14 / DB16 and Worker v19, and that is OBSERVED, not assumed** — live all-asset parity run `35087770010`, `workflow_dispatch` on `main` @ `8f90725`, VERDICT PASS against an `EXPECTED` block of `24.0.14` / `FreightLogic v24.0.14` / Worker `19`. That gate fails the job on anything but PASS and `UNOBSERVED` is also non-zero, so a success is a positive observation rather than an absence of objections. v24.0.14 inherits PR #210's zero-token driver onboarding (`POST /admin/invites` + unauthenticated `POST /claim`) and adds Worker v19's proactive legacy-plaintext cleanup.

*This overview previously read "**v24.0.15 source candidate** … Source-only: not deployed
and not live-observed. Production serves **24.0.14 / DB16 / Worker v19**." That was true
when the candidate was written and stopped being true when 24.0.15 deployed; issue #225
was opened to correct it. It is corrected rather than quietly overwritten, because a
release record that keeps a superseded deployment claim is the drift class this file now
records against itself six times. The instance before this one was worse than cosmetic —
it understated production by two app generations and two Worker generations, so a reader
would have re-run a deployment sequence that had already happened, or certified against a
candidate production had stopped serving days earlier. The rule that prevents it is the
one the certification documents already state: **a superseding record is due the day a
shipped file deploys, not the day it merges, and not whenever somebody notices.***

The intermediate generations are part of the record: **Worker v18** deployed (run `35037355686`, every post-deploy check green including `/health` reporting 18) and **app 24.0.13** observed live (parity run `35037460402`) before PR #211 superseded both with v24.0.14 / Worker v19.

**No build system.** No npm, no bundler, no transpiler. Everything ships as flat files.

**v24.0 authority rule:** `app.js` is the sole deterministic owner of load verdict, grade, economics, and bid range. USA scoring and `midwest-stack-authority.js` are evidence/advisory layers. Cloud Worker `/evaluate` may explain or challenge assumptions, but it must project—not recalculate—the canonical decision.

---

## File Structure

```
index.html                 — Single-page app shell: every `#view-*` section the canonical
                             router owns (`views` in app.js is built from this markup at
                             parse time, so a view added at runtime cannot be routed to)
styles.css                 — Extracted presentation layer, Design System v3.0 "Command".
                             gpt-owned; carries no version string by design (CG-11)
app.js                     — Core application (~1.1MB, all logic in one IIFE). Nothing in it
                             is a global — other scripts cannot call into it
modern-shell.js            — Driver-facing structural shell: the Today/Loads/Evaluate/Trips/
                             Money tab bar and the More entry. Loaded by dynamic import from
                             sw-bridge.js. Structural ONLY — it owns no route, renderer or
                             state; tabs are plain hrefs into the canonical hash router
admin-driver-ui.js         — Admin driver management UI (injected via service worker)
midwest-stack-authority.js — Midwest Stack v2 authority overlay; TRUE_RPM decision layer
                             (injected via service worker, not referenced from index.html)
sw-bridge.js               — Service worker auto-update bridge (SKIP_WAITING + reload)
service-worker.js          — PWA offline caching; injects admin-driver-ui.js and
                             midwest-stack-authority.js into HTML responses; precaches
                             modern-shell.js in the install-blocking critical shell
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
scripts/                   — `verify-cloudflare-parity.mjs` deploy-parity checker;
                             `lib/deploy-assets.mjs` is the shared runtime-asset inventory +
                             `.assetsignore` matcher it and `tests/unit/deploy-asset-coverage.spec.mjs`
                             both read, so the gate and its regression cannot drift apart
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
7. **IndexedDB layer** — `initDB` (current DB16 schema), `migrateFromLegacyDB`, `ensureLocalUserId`, `tx`, `idbReq`, CRUD for all stores
8. **Data stores:** logical `trips` (DB16 maps to `tripRecords`), `expenses`, `fuel`, `receipts`, `receiptBlobs`, `settings`, `auditLog`, `marketBoard`, `laneHistory`, `weeklyReports`, `reloadOutcomes`, `bidHistory`, `documents`, `gpsLogs`
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

### IndexedDB schema (`DB_VERSION = 16`, `DB_NAME = 'FreightLogic_v18'`)
- `trips` — retained legacy/rollback store from pre-v16; old keyPath: `orderNo`
- `tripRecords` — authoritative v16 trip store; keyPath: `id`, non-unique `orderNo` index. Runtime `tx('trips')` maps here when present
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
DB16 additionally creates `tripRecords` with stable internal `id` identity and a
non-unique `orderNo` index, then copies surviving pre-v16 `trips` rows into it.
The legacy `trips` store is deliberately retained for rollback; external order
numbers are evidence/lookup values, never authoritative record identity. Migrated
rows whose old `isPaid:false` cannot be proven explicit enter payment UNKNOWN.

### User namespace
`ensureLocalUserId()` generates a stable `usr_<16hex>` on first boot, stored in
`settings['localUserId']`. Foundation for multi-user import/restore isolation.

---

## Key Constants

```js
const APP_VERSION = '24.0.18';
const DB_VERSION = 16;
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
| Backup token (`flk_…`) | IndexedDB (`settings`) | Persistent bearer credential; excluded from ordinary exports |
| Encryption passphrase | `sessionStorage` (`fl_cloud_pass`) | Cleared on tab/browser close — never written to disk |
| Admin token plaintext | `sessionStorage` (`fl_admin_tok`) | Cleared on tab/browser close; optional encrypted-at-rest wrapper uses `settings['cloudAdminTokenEnc']` behind App Lock/PIN |
| Device ID | `localStorage` (`fl_device_id`) | Persists — non-secret identifier |

Do not move the passphrase or admin token back to persistent storage.

**Re-entry friction is solved by the OS keychain, not by persisting the secret.**
Because `fl_cloud_pass` is session-scoped, it clears on every browser close, and
`cloudIsEnabled()` requires it — so cloud backup goes inactive on every restart.
Until v24.0.5 nothing surfaced that except the Diagnostics `dxCloud` row, so
backups silently stopped and the operator only found out at restore time. Two
things now handle it, and both must be preserved:

- `cloudBackupPaused()` + `renderCloudPausedBanner()` make the inactive state
  visible on Home with a one-tap Resume. The banner deliberately does **not**
  auto-dismiss (unlike `showCloudSyncBanner()`'s 12s timeout) — an informational
  notice may vanish, "you are not being backed up" may not.
- `openCloudReconnect()` renders a **real credential form** — `<form>`, a
  read-only `autocomplete="username"` account field carrying `localUserId`, an
  `autocomplete="current-password"` field, and a genuine `type="submit"` — so
  iOS Keychain and other password managers offer to save it once and autofill
  with Face ID thereafter. That is what removes the typing.

Do not "simplify" that modal back into a bare input with a click handler: a
password manager keys its save prompt off a real submit event and ignores
`display:none` username fields, so the autofill silently stops working and the
operator is back to typing a passphrase on a phone. `tests/integration/
cloud-backup-paused.spec.mjs` CBP-08 asserts every part of that shape, and
CBP-07 asserts the passphrase never reaches `localStorage` or the settings
store — so the friction can never be resolved by weakening the encryption
instead.

The admin token grants create/list/revoke over **every** driver account, so it is the most
sensitive credential in the app. PR #210's zero-token onboarding keeps decrypted admin
material session-scoped; persistence is allowed only as AES-GCM ciphertext in
`settings['cloudAdminTokenEnc']`, keyed through the App Lock/PIN flow and written only
after the Worker verifies the credential. `admin-driver-ui.js` deliberately stands down
from the legacy admin-driver flow and its legacy-token purge is delete-only: stale
plaintext localStorage credentials must never be promoted back into a live session.

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

- `manifest.json` references `v=24.0.18` cache-busting query on the manifest link.
- `service-worker.js` handles offline caching; version `24.0.18`; caches `sw-bridge.js` and `modern-shell.js`; injects both the `admin-driver-ui.js` and `midwest-stack-authority.js` script tags into HTML responses via `injectEnhancementScripts()` (each guarded by an `injectBeforeBodyClose()` idempotency check); broadcasts `SW_ACTIVATED` message to all open clients on activate. The `install` event's critical (install-blocking) shell includes `midwest-stack-authority.js` and `vendor/xlsx.full.min.js` (X-08/X-10, v23.9) — see "Cloud Backup Worker" and the v23.9 changelog section below.
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
  6. `?v=` queries on `app.js` and `sw-bridge.js` script tags in `index.html` (`voice-load.js`
     was removed in v24.0.17 by operator decision, Issue #230)
  7. ~~Design-system header comment.~~ **RETIRED as of v24.0.4 — nothing to bump.**
     This item pointed at a comment in `index.html` that has not existed since the CSS
     extraction, so it guarded a location that could not drift while the real marker in
     `styles.css` drifted through 24.0.1, 24.0.2 and 24.0.3 unnoticed (found by the
     v24.0.3 recon). The gpt lane fixed it in PR #138 by **deleting the version from the
     `styles.css` header** rather than bumping it — `styles.css:2` now reads
     `FREIGHT LOGIC — DESIGN SYSTEM v3.0 "Command"` with no release number. That is the
     better fix: a presentation file carrying no version cannot drift, and it removes a
     cross-lane bump request from every future release. Keep it that way; do not
     reintroduce a version string here. `tests/unit/cache-generation.spec.mjs` CG-11
     asserts the absence, so a reintroduced version fails on the very next release
     rather than three releases later, and the quick-audit grep below still lists
     `styles.css`. Restored in v24.0.5 after the v24.0.5 landing commit reverted this
     item to its pre-retirement wording.
  8. `VERSION` const and header comment in `midwest-stack-authority.js`
  9. Header comment in `sw-bridge.js`
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
      along with items 3–6, 11, 12 and 14, so most of this list is machine-checked
      rather than remembered. **Item 15 was named here but was never actually
      checked** — nothing read `midwest-stack-config.json`'s `appTarget`, and it
      drifted again at v24.0.11 exactly as it had at v24.0.3. `CG-14` closes that;
      the claim is true now, and was not before.

  Quick audit — every shipped file should report the new version:
  ```bash
  grep -rno "2[0-9]\.[0-9]\+\.[0-9]\+" app.js index.html manifest.json service-worker.js \
    midwest-stack-authority.js sw-bridge.js styles.css midwest-stack-config.json \
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
- Stage 1: paste area + Parse action (the voice button was removed in v24.0.17, Issue #230)
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

---

## v24.0.4 "Fail Closed" — the behavioural half of the recon findings

v24.0.3 moved the release identity but changed no behaviour. This release fixes
the defects `RECON_24_0_2.md` confirmed, per
`.agents/inbox/gpt-to-claude-v2404-core-corrections-2026-09-03.md` (Issue #119).
`DB_VERSION` stays **15** and the Worker stays **v13** — neither's semantics changed.

**1 — An unknown location no longer becomes a market.** `naLookupMarket('')`
returned Toronto: the fuzzy pass tests `key.includes(norm)`, and every string
contains the empty string, so the *first* table entry always won. A blank origin
**and** destination therefore both resolved to Toronto and earned a `+8`
"favorable" Ontario↔Ontario corridor bonus for a lane the operator never supplied.
One- and two-character fragments matched on a stray letter (`'a'`→`mississauga`,
`'x'`→`halifax`). `NA_MIN_FUZZY_CHARS = 3` now gates the fuzzy pass; exact table
hits are still honoured at any length. `usaLookupMarket()` needed the same guard —
it is the fallback at every `naLookupMarket(x) || usaLookupMarket(x)` call site, so
without it the fix would have been a no-op.

*Found while fixing this, not in the packet:* `'Gary'` (Gary, Indiana — Tier 1)
resolved to `'calgary'` (ALBERTA), because `'calgary'.endsWith('gary')`, scoring an
Indiana load against the `premium_only` "Any → Alberta" corridor. The two substring
directions are not equally safe: `norm.includes(key)` means the input carries extra
qualifiers around a real key and is trustworthy; `key.includes(norm)` matches any
longer name that merely *contains* the input. A genuine abbreviation is a **prefix**,
so `naFuzzyPlaceMatch()` requires `key.startsWith(norm)` in that direction.
`'Gary'` now returns `null` (fail-closed) rather than the wrong market — it is
absent from `USA_MARKETS` entirely, and `MW.tier1` omits it while the overlay's
`marketRoles.tier1` includes it. That table gap is **reported, not invented**:
adding a market needs real coordinates and operator authority.

**2 — An unknown deadhead stays unknown on every intake.** The root cause was the
parser's own initializer, `deadheadMiles: 0` — an unstated deadhead was
indistinguishable from a verified zero, so every downstream `knownNum()` check saw
a genuine `0`. It is now `null`. Quick Evaluate additionally coerced it
(`Number(x) || 0`) and wrote `"0"` into `#mwDeadMi`, satisfying the M1 blank-deadhead
guard with a value nobody supplied: `Chicago→Detroit, 280mi, $560` produced
**A / ACCEPT / True RPM $2.00** while the full evaluator refused to grade the very
same load. F23 had the mirror-image bug — `Number(x) || parsed.emptyMiles` and
`dh || ''` both destroyed an **explicitly typed 0**, so the inbox could never record
a verified zero. An unstated deadhead also rendered as the literal text
`"0 deadhead"`. All four paths now distinguish missing from zero.

**3 — The advisory overlay no longer owns money or a verdict.**
`midwest-stack-authority.js` labelled itself `ADAPTER_ONLY` while carrying its own
mode floors, grade ladder and regional compression multipliers, computing
`floorBid/winBid/askBid` and an independent verdict, and rendering them as
`#mwEvalOutput.nextSibling` — directly beneath the canonical result. They
contradicted: on Minneapolis→Chicago at True RPM `$1.19` the canonical card read
**REJECT / F / PASS** while the overlay read **"Signal: TAKE_IF_LIVE"** with a `$475`
floor — below the `$1.25` hard reject, on a load whose Dead Zone gate had failed all
three checks. `assessLoad()` no longer returns `recommendation`, `posted.grade`, or
any bid; the panel is now "Market Context · Advisory" and renders destination role,
region and risk flags only. The bid-mode selector is gone with the ladder it drove —
a control that no longer changes any money is a second authority in appearance.
What survives is `dzGate`, which is what X-04 actually promised: proof that this file
and the main evaluator called the same `window.isDeadZoneEligible()`. The parity
spec now asserts the gate outcome directly instead of inferring it from a verdict
string, which is strictly stronger; M1-19 asserts the absence structurally rather
than trusting the `ADAPTER_ONLY` label.

**4 — The service worker never answers a subresource with HTML.** Every same-origin
`.js` was classified as app logic, and the failure path was
`cache.match(req) || cache.match(APP_SHELL)`. `cache.match(req)` does not pass
`{ ignoreSearch: true }`, so any `?v=` drift was a hard miss and a `<script src>`
received `index.html` — HTTP 200, `Content-Type: text/html`. The browser refuses to
execute it silently: no 404, no console error, the script simply vanishes. There was
also no bound on which same-origin scripts got cached. `KNOWN_ASSET_PATHS` is now
derived **from `CORE` itself**, so the fetch policy cannot drift from what
`install()` precaches; known assets fall back query-insensitively (so drift
self-heals to the right file); and only a navigation may receive HTML — everything
else gets an honest `504 text/plain`.

**5 — Portable payloads carry no credentials.** Both export paths used a two-key
denylist, so the bearer `cloudBackupToken` and the `appLockPin` PBKDF2 hash
travelled in the clear in every local export, plus device-local lockout state.
(`ALLOWED_SETTINGS_KEYS` is not a defence: it governs what an import *accepts*, and
it explicitly names both.) `isSettingExportSafe()` / `exportSafeSettings()` is now
the single policy for local export, cloud full backup, cloud delta **and every
checksum input**. It excludes named secrets *and* anything whose key name looks like
a credential, so a secret added later is withheld by default. Deliberately not a
pure allowlist: that inverts the failure into silent backup data loss for new benign
keys — the X-07 class of gap. Checksum wording is corrected throughout: an unkeyed
SHA-256 stored beside the data it covers is a **corruption check**, not proof
against deliberate editing.

**6 — No profit claim without a denominator.** The metric tile printed
"True Profit" unconditionally; with `opCostPerMile` unset that number was only
revenue − fuel. It now renders as unavailable. The wizard never collected monthly
miles, so a driver could complete onboarding having supplied every input the
derivation needs *except* the denominator — it is now collected, and
`opCostPerMile` is derived when both sides are real.

**7 — Cargo length reconciled to operator truth.** `VAN_PROFILE_DEFAULT.cargoLengthIn`
was `130`, from published Transit T250 copy. `docs/OPERATOR_TRUTH.md` records a hard
**121-inch** usable limit (OPERATOR_CORRECTION 2026-08-20, after a 176 in load was
rejected on fit). Every load between 122 in and 130 in was scoring as *fitting* and
proceeding to a full grade and bid, for freight this van cannot carry.

**Tests.** `tests/integration/v2404-fail-closed.spec.mjs` (11) and
`tests/integration/sw-subresource-semantics.spec.mjs` (8, driving the real worker
with the origin killed outright — Playwright's `setOffline()` does not reliably
apply to service-worker fetches). Every new assertion carries a negative control:
reverting the parser default fails V2404-05/06, reverting the export policy fails
V2404-10, and reverting the SW fallback to `APP_SHELL` fails SW-03/04.

**Still HOLD.** Live Cloudflare and physical-iPhone gates are unchanged and remain
the operator's. Nothing here instructs a reinstall or a website-data clear.

---

## v24.0.5 "Source Integrity" — the two findings v24.0.4 reported but did not invent

Landed by the gpt lane in PR #146 under a held `app-js` lock and six temporary
exact-file lane reassignments (since restored in PRs #148/#149). It closes both gaps
v24.0.4 deliberately **reported rather than fixed**, because each needed a fact the
core lane could not supply on its own authority: real coordinates for a missing market,
and a persistence contract for a field the trips schema had always coerced.
`DB_VERSION` stays **15** and the Worker stays **v13** — neither's semantics changed.

**1 — UNKNOWN deadhead now survives persistence, not just intake.** v24.0.4 fixed the
four *intake* paths (parser initializer, Quick Evaluate, F23, rendering) so an unstated
deadhead stopped reading as a verified zero. But the `trips` store itself still coerced
it on every write, so the distinction was destroyed the moment a load became a trip:

- `newTripTemplate`'s initializer was `emptyMiles: 0` — the same root-cause shape as the
  parser's, one layer down.
- `sanitizeTrip()` ran `posNum(raw.emptyMiles, 0, 300000)`, which floors a missing,
  blank, non-numeric or negative value to `0`. It is now `knownNum()` with an explicit
  range check and `null` otherwise, and validation emits a real
  `'Deadhead miles are unknown'` review reason.
- XLSX import mapped a blank deadhead cell through `Number(… || 0)`; a blank cell is now
  `null`, a present `0` still a real zero.
- The trip form read `trip.emptyMiles || ''` (which blanks an explicit `0`) and wrote
  `Math.max(0, Number(x || 0))` (which invents one). Now `?? ''` and `knownNum()` — the
  two halves of the same round trip, previously destroying a verified zero in both
  directions.

**Unknown deadhead is quarantined from history, not silently averaged.** New
`tripHasKnownDeadhead(trip)` gates every consumer that derives True RPM or lane/broker
intelligence from stored trips, alongside the existing `needsReview` check. A trip whose
deadhead was never stated no longer contributes a flattering RPM to a lane average, a
broker record, or a historical comparison — it is excluded and visible, which is the
same `knownNum()` doctrine v24.0.1 applied to the canonical decision, now applied to the
historical evidence that feeds it.

**2 — Gary, Indiana is canonical geography.** v24.0.4 found `'Gary'` resolving to
`'calgary'` (Alberta) because `'calgary'.endsWith('gary')`, and fixed the *matching* rule
so it fails closed to `null`. But the underlying table gap was real and was reported
rather than papered over: `USA_MARKETS` had no Gary at all, and `MW.tier1` omitted it
while the overlay's `marketRoles.tier1` included it — the two halves of the doctrine
disagreed. Gary is now in `USA_MARKETS` with real coordinates
(`41.5955922, -87.3452279`), zone `MIDWEST`, role `anchor`, and in `MW.tier1`, so
canonical and overlay Tier 1 finally agree.

**Markers.** `APP_VERSION`, `SW_VERSION` (and therefore `CACHE_NAME`), `ADMIN_UI_TAG`,
`MIDWEST_STACK_TAG`, `CORE`, the install-blocking `critical` array, the `index.html`
manifest and script `?v=` queries, `manifest.json` `name`, `midwest-stack-config.json`
`appTarget`, the overlay `VERSION` const, every module header, and the parity script's
`EXPECTED` block all move together to `24.0.5`.

**Tests.** `tests/integration/v2404-fail-closed.spec.mjs` gained V2405-01 (`sanitizeTrip`
preserves UNKNOWN vs. explicit zero across missing/blank/invalid/negative/zero/positive)
and V2405-02 (a real IndexedDB round trip never manufactures `0` from `null`), and its
Gary assertion (V2404-04) was strengthened from the negative property it could assert
at the time — `gary !== 'calgary/ALBERTA'`, which passed only because the lookup
fail-closed to `null` — to the exact positive one now that the market exists:
`gary === 'gary/MIDWEST/US/anchor'` plus Tier 1 membership. The spec got stronger, not
weaker, which is the right way to close a reported-not-invented gap. PRs #148/#149
then repaired an IndexedDB-readiness race in the shared harness and restored normal
`tests/` ownership. Full suite re-run on `556f5b0` after that harness change, since it
sits underneath all forty specs: **372 passed, 0 failed across 40 spec files**, up from
369/40 at v24.0.4 (`ff9d9ab`): V2405-01 and V2405-02 here, plus CG-11 from PR #144. `scripts/verify-cloudflare-parity.mjs --static-only` is green at
`24.0.5`, and `scripts/m7-certify.mjs` reports 13/13 automated gates clean.

**Documentation debt this release left, closed here.** v24.0.5's own landing commit
(`eded539`) bumped only CLAUDE.md's Project Overview line, leaving the Key Constants
`APP_VERSION` and both PWA-section references reading `24.0.4` — checklist item 10 names
all three sections. It also reverted checklist item 7 to its pre-retirement wording,
which is factually wrong now: `styles.css` carries no version to bump and CG-11 asserts
it stays that way. Both are corrected above, along with this section, which the release
shipped without.

**Still HOLD.** The canonical certification state is
`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-03.md` (which supersedes the
`2026-09-02` document the v24.0.3 and v24.0.4 sections above cite). Its HOLD names two
things: the proof-backed core corrections, and the live/physical gates. v24.0.4 and
v24.0.5 are those corrections — whether they discharge that half is a `docs/` (gpt-lane)
judgement, requested through `/.agents/inbox/`, not something this section may assert.
The live Cloudflare and physical-iPhone gates are unchanged either way and remain the
operator's; they are not reachable from an automated environment (the agent proxy
refuses to tunnel to both deployed origins, re-tested at this release). `m7-certify`
reports 13/13 automated gates clean at `24.0.5` and `NOT CERTIFIABLE`, which is the
correct pairing. Nothing here instructs a reinstall or a website-data clear — that would
destroy the local IndexedDB evidence the installed-origin investigation still needs.

---

## v24.0.6 "Backup You Can Trust" — the silent-backup repair, and gate 2 made runnable

Landed in PR #160 under a held `app-js` lock. `DB_VERSION` stays **15** and the Worker
stays **v14** — neither's semantics changed.

**1 — Cloud backup was switching itself off after every browser close, silently.**
The backup token lives in IndexedDB and survives restarts; the encryption passphrase
lives in `sessionStorage` and does not. `cloudIsEnabled()` requires **both**, so the
moment a browser session ended every automatic push began no-opping — both
`visibilitychange` handlers, `cloudScheduleSync()`, and `emergencyAutoBackup()` — and
every one of those call sites swallows its result with `.catch(()=>{})`.

The only surface in the app that reported this was the Diagnostics panel's `dxCloud`
row ("Token set, no passphrase"), four taps deep under More → Advanced. So the lived
behaviour was: close the app, come back the next day, believe you are backed up, and
not be. For a bookkeeping app whose entire cloud story is disaster recovery, that is
the worst available failure mode, because it is only discovered at restore time.

- `cloudBackupPaused()` — token present, passphrase absent. Deliberately returns
  `false` when no token exists: nagging a driver who never enabled cloud backup would
  train them to dismiss the one banner that matters.
- `renderCloudPausedBanner()` — called from `renderHome()`, so it cannot be missed the
  way the Diagnostics row was. It does **not** auto-dismiss, unlike
  `showCloudSyncBanner()`'s 12-second timeout: an informational "backup found on
  server" notice may vanish, "you are not being backed up" may not.
- `openCloudReconnect()` — one field, one tap, and it verifies before claiming success.

**2 — Re-entry friction is solved by the OS keychain, not by persisting the secret.**
`openCloudReconnect()` renders a real credential form — a `<form>`, a read-only
`autocomplete="username"` account field carrying `localUserId`, an
`autocomplete="current-password"` field, and a genuine `type="submit"` — so iOS
Keychain and other password managers offer to save it once and autofill with Face ID
thereafter. Three details are load-bearing: the handler binds to the form's **submit**
event (a password manager keys its save prompt off a real submit and is blind to a
click handler), the account field is **visible** and read-only (Safari's heuristics
ignore `display:none` username fields), and the account value is `localUserId` so the
saved credential is scoped to this install rather than a guessable constant.

The passphrase remains `sessionStorage`-only. See the Credential Storage Rules section
above, which now records this and says not to undo it. CBP-07 fails if the passphrase
ever reaches `localStorage` or the settings store, and CBP-08 asserts the whole form
shape — so the friction can never be resolved later by weakening the encryption, and a
refactor cannot flatten the modal back into a bare input without CI noticing that
autofill has stopped working.

**Found while building this:** the first version of the reconnect handler tested
`cloudPushBackup()`'s return value. That function returns `undefined` on *every* path —
success, "up to date", both early-outs, and the catch alike — so it would have reported
success on failure and left a broken credential pair in place. It now compares
`lastCloudSync` across the call, which the function does advance on success and leaves
untouched in its catch; the same signal the existing `visibilitychange` handler uses.

**3 — Completion gate 2 is now a button.** `.github/workflows/deploy-backup-worker.yml`
is **manual dispatch only**, requires typing `DEPLOY`, and runs with
`permissions: contents: read`. It never triggers on push, comment or schedule — that
distinction is deliberate, because the v24.0.1 comment-triggered, branch-pushing CI
repair machinery was removed on purpose and must not return. It runs the preflight, a
`wrangler --dry-run`, the deploy, then verifies `/health` is 200 reporting version 14,
that CORS echoes the real app origin rather than `*`, and that unauthenticated
`/admin/users` and `/evaluate` still return 401. Those four are chosen because the
deployed v7 fails exactly the first two, so a deploy that did not land cannot report
success. One-time setup is a single repository secret, `CLOUDFLARE_API_TOKEN`.

**Why this shipped as a version bump.** An `app.js` change alone is undeliverable: a
browser installs a new service worker only when the worker script's own bytes differ,
and `CACHE_NAME` is `freightlogic-${SW_VERSION}`. Without the bump every installed PWA
would keep serving the pre-repair shell from cache. This is the v24.0.3 lesson applied
rather than relearned.

**Two pieces of standing drift closed in the header while bumping it:**
- `app.js`'s header block read `v24.0.4` as its top line while `APP_VERSION` was
  `24.0.5` — the only live version CONFLICT in the tree, and exactly what checklist
  item 1 exists to catch.
- v24.0.5 never wrote a header changelog entry at all. Backfilled from what that
  release actually shipped, rather than relabelling a neighbouring entry — which is the
  specific failure mode item 1 names.

**Tests.** `tests/integration/cloud-backup-paused.spec.mjs` (8, new). Every
`chromium.launch()` in the suite now honours an optional `FL_CHROME_PATH` — the two in
`tests/lib/harness.mjs` plus five specs that launch directly and therefore bypass any
harness-level launch policy (`sw-subresource-semantics`, `field-resilience` ×3,
`backup-restore-parity`). Unset, as in CI, the launch options are byte-identical to
before; CI proved that by returning the same total. Full suite: **384 passed, 0 failed
across 41 spec files**, run both locally against real headless Chromium and in CI.

**Deployed-Worker findings recorded.** `AUDIT_REPORT.md` gained P-01…P-07 — the first
OPEN findings in that report. The live backup Worker is **v7**, not v13: it stores every
driver bearer token in KV in plaintext, returns those tokens from `GET /admin/users`,
lets the model own verdict and grade in `/evaluate` (a live violation of the v24.0
authority rule), and has no `GET /backup/delta` at all, so X-01 is active in production
and pruned deltas are already unrecoverable. All seven close by deploying the v14 source
that already exists; none needs a code change. The v7 → v14 transition was verified safe
against the deployed bytes — `getPtr()` lazily seeds from `list({prefix})`, the driver
path migrates and deletes legacy plaintext token keys, v7's token and user-id formats
both satisfy v14's validators, and secrets survive a deploy.

**Gate 2 is CLOSED — Worker v14 deployed and verified 2026-09-13T05:06:45Z.**
Run `34739479229` deployed it through `.github/workflows/deploy-backup-worker.yml` after
the operator added the `CLOUDFLARE_API_TOKEN` secret. Verified two independent ways: the
workflow's live checks against the production origin (`/health` HTTP 200 reporting
version `14`; CORS echoing `https://freightlogic-v2.fimseitef.workers.dev` rather than
`*`; unauthenticated `/admin/users` and `/evaluate` both still 401), and the Cloudflare
control plane showing `freightlogic-backup` `modified_on 2026-09-13T05:06:45Z`, matching
the deploy step. The dispatch before it (run `34738415856`) is worth keeping in the
record: it failed at the token guard in 9 seconds without touching anything, which is
what proved the guard chain works rather than merely being written.

That closes P-01 through P-07 in `AUDIT_REPORT.md` **with one residue**: v14's plaintext
`token:` cleanup is lazy, deleting each key only when that token is next used or its user
is revoked. Every driver token minted under v7 must be treated as exposed at rest until
rotated. Rotation is an operator action, not a deploy side effect.

**Still HOLD.** Certification is unchanged pending the `docs/` lane's judgement, which was
requested through `/.agents/inbox/`. Gate B5 is closed by `scripts/verify-rollback.mjs`,
which also established that **neither component has a clean rollback target** — the
Worker's only prior version is v7, so rolling back is a security regression, and rolling
the app back past `39882fa` raises `payloadLbs` 3000 → 3800 and drops the 54.8"
wheel-well constraint. Approved policy is fix-forward. The private-history and
physical-iPhone gates are unchanged and remain the operator's; neither depends on the
Worker deploy, so both can run in parallel with it.

**Documentation debt this release left, closed here.** v24.0.6's landing commit bumped
CLAUDE.md's Project Overview, Key Constants and PWA references but shipped no release
section — the same omission v24.0.5 made, which checklist item 10 does not currently
catch because it names version *references* rather than a section. This section is that
correction. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` still reads `24.0.5`; it is
gpt-owned under `/.agents/LANES.md` and was requested through `/.agents/inbox/` rather
than edited across lanes.

---

## v24.0.7 "Rotate Without Loss" — in-place driver token rotation

Worker **v14 → v15**. Rotating a driver's bearer token previously meant creating a new
driver and revoking the old one, because `POST /admin/users` was the only way to mint a
token — and it mints a new `userId` too. Every backup is keyed
`user:<userId>:device:<id>:backup:<ts>`, so a rotation silently orphaned that driver's
entire backup history: the data stayed in KV and nothing could address it again.

`POST /admin/users/:id/rotate` re-keys in place and keeps the identity, and the admin
panel gained a Rotate control returning a one-tap invite link. Rotation also deletes any
legacy v7 plaintext `token:` key immediately, which is what actually finishes the
P-01/P-02 cleanup that v14 only did lazily on a token's next use. `DB_VERSION` stays
**15**.

*This section was backfilled in v24.0.8 — v24.0.7's landing commit shipped without one,
the same omission v24.0.5 and v24.0.6 made. See the checklist note at the end of the
v24.0.8 section.*

---

## v24.0.8 "Loads Actually Opens" — the structural shell, repaired

PR #168 landed the five-surface driver shell — Today / Loads / Evaluate / Trips /
Money — and the full suite was green at **392 passed / 0 failed across 42 spec
files**. It was green because nothing in the suite touched the shell. The Loads
tab, the central new surface of that pass, was dead on arrival. `DB_VERSION` stays
**15** and the Worker stays **v15** — neither's semantics changed.

**1 — The Loads tab showed the Today screen.** `modern-shell.js` created
`#view-loads` itself, at import time. `app.js` builds its `views` map at **parse**
time from markup that already exists:

```js
const views = { home:$('#view-home'), trips:$('#view-trips'), … };
```

so there was no `loads` entry, and `navigate()` resolves an unknown hash to `home`.
Tapping Loads therefore rendered `view-home` while `#view-loads` — never registered
with any router — stayed `display:none` for the life of the page. The hash read
`#loads` and the Loads tab highlighted itself, which is exactly why this looked
fine: **every signal except the one that matters was already correct.**

The consequence was larger than one empty tab. PR #168 had *relocated*
`#loadInboxCard` out of `view-omega` into that surface, so the Smart Load Inbox
(F23) — paste a broker email, score it — became unreachable from anywhere in the
app.

`#view-loads` is now real markup in `index.html`, so it exists before `views` is
built; `loads` is a real route with a real renderer (`renderLoadsView()`, beside
`renderLoadInbox()`); and `#loadInboxCard` has exactly one mount point, which the
Loads route owns. `_refreshInboxRecentBar()` re-renders the recent-paste bar on
each visit, because `renderLoadInbox()` short-circuits on `inboxInit` and that bar
is session state other surfaces write to. `_renderInboxRecent()` now clears its
container first — it returned early on an empty list, which would have left a
previous session's entries on screen once it started being re-rendered.

**2 — Three more paths in the adapter could never have run.** `renderLoads()`
called `window.renderLoadInbox` and `window.renderOmega`; the More button called
`window.navigate`. `app.js` is one IIFE and exports none of those, so all three
were permanently `undefined` — and silently: no throw, no console error, the
`catch` never fired because nothing threw. `currentPrimaryRoute()` queried
`.view.active`, a class the app has never used (visibility is inline
`style.display`), and was itself never called.

The adapter is now what its own header claims: it builds the tab bar, moves the
live `#navUnpaidBadge` node into it rather than minting a second one, adds the More
entry, and normalizes the two driver-facing aliases (`#today`, `#evaluate`). Tabs
are plain `href`s and carry the **canonical** route name in `data-nav`, so
`app.js`'s own `setActiveNav()` drives the highlight — the pre-24.0.8 bar declared
`data-nav="evaluate"`, a name the router never produces, so the centre tab was
unhighlighted on every navigation the adapter did not itself perform. No click
interception, no second router, no `stopImmediatePropagation`.

**3 — The Market Intel surface became unreachable.** The old bar carried an Intel
tab, and `index.html`'s nav anchor was the **only** link to `#intel` anywhere in the
app. The shell replaces that `<nav>` wholesale, and `MORE_TILES` had no Intel entry —
so the route, `renderIntel()`, and all five of its tabs (Overview, Lanes, Reloads,
Brokers, Tools) stayed perfectly intact and reachable only by typing the hash. A
`Market Intel` tile in More's PRIMARY section restores it, which is what makes
"secondary tools remain accessible through More" true rather than assumed. Every
other route was already covered: `expenses`, `fuel` and `insights` have tiles, and
`more` has the header control.

**4 — `voice-load.js` threw on every fresh session.**

```js
try { return JSON.parse(raw); } catch (_) { return fallback; }
```

`sessionStorage.getItem()` returns `null` for a key never written, and
`JSON.parse(null)` is **valid JSON** that yields `null` — it does not throw, so the
catch never ran and the `[]` fallback was never applied. `getDraftStore()` handed
back `null`, and `loadLatestDraft()` died on `store.length`. That aborted `init()`
before its first `renderReview()` and before the no-speech-recognition fallback
could hide the voice button. `safeJSONParse` now validates the **shape**, not just
the parse. `getCorrectionStore()` had the same latent defect on its write path.

**Why this is a version bump.** All cache-busters were `?v=24.0.7` and `CACHE_NAME`
is `freightlogic-${SW_VERSION}`. An `app.js` + `index.html` + `modern-shell.js`
repair landed without bumping would never reach an installed PWA. This is the
v24.0.3 lesson applied rather than relearned.

**Release-identity coverage for `modern-shell.js`.** It is release-bound but is
requested by `sw-bridge.js` via dynamic import, **not** by `index.html` — so CG-04
and CG-05, which read `index.html`, could never see it, and neither could the
parity script. A stale import string would have shipped the previous generation's
tab bar with every other marker reporting green. Now covered on every axis:
`scripts/verify-cloudflare-parity.mjs` fetches the deployed `sw-bridge.js` and
`modern-shell.js` and asserts the import string, the exposed global, and the
service-worker precache entry; CG-07's header sweep includes the file; and CG-12
asserts the bridge import, the precache URL and the install-blocking `critical`
array all agree. This satisfies the requirement in
`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md` §2 that the next parity
run include `modern-shell.js`.

**CG-13 is the assertion that would have caught the original defect.** It parses
the tab bar's `href`s and `app.js`'s `views` map and fails if the shell can produce
a hash the router cannot resolve, or if a mapped view is missing from
`index.html` — a runtime-injected section being too late by construction. It also
requires `data-nav` to equal the canonical route name.

**Tests.** `tests/integration/modern-shell-routing.spec.mjs` (12, new) drives the
real app in Chromium and asserts **computed visibility and rendered content**, not
the hash or the highlighted tab — both of those were already correct while the
surface was dead, which is how this shipped green. Plus CG-12/CG-13 static
assertions. MS-12 asserts reachability structurally — every route the app can
render must be reachable from the tab bar or a More tile, with no exceptions list —
so the next navigation change cannot orphan a surface the way this one did.

Every new assertion carries a negative control: reverting the `views` registration
fails MS-02/03/04/05/06 and CG-13; restoring `data-nav="evaluate"` fails CG-13; a
stale bridge import fails CG-12; reverting `safeJSONParse` fails MS-10; removing the
Intel tile fails MS-12. Full suite: **406 passed, 0 failed across 43 spec files**, up
from 392/42.

**Version-bump checklist, items 7 and 13.** `styles.css` still carries no version
(CG-11 holds). `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` is gpt-owned under
`/.agents/LANES.md`; the `24.0.8` bump and the `modern-shell.js` parity line were
requested through `/.agents/inbox/` rather than edited across lanes. This release
also backfills the v24.0.7 section CLAUDE.md never got — three consecutive releases
(24.0.5, 24.0.6, 24.0.7) shipped without one, so checklist item 10 should be read
as requiring a release *section*, not only bumped version references.

**Still HOLD.** Nothing here touches the live gates. The canonical certification
state remains `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md`: Worker
v15 redeploy, exact production parity on the frozen candidate, private-history
reconciliation, and the physical-iPhone checklist are all unchanged and all remain
the operator's. This release changes what that parity run must target — the frozen
candidate is now `24.0.8`, and it must include `modern-shell.js`.

---

## Deployment asset coverage — the 404 that passed 24/24

Tooling only. No shipped file changed, so no version marker moved and no release
section is warranted: `APP_VERSION`, `SW_VERSION`, `DB_VERSION` 15 and Worker v15
are all untouched.

**The defect.** On 2026-09-13, against `c02ed36`, the gpt lane observed
`scripts/verify-cloudflare-parity.mjs` reporting **24/24 checks PASS** while
`admin-driver-ui.js` returned **HTTP 404** from the deployed origin. Two
independent blind spots produced that, and either alone was enough:

1. `.assetsignore` named `admin-driver-ui.js`, so the Cloudflare Workers assets
   uploader never published it — while `service-worker.js` precached it in `CORE`
   *and* injected a `<script>` tag for it into every HTML response. Two lists
   disagreed and nothing compared them. (PR #173 removed the exclusion; nothing
   stopped it being reintroduced.)
2. The live parity half fetched a **curated subset** — index, service worker,
   overlay, bridge, shell, manifest. An asset outside that list could 404 in
   production with every check green. `admin-driver-ui.js` was outside it, and it
   is reachable only through the injected tag, so no markup-based check could see
   it either.

**The repair, in the lane that owns it** (`scripts/`, `tests/` are claude-owned;
`.assetsignore` is SHARED and was not touched here):

- `scripts/lib/deploy-assets.mjs` (new) is the single inventory. It derives the
  runtime asset set from the real declarations — SW `CORE`, the install-blocking
  `critical` array, `ADMIN_UI_TAG`/`MIDWEST_STACK_TAG`, `index.html`'s own
  same-origin refs, and `sw-bridge.js`'s dynamic import — plus a conservative
  gitignore-subset `.assetsignore` matcher that names the pattern that decided an
  exclusion. Both SW arrays mix quoted literals with bare const identifiers, so
  `APP_SHELL` is resolved rather than skipped (a literals-only scan silently drops
  `index.html` itself), and comments inside them are stripped before that scan, or
  CORE's own X-10 note ("no CDN fallback") reads as an unresolvable entry. An
  identifier that genuinely cannot be resolved is reported as a hard failure, never
  dropped — a quietly shorter inventory is the same failure shape as the original
  defect. Current inventory: 23 assets. Both the gate and its regression import
  this module, deliberately: a second copy would reproduce the defect one level
  up.
- `scripts/verify-cloudflare-parity.mjs` gained a local exclusion check (runs
  under `--static-only`) and a live sweep of **every** declared asset with bounded
  concurrency. The existing named checks stay — they assert CONTENT (version
  strings, exposed globals, precache entries), which a 200 does not; the sweep
  asserts DELIVERY, which is the axis that failed. It also rejects a `200` whose
  `Content-Type` is `text/html` for a `.js`/`.css`/`.json`/image request: the
  SPA-fallback shape where the browser refuses to execute the response with no
  404 and no console error, so the script silently vanishes. No declared asset is
  ever "optional" here — an optional miss reported as full production parity is
  the defect restated.
- `tests/unit/deploy-asset-coverage.spec.mjs` (new, 5) closes the offline half:
  DAC-01 every requested asset exists on disk; **DAC-02** none is excluded by
  `.assetsignore`; DAC-03 the reverse direction — `cloud-backup-worker.js`,
  `wrangler.jsonc`, `CLAUDE.md`, `.git/` must STAY excluded, because
  `wrangler.jsonc` publishes `assets.directory: "."` and relaxing an entry to
  clear a 404 would serve the Worker source publicly; DAC-04 the gate still
  imports and actually CALLS the shared sweep (commented-out code does not
  satisfy it); DAC-05 pins `admin-driver-ui.js` by name.

**Negative controls, all verified to fire:** re-adding `admin-driver-ui.js` to
`.assetsignore` fails DAC-02 and DAC-05; a `vendor/` directory entry fails DAC-02;
an `icon*.png` glob fails DAC-02; dropping the `cloud-backup-worker.js` exclusion
fails DAC-03; commenting out the sweep call or removing the shared import fails
DAC-04; a bogus identifier inserted into `CORE` fails DAC-01/02/05 as an
unparseable declaration rather than shrinking the inventory in silence. The live half was driven against a real local origin: deleting
`admin-driver-ui.js` reproduces `HTTP 404 (requested by service-worker.js CORE,
service-worker.js ADMIN_UI_TAG (injected))` and exits 1, and an origin that serves
`index.html` for a missing `.js` is caught by the content-type check rather than
passing as 200.

Per the handoff, the suite stays offline: the sweep is in the operator gate, not
in `tests/run-all.mjs`. A gate that needs the internet is a network gate, not a
code gate.

---

## v24.0.9 "Can You Even Get There" — the pickup you cannot reach

Closes the highest-value item from the 2026-09-12 operator-data pass, which was
reported rather than built at the time because it needed a fact this lane could
not supply on its own authority. `DB_VERSION` stays **15** and the Worker stays
**v15** — neither's semantics changed.

**The defect.** The evaluator had no notion of time at all. It would grade,
price and recommend a bid on a load whose pickup had already closed, or that sat
further away in deadhead than the remaining window allowed. The operator dataset
contained a real instance — quote 1079840, a **225-mile deadhead against a 19:00
cutoff** — and nothing in the app detected it. Every other gate in the evaluator
asks whether the load is *worth* taking; none asked whether it can be taken at
all. Dimensional feasibility had been covered since 7D; temporal feasibility had
not been covered at all.

**The gate.** `checkPickupFeasibility()` runs immediately after the 7D
dimensional gate and **before any economics**, mirroring it exactly: it blocks
with a "CAN'T TAKE" card in place of the normal result, and is otherwise
silent. A load with no cutoff entered is not blocked — most postings state none,
and this is a safety net, not a requirement. Ordering is pinned by PF-07: a load
failing both gates reports the dimensional conflict, because `checkVanFit()`
runs first.

**Why there is no default speed, and why that is the whole design.** Converting
deadhead miles into drive time needs an average speed, and that is an operator
fact this repository has no authority to invent. `VAN_PROFILE_DEFAULT` is the
cautionary precedent: its published-brochure cargo length was wrong by nine
inches against the operator's own measurement, and every load between 122" and
130" scored as *fitting* for freight the van could not carry (fixed in v24.0.4).
A guessed speed fails the same way, except the failure is worse — it would
**reject** loads the driver could actually make, and a false CAN'T TAKE is
invisible, because the driver never learns what they turned down.

So `settings['planningAvgMph']` has **no default** and the gate is inert until
the operator sets it — the same shape as the EIA fuel feed, which returns `null`
early without `settings['eiaApiKey']` rather than inventing a price. The
consequence worth stating plainly: **this release cannot change the verdict on
any load scored the way loads are scored today.** It only becomes able to block
anything after the operator supplies one number they alone know.

**UNKNOWN discipline, applied throughout** — the same `knownNum()` doctrine
v24.0.1 applied to the canonical decision:
- Planning speed unset, or stored out of the 5–85 mph sanity range, returns
  `applicable: false` / `PLANNING_SPEED_UNSET`. An out-of-range value is **not
  clamped** into range: substituting a bound would run the gate on a number the
  operator never chose, which is the blank-deadhead-means-zero defect wearing a
  different hat. A typed `655` disables the check; it does not become `85`.
- No cutoff → `NO_CUTOFF_SUPPLIED`. Unparseable cutoff → `CUTOFF_UNPARSEABLE`.
- An **unstated** deadhead → `DEADHEAD_UNKNOWN`, never zero. Treating blank as
  zero would make every distant load look instantly reachable.
- An **explicit** `0` deadhead is a verified fact (the driver is at the pickup):
  zero drive time, still applicable, reachable.
- An inapplicable check never reports `reachable` at all — it is not a pass.

**Advisory, not authority.** A reachable-but-narrow window (under 30 minutes of
slack) sets `tight` and fires a toast. It never blocks, and it deliberately does
not touch verdict, grade, True RPM or the canonical bid range — so it is a toast
rather than anything rendered into the authoritative result card. The block card
itself prints every number that produced it, the operator's own planning speed
included, so a CAN'T TAKE is never a verdict the driver has to argue with.

**Surfaces.** `#mwPickupCutoff` (a `datetime-local`, optional) in the evaluator's
More Details, beside the 7D dimension fields. Settings gains a **Trip Planning**
section whose copy states outright that there is no default on purpose and that
the check stays off until the operator sets a figure. An empty or out-of-range
entry **clears** the setting rather than storing a fallback.

`planningAvgMph` is added to `ALLOWED_SETTINGS_KEYS` in the same change that
introduces it — a settings key the app writes but the importer drops is the X-07
class of gap, and this is the third time that list has needed a retrofit.

**Why this is a version bump.** All cache-busters were `?v=24.0.8` and
`CACHE_NAME` is `freightlogic-${SW_VERSION}`. An `app.js` + `index.html` change
landed without bumping would never reach an installed PWA. This is the v24.0.3
lesson applied rather than relearned; CG-01 enforces `SW_VERSION == APP_VERSION`
and all 13 CG assertions are green at `24.0.9`.

**Tests.** `tests/integration/pickup-feasibility.spec.mjs` (8, new) drives the
real evaluator UI in Chromium and asserts **computed content**, not internal
state. `tests/unit/pure-functions.spec.mjs` gained 12 `[PF]` cases covering the
UNKNOWN matrix above. Cutoffs are computed relative to `Date.now()` inside the
page rather than pinned to a literal, so this spec cannot become the date
time-bomb recorded in `gpt-to-claude-v2402-date-fixture-timebomb-2026-09-02.md`.

Negative controls, all verified to fire: making `getPlanningAvgMph()` fall back
to `55` fails PF-01 and the `getPlanningAvgMph` unit case; treating an unstated
deadhead as `0` fails the UNKNOWN-deadhead case; dropping the range check so an
out-of-range speed clamps fails the out-of-range case; and neutralizing the
block so economics render for an unreachable pickup fails PF-02/03/05.

**Deliberately not built, and why.** The `tight` flag is computed and returned
but is only surfaced as a toast — rendering it inside the result card, and
carrying pickup feasibility into `buildEvaluationEvidence()`, both belong with
the v24.1 Confidence + Evidence contract rather than being bolted on here. The
parsers (F23/F27) do not yet populate `#mwPickupCutoff`; manual entry is the v1
surface, exactly as the 7D dimension fields shipped.

**Still HOLD.** Nothing here touches the live gates. The canonical certification
state remains `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md`, and
this release changes what its parity run must target — the candidate is now
`24.0.9`. `docs/` is gpt-owned under `/.agents/LANES.md`, so the checklist bump
was requested through `/.agents/inbox/` rather than edited across lanes.

---

## Live-parity runner — closing the observation gap, and UNOBSERVED as a real outcome

Tooling only. No shipped file changed, so no version marker moved: `APP_VERSION`
and `SW_VERSION` stay `24.0.9`, `DB_VERSION` 15, Worker v15. Requested by the gpt
lane in `.agents/inbox/gpt-to-claude-live-parity-runner-2026-09-14.md`; `.github/`
and `scripts/` are claude-owned, so it was built rather than handed back.

**The gap.** The live half of `scripts/verify-cloudflare-parity.mjs` had been
UNOBSERVED for the whole v24.0.x line — not because anyone doubted it, but
because no environment that could run it could also reach production. This
repo's agent proxies refuse to tunnel to the deployed `workers.dev` origins, and
the operator works from a phone. GitHub-hosted runners have ordinary outbound
access, so the observation that was impossible everywhere else is a button there.

`.github/workflows/verify-live-parity.yml` — `workflow_dispatch` only,
`permissions: contents: read`, no secrets, Node 22, no npm install (the verifier
is plain Node with global `fetch`). It records the exact SHA under verification,
runs the real verifier with no `--static-only` shortcut, writes the full log to
the job summary, and on anything but PASS it stops and reports. It never deploys
and never writes to the repository: auto-repairing production from a verification
job is the branch-pushing CI machinery this file records as removed on purpose.

**The part that actually mattered: three outcomes, not two.** The request assumed
PASS / FAILURE / UNOBSERVED already existed. They did not — an unreachable origin
was recorded as one more failed check, indistinguishable from a real mismatch.
That conflation is dangerous in both directions: a network outage gets written
into a certification record as evidence that production is broken, and — worse —
a run that observed nothing can be cited as though it had looked. `report()` now
ends in an explicit verdict:

| Verdict | Exit | Means |
|---|---|---|
| `PASS` | 0 | live evidence observed, everything agreed |
| `FAILURE` | 1 | real evidence of a mismatch, or a static check failed |
| `UNOBSERVED` | 2 | origins not reachable; **no** parity claim in either direction |

This is the same UNKNOWN-is-not-a-value doctrine v24.0.1 applied to the canonical
decision and v24.0.9 applied to the pickup gate, applied to the release gate
itself. Three properties keep it honest:

- **Exit 2 is still non-zero**, so `deploy-backup-worker.yml`,
  `scripts/deploy-backup-worker.sh` and `m7-certify` all keep failing closed
  exactly as before. An unobserved gate is not a passed gate.
- **A static failure outranks unreachability.** The CSP and asset-exclusion
  checks need no network, so their failure is evidence regardless — reporting
  UNOBSERVED while `index.html` and `_headers` genuinely disagree would hide a
  source defect behind a network excuse.
- **Any HTTP response at all counts as observation**, including a 404 or a 500.
  Unreachability means *zero* responses and at least one transport error. An
  origin that is up and serving 404s is a failed deploy — the exact 2026-09-13
  defect — and must read as FAILURE, not as "couldn't look".
- **`--static-only` can never be UNOBSERVED.** It deliberately never attempts the
  live half, so every offline developer run stays a clean PASS.

**Tests.** `tests/unit/live-parity-runner.spec.mjs` (new, 10). LPR-05…LPR-10
**spawn the real verifier** and assert its real exit code rather than grepping
the source for the strings that would produce one: `--static-only` → 0;
`https://unreachable.invalid` (RFC 2606, deterministic offline) → 2; a local
server that 404s everything → 1; a local server that answers once and then
destroys every connection → 1. LPR-01…LPR-04 pin the workflow's shape.

Negative controls, all verified to fire: collapsing UNOBSERVED back into FAILURE
fails LPR-06/08; adding a `push:` trigger fails LPR-01; `contents: write` fails
LPR-02; and dropping the "a response arrived" record fails LPR-10.

That last one is worth keeping in the record. It did **not** fire against the
first two verdict tests — an all-404 origin produces no transport errors, so the
verdict was already correct there by a different route. Only the *partial* case
(answers once, then dies) actually depends on that record, and the control stayed
silent until a test for it existed. A negative control that does not fire is the
finding, not a formality.

`runVerifier()` is deliberately async: the synchronous form blocks this process's
event loop, so the in-process HTTP server in LPR-09/10 could never accept the
connection and the verifier timed out against a server that was, from its own
side, perfectly up — reporting UNOBSERVED and making a test-harness deadlock look
like a product defect.

**What this does not close.** Authenticated `/evaluate`, `/extract`,
backup/restore and token-rotation smokes are a separate gate needing a dedicated
non-published test identity, and are deliberately not in this workflow. A PASS
here is live evidence for the unauthenticated app/static/Worker-health sweep and
nothing more.

---

## v24.0.10 "Sixteen Pixels" — the root cause behind the mobile form-size fix

A cache generation so that the mobile form-size repair can actually reach an
installed client, plus the root-cause half of that repair. `DB_VERSION` stays
**15** and the Worker stays **v16** — neither's semantics changed.

**Two lanes fixed the same defect in parallel, and both halves are kept.** iOS
Safari zooms the viewport when a form control whose computed `font-size` is under
16px takes focus, which on the evaluator threw the driver out of the load they
were pricing.

- The **gpt lane** shipped the safety net (`b445ccc`, `styles.css`):
  `@media (max-width: 480px) { input, select, textarea { font-size: 16px !important } }`.
  It covers every control at mobile widths and needs no knowledge of which ones
  are wrong.
- This release removes the **root cause** for the two that actually were wrong.
  `#mwCurrency` (USD/CAD — not decorative on an app whose doctrine includes
  border loads) and `#mwModeSelector` carried inline `font-size:13px` in
  `index.html`. Inline styles beat a stylesheet rule without `!important`, so the
  net was load-bearing; with the source values corrected it no longer has to be,
  and the two fields are also correct above 480px, where the net does not apply.

They survived every prior pass because they sit behind the **"More Details"**
toggle. Collapsed, the evaluator exposes three fields — revenue, loaded,
deadhead — and all three were already ≥16px. The other 33, including origin,
destination, broker, the 7D dimension fields and the v24.0.9 pickup cutoff, were
not being measured.

**Why this is a version bump, and why it was the blocking half.** All
cache-busters were `?v=24.0.9` and `CACHE_NAME` is `freightlogic-${SW_VERSION}`.
`styles.css` carries no `?v=` of its own — it is cached under the
version-derived `CACHE_NAME` via the service worker's `CORE` list — so **neither**
lane's fix could reach an installed PWA while the generation stood still. The
gpt-lane CSS repair landed at `24.0.9` and was undeliverable for the same reason
the `index.html` change would have been. Every governed marker now moves together
to `24.0.10`; `scripts/verify-cloudflare-parity.mjs --static-only` is green,
all 13 CG assertions pass, and `workerVersion` stays `"16"`.

### Parallel-work collision, recorded rather than hidden

`.agents/LANES.md` on `main` records a **temporary operator-directed takeover of
`scripts/` and `tests/` by the gpt lane (2026-09-14)**. Both lanes were asked for
the same two 2026-09-14 inbox items and both built them, so this branch arrived
with four conflicts against `main`, including an **add/add** on
`tests/integration/six-width-layout.spec.mjs`.

Resolution: `main`'s versions were taken for every file in the lane gpt currently
holds — `scripts/verify-rollback.mjs`, `scripts/verify-cloudflare-parity.mjs`,
`tests/run-all.mjs` and the six-width spec. Their merged work stands; nothing was
overwritten to prefer this lane's copy. The claude-lane duplicates
(`tests/unit/rollback-verifier.spec.mjs` and `scripts/lib/release-candidate.mjs`)
were deleted rather than landed alongside, because two specs asserting the same
contract is how the two copies drift apart.

**One exact-file lane reassignment, operator-approved.** The generation bump
needs `scripts/verify-cloudflare-parity.mjs`, which the takeover row hands to
gpt — and CG-08 derives that file's `EXPECTED` block from `APP_VERSION`, so the
marker bump cannot be split from the app bump. Lanes CI correctly rejected the
cross-lane edit. `.agents/LANES.md` now carries an exact-file row giving that one
file to claude; it is narrower than the `scripts/` row and wins by longest-match,
so the rest of `scripts/` and all of `tests/` stay with gpt, and `workerVersion`
stays theirs to move. It returns with the `scripts/` row when the takeover ends.
Claimed under `claude-lanes-parity-file-reassign`, after reaping gpt's
`gpt-worker-v16-authority-hotfix` lock — stale since 09:40Z against a 17:13Z
reap, covering work already merged to `main` — and logging that reap in
`.agents/STATUS.md` per the protocol, rather than treating a grantless lock as
ignorable.

**Three findings from the discarded work are worth keeping even though the code
is not**, and are offered to the gpt lane through `/.agents/inbox/` rather than
forced across the lane boundary:

1. **`document.documentElement.scrollWidth` cannot detect overflow in this app.**
   `styles.css` sets `body { overflow-x: hidden }`, so the page never reports a
   scrollWidth wider than the viewport however far content spills. Injecting
   `.app { min-width: 900px !important }` left a scrollWidth-based assertion
   green. The surviving spec's `innerWidth === width` assertion is the one doing
   the real work there; its `rootScrollWidth`/`bodyScrollWidth` checks cannot
   fail.
2. **Under mobile emulation the layout viewport expands** to fit content wider
   than the device — `window.innerWidth` reported 900 at a 320px device — so any
   geometry compared against `innerWidth` is compared against a viewport that has
   already grown to accommodate the overflow. Measure against the device width the
   test set.
3. **A `@media (pointer: coarse)` block raises several controls to 44px.** A spec
   that boots a desktop context asserts touch-target minimums against rules that
   never applied to it.

Also recorded: opening `FreightLogic_v18` from a test with no explicit version
creates it **at version 1**, so `app.js`'s `if (old < 1)` block — the only place
`trips`, `expenses` and `fuel` are created — is skipped on the upgrade to 15. The
database comes up at v15 with those three stores missing and every other one
present. That is not reachable in production (a real v1 database is created *by*
that block) and `app.js` was deliberately not changed for it, but it will bite any
future spec that seeds settings directly and then writes a trip.

### Agent relay protocol

`.agents/RELAY_PROTOCOL.md` (new) records the owner's standing instruction that
work alternates between the two agents at a usage limit: whichever agent stops
because it is out of usage hands off, and the other picks the in-flight work up
without waiting to be asked. It is explicit that a handover changes **who is
typing and nothing else** — lane ownership, the `app.js`/SHARED lock protocol,
commit prefixes, the full-suite gate and release-marker discipline all survive it
unchanged.

This release is itself the argument for that document: both lanes spent a session
building the same two deliverables because neither knew the other had started.

---

## Worker v17 "Same Millisecond" — the backup key that overwrote the backup before it

Worker **v16 → v17**. `DB_VERSION` stays **15** and the app/PWA stays **24.0.10** —
no app source changed, so no cache generation moves.

**The defect.** A backup or delta key is
`user:<userId>:device:<id>:(backup|delta):<ts>`, and `<ts>` was
`new Date().toISOString()` — millisecond precision. KV keys are unique, so two
writes landing in the same millisecond produced the **same key**: the second
`put()` silently overwrote the first, the pointer recorded one key where two
writes had happened, and one backup or delta was gone. Every gate still reported
success, because from the Worker's point of view both requests returned `200`.

That is data loss in the one component whose entire purpose is disaster
recovery, and it is reachable by ordinary use: `cloudPushBackup()` followed
immediately by a delta, or two deltas back to back, land inside one millisecond
on any machine fast enough.

**How it surfaced.** `tests/unit/worker-pointer-race.spec.mjs` (WPR-01/WPR-02,
merged with the v16 pointer-race fix in PR #190) began failing on `main` —
**451 passed, 2 failed across 49 spec files** — when run on a host fast enough to
put both of its writes in one millisecond. CI had been passing it by timing luck.
The spec was right and the Worker was wrong; nothing about the spec was relaxed.

**The fix.** `nextBackupTs()` — a module-scope monotonic clock that never returns
a millisecond it has already returned in this isolate. Both write sites use it.

- The key **shape** is unchanged (`YYYY-MM-DDTHH-MM-SS-mmmZ`), which matters
  twice over: `deltaTsFromKey()` parses it back into a real ISO instant for the
  client, and `getPtr()`'s plain lexical `sort()` is only chronological because
  the transform is monotonic for same-length strings. A random suffix would have
  broken both, so there deliberately is not one.
- Existing keys, pointers and the client's chronological restore are untouched.
- Cross-isolate same-millisecond writes from one device remain theoretically
  possible. They are not made worse: the pointer append is already idempotent
  (`ptr.keys.includes(key)`), and a client serializes its own pushes. The
  realistic, deterministic, single-isolate case is what is closed here.

**Tests.** WPR-03 (new) freezes `Date.now()` and drives four deltas through the
real Worker inside one frozen millisecond, asserting four unique keys, lexical
order still equal to chronological order, all four payloads readable, and the key
shape still parseable. This is the assertion that cannot pass by timing luck —
WPR-01/02 depend on the host being fast, WPR-03 depends on nothing.

Negative control, verified to fire: reverting `nextBackupTs()` to
`new Date().toISOString()` fails WPR-03 while WPR-01/02 **pass** — which is
precisely the original defect's signature and the reason it survived CI.

**Version markers.** Only two Worker markers exist and both moved: the
`cloud-backup-worker.js` header and `GET /health`'s reported `version`.
`scripts/verify-cloudflare-parity.mjs`'s `workerVersion` pin moved to `"17"`.
Everything else already derives the number (`scripts/deploy-backup-worker.sh`,
both deploy/verify workflows, `tests/unit/worker-canonical-absence.spec.mjs`).
`tests/unit/cache-generation.spec.mjs` CG-09 **stopped pinning a literal**: it now
reads the generation out of `cloud-backup-worker.js` and asserts the header, the
`/health` response and the parity gate all name the same number — the invariant
rather than the value, so a future Worker bump needs no edit here.

**DEPLOYED 2026-09-14T19:05Z.** Run `34884719806` deployed v17 from `main` @ `d58bfbe`
through the `DEPLOY`-confirmed dispatch of
`.github/workflows/deploy-backup-worker.yml`. Verified three independent ways:
the workflow's own post-deploy checks, the auto-triggered authenticated smoke
(run `34884786623`, PASS against the deployed Worker), and a live parity
re-dispatch (run `34885000070`) reporting
`Worker reports v17 — {"ok":true,"version":"17"}` with all 23 runtime assets
loading and none served as HTML.

---

## B5 rollback gate — derived, not pinned

Tooling only. No shipped file changed.

`scripts/verify-rollback.mjs` hardcoded its candidate SHA
(`5446b097…`), its app generation (`24.0.9`) and its Worker generation (`16`). At
`24.0.10` it therefore reported a clean **PASS** while describing a superseded
candidate — a green gate for the wrong release, which is the same failure class as
the stale `?v=` markers, the stale parity checklist and the stale
`midwest-stack-config.json` `appTarget` this file already records three times over.
The gate needed a hand edit every release, and the release it was meant to certify
is exactly when nobody remembers to make it.

Every fact is now derived at run time:

- the candidate is `HEAD`, and its generation is read from `app.js`;
- the Worker generation is read from `cloud-backup-worker.js`;
- the **previous** generation is found from history — the commit that introduced
  the current `APP_VERSION` (`git log -S`), then its first parent — with a walk of
  `app.js` history as a fallback if that marker ever lands inside a merge.

The safety-gate comparison is generalized with it. It previously hardcoded
`checkPickupFeasibility` and **failed** if the previous generation also contained
it — which is what a same-feature adjacent release always looks like. It now checks
a named list (`checkPickupFeasibility`, `checkVanFit`, `isDeadZoneEligible`,
`knownNum`), reports each one missing from the predecessor as proof that rolling
back is unsafe, and when the predecessor retains all of them says so honestly:
**no regression is proven, and that is not an approval.** No path through this
script can produce a safe rollback target; the policy stays FIX FORWARD.

`tests/unit/rollback-verifier-current.spec.mjs` was rewritten to match (RBV-01…06).
It asserted the pinned literals before, so it needed the same per-release edit and
would have gone stale in lockstep with the thing it guards. RBV-01 now fails if a
40-hex SHA or an `EXPECTED_*_VERSION` literal is reintroduced into the code; the
rest assert the derivation against the tree the spec is actually running on, so it
stays correct at the next release with no edit.

Negative controls, all verified to fire: a bogus identifier in `SAFETY_INVARIANTS`
exits 1; reintroducing `EXPECTED_APP_VERSION = '24.0.10'` fails RBV-01; pointing
the parity-alignment check at a different Worker generation fails the gate.

---

## Completion sweep 2026-09-14 — live gates observed

Three certification gates that had stood open as **NOT RUN / UNOBSERVED** were
actually run in this session, from GitHub-hosted runners (the only environment in
this project that can reach the deployed origins).

| Gate | Result | Evidence |
|---|---|---|
| All-asset live Cloudflare parity | **PASS** | run `34882621810`, `workflow_dispatch` on `main` @ `10430bf` |
| Authenticated Worker contracts | **PASS** | run `34882777324`, 21 passed / 0 failed against the deployed Worker |
| Six-width visual acceptance (320/375/390/393/430/440, both themes) | **PASS** | `integration/six-width-layout.spec.mjs`, 2/0 |

The parity run is worth recording in full, because the **push**-triggered run on the
same SHA (`34874397592`) had **failed** eleven seconds after the v24.0.10 merge:
`sw-bridge` import, service-worker precache and manifest name all still read
`24.0.9` because Cloudflare had not finished deploying yet. The re-dispatch is the
first observation of v24.0.10 actually being served. Both runs agree that all **23**
declared runtime assets load and none is served as HTML, and that the deployed
Worker reports v16.

A push-triggered parity run that fires immediately after a merge will keep racing
the Cloudflare deploy this way. Its FAILURE is real evidence about the origin *at
that instant* and must not be dismissed, but it is not evidence about the release —
re-dispatch and record the later run.

The authenticated run seeds an expiring synthetic driver identity in production KV,
exercises full backup, delta write, `GET /backup/delta` retention/ordering/gap
counters, `GET /list` scoping, `GET /status`, malformed-token and tokenless denial,
and in-place token rotation, then cleans up. No operator data and no real driver
credential is involved.

**Still open, and genuinely not reachable from here:**

- **Private-history reconciliation.** The recovered August 27 M6 bundle is not in
  the repository and not mounted in this session. Not reconstructable from
  summaries — that is the whole point of the gate.
- **Physical iPhone Safari + installed-PWA checks**, including the pickup-feasibility
  surface. Operator-only, and `FIELD_TEST_CHECKLIST.md` remains the instrument.
*(Worker v17 deployment was the third open item here and is now closed — see the
v17 section above.)*

Full suite after this sweep, run locally against real headless Chromium:
**457 passed, 0 failed across 49 spec files** — up from 451/2 on `main`, which is
the W-01 repair (+1 new assertion, 2 restored) plus the six rewritten B5
assertions. Nothing was skipped, quarantined or weakened.

---

## Completion sweep, second round — the last two gates, and one lane

Tooling, governance and documentation. No shipped file changed: `APP_VERSION`
and `SW_VERSION` stay `24.0.10`, `DB_VERSION` 15, Worker v17.

### The repository is one lane now

`.agents/LANES.md` had a 2026-09-14 paragraph handing `.github/`, `scripts/`,
`tests/` and `cloud-backup-worker.js` to the gpt lane "while Claude is idle,"
ending "after Issue #119 is closed **or** when the takeover is explicitly
ended." The operator ended it explicitly, and every non-`SHARED` path is now
`claude`. The four exact-file rows that had been carved out of the takeover are
deleted rather than kept — their parent rows own them again, and a redundant
narrower row is just another thing to go stale.

**What did not change is the more important half.** `SHARED` is still `SHARED`:
`app.js` still needs `lock/app-js` and a full suite, and so do `index.html`,
`service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json` and the
protocol surface. That serialization was never about two *agents* — it is a
1.1MB single-IIFE file where two concurrent editors lose work whoever they are,
and release-critical files where a silent concurrent edit ships a broken
generation. Commit-prefix discipline, the full-suite gate and release-marker
discipline are untouched. A path with no row still fails closed, and
`tests/unit/lane-guard.spec.mjs` still passes 19/19 against the rewritten map.

Restoring the split is a pure revert of the consolidation. Nothing in
`scripts/lane-guard.mjs` encodes a two-agent assumption, and it reads the table
rather than a generated copy, so the split can come back without touching code.

### Gate 2 — production service-worker / offline behaviour

The completion plan's second blocking item asked to "prove the exact candidate,
including the formerly missing admin runtime asset, survives normal
update/reload/offline behavior without destructive clearing." Nothing in the
repository could do that: `verify-cloudflare-parity.mjs` fetches each declared
asset and asserts status and content, which proves **delivery**, not what a
browser does after installing the deployed worker.

`scripts/verify-production-sw.mjs` + `.github/workflows/verify-production-sw.yml`
(read-only, no secrets, manual dispatch plus every push to `main`) close it.
Against production, in order: the worker installs and activates; the page is
controlled after one reload; `admin-driver-ui.js` and `midwest-stack-authority.js`
are injected **and actually fetchable as script**; all 23 declared assets are in
the precache under the current generation; the driver shell renders with no
uncaught errors; with the network verifiably down a subresource miss returns
`504 text/plain` rather than the HTML shell while a drifted `?v=` on a known
asset self-heals; the cached shell is a complete current-generation document;
and exactly one generation cache survives.

**Three things this gate had to learn the hard way, all worth keeping:**

1. **Offline emulation lapses across a navigation.** `context.setOffline()` is
   documented as unreliable for service-worker fetches, and CDP
   `Network.emulateNetworkConditions` is scoped to the target it is sent to — a
   service worker is a separate target, and it *restarts* on navigation. The
   same uncached path returned the worker's offline marker before a reload and a
   live origin 404 immediately after one. Re-applying the emulation and
   re-attaching a fresh CDP session were both tried; neither carries over. So
   every offline claim is re-proved at the moment it is made, and the one claim
   that cannot be — the offline **navigation** itself — is stated as not
   observed rather than implied. That is checklist item A4, on a device.
2. **The offline-effectiveness probe had to catch the defect too.** The probe
   reads the worker's own `X-FL-Offline: 1` marker, which a worker carrying the
   pre-v24.0.4 defect never emits — so a *broken* worker read as "offline
   emulation did not take" and skipped the very check that catches it. Observed,
   not theorised: reintroducing the defect in a mirrored origin turned the gate
   UNOBSERVED instead of FAILURE. The probe now also inspects the body: a 200
   HTML answer for a path that has never existed **is** the masquerade, in any
   network state.
3. **`freightlogic-share-v2` is not a stale generation.** The first
   single-generation assertion counted every `freightlogic-*` cache and failed
   on SHARE_CACHE, which is supposed to be there. Only version-shaped names are
   generations.

Negative controls, all verified to fire: an unreachable origin → UNOBSERVED
(exit 2); an origin with `admin-driver-ui.js` deleted → FAILURE on two
independent axes (injected-but-404, and missing from the precache), reproducing
the 2026-09-13 defect exactly; a mirrored origin with the pre-v24.0.4
`offlineFailure` reverted to the app shell → FAILURE on the masquerade. A
healthy origin still passes 16/16.

`tests/unit/production-sw-gate.spec.mjs` (7, new) pins the workflow's authority
(read-only, no secrets, no deploy path, dispatch input never reaching the shell),
the three-verdict semantics, and each assertion that exists because a real defect
once got past a green check.

### The certification record now matches the candidate

`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md` supersedes the
2026-09-14 addendum and is the certification authority. Five of that addendum's
seven blocking items are closed by actual observed runs (live all-asset parity,
production service worker, authenticated Worker authority + backup, six-width
visual acceptance, rollback/fix-forward), plus W-01 — a data-loss defect nobody
had listed, because nobody knew it was there.

`FIELD_TEST_CHECKLIST.md` was **two generations stale**, reading `24.0.9` /
Worker `v15` while production served `24.0.10` / `v17`. That is not cosmetic: a
tester would have confirmed the wrong build and recorded a PASS for a candidate
that is not the one being certified. It now carries the current generations, its
B-section records what was actually observed, it gained **B6** for the new
production service-worker gate, and it deliberately **no longer carries its own
copy of the candidate SHA** — it reads it from the certification document, which
is the same anti-drift move as the derived B5 gate.

`scripts/m7-certify.mjs`'s live-gate list said `PENDING` with a local command,
which is still true of any local invocation and is why it stays `PENDING` — a
local run observes nothing live, and saying otherwise is the inference that
runner exists to refuse. It now names the GitHub workflow for each, and includes
the new production service-worker gate.

### Still HOLD, and now precisely two things

- **Private-history reconciliation.** The five raw M6 files are not in this
  repository and have not been mounted in any session. The instrument is
  committed and ready; only the data is missing. Reconstructing the bundle from
  summaries would test the summary, not the source, which is the one thing this
  gate exists to catch.
- **Physical iPhone A1-A10.** Safe-area insets, the software keyboard,
  background GPS across a real lock/unlock, iOS permission revocation mid-trip,
  installed-PWA update behaviour, and a genuine Airplane Mode round trip —
  including the offline navigation gate 2 declines to claim.

Everything else that could be observed from an automated environment has been,
on the live production origin, at this exact generation.

Full suite: **464 passed, 0 failed across 50 spec files** (from 457/49).

---

## v24.0.11 "Exact Economics" — the OMEGA continuation

Landed as `fb408a0` (PR #200) under a held `lock/app-js`. `DB_VERSION` stays **15**
and the Worker stays **v17** — neither's semantics changed.

**What the release itself did.** Unknown mileage now suppresses whole-period RPM and
all-miles rather than summing an unstated deadhead as a verified zero, and suppresses
per-load score and counter-offer the same way. `deriveUnifiedEconomics()` validates
mileage and cost inputs and compares **unrounded** True RPM, leaving rounding to
display, so a just-below-floor RPM can no longer round up across a protective
threshold. Density classification uses complete city identity with supported state
qualifiers, so Calgary stops reading as Gary and Daytona Beach as Dayton. The weekly
report's temporal-dead-zone crash and its mismatched week-key inverse are repaired.
`scripts/verify-release-generation.mjs` joins the suite: agreement among version
markers is insufficient if deployed bytes changed under a reused generation.

### The settings cache made an absent MPG look like a verified zero

The continuation was correct and still failed CI at **455 passed / 25 failed**. All
25 came from one **pre-existing** defect it merely exposed.

`getSetting(key, fallback)` cached `fallback` under `key` when the record was
**absent**, so the *first* reader's default silently became the app-wide value for
every later reader passing a different one. Home's KPI card reads
`getSetting('vehicleMpg', 0)` on every render and runs before the evaluator's
`getSetting('vehicleMpg', MW.mpg)`. For an operator who had simply never entered an
MPG, that cached a `0` nobody supplied — and canonical economics is **right** to
refuse `mpg <= 0`. An ordinary, complete, perfectly gradeable load therefore rendered
**no grade at all**. That is a production defect, not a test artefact, and the
validation was not relaxed to clear it. `getSetting` now returns the caller's own
fallback and caches only what the store actually held.

That single fix accounted for 22 of the 25: `m3-real-evidence-wiring` (11),
`dz-exit-grade-cap` (4), `dz-gate-parity` (3), `pickup-feasibility` (3),
`van-fit-precheck` (1) and `V2404-07` (1) were the same blanked grade seen from six
directions. The last three were two invalid assertions in the new spec, corrected in
the spec: `OI-06` passed the whole CSV **string** to `parseCSVLines(lines)`, which
takes an **array of lines**, so `for...of` iterated *characters* and every parsed row
was one character wide; `OI-11` asserted `naLookupMarket('Boston')`, and Boston is in
no market table.

**Live parity is OBSERVED at this generation**, not inferred: run `34929870640` on
`fb408a0` reports index/`app.js`/`voice-load.js`/`sw-bridge.js`/`modern-shell.js`/
service worker/manifest all at `24.0.11`, Worker `/health` v17, all **23** declared
runtime assets loading and none served as HTML, `VERDICT: PASS`. The production
service-worker gate (`34929870633`) and the suite (`34929870661`) are green on the
same SHA. Full suite at `fb408a0`: **481 passed, 0 failed across 52 spec files**.

---

## v24.0.12 "Delivery Generation" — a test that passed with the defect reinstated

**No runtime behaviour changes.** `app.js` gains exactly two test-only exports;
`DB_VERSION` stays **15** and the Worker stays **v17**.

### OI-11 passed with the defect reinstated

Worth recording on its own, because it is the failure mode this suite exists to
catch. After `OI-11` was repaired by dropping Boston, it asserted four names —
Dayton, Edmonton, Gary, Calgary — through `naLookupMarket`. **Every one of them still
resolves under the OLD, defective normalizer**, so the test guarding the
market-identity fix could not fail on it. Verified by negative control: reverting
*both* separator fixes in `usaNormCity`/`caNormCity` left the whole spec at **13
passed / 0 failed**.

Two independent routes around it. `Dayton` normalizes through `usaNormCity`, where no
US state is spelled `on`, so the Canadian normalizer's bug never touches it.
`Edmonton` → `'edmont'` under the old rule, and the fuzzy pass accepts
`key.startsWith(norm)`, so `'edmonton'.startsWith('edmont')` still matches. A
lookup-based assertion can only reach names that are *in* a table, and those are
exactly the names that survive the bug.

`OI-11` now asserts `usaNormCity`/`caNormCity` **directly** — the unit the separator
rule actually lives in — over `Boston` and `Tacoma` (in no table; `'bost'` and
`'taco'` under the old rule) alongside the four table names, and separately proves
the rule was **narrowed rather than disabled** by requiring a genuinely
separator-qualified state or province to still be stripped, by comma and by space.
Both normalizers are exposed on `__FL_TESTS` for this. `OI-14` adds the end-to-end
half the seam-level `OI-13` does not cover: delete `vehicleMpg`, reload to empty the
cache, render Home, then evaluate an ordinary load and require a real letter grade —
the actual production sequence that cost 22 assertions.

Negative controls, all verified to fire: reverting either normalizer separator fix
fails `OI-11` (it did **not** before this change); reverting the `getSetting` repair
fails `OI-13` and `OI-14`.

### Two markers the release left stale

- `midwest-stack-config.json` `appTarget` read `FreightLogic v24.0.10`. This is
  checklist **item 15**, which item 16 has claimed since v24.0.3 is machine-checked.
  It was not — nothing read the field; the parity script checks only that the service
  worker *caches* the file, which a stale `appTarget` passes happily. So it drifted
  again, one release after being written down as covered. **`CG-14`** now asserts it
  against `APP_VERSION`, and item 16's wording is corrected.
- `CLAUDE.md` itself shipped `fb408a0` with all three governed locations still at
  `24.0.10` and no release section at all — checklist item 10, and the fourth time
  this file has recorded that omission about itself. This section is that correction.

### Why an inert change still moved the generation

The two `__FL_TESTS` exports are gated behind `window.__FL_TESTS_ENABLED` and do
nothing in production — and they still required a generation bump, because they change
`app.js`'s deployed **bytes**. `scripts/verify-release-generation.mjs` RG-03 caught
this commit doing exactly that under a reused `24.0.11`, which is the gate working as
designed: `CACHE_NAME` is `freightlogic-${SW_VERSION}` and the `?v=` query is the only
other identity a child asset carries, so an installed client holding the `24.0.11`
shell would never fetch the changed file. "Inert in production" is an argument about
behaviour, not about delivery, and the generation rule is about delivery. This is the
v24.0.3 lesson applied rather than relearned, and every governed marker moved together.

### Deployment status — DEPLOYED and OBSERVED LIVE 2026-09-15

This section shipped reading *"v24.0.12 is source-only. It has not been deployed and
has not been observed live."* That was accurate when written and stopped being accurate
about ninety minutes later, when the re-dispatch it itself called for came back PASS.
It is corrected here rather than quietly overwritten, because a release section that
keeps a superseded claim is the drift class this file records against itself four times
over.

Production serves **24.0.12**. Two independent live gates, both `workflow_dispatch` on
`main` @ `4f2daf2`:

- **Live all-asset parity** — run `34939229143`, `VERDICT: PASS`. `sw-bridge` imports
  `modern-shell.js` v24.0.12 and the worker precaches it at that generation, the
  manifest name is `FreightLogic v24.0.12`, Worker `/health` returns
  `{"ok":true,"version":"17"}`, **all 23** declared runtime assets load, and none is
  served as HTML.
- **Production service worker** — run `34939417958`, **16 checks / 0 failures**,
  `VERDICT: PASS`. The precache is `freightlogic-24.0.12` carrying all 23 assets, the
  cached shell requests `?v=24.0.12`, `admin-driver-ui.js` and
  `midwest-stack-authority.js` are injected **and fetchable as script** (HTTP 200,
  `text/javascript`), an offline subresource miss is `504 text/plain` rather than the
  HTML shell, a drifted `?v=` self-heals, and exactly one generation cache survives.

**The push-race recurred exactly as predicted and must not be cited.** Both workflows
also fired on the push at 06:51Z and both FAILED — `34938834929` and `34938834924` —
about five minutes before the dispatched runs passed. They observed the previous
generation still being served while Cloudflare finished deploying. That is real
evidence about the origin at that instant and is not evidence about the release.

The certification authority for this candidate is
`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-15.md`.

Full suite: **483 passed, 0 failed across 52 spec files** — `fb408a0`'s 481 plus
`OI-14` and `CG-14`.

**Still HOLD.** Physical iPhone A1–A10 and M6 raw-data certification remain OPEN, and
nothing in this release touches either.

---

## Workflow authority — the prohibition that was upheld by a YAML error

Tooling and CI metadata only. No shipped file changed, so no version marker moved:
`APP_VERSION` and `SW_VERSION` stay `24.0.12`, `DB_VERSION` 15, Worker v17.

**The finding.** This file has recorded since the v24.1 section that the v24.0.1
comment-triggered, branch-pushing CI repair machinery *"was removed on purpose and
must not return"*, and `.github/workflows/deploy-backup-worker.yml` repeats the rule
in its own header. Neither sentence was enforced by anything.

On 2026-09-15 a workflow appeared on a side branch that triggered **on push**, took
**`permissions: contents: write`**, auto-applied a 608-line patch advancing
`APP_VERSION`, `DB_VERSION` 15 → 16 and the Worker to v18, and finished with
`git push origin HEAD:<its own branch>`. It never ran — it failed to start with zero
jobs — so nothing was auto-committed. **The prohibition held because the thing
violating it happened to be broken.** That is not a prohibition; it is luck, and it
is the same shape as `OI-11` passing with the defect reinstated (v24.0.12) and
checklist item 15 being documented as machine-checked while nothing read the field.

**The gate.** `tests/unit/workflow-authority.spec.mjs` (new, 6 assertions, wired into
`tests/run-all.mjs`) globs **every** file in `.github/workflows/` and fails if any one:

- **WFA-01** declares no explicit top-level `permissions:` block — an absent block
  inherits the repository default, which may be write;
- **WFA-02** requests write authority (`contents: write`, `write-all`, or a write on
  `packages`/`id-token`/`pull-requests`/`issues`/`actions`);
- **WFA-03** performs a repository write — `git push`, `git commit`, `git tag`,
  `peter-evans/create-pull-request`, `stefanzweifel/git-auto-commit-action`,
  `ad-m/github-push-action`, `gh pr create|merge`, or `gh api -X POST|PUT|PATCH|DELETE`.
  CI may verify and it may deploy; it may never author a commit;
- **WFA-04** triggers on `issue_comment`, `repository_dispatch` or
  `pull_request_target`. `workflow_run` stays allowed — it is already gated on a
  first-party workflow and `verify-authenticated-worker.yml` depends on it.

**WFA-05** keeps `deploy-backup-worker.yml` as the one workflow that changes the
world, and keeps it gated: manual dispatch only, never `push` or `schedule`, still
requiring the typed `DEPLOY`, and holding no git write authority — it pushes to
Cloudflare, not to this repository.

It applies **by glob**, so a new workflow is covered the moment it lands rather than
when someone remembers to add it to a list. Every check reads executable lines only,
with comments stripped: scrubbing prose would let a workflow pass by deleting the
paragraph explaining why it is safe.

**WFA-06 is the assertion that keeps the rest honest.** The four rules are pure
functions over workflow text, and WFA-06 runs them against a reduced copy of that
exact offending workflow and requires each one to reject it — so the negative control
is a permanent test rather than something checked once by hand and then trusted. It
also asserts the inverse in both directions: a real compliant workflow
(`verify-live-parity.yml`) must not be flagged, and a *comment describing* the
prohibition must not read as violating it. A guard that fires on its own
documentation gets disabled, and a guard nobody has watched fail is the defect this
suite exists to catch.

**It found a real pre-existing gap on its first run**, which is the argument for it.
`tests.yml` and `lanes.yml` carried **no `permissions:` block at all** and were
inheriting the repository default. Both now declare `contents: read`; neither uploads
artifacts nor calls the GitHub API, so this is least privilege with no behaviour
change. The offending side-branch workflow was not the only exposure, merely the
visible one.

**Not in scope, deliberately.** This gate governs what reaches `main`. A workflow on
a side branch that pushes to *itself* is outside any PR check by construction — the
gate stops such machinery landing, it cannot stop it running where it already sits.
Removing it from that branch is the owning lane's, requested through `/.agents/inbox/`
rather than edited across lanes.

Full suite: **489 passed, 0 failed across 53 spec files** (from 483/52).

---

## iOS 27 / Safari 27 assessment — the device gate is A1-A11

Documentation and tooling only. No shipped file changed, so no version marker moved:
`APP_VERSION` and `SW_VERSION` stay `24.0.12`, `DB_VERSION` 15, Worker v17. The
runtime candidate is still `4f2daf2`.

iOS 27 and Safari 27 shipped 2026-09-14, one day before v24.0.12's live gates were
observed. `docs/IOS27_SAFARI27_ASSESSMENT_2026-09-15.md` is the full assessment,
checked against primary WebKit/Apple sources **and** against this repository's code.
Its outcomes, so they are not re-litigated:

| Safari 27 item | Outcome |
|---|---|
| Customizable `<select>` (`appearance: base-select`) | **Adopt**, in flight as PR #206 (gpt lane, `styles.css`). 29 selects, not 16: 13 are built inside `app.js` via `innerHTML`, so selectors must be structural. The v24.0.10 ≥16px rule stays load-bearing. |
| Scroll anchoring | **Free.** `overflow-anchor` appears nowhere; nothing to add. |
| Service Worker Static Routing | **NOT YET APPLICABLE.** The fetch handler already returns early for non-GET and cross-origin, so every class a static route would target already bypasses the worker; a rejected `addRoutes` inside `install` is an install-abort path and the only gate that would catch it runs against production. |
| ReadableStream improvements | **Available, no code.** Every large-payload path ends at an API that needs the whole buffer (SheetJS, `checksumFull`, `crypto.subtle`, Blob receipts). |
| Background Sync | **Still absent.** The circulating claim that iOS 27 adds it is false; `cloudBackupPaused()` / `openCloudReconnect()` remain the correct design. |

**The finding that widened the gate.** Safari 27 carries 525 fixes, 30 of them SVG, and
WebKit frames the release as existing features behaving *differently — more
correctly*. FreightLogic renders hand-built SVG in the F31 Earnings Trends chart and the
driver tab-bar icons, and no gate in this repository asserts pixels. So
`FIELD_TEST_CHECKLIST.md` gained **A11** (chart, tab-bar icons, select zoom-on-focus,
scroll anchoring, persisted-storage grant, cloud-backup paused banner), and the
physical-iPhone gate is **A1-A11** everywhere: the certification state document, the
field checklist's section-B and section-D cross-references, the parity checklist, and
`scripts/m7-certify.mjs`'s physical-device list. Earlier sections of this file that say
A1-A10 were accurate when written and are left as history.

**PR #206 cannot land alone, by design.** It changes `styles.css`, a declared runtime
asset, with no generation bump, and `RG-03` correctly fails it. Every marker file for the
bump is SHARED or claude-owned. The gpt lane's disposition
(`gpt-handoff-response-2026-09-15.md` on `agent-coordination`) is **one** coordinated
generation together with its full-repair pass, which as of this writing holds
`lock/app-js` over every SHARED runtime file. Do not land a separate v24.0.13 for the
CSS alone; two lanes must not each claim a generation.

**Reported, not fixed — one residue of the gpt money-integrity packet.**
`gpt-omega-infinity-money-integrity-2026-09-15.md` named four secondary surfaces
where an unknown deadhead still entered a denominator as zero. v24.0.11 closed
three: `exportTripsCSV()` now reads `tripAllMiles()` (OI-06), `computeLoadScore()`
returns `available: false` (OI-04), and `renderLiveScore()` defers to it. The fourth,
`tripRow()` (`app.js`, `function tripRow`), still computes
`Number(t.loadedMiles||0) + Number(t.emptyMiles||0)` and renders the result as a
`$/mi` figure with a letter grade chip, in both compact and full modes. A trip whose
deadhead was never stated therefore shows a loaded-only RPM dressed as True RPM on the
Home recent-trips list and the Trips page. No `OI-*` assertion covers `tripRow`. It is
recorded here rather than fixed because `app.js` is under the gpt lane's
`lock/app-js` for the full-repair pass; it belongs in that pass or the next held lock,
with a regression that renders a trip with `emptyMiles: null` and asserts `—` / `?`
rather than a number, alongside an explicit-zero control.

**Still HOLD.** Physical iPhone A1-A11 and M6 raw-data certification remain OPEN, and
nothing here touches either.

---

## v24.0.13 "Zero-Token Onboarding" — the credential that used to live in an inbox

Worker **v17 → v18**. `DB_VERSION` stays **15**. Onboarding a driver no longer
involves a token anybody can see, hold, or forward.

**The defect this closes is not a bug, it is the design.** The only way to onboard a
driver was `POST /admin/users`, which returns a permanent `flk_` bearer token — and
that token then had to reach the driver's phone, which meant a human sent it. Both
prior surfaces did exactly that: `cloudAdminCreateUser()` and
`cloudAdminRotateToken()` each ended by rendering the token into a `#token=` setup
link for the owner to share, and `admin-driver-ui.js` did the same independently. So
a live credential came to rest in an inbox or an iMessage thread and stayed there,
readable by anyone who later picked up either device, long after that driver had been
onboarded or even revoked. Rotating did not help: it produced a second permanent
token to send the same way.

**The replacement.** `POST /admin/invites` mints a 24-character claim code — 15 random
bytes, 120 bits, base32 with `0`/`1`/`8` omitted so it cannot be misread off a phone
screen. Only its SHA-256 hash is stored, under `inv:<hash>`, exactly as driver tokens
are stored as `tokh:<hash>`; a KV dump yields no usable invite. `POST /claim` redeems
it for a token that is handed straight to the claiming device. The code rides the URL
**fragment** (`#i=`), which browsers never send to an origin, so it cannot reach a
Worker log, an access log, or a `Referer` header.

Three properties are load-bearing:

1. **`/claim` is unauthenticated, and sits above the `X-Backup-Token` gate.** That is
   not an oversight — it is how a device acquires its first token, so guarding it with
   the credential it issues would be circular. What stands in for authentication is the
   120-bit code plus a 10/hr per-IP limit, checked *before* the code is parsed.
   `WIC-15` fails if the handler is ever moved below the gate.
2. **The fragment is stripped before the first `await`.** `flCaptureClaimCode()` is
   synchronous end to end and runs on the first line of boot. An `await` yields to the
   event loop, and anything reading `location.href` in between would capture a live
   invite. `ZTO-06` proves the ordering by reading the page URL *inside* the
   intercepted `/claim` handler — checking afterwards would pass even on late cleanup.
3. **Identity survives every path that issues a new token.** Backups are keyed
   `user:<userId>:device:<id>:...`, so minting a second `userId` orphans every backup
   the driver has made — the data stays in KV with nothing able to address it again.
   That is the failure v15's in-place rotation was added to prevent, and there are now
   two ways to reintroduce it, both closed:
   - **Re-claim** (same code, up to `maxClaims` = 3) returns the same account with a
     fresh token and revokes the previous one. This is what makes the iOS Safari →
     Home Screen storage split recoverable: the driver opens the same link again from
     the installed app. Re-putting the invite re-derives the **original** expiry,
     because Cloudflare resets a TTL on every put and a repeatedly-claimed invite
     would otherwise never expire at all (`WIC-09`).
   - **Re-invite** (a new code for an existing driver) passes `userId` to
     `POST /admin/invites`, which binds the invite to that account so claiming it
     takes the re-claim branch. **This was a real defect found in review, not a
     hypothetical**: the endpoint as first written always set `userId: null`, so the
     Drivers list's Re-invite button would have minted a second account and orphaned
     the driver's history while appearing to work. `WIC-16` gives the driver real
     backup history, re-invites, and asserts the new token reaches it and that the
     admin listing still shows **one** driver; reverting the binding fails it.
     A revoked driver cannot be re-invited (409) and an unknown one is 404.

**Admin access is entered once and is never shown again.** It is verified with
`GET /admin/users` and persisted **only on a 200** — a rejected token leaves nothing
on disk. What is stored is AES-GCM ciphertext keyed by PBKDF2 over the device PIN
(`cloudEncrypt`, the same primitive cloud backups use). The decrypted value still
lives only in `sessionStorage` and still dies with the tab, so the Credential Storage
Rules above are unchanged in substance: what is new is a ciphertext at rest that is
not a credential unless you also know the PIN.

**Admin access therefore requires App Lock**, and that is deliberate rather than
incidental: with no PIN there is no key, and the only way to persist would be in the
clear — which is the thing the rule prohibits. The panel says so instead of silently
falling back.

**Three removals, one of which was a live shadowing bug.** `cloudAdminCreateUser()`,
`cloudAdminShare()`, `cloudAdminRotateToken()` and the token-based
`cloudAdminShowInvite()` are gone; leaving them would have kept a second path that
still puts a permanent credential in an inbox, making the feature opt-in rather than
true. Removing the old `cloudAdminShowInvite()` also fixed a defect this change would
otherwise have shipped: **two top-level declarations of that name stood in the same
IIFE scope**, so hoisting made the later, token-based one win at *every* call site —
including the new invite flow, which would have silently rendered a token instead of a
claim link. That is precisely the `getBrokerIntel()` defect v23.8.3 found and this file
records. It was caught by reading the declarations, not by observing the symptom.
`admin-driver-ui.js` now stands down explicitly (`ADMIN_UI_STANDS_DOWN`) rather than
by accident — removing `#adminDriverName` from `index.html` already made its element
guard fail, but "correct because an element happens to be missing" is not a property
anyone can rely on while editing markup.

**The legacy-token purge is kept and narrowed.** `purgeLegacyTok()` was only reachable
through `saveTok`/`loadTok`/`getTok`, which the stand-down makes unreachable — so it
now runs unconditionally at load, which is what this file has always described it as
doing. It is also **delete-only** now: it used to promote a surviving `localStorage`
token into `sessionStorage`, and with admin access gated behind the PIN that would
walk straight around the gate. Removing the on-disk copy was always the point.

**Guardrail 1 was already satisfied and is now named.** `isSettingExportSafe()` /
`exportSafeSettings()` (v24.0.4) is the single policy for local export, cloud full
backup, cloud delta **and every checksum input**, and its name-pattern arm already
withheld `cloudAdminTokenEnc` because it contains "token". It is named explicitly in
`SETTINGS_NEVER_EXPORT` anyway: this is the most powerful credential in the app, and a
key that important should not depend on a regex nobody re-reads. `ZTO-05` re-computes
`checksumFull` over the payload's own settings array, which is the exact X-05 failure
shape — filter first, then checksum.

`driverDisplayName` (written by a successful claim) is added to
`ALLOWED_SETTINGS_KEYS` in the same change that introduces it. `cloudAdminTokenEnc`
deliberately is **not**: an imported admin token must never be accepted.

**Tests.** `tests/unit/worker-invite-claim.spec.mjs` (17) drives the real exported
fetch handler against an in-memory KV that honours `expirationTtl` — without TTL the
72-hour expiry, the non-extension on re-put, and the rate-limit window are all
invisible. `tests/integration/zero-token-onboarding.spec.mjs` (14) drives the real app
in Chromium with every Worker call intercepted. ZTO-13 pins the claim wizard as a
**real credential form** for the same reasons CBP-08 pins `openCloudReconnect()`'s
(v24.0.6) — a real `<form>`, a visible read-only `autocomplete="username"` field, an
`autocomplete="new-password"` field and a genuine `type="submit"` — and additionally
requires the account value to equal `localUserId`, the same value `openCloudReconnect()`
declares. If those two disagree, the credential the keychain saves at claim time is not
the one it offers back when the session ends, and the driver retypes a 10+ character
passphrase on a phone forever. ZTO-14 asserts the passphrase itself never reaches
`localStorage` or the settings store, so the friction can never be resolved later by
weakening the encryption instead.

Two harness findings worth keeping, both of which first read as product defects:
- **A time test must move every clock it depends on.** WIC-09 advanced only the KV
  stand-in's clock while the Worker derived its remaining TTL from `Date.now()`, and
  "failed" reporting a three-day extension that was really two clocks 71 hours apart.
- **`page.goto('…/index.html#i=CODE')` from `…/index.html` runs nothing.** It is a
  same-document navigation: the hash changes, boot never re-executes, and the wizard
  never opens. The spec bounces through `about:blank` to force a real load, which is
  what tapping a link in Messages actually does.
- Related: `sessionStorage` survives a reload. Only closing the tab clears it, so
  ZTO-03 ends the session explicitly rather than asserting a reload does it.

Negative controls, all verified to fire: reverting the `remainingTtl` derivation fails
WIC-09; storing the code instead of its hash fails WIC-03 and WIC-12; making a
re-claim mint a new `userId` fails WIC-07; dropping the revoked-driver guard fails
WIC-10; moving `/claim` below the driver-token gate fails WIC-15; unbinding the
re-invite (`userId: null`) fails WIC-16.

**DEPLOYED, in the order this section required, and then superseded.** This paragraph
shipped reading *"NOT DEPLOYED … Worker v18 and app 24.0.13 are source-only"*, which was
true when written. Worker v18 went first — run `35037355686`, every post-deploy check
green including `/health` reporting 18, CORS echoing the real app origin and both
unauthenticated boundaries still denying — because the app's Invite and claim flows call
`POST /admin/invites` and `POST /claim`, neither of which existed on the deployed v17.
App 24.0.13 followed and was observed live by parity run `35037460402`.

**The push-race recurred and must not be cited.** Parity run `35032822316` FAILED eleven
seconds after the #210 merge because Cloudflare had not finished deploying. That is real
evidence about the origin at that instant and is not evidence about the release; the
re-dispatch is the observation of record. Fourth recorded occurrence.

Both generations are now **superseded**: PR #211 carried Worker v19 and app v24.0.14, and
production serves those — see the corrected Project Overview above. Do not deploy v18
again.

**The invite/claim contract is now verified against the deployed Worker, which it was
not when this shipped.** `tests/unit/worker-invite-claim.spec.mjs` (17) proves it against
the real fetch handler with an in-memory KV — a SOURCE gate — and every live gate that
existed predated `/admin/invites` and `/claim` entirely, so the only flow in this app that
MINTS a credential reached production unobserved. `scripts/verify-live-invite-claim.mjs`
closes that inside `Verify Authenticated Worker`: **B7 is OBSERVED PASS against Worker
v19**, run `35049144080`. See `FIELD_TEST_CHECKLIST.md` B7 for what it does and does not
claim, and for the two operational warnings — do not dispatch it twice inside one clock
hour (`/claim` is 10/hr per IP and the gate spends up to 6), and do not dispatch it while
a Worker deploy is still landing. Both give UNOBSERVED, which is neither a pass nor a
product failure.

**Still HOLD.** Physical iPhone A1-A11 and M6 raw-data certification remain OPEN.
`FIELD_TEST_CHECKLIST.md` gains no new row here, but the device gate for this release
includes the one thing an automated environment genuinely cannot answer: whether a
claim performed in Safari is still present after **Add to Home Screen**, or whether
that install is a separate storage partition. If it is separate, the re-claim path is
the recovery, and it is what the "One more thing" prompt tells the driver to do.

---

## v24.0.15 "Two Findings, A Residue, And One Position" — the open items, closed

`DB_VERSION` stays **16** and the Worker stays **v19** — no schema and no Worker
semantics changed. Three defects, all in `app.js`, all previously recorded as
reported-not-fixed because the repair needed a release generation and that is a deploy
commitment rather than a cleanup side effect — **plus Issue #216**, reported from a real
device while this generation was still undeployed and folded in here rather than opening
a second one (see its own subsection below).

**V-1 — two concurrent vehicle-profile seeds minted two profiles and discarded one.**
`ensureVehicleProfiles()` is a read-modify-write, and two callers could both be parked
on the IndexedDB round trip that observes `vehicleProfiles` absent before either wrote.
Both then minted a profile with its own fresh id and each overwrote the whole array, so
one was silently discarded — and with it the `vehicleTaxMethod` election that gates the
F30 Schedule C export. `setSetting` populates `SETTINGS_CACHE` synchronously before
awaiting its transaction, which narrows the window but cannot close it: the window
*precedes* any cache write.

Reachable without a harness. `refreshVehicleTaxMethodRow()` reads through it on any
render that populates Settings, and `openVehicleTaxMethodModal()` and
`openTaxSeasonExport()` read through it too; on a fresh install any two overlapping is
enough. Fixed with one module-scope in-flight promise so concurrent callers await the
same seed. Two distinct profiles in **30/30** iterations before, **0/30** after.

**V-2 — the first-run modal took the keyboard from an open claim wizard.**
`openClaimWizard()`'s own comment says it covers the app at z-index 12000 "while the rest
of boot continues behind it". The rest of boot includes `checkFirstRunSetup()` on an
**800 ms** timer, and `openModal()` ends by focusing the first focusable element it
contains. So ~800 ms after a driver tapped an invite link, mid-way through typing, focus
jumped to a modal behind the wizard — into a masked field, with a confirmation that would
then refuse to match, for a passphrase that by design cannot be reset.
`checkFirstRunSetup()` now returns early while a `#claimWizard` is open: deferred, not
cancelled, and deliberately **not** marked complete, so an abandoned claim still gets
setup on the next boot.

**The `tripRow` residue — the fourth site of the unknown-deadhead sweep, and the only one
rendering the coercion as fact.** `Number(t.loadedMiles||0) + Number(t.emptyMiles||0)`
made an unstated deadhead into a verified zero, so a trip whose deadhead was never
entered printed a **loaded-only** rate as `$x.xx/mi` with a letter-grade chip beside it —
on the Home recent-trips list and the Trips page, the two surfaces a driver looks at
most. v24.0.11 closed the same coercion in `exportTripsCSV()` (OI-06),
`computeLoadScore()` (OI-04) and `renderLiveScore()`; this file has carried the fourth as
reported-not-fixed since. It reads `tripAllMiles()` now, which returns `null` unless BOTH
loaded and deadhead are known. Every consumer already guarded on `miles > 0` / `rpm > 0`,
so an unknown trip falls through to the existing `—` and `?` treatments, and an explicit
zero deadhead still grades normally.

**How all three were found, which is the part worth keeping.** None came from a report.
`main` was intermittently red and being cleared by re-running: Tests run `35084126731`
attempt 1 failed four assertions in `tax-export-csv-corruption`, attempt 2 on the same
SHA passed. Root-causing that instead of re-running produced V-1. A separate intermittent
failure in the same tree (ZTO-09) produced a repair that **shipped as an empty function**
— a negative-control edit was never restored, and neither verification could see it
(`grep -c` counts an identifier; an unloaded re-run passes either way). Widening the
assertion that the empty body had been hiding, from "does the wizard focus the passphrase
field" to "does focus *stay* there", is what produced V-2.

**Tests.** `tests/integration/vehicle-profile-race.spec.mjs` retagged `[FINDING V-1 /
FIXED]`, `[FINDING V-2 / FIXED]` in `zero-token-onboarding.spec.mjs` merged beside
ZTO-15 as its paired control, and **OI-15** in `omega-economics.spec.mjs` — the
regression this file asked for by name, rendering a trip with `emptyMiles: null` and
asserting `—`/`?` with an explicit-zero control, driven through the real `tripRow()`
rather than a helper because what was wrong was what the driver saw. `tripRow` is
exposed on `__FL_TESTS` for it, behind `__FL_TESTS_ENABLED` like everything there.

Every negative control verified to fire: reverting the in-flight promise fails V-1 while
the uncontended control still passes; reverting the claim-wizard guard restores
`modalClose`; reverting `tripAllMiles(t)` in `tripRow` fails OI-15.

Full suite with the #216 work folded in: **557 passed, 0 failed across 59 spec files**
(v24.0.15's own 549/58 plus `position-authority.spec.mjs`).

**Two new gates, from the empty-function incident.** `RH-01` scans `tests/unit` and
`tests/integration` on disk and requires every spec to be both imported and listed in
`run-all.mjs` — a directory scan, not a maintained list, because a list has the same
failure mode it is checking. `RH-02` fails any spec carrying an active `NEGATIVE CONTROL`
comment marker, so a control edit cannot reach `main` again; its own control fires
against the exact text that shipped.

### Issue #216 — the Today screen reported two conflicting positions at once

Folded into this same generation rather than opening a second one: v24.0.15 had not
deployed, so the changed bytes reach a client on the same fetch either way, and two
generations for one undeployed release is the thing `CLAUDE.md` tells both lanes not to do.

**Observed** 2026-09-16 20:04 CT, iPhone, installed Home Screen PWA, app 24.0.14. In one
viewport the alert banner read `Athens, TN — Limited reload options. Consider
repositioning` directly above `YOUR POSITION: Columbus, OH · anchor market · Midwest`
with verdict **HOLD**. The driver was told to reposition out of a market the app
simultaneously said he was not in.

**Four independent mechanisms**, all reproduced against the real app in headless
Chromium before any of them was fixed:

1. **Opposite tie-breaks on equal `created`.** Both surfaces meant "the most recently
   created trip's destination" and ordered by the same key.
   `renderPositionContextBanner()` read `listTrips()` → the `created` **index** with
   cursor `'prev'`, and IndexedDB breaks equal index keys by **primary key descending**.
   `renderPositioningCard()` read `_getTripsAndExps()` → `dumpStore()` (store order =
   primary key **ascending**) → `Array.prototype.sort`, which is **stable**, so an equal
   `created` keeps store order. Under DB16 the primary key is a random UUID, so on a tie
   the two surfaces picked **opposite** trips — random per install, stable forever
   afterwards, which is why this presented as a fixed contradiction rather than a
   flicker. Ties are ordinary: `sanitizeTrip()` defaults `created` to `Date.now()` and
   trips are written in tight loops by import and by the cloud-restore merge.
2. **The card read a 120 s cache; the banner read IndexedDB fresh.** Any trip write that
   did not call `invalidateKPICache()` left them up to two minutes apart. Reproduced:
   banner `Knoxville, TN`, card `Athens, TN`.
3. **They answered different questions.** The card resolved GPS first; the banner had no
   GPS awareness at all. While a tracking session was live, nothing disclosed which was
   which.
4. **The banner had no UNKNOWN state, and carried a live geography defect.** It tested
   `MW.tier1/tier2/avoid` with `city.includes(c)` on the raw destination. `MW.avoid` is
   `['deep southeast','rural southeast','deep texas','far northeast']` — not one of them
   a city name — so that branch was unreachable and **every** unrecognised city fell
   through to a final `else` emitting the *same* "Limited reload options. Consider
   repositioning" directive. Athens, TN was never assessed as thin; it was not
   recognised, and the absence was rendered as a confident adverse directive. That is the
   `naLookupMarket('')`→Toronto class (v24.0.4) and the blank-deadhead class (v24.0.1).

**Worse, and not in the original report: `Calgary, AB` was being priced as a Midwest
Tier 1 anchor.** `'calgary, ab'.includes('gary')` is true, so the banner told the driver
to **"Hold for $1.60+"** on an Alberta city. v24.0.4 fixed exactly this in the *lookup*
functions; this surface never used them. Confirmed against the running app before the
fix, with `naLookupMarket('Calgary, AB')` correctly returning `calgary/ALBERTA` at the
same moment.

**The repair.** `resolveDriverPosition()` is the single owner of "where is the driver" —
GPS, then the last trip — and every surface calls it. Ordering is an explicit **total**
order (`created` desc → `deliveryDate` desc → `id` desc) rather than one that falls out
of storage internals, and position always comes from the indexed read, never the KPI
cache. `classifyPositionMarket()` resolves identity through the canonical fail-closed
lookup and keys the doctrine tier on the **resolved market key**, which is what preserves
Cincinnati and Toledo at the Tier 1 standing v24.0.1 gave them in `MW.tier1` — keying on
`USA_MARKETS.role` instead would have silently demoted both to support.

`updatedAt` is deliberately **not** in the ordering chain: it records when a row was last
written, not where the driver was, so including it let an edit to an ancient trip move
his reported position. It was in the first version and was caught by the ambiguity test
refusing to fire, not by reading.

**Two deliberate behaviour changes, named rather than slipped in.** The banner is now
GPS-aware, because it shares the resolver — while a tracking session is live it says
`Near <market>` instead of naming a delivery the driver has since driven away from. And
the old `city.includes('transitional')` branch is gone: it matched the literal word
"transitional" inside a destination string, which no real place name contains, so it was
unreachable in production and there is no doctrine tier behind it. Nothing else the
banner could previously say has been dropped.

A genuine tie that **disagrees** about the destination sets `ambiguous`. The pick stays
deterministic — that is what stops the two surfaces contradicting each other — but the
banner, which issues a *directive*, stands down to "confirm your position before
pricing" rather than pricing off a coin flip.

**Tests.** `tests/integration/position-authority.spec.mjs` (8, new), driving the real app
and asserting **rendered content**, not internal state — the hash and the highlighted tab
were already correct while the surface was wrong, which is how v24.0.8 shipped green.

Two things the controls found, both kept:

- **PA-01 initially passed against the reinstated defect, about half the time.** With
  random UUIDs, which of the two tied trips the pre-fix card picked was a coin flip, so
  the regression guarding the reported defect could not reliably fail on it — the `OI-11`
  failure mode this file already records. The trip `id`s are **pinned** now
  (`sanitizeTrip` preserves a supplied `id`), so the pre-fix card deterministically names
  Columbus while the banner names Athens: the operator's screenshot, every run.
- **The render-generation guard is unproven and is labelled as such.** Both surfaces are
  fired and forgotten from `renderHome()` and both `await` before painting, so two renders
  can complete out of order; each now takes a ticket and abandons rather than painting
  over a newer one. But **no assertion in this suite fails without it** — with the
  resolver reading IndexedDB at resolve time, an overlapping render re-reads current data
  and reaches the same answer. It is kept because `getPositioningBrief()` does live NWS
  I/O in production where the ordering is genuinely unconstrained, not because a test
  demands it. A negative control that does not fire is the finding, not a formality.

**Also corrected while bumping:** the PWA section above read `24.0.13` for both the
manifest `?v=` and the service-worker version — **two generations stale**, and the third
occurrence of checklist item 10 drifting in this file.

**Source-only.** v24.0.15 is **not deployed and not live-observed**. Production serves
24.0.14 / DB16 / Worker v19, and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md`
remains the current authority because it certifies exactly that. A superseding document is
due **the day this deploys**, not the day it merges — which is the rule this release line
learned the hard way and `FIELD_TEST_CHECKLIST.md` now states. After deploying, re-dispatch
live parity rather than citing the push-triggered run, which races the Cloudflare deploy.

**Still HOLD.** Physical iPhone A1-A12 and authentic M6 raw-data certification are
unchanged and remain the operator's.

---

## v24.0.18 "Never Press Backup" — Issue #205 §3, and the queue that was deliberately not built

`DB_VERSION` stays **16** and the Worker stays **v20 source / v19 deployed** — no schema
and no Worker semantics changed, and **no migration was spent**, which is the point of
the design below.

Issue #205 §3 asks that "the normal user should never need to remember to press Backup".
Most of that model was already here and is worth naming before the gap: every mutation
calls `invalidateKPICache()` → `cloudScheduleSync()` (**27 call sites**, covering trips,
expenses, fuel, mark-paid, imports, settings and maintenance), delta sync sends only what
changed, restore is revision-aware, and a manual action stays in Settings as a
diagnostic. Three things were missing, and only three.

**1 — Pending work was not observable.** Nothing could answer "how many changes are
waiting", so §3's `3 changes waiting` could not be shown and an operator had no way to
tell automatic sync had stopped except at restore time — the same discovery-at-restore
failure v24.0.6 fixed for the paused case.

**2 — The intent was not durable.** `cloudScheduleSync()` is a 30-second **in-memory**
debounce. Close the app inside that window, or fail the push, and the timer dies with the
page. The *data* was never at risk — local save always happens first — but the *sync*
silently did not happen, which is exactly what this section is about.

**3 — A failure left no trace.** Both failure paths in `cloudPushBackup()` called
`cloudScheduleRetry()` and, when `silent`, said nothing and persisted nothing. A
repeatedly failing sync was indistinguishable from a quiet one.

### Why there is no separate queue — the decision worth reading

The obvious implementation is a durable queue store of pending mutations. This
deliberately does **not** do that, because FreightLogic **already has** a durable
definition of pending work: `lastCloudSyncedAt`, the delta watermark that
`cloudPushBackup()` itself selects records against. Anything whose `updatedAt` is newer
than the watermark is, by that function's own definition, not yet on the server.

Deriving the count from the watermark **cannot drift from what a push would actually
send**. A parallel queue can: it would be a second list of what needs syncing, maintained
by hand at 27 call sites, and two lists that can disagree is the precise shape of the
X-07 restore gap (stores pushed but never restored) and the 2026-09-13 asset defect
(`.assetsignore` and `CORE` disagreeing while both gates read green). It also needs no
new object store, so `DB_VERSION` stays 16.

`SYNC_PENDING_STORES` covers the record stores delta sync filters by `updatedAt`.
**`settings` is excluded on purpose**: it has no revision field and is pushed wholesale
every time, so counting it would make "0 changes waiting" unreachable — a status surface
that can never read clean is one people stop believing.

A record whose `updatedAt` is missing or `0` is **not** counted as pending. It cannot be
*proven* newer than the watermark, and inventing pending work would make the row cry wolf
forever on legacy rows — the `knownNum()` doctrine of v24.0.1 applied to sync state.

### The surface, and why PAUSED renders nothing

`renderSyncStatusRow()` runs on every home render beside `renderCloudPausedBanner()` and
shows exactly the four states §3 names: `Synced`, `N changes waiting`,
`Offline — saved on this device`, `Sync problem — retrying`. `PROBLEM` outranks `PENDING`
when a failure marker exists.

Two states render **nothing** here, both deliberately:
- **OFF** (no token) — nagging a driver who never enabled cloud backup trains them to
  dismiss the one banner that matters, the same reason `cloudBackupPaused()` returns
  `false` with no token.
- **PAUSED** — the v24.0.6 fixed banner owns that state and offers the one-tap fix. Two
  fixed surfaces both speaking would cover the app, and the row is not a second authority
  on a state something else already explains.

`resumeSyncIfPending()` runs at boot **after** `navigate()`, so it never delays the
driver's first screen, and it no-ops when cloud backup is off, paused, or nothing is
pending — a forced push on every boot is the opposite of the ask. It is idempotent by
construction: it pushes the same delta the lost timer would have, and re-sending a delta
is already safe because restore is revision-aware.

### Tests

`SQ-01`…`SQ-07` in `tests/integration/cloud-backup-paused.spec.mjs` — the existing
registered spec, because `RH-01` requires every spec on disk to be registered in
`tests/run-all.mjs` and that file is still **gpt**-owned under the PR #227 exception. The
deadlock recorded at the end of the v24.0.16 section is unchanged and still worked around
rather than fixed.

They assert the **derived** count rather than a queue's bookkeeping, which is the whole
design: `SQ-01` advances the watermark alone and requires the same record to stop being
pending, with no queue to drain and nothing to mark done.

*A TDZ that would have killed the app on load was avoided by checking rather than
assuming:* `SYNC_PENDING_STORES` references `EVIDENCE_STORE` at module-evaluation time,
and `const` declarations are not hoisted — `EVIDENCE_STORE` is at `app.js:1564` and the
new const lands near 16318, so the order is safe. That is the `getBrokerIntel()`
shadowing class this file already records twice, caught by reading the declarations.

### Not deployed

**Source-only.** Deploy order is unchanged and still matters: **Worker v20 first** (it
remains undeployed; production serves v19, both dispatches having been refused at the
`DEPLOY` confirmation guard), then the app generation, then **re-dispatch** live parity
rather than citing the push-triggered run.

**Still HOLD.** Physical iPhone A1-A12 and authentic M6 certification are unchanged.
Issue **#224 remains OPEN**.

---

## v24.0.17 "One Less Surface" — a feature removal, a ceiling that binds, and a document root

`DB_VERSION` stays **16** and the Worker stays **v20 source** — neither's semantics
changed. Three issues, done as one generation because all three change deployed bytes
and two generations for one deploy is the thing this file tells both lanes not to do.

**This release STACKS ON an undeployed v24.0.16.** Worker v20 must still deploy before
the app generation, for the reason the v24.0.16 section gives: a driver whose token index
is stale gets a 403 only once v20 is serving.

### #230 — Voice Load removed completely, by operator decision

Not a hide and not a disable. `voice-load.js` is deleted; the `<script>` tag, the
evaluator microphone control `#mwVoiceBtn` and the status region `#mwVoiceStatus` are
gone from `index.html`; both the `CORE` list and the install-blocking `critical` array
drop the precache entry; and the driver-facing copy reads `Load Intake — Paste or Type`.

**The generation bump is what makes the removal real.** `CACHE_NAME` is
`freightlogic-${SW_VERSION}` and the `?v=` query is the only other identity a child
asset carries, so an installed iPhone holding the `24.0.16` shell would keep serving the
deleted module from cache indefinitely. A removal that cannot reach the device is not a
removal — the v24.0.3 lesson applied rather than relearned.

**Scope read wider than the issue's enumerated list, and this is the judgement to
check.** Items 1-5 name the module and the evaluator mic. But the issue's title says
*completely*, item 4 says "remove any other driver-facing wording that offers Voice
input", and the repository had **two further, independent** SpeechRecognition
implementations that the enumeration did not mention: F27 Load Intake's `#liVoice`
(`🎤 Voice`, its own recognizer and handler) and F23 Smart Load Inbox's `#f23VoiceBtn`
(`🎤 Voice`, backed by `_startInboxVoice()`). Removing only the module would have left an
operator who asked for complete removal looking at two live Voice buttons doing the same
job. Both are removed, along with the F28 Diagnostics `dxVoice` capability row, which
would otherwise report "Voice Input: Supported" in an app that has no voice input — the
X-11 dead-claim class this file already records fixing once. The `SpeechRecognition`
plumbing goes with them; nothing replaces it, per the issue's non-goal.

Ordinary typed and pasted intake is untouched, which `RH-05` asserts by name rather than
leaving to inspection: `#btnLoadIntake`, `#mwRevenue`, `#mwLoadedMi`, `#mwDeadMi`,
`openLoadIntake` and `parseLoadTextForInbox` all survive.

**The expectations that REQUIRED the module are inverted, not weakened.**
`scripts/verify-cloudflare-parity.mjs` asserted the deployed index references
`voice-load.js?v=<gen>`; it now asserts the index does **not** reference `voice-load.js`
at all, so a reintroduced tag or a stale deployed index fails rather than passing
quietly. `CG-04`'s versioned-asset floor moves 4 → 3 (app.js, sw-bridge.js, manifest)
and `CG-07`'s header sweep drops the file. The deploy inventory in
`scripts/lib/deploy-assets.mjs` needed no edit at all: it derives from the real
declarations, so deleting the CORE entry and the script tag dropped the asset by itself —
**23 declared runtime assets → 22**, which is the design working.

### #232 — the import ceiling now binds before materialization

`LIMITS.MAX_IMPORT_BYTES` (30 MB) was checked before the read in `importJSON()` and
`importCSVFile()`, but the TXT route ran `await file.text()` and the XLSX route ran
`await file.arrayBuffer()` **plus a full SheetJS parse** first, meeting the ceiling only
afterwards, on the synthetic CSV they had already built from the resident source. A
rejection that lands after the whole file is in memory does not bound the spike it exists
to prevent.

`importExceedsSizeLimit(file)` is one helper used by all four routes plus a pre-dispatch
backstop in `importFile()`, so the sites cannot drift apart the way the two asset lists
did in the 2026-09-13 defect, and a NEW route fails closed. The operator-facing limit is
unchanged; streaming was deliberately not the fix, per the issue and the #204 assessment
— every terminal operation here still needs a complete buffer.

`ICT-11`…`ICT-14` assert the **ordering**, not the limit's value, because ordering was
the whole defect: each oversized input instruments its own readers, so the assertion is
"was the byte-producing call ever invoked". A message-level assertion could not have
caught this — a guard that rejects only after reading still produces the right toast.
`ICT-14` covers the guard's own failure mode, over-rejection: exactly at the ceiling is
allowed, a 0-byte file is still read, and an input with no size is not treated as
oversized.

**The probe throws after recording, and that detail is load-bearing.** The first version
returned usable bytes, so with the guard reverted the route continued into the real
interactive importer and the run **hung** instead of failing. A negative control that
cannot run is not a control; the reader now records the attempt and throws, the route's
own try/catch swallows it, and an unguarded route fails fast with the read recorded.

### #228 — the repository root was the document root

`wrangler.jsonc` publishes `assets.directory: "."`, so every file in the repository is
served at the app origin unless `.assetsignore` withholds it, and that list named only
seven entries. External verification had already observed `AUDIT_REPORT.md` and
`FIELD_TEST_CHECKLIST.md` returning **HTTP 200** on the app origin — the second of those
being the physical-device certification gate itself.

Withheld now: `AGENTS.md`, `AUDIT_REPORT.md`, `FIELD_TEST_CHECKLIST.md`,
`RECON_24_0_2.md`, `UI_BRIEF_V24.5.md`, `FreightLogic_UI_Reference.html`, and the
repository-only directories `.agents/`, `.claude/`, `.github/`, `.githooks/`, `docs/`,
`schemas/`, `scripts/`, `tests/`.

**Deliberately still served, both named in `DAC-07` so a later broadening cannot take
them out quietly:** `field-certification.html` / `field-certification.js` are the
operator-approved same-origin device companion, and A1-A12 are executed against them on
the real iPhone; `vendor/xlsx.full.min.js` is the bundled parser the install-blocking
shell precaches.

Over-exclusion is this repair's own failure mode — it produces exactly the 2026-09-13
production 404 in the opposite direction — so it was verified against the derived
inventory rather than by reading: **0 of the 22 declared runtime assets is excluded**,
which the parity gate reports on every run and `DAC-02` asserts.

### Tests

`RH-04`/`RH-05` (Voice absence and intake survival), `DAC-06`/`DAC-07` (asset boundary
both directions), `ICT-11`…`ICT-14` (import ordering), and `MS-11` retargeted from
proving `voice-load.js` hydrated a fresh session to proving the removal is clean at
runtime — no global, no DOM node, no script element, **and no request for the deleted
module**, which is the half a static file check cannot see. `MS-10` still fails if the
removal broke boot.

**No new spec file, and that is deliberate.** `RH-01` requires every spec on disk to be
registered in `tests/run-all.mjs`, and `run-all.mjs` is owned by the **gpt** lane under
the PR #227 exception — the deadlock this file records at the end of the v24.0.16
section, still unresolved. Every assertion here went into an already-registered spec, so
the sweep needed no cross-lane edit and `RH-01` stays green. That deadlock still blocks
any future Claude regression that genuinely needs its own file.

**`RH-02` fired on this release's own author.** The `ICT` comment block used the singular
`NEGATIVE CONTROL` marker form that `RH-02` bans as leftover scaffolding, and the spec
failed until it was reworded. Second consecutive release in which that gate caught the
person who added it.

Full suite on the exact candidate head, first attempt, real headless Chromium:
**615 passed, 0 failed across 64 spec files.** Nothing was skipped, quarantined or
weakened. Every negative control fired: reverting the TXT guard fails `ICT-11` with
`["text"]` recorded and the XLSX guard fails `ICT-12` with `["arrayBuffer"]`, while
`ICT-13` stays green — which proves the three layers are independent rather than one
guard tested three ways; restoring any single Voice Load reference fails `RH-04`;
re-admitting a withheld document fails `DAC-06`, and excluding `field-certification.js`
fails `DAC-07`.

**An earlier run of this suite was discarded rather than reported.** The #232 control's
chained restore overwrote the Voice removal mid-run, so the tree changed underneath a
suite already in progress. That run's numbers would have described a tree that never
existed; it was killed, the removal re-applied, and the suite re-run from the top on the
final head. "First-attempt exact-head result is the evidence" only means anything if the
head holds still for the whole attempt.

### Deployed and OBSERVED — app only. Worker v20 is still v19 in production.

This section shipped reading *"Source-only. v24.0.17 is not deployed and not
live-observed."* That was true when written and stopped being true about twenty minutes
later, when PR #233 merged and Cloudflare deployed the app. It is corrected here rather
than quietly overwritten, for the reason this file now records against itself seven
times: a release record that keeps a superseded deployment claim is the drift class.

**The app half is OBSERVED at 24.0.17.** Live all-asset parity, `workflow_dispatch` on
`main` @ `3461ad9` (run `35274866403`): `index.html` references `app.js` and
`sw-bridge.js` at 24.0.17, **`index.html` does not reference `voice-load.js`** — the
inverted #230 assertion, observed live — service worker `24.0.17`, `sw-bridge` imports
and the worker precaches `modern-shell.js` at 24.0.17, manifest name
`FreightLogic v24.0.17`, **all 22** declared runtime assets load with none served as
HTML, and CSP byte-identity holds. The production service-worker gate passed on the same
SHA (run `35272368177`), and `Tests` passed on the merge commit (run `35272368176`).

**The deploy order was inverted, and exactly one check says so:**

```
FAIL  Worker reports v20 — {"ok":true,"version":"19"}
```

The app generation reached production while the Worker did not. Worker v20 has been
dispatched twice (runs `35211428043`, `35213350763`) and **both refused in ~7 seconds**:
`Select DEPLOY in the confirmation control to run this. Nothing was deployed.` That is
the confirmation guard working exactly as the v24.0.6 section describes it working — it
is not a broken workflow and needs no repair. Worker v20 remains an **operator dispatch**
with `DEPLOY` selected.

This is tolerable rather than harmless, and the v24.0.16 section says why: the app is
unchanged in what it calls, so nothing breaks, but a driver whose token index is stale
gets a 403 only once v20 is serving, and the CORS narrowing has not landed. Deploy the
Worker, then re-dispatch parity; the single failing check flips and nothing else has to
move.

**The push-triggered parity run FAILED and is not the evidence** (run `35272368173`,
43 seconds after the merge) — but note what distinguished it this time: the
**re-dispatch also failed**, which is what proved this was a real mismatch rather than
the seventh occurrence of the Cloudflare race. A re-dispatch that fails the same way is
evidence; a re-dispatch is not a way of making a failure go away.

**Still HOLD.** Physical iPhone A1-A12 and authentic M6 raw-data certification are
unchanged and remain the operator's. Issue **#224 remains OPEN** — the `db === null` race
did not reproduce and nothing here touches it.

---

## Asset boundary, live half — the static check that could not have caught it

Tooling only. No shipped file changed, so no version marker moved: `APP_VERSION` and
`SW_VERSION` stay `24.0.17`, `DB_VERSION` 16, Worker v20 source / **v19 deployed**.
`scripts/` and `tests/` are claude-owned, so no lock was required.

**The gap this closes is in v24.0.17's own #228 work, found by reading the issue against
what shipped.** Issue #228 item 1 asked for *"a deployment regression that requests every
known internal/repository-only path and fails unless the result is non-public (prefer
404)"*. What shipped was `DAC-06`, which reads `.assetsignore` — the **static** half. That
is a necessary check and it is not the one the issue asked for, because a static
assertion could not have caught the reported defect: `AUDIT_REPORT.md` and
`FIELD_TEST_CHECKLIST.md` were observed at **HTTP 200 on the live origin** by external
verification, and nothing in this repository noticed. `.assetsignore` being correct in the
repository says nothing about what the deployed origin is actually serving — which is the
2026-09-13 lesson restated, where a curated subset reported 24/24 PASS while a declared
asset 404'd.

`runWithheldPathChecks()` requests **20** repository-only paths against the real app
origin and fails on a `200`. Three properties keep it honest:

- **Non-public means 404 or 403, and nothing weaker.** A 200 is the defect.
- **A 500 or a transport error is reported SEPARATELY** and never counted as withholding.
  "Not obviously served" is not the same fact as "withheld", and collapsing them would let
  an outage read as a security pass — the same UNKNOWN-is-not-a-value doctrine v24.0.1
  applied to the canonical decision and the live-parity runner applied to `UNOBSERVED`.
- **It names the evidence, not just the status.** A short body prefix distinguishes "the
  document is really being served" from an origin answering 200 with an SPA shell for
  every unknown path.

The list deliberately includes `cloud-backup-worker.js` and `wrangler.jsonc` — the Worker
source with its auth middleware is the most damaging thing a `"."` document root could
serve, and `DAC-03` already asserts they stay excluded statically. Both directions now
have both halves.

`DAC-08` asserts the gate actually **calls** the sweep, with comment lines stripped first,
because a call that exists only inside a `//` comment reports nothing at runtime — the
`DAC-04` convention, which exists because commented-out code once satisfied a check.
Negative control verified to fire: commenting out the `await runWithheldPathChecks(checks)`
call fails `DAC-08` while the other seven stay green.

**What this does not yet claim.** The sweep is in the operator gate, not in
`tests/run-all.mjs` — a gate that needs the internet is a network gate, not a code gate,
per the standing rule. So #228 is **not** closable on this commit alone: it closes when a
live parity run is dispatched and reports the new check PASS against the production
origin. Until then the repair is proven in configuration and unproven in production.

---

## v24.0.16 "Trust Boundaries" — three documented boundaries that nothing enforced

Worker **v19 → v20**. `DB_VERSION` stays **16**. Scope is the four issues the GPT
lane handed to this lane in `.agents/inbox/gpt-to-claude-security-followup-2026-09-17.md`
once PR #223 landed, in the order it suggested: the trust-boundary items first,
then the executable-supply-chain one.

What the three security issues have in common is worth naming, because it is the
same shape three times: **each boundary was written down and none of it was
enforced.** The export-side secret policy said in its own comment that the
import allow-list "is not a defence here"; the CSP kept a CDN whitelisted for a
fallback that the CSP itself already blocked; the Worker's rotation endpoint
existed to retire a token while auth would still accept a superseded one. A
comment describing a boundary is not a boundary — the same finding this file
records against `ADAPTER_ONLY` (v24.0.4), against checklist item 15 being
"machine-checked" when nothing read the field (v24.0.12), and against the
workflow prohibition that held only because the thing violating it was broken.

### #219 — an import may restore data, never install a credential

`importJSON()`'s `ALLOWED_SETTINGS_KEYS` admitted `cloudBackupToken`,
`cloudBackupUrl`, `appLockPin`, `fmcsaApiKey` and `eiaApiKey`, and the writer put
every accepted row straight into the `settings` store. `cloudGetConfig()` reads
back **both** the token and the URL, so a crafted file handed to an operator and
fed to "Import Data" could silently repoint every later backup at an attacker's
endpoint using an attacker's bearer token, and replace the device PIN hash on the
way past.

`isSettingImportSafe()` reuses `isSettingExportSafe()` — a value too sensitive to
leave the device is too sensitive to accept from a file, and one policy cannot
drift from itself — plus the **asymmetric half**: `cloudBackupUrl` and
`appLockEnabled` are safe to *export* and carry security *authority*, so
accepting them is the defect even though emitting them is not. That asymmetry is
the part most likely to be "simplified" away later; ICT-06 asserts the subset
relation directly rather than key by key. Blocking the URL degrades nothing —
absent it the hardcoded `CLOUD_WORKER_URL` still applies, and the passphrase and
token are not in any payload regardless. The credential keys are removed from the
allow-list as well, so reopening the hole takes two edits and either alone fails.

**Second half:** `mode === 'skip'` tested `x.id !== undefined`, but `settings` has
keyPath `key`, so no settings row ever satisfied it and every one fell through to
`put()` — `skip` overwrote existing settings on every import, the exact opposite
of the mode's meaning. `idbRecordHasOwnKey()` reads the store's real keyPath,
fixing `settings` and `receipts` (`tripOrderNo`) at once rather than adding a
second hardcoded name the next store would miss.

**Found while fixing that, and PRE-EXISTING:** a duplicate key in `skip` mode
aborted the whole import. IndexedDB raises `ConstraintError` asynchronously as a
request error that bubbles to the transaction, so the synchronous `try/catch`
never saw it — re-importing any file that shared one record id imported
**nothing**, under a cheerful "Import complete". The old guard already routed
id-bearing trips through `add()`, so this was reachable before this release; it
only surfaced now because the keyPath repair lets `settings` reach `add()`, where
duplicate keys are the normal case rather than the exception.

The add-only settings merge in `mergeRestoreData()` is gated too, labelled as
defence in depth rather than the reported defect: it could never *overwrite* a
local credential, but it could *install* one absent locally — which is exactly a
fresh device mid-disaster-recovery.

A refused key is named in the toast. A withheld credential is a deliberate
refusal, not a parse failure, and an operator restoring their own file should
learn why the endpoint did not come back. Key names only; never a value.

### #221 — the token index is not the authority, and a link is not a credential

**Canonical-user token authority.** Driver auth resolved the presented bearer
token through `tokh:<sha256(token)>` and trusted what it found, checking only
`tokenData.active`. It never asked the account whether that was still its token.
`POST /claim` and `/admin/users/:id/rotate` re-key in place: they write a fresh
`tokh:<newHash>` plus `user:<userId>` and delete the hash they **observed**. KV
has no transaction and no compare-and-swap, so two overlapping claims can each
read the same prior state and each write a token record — the last `user:` write
wins, but the loser's `tokh:` entry survives, because the winner deleted a
different hash.

That is not cosmetic residue. It is **two simultaneously live bearer credentials
for one account**, one of which the account does not name and nobody can see,
valid indefinitely — including after a rotation performed specifically to retire
it. Backups are keyed by `userId`, so the stale credential reads and writes the
live driver's real data. Auth now loads `user:<userId>`, requires it active and
naming the exact hash presented, deletes that superseded index entry, and returns
403. It does **not** pretend KV became atomic — the claim-count increment is still
a race and is still documented as one; it makes the user record the only authority
on which hash is current. A legacy v7 record carrying plaintext `token` and no
`tokenHash` has its hash derived rather than waved through, so there is no
fail-open branch; a record with neither is malformed and refused.

**Raw token links retired.** `cloudCheckSetupLink()` accepted `#token=<flk_…>`
and `?token=<flk_…>`, filled the credential field and navigated to Settings. Both
were the human credential transport that v24.0.13's zero-token onboarding exists
to eliminate, kept alive for compatibility with a flow already deliberately
retired. The query form is strictly worse than the fragment: a query string **is**
sent to the origin, so the token reaches the access log and any `Referer` before
any client-side cleanup can run — which is why that case is reported as
exposed-and-revoke rather than merely unsupported.

**Worse than the issue states, found while testing:** the old cleanup was only
reachable through `cloudInitUI()`, which runs inside `renderInsights()`. So the
`history.replaceState` fired only if the operator happened to open Settings, and
until then a bearer token sat in the address bar, in session history and in any
screenshot. `flStripLegacyTokenLink()` now runs on the same synchronous line of
boot as `flCaptureClaimCode()`, for the same documented reason, and returns the
**transport** rather than the token so the value cannot reach a log this way. A
legacy link is reported, not ignored: silence would leave an operator holding a
real invite with no idea why nothing happened. The `#i=` claim flow and the
Settings field an operator types into themselves are untouched.

**CORS.** The legacy `freightlogic.pages.dev` / `www.` origins are removed. That
Pages origin is not the live app and has not been for the whole v24.0.x line;
"accepted during migration" outlived the migration. `env.ALLOWED_ORIGIN` remains
the exact-match hook, so re-adding an origin is a variable, not a code change.

### #220 — `script-src` is `'self'` alone

`loadTesseract()` fell back to jsDelivr three times over — the engine script,
`workerPath` and `corePath` — and `loadScriptWithFallback()` carried an SRI TODO
with no `integrity` attribute, so nothing pinned the bytes. That is unpinned
third-party JavaScript running in this origin with the same access to IndexedDB
as the operator's entire trip history, expenses, receipts and the locally stored
cloud credential. After X-10 bundled SheetJS, this fallback was the only reason
`cdn.jsdelivr.net` was still in the CSP at all.

**And it was already dead, which is proved rather than argued.** The shipped CSP
cannot run that path to completion: `connect-src` has no
`tessdata.projectnaptha.com`, where `Tesseract.createWorker('eng', …)` must fetch
`eng.traineddata.gz`, and `worker-src 'self' blob:` forbids a cross-origin
worker. OCR-01/02 record the real `securitypolicyviolation` event naming that
exact URI and the `SecurityError` at worker construction. OCR-01 carries its own
discriminator: an **allowed** origin is equally unreachable from the test sandbox
and produces **no** violation — without that control, "a fetch failed" would
prove nothing about the policy.

So the CDN path could load and run foreign code while never producing a single
character of OCR. Removing it takes away no working capability, which is what
makes this the honest option of the two the issue offers rather than a feature
deletion dressed as a security fix. `script-src` is now `'self'` alone and
jsDelivr is gone from `connect-src`, byte-identically in `index.html` and
`_headers` (checklist item 12).

**The vendored files are deliberately not committed, and that is an operator
decision left open.** The self-hosted path is unchanged — drop the three files
into `vendor/` and OCR works with no code change — but together with the English
model the CSP now also requires be self-hosted they are ~15 MB (engine ~66 KB,
worker ~124 KB, SIMD LSTM core ~3.9 MB, `eng.traineddata.gz` ~10.9 MB).
Committing that much third-party binary to a flat-file repo whose service worker
precaches its assets is not a side effect of a security fix. `README.txt` records
the exact versions, the sizes, and the requirement that anything added be
version-reviewed, licensed in `vendor/`, and added to
`scripts/lib/deploy-assets.mjs` so the parity gate sweeps it.

**Two defects found while making the unavailable path honest,** both of which
meant OCR raised a `TypeError` rather than an explanation even with an engine
present: the receipt-camera path called `Tess.createWorker('eng')` on the return
value of `loadTesseract()`, which is a ready **worker** and has no
`createWorker`; and the Quick Evaluate screenshot path never checked the result
at all. Both now report "not installed" and name the alternative.

### #224 — NOT closed, and this section says so

The `db === null` race **did not reproduce here.** The full suite ran green on the
first attempt on this tree, and targeted probes found no post-readiness
re-bootstrap: an idle app page over 4 s (0/8), a second tab waiting only for
`#appMeta` (0/12), and the same under 20× CPU throttling (0/8). The issue forbids
clearing it with a rerun, so the root cause remains unproven and #224 stays OPEN.
`main` must not be described as having all automatable gates green.

**What is fixed is real, and there was more of it than reading found.** 15 call
sites waited only for `#appMeta` to have text on a page the spec itself opened or
reloaded — insufficient by the harness's own comment, since `appMeta` populates
*before* `initDB()` assigns the handle. Two were tabs in
`toctou-concurrent-edit`. The other 13, in `field-resilience` (10),
`backup-restore-parity` (2) and `batch-a-release-integrity` (1), are the more
interesting shape: each is a deliberate `page.reload()` followed by that weak
wait. **A reload IS the re-bootstrap #224 deduces** — it re-runs the IIFE past
`let db = null` — so those sites were the reported mechanism written into the
suite in 13 places. Whether that is also the CI failure cannot be claimed: the CI
failures were in specs that do not reload. `HR-02` found all 13; reading had
found 2, which is the argument for writing it as a directory sweep rather than a
list of the sites already known.

**Diagnostics, which is step 1 of the issue.** Every tracked page is stamped per
document at init-script time; main-frame navigations, page errors and console
errors are recorded; and `createSuite()` prints all of it for every live page
whenever an assertion fails, including whether the handle is usable *right now*
and whether the document changed since readiness. The next CI failure therefore
arrives with its evidence instead of prompting another rerun. Harness-only — no
production bytes changed for diagnostics — and deliberately not a retry, a
timeout bump, a skip or a weakened assertion; the issue forbids all four and each
would hide the transition being hunted. HR-03 asserts the failure path contains
no retry or skip.

### Why this is a version bump

`app.js`, `index.html`, `_headers`, `modern-shell.js` and the Worker all changed.
`scripts/verify-release-generation.mjs` refused the tree at a reused `24.0.15`
(`"Runtime assets changed without a new release generation"`), which is the gate
working as designed — `CACHE_NAME` is `freightlogic-${SW_VERSION}` and the `?v=`
query is the only other identity a child asset carries, so an installed client
holding the `24.0.15` shell would never fetch the changed files. **CG-07 caught a
marker the manual pass missed** (`modern-shell.js`'s header), which is exactly
what item 16 machine-checks it for. All 14 CG assertions and
`--static-only` parity are green at `24.0.16`.

### One cross-lane blocker, not resolved in this lane

PR #227 added a `tests/run-all.mjs` row to `.agents/LANES.md` owned by **gpt**, as
an "exact exception limited to registering `field-certification-runner.spec.mjs`".
The Notes describe a narrow grant; the Owner column is what `lane-guard` reads,
and it reads `gpt`. That deadlocks with **RH-01**, which fails unless every spec
on disk is registered in `run-all.mjs`: a Claude regression cannot be registered
without editing a gpt-owned file, and not registering it fails RH-01. This is not
specific to this release — it blocks every future Claude regression.

Requested through `/.agents/inbox/claude-to-gpt-run-all-ownership-deadlock-2026-09-17.md`
rather than edited across lanes, and rather than editing the ownership map to
grant this lane a path another lane was granted three commits earlier. The four
registrations this release needs are on the branch and Lanes CI will reject that
one file until the row is narrowed.

### Not deployed

**Source-only.** v24.0.16 is not deployed and not live-observed. Worker v20 must
deploy **before** the app generation, as v18 did for v24.0.13: the app is
unchanged in what it calls, but a driver whose token index is stale gets a 403
only once v20 is serving, and the CORS narrowing must land with it. After
deploying, re-dispatch live parity rather than citing the push-triggered run,
which races the Cloudflare deploy — five recorded occurrences now.

`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-17.md` is the superseding
authority for the 24.0.15 production observation that issue #225 asked for, and
records this candidate as source-only.

**Still HOLD.** Physical iPhone A1-A12 and authentic M6 raw-data certification are
unchanged and remain the operator's.
