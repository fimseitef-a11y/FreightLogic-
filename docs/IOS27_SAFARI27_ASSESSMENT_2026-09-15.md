# iOS 27 / Safari 27 — what FreightLogic can actually use

Date: 2026-09-15
Scope: Issue #204, checked against primary sources and against this repository's own code.
Status: **assessment only.** No shipped file is changed by this document, and nothing here is a device observation.

iOS 27 and Safari 27 were released **2026-09-14**. Safari 27 ships 58 new features, 525 fixes and 4 deprecations — the largest fix count in a recent Safari release, and WebKit describes the release as weighted toward existing features behaving more correctly rather than toward new surface.

## How to read this document

Every row is labelled by how it was established:

- **PRIMARY** — stated by WebKit/Apple. Quoted or paraphrased from the source named.
- **CODE** — established by reading this repository at `4f2daf2`.
- **UNVERIFIED** — appears in secondary coverage only and is **not** relied on.

The one thing this document cannot do is observe behaviour on a device. Everything below that says "confirm on device" is exactly that, and belongs to the A-series checklist, not here.

## Correction first — the claim that is circulating and is wrong

**"iOS 27 expands PWA support with push notifications and background sync."** Several secondary outlets are carrying a version of this. The background-sync half is **false**.

- **PRIMARY:** no WebKit source for Safari 27 mentions the Background Sync API, Periodic Background Sync, or Background Fetch.
- Background Sync remains unsupported in Safari on iOS 27, and there is no signal it is coming.

This matters more to FreightLogic than any feature on the list, because Background Sync is the single API that would fix the app's most-documented real-world failure: cloud backup going inactive when the browser closes (v24.0.6, `cloudBackupPaused()`). **It is still not available.** The `renderCloudPausedBanner()` / `openCloudReconnect()` approach stays the correct answer, and nothing in iOS 27 makes it obsolete.

Web Push itself has been available for installed Home Screen web apps since iOS 16.4 and is not new in 27.

---

## 1. Customizable `<select>` — ADOPT (already in flight)

- **PRIMARY:** Safari 27 adds customizable select. `appearance: base-select` opts a select in; `::picker(select)`, `::picker-icon`, `::checkmark` and `<selectedcontent>` become styleable, while keyboard navigation, semantics and screen-reader support are preserved. WebKit explicitly recommends progressive enhancement.
- **CODE:** FreightLogic has **29 select elements** — 16 declared in `index.html` and 13 more built inside `app.js` via `innerHTML`. That is a larger surface than anyone has been treating it as, and it is the strongest argument for doing this at all.

**Assessment: worth it, and the risk is genuinely low** because the feature is opt-in per element. A browser without `@supports (appearance: base-select)` renders exactly what it renders today.

Two cautions that follow from this repo's own history rather than from WebKit:

1. The **≥16px mobile form-control rule is load-bearing** (v24.0.10 "Sixteen Pixels" — iOS zooms the viewport on focus of any control under 16px, which threw the driver out of the load they were pricing). `#mwCurrency` and `#mwModeSelector` were the two root-cause offenders and are both selects. Any restyle must not reintroduce a sub-16px computed size.
2. The 13 selects built inside `app.js` are **not** reachable from `styles.css` by id if they are styled inline. Check them, or the enhancement will look half-applied.

This is in PR #206 in the GPT lane. No objection from this lane; the `@supports` gating there is correct.

## 2. Scroll anchoring — FREE, already benefiting

- **PRIMARY:** Safari 27 adds scroll anchoring, which prevents visual jumps when content loads above the viewport. It is automatic browser behaviour; a page only loses it by opting out with `overflow-anchor: none`.
- **CODE:** independently re-checked across `styles.css`, `index.html`, `app.js` and `modern-shell.js` — **`overflow-anchor` does not appear anywhere in the repository.**

**Assessment: nothing to do, and nothing should be done.** FreightLogic gets this automatically. Adding `overflow-anchor` rules to "claim" the feature would be pure churn, and could only make things worse. The surfaces that stand to gain are the ones that inject content above existing rows — Smart Load Inbox recent pastes, Trips, Expenses.

Issue #204 already had this checked. The check is confirmed, not merely repeated.

## 3. Service Worker Static Routing API — **NOT YET APPLICABLE**

This is the item issue #204 asked to inventory, and the inventory produces a clear answer.

- **PRIMARY:** Safari 27 adds the Service Worker Static Routing API. `InstallEvent.addRoutes()` declares routing rules the browser applies **before service-worker startup**, so selected requests can bypass the worker entirely. The stated benefit is reduced overhead for high-performance PWAs.

**CODE — the inventory.** `service-worker.js`'s fetch handler opens with two early returns, before any `respondWith`:

```js
if (req.method !== 'GET') return;
if (url.origin !== self.location.origin) return;
```

So every candidate request class is **already** falling through to the network untouched:

- all cross-origin traffic, which is the entire backup/API surface — `POST /backup`, `POST /backup/delta`, `GET /backup`, `POST /evaluate`, `POST /extract`, `GET /status` against `freightlogic-backup.fimseitef.workers.dev`;
- all non-GET same-origin traffic, except the deliberately handled share-target POST.

Every remaining same-origin GET is a precached shell asset, which is exactly what must **not** bypass the worker.

**Assessment: the semantic benefit is already achieved; only service-worker cold-start latency remains, and it is not worth the risk here.**

1. **The win is small and invisible.** A static route would save spinning up the worker before a request that is already a multi-hundred-millisecond round trip to Cloudflare. A driver cannot perceive that.
2. **The risk is concentrated in the worst possible file.** `install` is `event.waitUntil(async () => { … })` around an `await cache.addAll(critical)` whose failure is deliberately allowed to abort install. A rejected `addRoutes` promise inside that block is an install-abort path, and "failure to register a route must not abort install" would have to be proved, not assumed.
3. **The gate that would catch a mistake runs only against production.** `verify-production-sw.mjs` asserts exact offline semantics — `504 text/plain` on a subresource miss, query-insensitive self-heal on a known asset, one generation cache — against the deployed origin. A defect introduced here is observable only *after* deploying it to the operator.
4. **Safari 27 is a first implementation**, days old, on a file this repository has already had to repair twice for subtle response-type defects (v24.0.4 item 4, and the CG-05 HTML-for-a-subresource shape).

Record **NOT YET APPLICABLE** and close the checkbox. This is a real outcome, not a deferral: the API exists to solve a problem FreightLogic solved differently and already does not have.

Revisit only if a same-origin, network-only, high-frequency request class ever appears — there is none today.

## 4. ReadableStream improvements — AVAILABLE, no qualifying hot path

- **PRIMARY:** Safari 27 adds three ReadableStream improvements: async iteration with `for await...of`, `ReadableStream.from()`, and transferable streams.

**CODE — the audit issue #204 asked for**, over the large-payload paths:

| Path | Verdict | Why |
|---|---|---|
| Excel import (`loadSheetJS`, `vendor/xlsx.full.min.js`) | No | SheetJS parses a complete `ArrayBuffer`. It has no streaming entry point, so a stream would be materialised right back into a buffer. |
| JSON export/import (`LIMITS.MAX_IMPORT_BYTES` 30MB) | No | `exportJSON()` computes `checksumFull` over the whole payload, and the protected checksum covers lifecycle and evidence. A checksum over the whole document requires the whole document. |
| Cloud backup encrypt/decrypt | No | `crypto.subtle.encrypt`/`decrypt` are not streaming APIs. They take and return complete buffers. |
| Receipt blobs | No | Already `Blob`/Cache API; bounded by `MAX_RECEIPT_BYTES` 6MB and `MAX_RECEIPT_CACHE` 40. |

**Assessment: mark available-for-future and write no code.** Every candidate path ends at an API that needs the whole buffer, so streaming would add a layer without removing a materialisation. Issue #204's own instruction — *"Do not rewrite stable code simply to use a new API"* — is the right call, and the audit is now done rather than pending.

`for await...of` over a `ReadableStream` is still worth remembering as a readability win if a genuinely streaming path is ever added, and it removes a real Safari-only failure mode (WebKit previously had no `Symbol.asyncIterator` on `ReadableStream`, which broke libraries that assumed it).

## 5. The 525 fixes are the part nobody has planned for — **NEW, needs device evidence**

This is not on issue #204's list and it is the item this assessment most wants to add.

- **PRIMARY:** Safari 27 contains **30 SVG fixes**, including changes based on recent SVG 2 decisions, and WebKit characterises the whole release as existing features *behaving differently — more correctly — than before*.
- **CODE:** FreightLogic renders **hand-built SVG** in two places that a driver looks at constantly:
  - **F31 Earnings Trends** — `renderEarningsTrends()` is a pure SVG bar chart *"(no canvas)"*, built from `<rect>` bars with a `<polyline>` net-overlay line and `<text>` labels.
  - **The driver tab bar** — `modern-shell.js` and `index.html` carry inline `<svg>` nav icons with explicit `stroke-width`, sized by CSS.

A correctness fix is still a rendering change. Chart geometry, text placement, or icon stroke rendering can move, and **none of it is visible to this repository's gates**: the six-width layout spec asserts no horizontal overflow and interactive geometry, not that a bar chart looks right, and the production service-worker gate asserts delivery and offline semantics, not pixels.

**Assessment: add an explicit iOS 27 visual regression check to the physical-device checklist.** It costs one screen each and it is the only way this class of change gets caught. Done in `FIELD_TEST_CHECKLIST.md` in the same change as this document.

The same reasoning applies to Apple's claim that Safari 27 improves JavaScript performance, web-app loading and animation efficiency — plausible and welcome for a 1.1MB single-IIFE app, but it is a vendor claim, not a measurement, and this document does not treat it as evidence either way.

## 6. Storage and the seven-day cap — UNCHANGED, and already handled

Worth stating because it is the highest-stakes iOS behaviour for a bookkeeping app, and because nothing in iOS 27 changes it.

- **PRIMARY/BACKGROUND:** Safari's ITP applies a seven-day cap to script-writable storage — IndexedDB included — after seven days of *Safari use* without user interaction with the site. For a **Home Screen web app** the counter is effectively never reached, because launching the app is interaction with that site. `navigator.storage.persist()` is the documented mitigation.
- **CODE:** `requestPersistentStorage()` (`app.js:602`) calls `navigator.storage.persist()` and is invoked at boot (`app.js:21227`), with `checkStorageQuota()` alongside it. ITP/Safari detection already exists.

**Assessment: no change needed, but one device check is worth adding** — confirm `navigator.storage.persisted()` actually returns `true` on iOS 27 for the installed app. It is one line in Diagnostics and it is the difference between believing the data is durable and knowing it.

## 7. Everything else in Safari 27 — not applicable, recorded so it is not re-litigated

| Feature | Why not |
|---|---|
| Grid Lanes (CSS masonry) | FreightLogic's surfaces are single-column lists and a two-column `.grid2`. A masonry layout would be harder to scan one-handed in a vehicle, not easier. |
| `<model>` element (3D) | No 3D content. |
| WebAssembly JSPI | No WebAssembly. |
| Transform-aware anchor positioning | The app uses no anchor positioning. Possible future value for popovers; nothing to change today. |
| `:heading`, `revert-rule`, `stretch` | Minor CSS conveniences, `styles.css` lane, no behaviour at stake. |
| Digital Credentials API (added 26, fixed in 27) | Identity-document presentment. No use case; adopting it would widen the privacy surface of a financial app for nothing. |
| Safari MCP server | macOS developer tooling, not an iPhone runtime API. Useful for QA, and explicitly **not** a substitute for A1-A10 on a device. |

## What this changes in the repository

- `FIELD_TEST_CHECKLIST.md` gains an iOS 27 regression section — the SVG/chart and tab-bar visual check, and the persisted-storage confirmation.
- Issue #204's Static Routing and ReadableStream checkboxes are answerable now: **NOT YET APPLICABLE** and **available-for-future, no code**, both with the inventory behind them.
- Nothing else. No shipped file changes, so no release generation moves.

## What this deliberately does not do

It does not touch the native-capability half of issue #204 — App Intents, Siri, Foundation Models, Spotlight, widgets, Live Activities. Those need a native target that does not exist, and the issue's own guardrail is "no Swift rewrite". The correct sequence is to keep the deterministic engine authoritative in the PWA and add a bounded bridge later; nothing in Safari 27 changes that sequencing, and nothing in this assessment should be read as starting it.
