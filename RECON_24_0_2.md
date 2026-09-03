# RECON_24_0_2.md — Read-Only State Reconciliation

**Mode:** read-only forensic audit. Nothing was modified, staged, committed, or pushed.
**Tree audited:** `c04b48a2aa6e5c3b1264c5ef26bec5ae406f871d` (== `origin/main`), working tree clean.
**Date of audit:** 2026-09-03.
**Method:** static source reading, plus live execution of the shipped files where a claim
needed proof — the real `midwest-stack-authority.js` evaluated in Node with DOM stubs, and
the real app driven in headless Chromium (Playwright 1.62.x / Chromium 1194) served from
this working tree over read-only HTTP. Every browser probe ran against unmodified files.

> Note on the prompt's framing: the audit found the premise "CLAUDE.md at main describes
> v23.8.2" and "does not mention vendor/" to be **REFUTED** at HEAD (see A2/A4-notes). The
> `styles.css` half of that premise is **CONFIRMED**. Prompt item **G5 arrived truncated**
> ("G5. Count") and could not be executed — see the closing section.

---

# BLOCK A — INVENTORY & VERSION STATE

## A1 — git state

```
$ git log --oneline -15
c04b48a Merge PR #137: merge-restore TOCTOU, strictly-increasing revisions, and test determinism
c917bd9 [claude] detach the service worker before seeding a versioned cache
1ce740f [claude] wait for every Diagnostics row the tests read
1332736 [claude] make the revision stamp strictly increase
4b5f25a [claude] settle the live-weather domain before M3R-07 compares
8f22462 [claude] assert the merge-restore invariant against source, not the engine
dfa8d2b [claude] close the merge-restore read/write TOCTOU
0282cf1 Merge PR #136: report install identity in Diagnostics
466df22 Merge PR #135: record merged v24.0.2 update-path repair
cc9c19a [claude] report install identity in Diagnostics
4fc4881 [gpt] record merged update-path repair
b300b08 [gpt] record merged update-path repair
f19984e [gpt] record merged update-path repair
fc51067 Merge PR #134: repair the service-worker update handshake (A1 field failure)
120128f [claude] repair the service-worker update handshake (A1 field failure)

$ git status --short
(empty — clean)

$ git branch -a
* claude/freightlogic-v24-recon-l9h6gd
  main
  remotes/origin/claude/freightlogic-v24-recon-l9h6gd
  remotes/origin/main
```

`HEAD` = `origin/main` = `c04b48a`. The **local** `main` ref is stale at `3fba27a`; the
checked-out branch is identical to `origin/main`, so all findings below are against the
current remote `main`.

## A2 — inventory

Root (`ls -la`, dotfiles included) contains, in addition to the icons:
`.agents/`, `.assetsignore`, `.git/`, `.githooks/`, `.github/`, `.gitignore`, `AGENTS.md`,
`AUDIT_REPORT.md`, `CLAUDE.md`, `FIELD_TEST_CHECKLIST.md`, `README.txt`, `_headers`,
`admin-driver-ui.js`, `app.js` (1,104,633 B), `cloud-backup-worker.js`, `dat-rateview.js`,
`docs/`, `index.html`, `manifest.json`, `midwest-stack-authority.js`,
`midwest-stack-config.json`, `schemas/`, `scripts/`, `service-worker.js`,
`styles.css` (50,460 B), `sw-bridge.js`, `tests/`, `vendor/`, `voice-load.js`,
`wrangler.jsonc`.

Requested presence/absence:

| Item | Verdict |
|---|---|
| `tests/` | **CONFIRMED PRESENT** — 43 files, 32 spec files |
| `.github/` | **CONFIRMED PRESENT** |
| `.github/workflows/` | **CONFIRMED PRESENT** — `tests.yml`, `lanes.yml` |
| `styles.css` | **CONFIRMED PRESENT** — 50,460 B |
| `vendor/` | **CONFIRMED PRESENT** — `xlsx.full.min.js` (881,727 B) + `.LICENSE` |
| `AUDIT_REPORT.md` | **CONFIRMED PRESENT** — 63,057 B |
| `AGENTS.md` | **CONFIRMED PRESENT** — 9,519 B (repo root) |
| `LANES.md` | **NOT PRESENT** at repo root — it exists as `.agents/LANES.md` (5,496 B) |
| `MIDWEST_STACK_CANONICAL_v7.md` | **NOT PRESENT** anywhere in the tree |
| `rate-overrides-2026-05.json` | **NOT PRESENT** |
| `rate-overrides-2026-07.json` | **NOT PRESENT** |

Also present and undocumented in `CLAUDE.md`'s File Structure block: `.github/V24_BANK_REPAIR_TRIGGER`
(content: `PR #76 guarded repair trigger. Remove after v24.0.1 release gate is complete.`),
`docs/ancs-poc/` (`README.md`, `forwarder.c`, `forwarder.h`).

`docs/` — 20 files + `ancs-poc/`. `schemas/` — 3 files. `scripts/` — 5 files
(`lane-guard.mjs`, `m6-import.mjs`, `m7-certify.mjs`, `verify-cloudflare-parity.mjs`,
`verify-live-authority.mjs`).

`dat-rateview.js` (8,805 B) is in the tree and is **referenced by nothing** —
`grep -rn "dat-rateview"` across `*.html *.js *.json *.mjs` returns only the file itself.

## A3 — version sweep (raw output)

```
$ grep -rno "2[0-9]\.[0-9]\+\.[0-9]\+" app.js index.html manifest.json \
    service-worker.js midwest-stack-authority.js sw-bridge.js voice-load.js \
    admin-driver-ui.js styles.css 2>/dev/null | awk -F: '{print $1" -> "$3}' | sort -u
app.js -> 20.0.0
app.js -> 21.0.0
app.js -> 21.3.0
app.js -> 22.0.0
app.js -> 23.0.0
app.js -> 23.1.0
app.js -> 23.4.0
app.js -> 23.4.1
app.js -> 23.7.0
app.js -> 23.8.0
app.js -> 23.8.1
app.js -> 23.8.2
app.js -> 23.8.3
app.js -> 23.8.4
app.js -> 23.9.1
app.js -> 24.0.0
app.js -> 24.0.1
app.js -> 24.0.2
index.html -> 24.0.2
manifest.json -> 24.0.2
midwest-stack-authority.js -> 23.8.3
midwest-stack-authority.js -> 24.0.2
service-worker.js -> 24.0.2
styles.css -> 24.0.0
sw-bridge.js -> 24.0.2
voice-load.js -> 24.0.2
```

`admin-driver-ui.js` emits nothing — `grep -n "VERSION\|v2[0-9]\."` on it returns no
matches; it carries no version marker of any kind. The `app.js` pre-24.0.2 hits and the
`midwest-stack-authority.js -> 23.8.3` hit are historical changelog prose, which
`CLAUDE.md:293` explicitly sanctions ("Historical changelog comments in `app.js`
legitimately name older versions — leave those alone").

## A4 — bump-location table

`CLAUDE.md`'s checklist now enumerates **14** locations, not 10. All are reported, plus
locations the checklist does not cover.

| # | Location | Expected 24.0.2 | Actual | DRIFT |
|---|---|---|---|---|
| 1 | `app.js` `APP_VERSION` + header | `24.0.2` | `app.js:92` `const APP_VERSION = '24.0.2';`; `app.js:4` `/** FreightLogic v24.0.2 USA ENGINE` | N |
| 2 | `service-worker.js` `SW_VERSION` + header | `24.0.2` | `service-worker.js:2` `const SW_VERSION = '24.0.2';`; `:1` `/* FreightLogic v24.0.2 — Browser Hardened Service Worker */` | N |
| 3 | SW `?v=` — `ADMIN_UI_TAG`, `MIDWEST_STACK_TAG`, every `CORE` entry | `24.0.2` | all `24.0.2` (see B1) | N |
| 4 | `manifest.json` `name` | `FreightLogic v24.0.2` | `manifest.json:2` `"name": "FreightLogic v24.0.2",` | N |
| 5 | `index.html` `<link rel="manifest">` `?v=` | `24.0.2` | `index.html:19` `<link rel="manifest" href="manifest.json?v=24.0.2">` | N |
| 6 | `index.html` `?v=` on app.js / voice-load.js / sw-bridge.js | `24.0.2` | `index.html:575-577`, all `?v=24.0.2` | N |
| 7 | Design-system header comment near top of `index.html` | `24.0.2` | **No design-system comment exists in `index.html` at all** (lines 1–18 verified). The comment now lives in `styles.css:2` and reads `FREIGHT LOGIC v24.0.0 — DESIGN SYSTEM v3.0 "Command"` | **Y** |
| 8 | `midwest-stack-authority.js` `VERSION` + header | `24.0.2` | `:8` `const VERSION = '24.0.2';`; `:1` `/* FreightLogic Midwest Stack v11 / Level X+ Advisory Overlay v24.0.2` | N |
| 9 | Headers in `voice-load.js`, `sw-bridge.js` | `24.0.2` | `voice-load.js:1` `/* FreightLogic v24.0.2 — Voice Load Module */`; `sw-bridge.js:1` `/* FreightLogic v24.0.2 — service worker update bridge */` | N |
| 10 | `CLAUDE.md` Overview / Key Constants / PWA | `24.0.2` | `CLAUDE.md:5` `**FreightLogic v24.0.2**`; `:120` `const APP_VERSION = '24.0.2';`; `:238` `version \`24.0.2\`` | N |
| 11 | `scripts/verify-cloudflare-parity.mjs` `EXPECTED` | `24.0.2` / Worker `13` | `:24-27` `serviceWorkerVersion: "24.0.2"`, `manifestName: "FreightLogic v24.0.2"`, `workerVersion: "13"`, `overlayScript: "midwest-stack-authority.js?v=24.0.2"` | N |
| 12 | CSP byte-identity `index.html` ↔ `_headers` | identical | 496 B each, `diff` clean, script prints `PASS index.html and _headers CSP are byte-identical` | N |
| 13 | `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` | `24.0.2` / DB `15` / Worker `13` | line 13 `- App / PWA / service worker: **\`24.0.2\`**`, `- IndexedDB schema: **\`15\`**`, `- Cloudflare Worker: **\`13\`**` | N |
| 14 | SW `critical` array contains overlay + vendor xlsx | both present | `service-worker.js:57` contains `'./midwest-stack-authority.js?v=24.0.2'` and `'./vendor/xlsx.full.min.js'` | N |

**Locations the checklist does NOT cover:**

| Location | Expected | Actual | DRIFT |
|---|---|---|---|
| `styles.css` header | `24.0.2` | `styles.css:2` `FREIGHT LOGIC v24.0.0 — DESIGN SYSTEM v3.0 "Command"` | **Y** |
| `midwest-stack-config.json` `appTarget` | `24.0.2` | `:3` `"appTarget": "FreightLogic v24.0.0",` | **Y** |
| `vendor/xlsx.full.min.js` | n/a — third-party (SheetJS 0.18.5) | no FreightLogic version marker | N/A |
| `_headers` | n/a — no version string; only the CSP (item 12) | — | N/A |
| `admin-driver-ui.js` | injected as `?v=24.0.2` by the SW, but the file itself carries **no** version marker | — | Uncovered |
| `dat-rateview.js` | — | no version marker; file is unreferenced | N/A |

**CLAUDE.md currency — direct answers to the prompt's premise:**

- "CLAUDE.md at main describes v23.8.2" — **REFUTED.** `CLAUDE.md:5` reads
  `**FreightLogic v24.0.2** is a production-ready PWA…`, and the file carries dedicated
  v24.0.1 and v24.0.2 sections.
- "does not mention vendor/" — **REFUTED.** `CLAUDE.md:35-38`, `:51-53`, `:238`, `:286` all
  reference `vendor/xlsx.full.min.js`.
- "does not mention styles.css" — **CONFIRMED.** `grep -n "styles.css" CLAUDE.md` returns
  **zero** matches, while `index.html:29` reads `<link rel="stylesheet" href="styles.css">`
  and `service-worker.js:13` precaches `'./styles.css'`. Worse, `CLAUDE.md:18` still
  asserts `index.html — Single-page app shell + all CSS`, which the 50,460-byte
  `styles.css` refutes. The File Structure block also omits `dat-rateview.js`, `AGENTS.md`,
  `.agents/`, `.githooks/`, `.github/`, `.assetsignore`, and names only 1 of the 5 files in
  `scripts/`.

## A5 — verbatim

```
app.js:92
const APP_VERSION = '24.0.2';

service-worker.js:2
const SW_VERSION = '24.0.2';
```

---

# BLOCK B — SERVICE WORKER / OFFLINE INTEGRITY

## B1 — `CORE`, `ADMIN_UI_TAG`, `MIDWEST_STACK_TAG` verbatim

```js
// service-worker.js:7-24
const ADMIN_UI_TAG = '<script src="admin-driver-ui.js?v=24.0.2"></script>';
const MIDWEST_STACK_TAG = '<script src="midwest-stack-authority.js?v=24.0.2"></script>';
const CORE = [
  './', APP_SHELL,
  './app.js?v=24.0.2',
  './voice-load.js?v=24.0.2',
  './styles.css',
  './admin-driver-ui.js?v=24.0.2',
  './midwest-stack-authority.js?v=24.0.2',
  './manifest.json?v=24.0.2',
  './midwest-stack-config.json',
  // X-10: SheetJS is now bundled (no CDN fallback) — precache it so Excel
  // import works fully offline from the very first install.
  './vendor/xlsx.full.min.js',
  './icon64.png','./icon128.png','./icon192.png','./icon256.png','./icon512.png',
  './icon180.png','./icon167.png','./icon152.png','./icon120.png','./icon1024.png','./favicon32.png','./favicon16.png',
  './sw-bridge.js?v=24.0.2'
];
```

(`APP_SHELL` is `'./index.html'`, `service-worker.js:6`.)

## B2 — CORE query vs. what `index.html` actually requests

| Asset | CORE query | index.html query | MATCH |
|---|---|---|---|
| `app.js` | `?v=24.0.2` (`sw:11`) | `?v=24.0.2` (`index.html:575`) | **Y** |
| `voice-load.js` | `?v=24.0.2` (`sw:12`) | `?v=24.0.2` (`index.html:576`) | **Y** |
| `sw-bridge.js` | `?v=24.0.2` (`sw:23`) | `?v=24.0.2` (`index.html:577`) | **Y** |
| `manifest.json` | `?v=24.0.2` (`sw:16`) | `?v=24.0.2` (`index.html:19`) | **Y** |
| `styles.css` | *(no query)* (`sw:13`) | *(no query)* (`index.html:29`) | **Y** |
| `admin-driver-ui.js` | `?v=24.0.2` (`sw:14`) | not in `index.html`; requested only via `ADMIN_UI_TAG` `?v=24.0.2` (`sw:7`) | **Y** |
| `midwest-stack-authority.js` | `?v=24.0.2` (`sw:15`) | not in `index.html`; requested only via `MIDWEST_STACK_TAG` `?v=24.0.2` (`sw:8`) | **Y** |
| icons / `midwest-stack-config.json` / `vendor/xlsx.full.min.js` | no query | referenced with no query | **Y** |

**Verdict: no mismatch at HEAD.** Verified in a live browser — the versioned cache
`freightlogic-24.0.2` holds exactly the CORE URLs, including
`http://…/app.js?v=24.0.2`, and `cache.match('app.js?v=24.0.2')` hits
(`{hit:true, ct:"application/javascript", len:1084764}`).

## B3 — fetch handler

```js
// service-worker.js:96-161
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method === 'POST' && (url.pathname.endsWith('index.html') || url.pathname.endsWith('/share-target') || url.pathname.endsWith('share-target'))) {
    event.respondWith((async () => {
      try {
        const formData = await req.formData();
        const files = formData.getAll('receipts');
        if (files && files.length) {
          const shareCache = await caches.open(SHARE_CACHE);
          await shareCache.put('/shared-meta', new Response(
            JSON.stringify({ count: files.length, ts: Date.now() }),
            { headers: { 'Content-Type': 'application/json' } }
          ));
          const ALLOWED_SHARE_TYPES = new Set(['image/jpeg','image/png','image/webp','image/gif','application/pdf','image/heic','image/heif']);
          for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const contentType = ALLOWED_SHARE_TYPES.has(file.type) ? file.type : 'application/octet-stream';
            await shareCache.put(`/shared-file-${i}`, new Response(file, { headers: { 'Content-Type': contentType, 'X-Filename': file.name } }));
          }
        }
      } catch {}
      return Response.redirect('./index.html#share', 303);
    })());
    return;
  }

  if (req.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;

  const isAppLogic = req.mode === 'navigate' || url.pathname.endsWith('.js') || url.pathname.endsWith('.html');
  const isStatic = /\.(json|png|ico|md)$/i.test(url.pathname);

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    if (isAppLogic) {
      try {
        const res = await fetch(req);
        const out = (req.mode === 'navigate' || url.pathname.endsWith('.html')) ? await injectEnhancementScripts(res.clone()) : res;
        if (res && res.ok) cache.put(req, out.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
        return out;
      } catch {
        const cached = (await cache.match(req)) || (await cache.match(APP_SHELL));
        if (!cached) return new Response('Offline — no cached page available', { status: 503, headers: { 'Content-Type': 'text/plain' } });
        return (req.mode === 'navigate' || url.pathname.endsWith('.html')) ? await injectEnhancementScripts(cached) : cached;
      }
    }
    if (isStatic) {
      const cached = await cache.match(req, { ignoreSearch: true });
      if (cached) return cached;
      try {
        const res = await fetch(req);
        if (res && res.ok) cache.put(req, res.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
        return res;
      } catch {
        return cached || (await cache.match(APP_SHELL));
      }
    }
    try {
      return await fetch(req);
    } catch {
      return (await cache.match(req)) || (await cache.match(APP_SHELL));
    }
  })());
});
```

**Which branch handles `.js` and `.html`?** The `isAppLogic` branch
(`service-worker.js:127`, `132-143`):
`const isAppLogic = req.mode === 'navigate' || url.pathname.endsWith('.js') || url.pathname.endsWith('.html');`
It is **network-first** — `fetch(req)` is attempted before any cache read.

**Does its cache lookup pass `{ ignoreSearch: true }`?** **NO.** Exact call,
`service-worker.js:139`:

```js
        const cached = (await cache.match(req)) || (await cache.match(APP_SHELL));
```

`{ ignoreSearch: true }` appears **exactly once** in the file, on the `isStatic` branch
(`service-worker.js:145`): `const cached = await cache.match(req, { ignoreSearch: true });`.
Since `isAppLogic` is evaluated first and `.js`/`.html` never reach `isStatic`, app logic
never gets that option.

**Consequence trace.** The prompt's conditional ("if `ignoreSearch` is absent AND B2 shows
any mismatch") — `ignoreSearch` **is** absent, but B2 shows **no** mismatch, so the
condition is **NOT MET at HEAD**. The mechanism is nonetheless real and was traced
end-to-end against the shipped worker by killing the origin server (a genuine network
failure, not emulation) and probing through the SW:

Cache-API ground truth, same session:
```
cache.match('app.js?v=24.0.2')                      -> { hit:true,  ct:"application/javascript", len:1084764 }
cache.match('app.js?v=99.9.9')                      -> { hit:false }
cache.match('app.js?v=99.9.9', {ignoreSearch:true}) -> { hit:true,  ct:"application/javascript", len:1084764 }
cache.match('app.js')                               -> { hit:false }
cache.match('./index.html')                         -> { hit:true,  ct:"text/html", len:51338 }
```

Through the real handler with the origin dead:
```
fetch('app.js?v=24.0.2') -> 200  application/javascript  1084764 B  "(() => { 'use strict';  /** FreightLogic v24.0.2 USA EN"
fetch('app.js?v=99.9.9') -> 200  text/html                 51338 B  "<!doctype html> <html lang=\"en\"> <head>   <meta charset"
fetch('app.js')          -> 200  text/html                 51338 B  "<!doctype html> <html lang=\"en\"> <head>   <meta charset"
fetch('dat-rateview.js') -> 200  text/html                 51338 B  "<!doctype html> <html lang=\"en\"> <head>   <meta charset"
```

So the trace is: **cache miss on the exact key → `cache.match(APP_SHELL)` hits →
`req.mode` is `script` and the pathname does not end in `.html`, so line 141 returns
`cached` unwrapped → the browser receives `HTTP 200` with `Content-Type: text/html` and a
51,338-byte HTML document in response to a `<script src>`.** Strict MIME checking refuses
to execute it; the script silently does not run and there is no 404 or 503 to signal it.
**Verdict: PARTIALLY CONFIRMED — the hazard is real and demonstrated, but it is not armed
at 24.0.2 because every `?v=` currently agrees.** It arms the moment one `?v=` marker
drifts between `index.html` and the SW arrays — the drift `CLAUDE.md:266-267` says has
"silently drifted in past releases".

## B4 — does the fetch handler cache un-precached same-origin `.js`?

**CONFIRMED — yes.** `service-worker.js:136`:

```js
        if (res && res.ok) cache.put(req, out.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
```

There is no allowlist, no key check, and no entry cap on this path. Proven live: before the
probe the `freightlogic-24.0.2` cache held **25** entries; after one
`fetch('dat-rateview.js')` — a same-origin `.js` that is **not** in `CORE` — it held **26**,
the new entry being `http://127.0.0.1:33403/dat-rateview.js`.

**Bounded or unbounded?** Unbounded per version, bounded across versions. There is no
per-entry or per-count limit inside the cache (contrast `enforceReceiptCacheLimit()` /
`LIMITS.MAX_RECEIPT_CACHE` for receipts). It is only ever emptied wholesale by the
`activate` handler deleting non-matching cache names (`service-worker.js:69-71`,
`await Promise.all(keys.map(k => keep.has(k) ? null : caches.delete(k)));`), i.e. on a
`SW_VERSION` bump. Any same-origin `.js`/`.html` URL the app fetches — including
query-string variants of the same file — accumulates until the next version bump.

## B5 — injection functions verbatim

```js
// service-worker.js:26-46
function injectBeforeBodyClose(html, tag) {
  if (html.includes(tag) || html.includes(tag.replace(/\?v=[^"']+/, '?v='))) return html;
  return html.includes('</body>') ? html.replace('</body>', `  ${tag}\n</body>`) : `${html}\n${tag}`;
}

async function injectEnhancementScripts(res) {
  try {
    if (!res || !res.ok) return res;
    const type = (res.headers.get('content-type') || '').toLowerCase();
    if (!type.includes('text/html')) return res;
    let text = await res.text();
    if (!text.includes('admin-driver-ui.js?v=')) text = injectBeforeBodyClose(text, ADMIN_UI_TAG);
    if (!text.includes('midwest-stack-authority.js?v=')) text = injectBeforeBodyClose(text, MIDWEST_STACK_TAG);
    const h = new Headers(res.headers);
    h.delete('Content-Length');
    return new Response(text, { status: res.status, statusText: res.statusText, headers: h });
  } catch (err) {
    console.warn('[FL-SW] Enhancement script injection failed:', err);
    return res;
  }
}
```

**Which scripts, under what conditions.** Two: `admin-driver-ui.js?v=24.0.2` and
`midwest-stack-authority.js?v=24.0.2`. Conditions, all of which must hold: the response is
truthy and `res.ok`; its `content-type` contains `text/html`; and the body does not already
contain `admin-driver-ui.js?v=` / `midwest-stack-authority.js?v=` respectively. Call sites
are `service-worker.js:135` (network path) and `:141` (cache-fallback path), each gated on
`req.mode === 'navigate' || url.pathname.endsWith('.html')`. Any thrown error is swallowed
and the **uninjected** response is returned (`:42-45`).

## B6 — `sw-bridge.js`

```js
/* FreightLogic v24.0.2 — service worker update bridge */
(function(){
  if (!('serviceWorker'in navigator)) return;

  let reloading = false;
  let skipWaitingRequested = false;
  let fallbackTimer = null;

  const reloadOnce = () => {
    if (!skipWaitingRequested || reloading) return;
    reloading = true;
    if (fallbackTimer){ clearTimeout(fallbackTimer); fallbackTimer = null; }
    window.location.reload();
  };

  // Only reload when we triggered SKIP_WAITING — not on first-install controllerchange
  navigator.serviceWorker.addEventListener('controllerchange', reloadOnce);

  // Expose for app.js "New version available" banner.
  //
  // Targets the WAITING worker, not `navigator.serviceWorker.controller`. The
  // controller is the OLD, already-active worker: its `skipWaiting()` is a
  // no-op, so the new version never takes over and the driver stays on the
  // version they already had. A caller that already holds the new worker (from
  // its own `updatefound` handler) should pass it, because `registration
  // .waiting` is not always populated at the moment the button is clicked.
  window._flRequestSWUpdate = async (worker) => {
    // Set FIRST: the flag is what tells the controllerchange handler above that
    // this reload was asked for. Activation can win the race against an await.
    skipWaitingRequested = true;
    let target = worker || null;
    if (!target){
      try {
        const reg = await navigator.serviceWorker.getRegistration();
        target = reg && (reg.waiting || reg.installing);
      } catch (e){ console.warn('[FL] SW update: registration lookup failed:', e); }
    }
    if (target) target.postMessage({ type: 'SKIP_WAITING' });
    // If the handshake never completes — the message is lost, the worker is
    // already gone, or activation fires no controllerchange — reload anyway
    // rather than leaving the app pinned to a version the driver was just told
    // is out of date. `reloadOnce` keeps this to exactly one reload whichever
    // path gets there first.
    if (fallbackTimer) clearTimeout(fallbackTimer);
    fallbackTimer = setTimeout(reloadOnce, 3000);
    return !!target;
  };

  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.getRegistration();
      if (!registration) return;
      // Skip immediate update() on load — browser already checked on navigation.
      setInterval(() => {
        registration.update().catch((e) => console.warn('[FL] periodic SW update failed:', e));
      }, 5 * 60 * 1000);
    } catch (e) {
      console.warn('[FL] service worker bridge init failed:', e);
    }
  });
})();
```

**Does it inject `voice-load.js` at runtime via `createElement('script')`?**
**REFUTED — NOT PRESENT.** The string `createElement('script')` does not occur in
`sw-bridge.js` at all. Across every shipped script it occurs exactly once, in `app.js:3761`,
inside `loadScriptWithFallback(urls, validate, finalError)` — the SheetJS/Tesseract loader,
which never loads `voice-load.js`.

Every reference to `voice-load.js` in the whole tree:
```
./app.js:11112:  // F10: Voice input handled by voice-load.js (loaded after app.js)
./app.js:17218:// Handled by voice-load.js with full draft review workflow, spoken number
./index.html:576:  <script src="voice-load.js?v=24.0.2"></script>
./scripts/verify-cloudflare-parity.mjs:108:  assert(checks, 'Index references voice-load.js v24.0.2', index.text.includes('voice-load.js?v=24.0.2'));
./service-worker.js:12:  './voice-load.js?v=24.0.2',
./service-worker.js:57:    const critical = ['./', APP_SHELL, './app.js?v=24.0.2', './voice-load.js?v=24.0.2', ...];
```
The two `app.js` hits are comments. **`voice-load.js` is loaded exactly once, by
`index.html:576`, at `?v=24.0.2`. It cannot be loaded twice.** Confirmed live: the DOM after
an SW-controlled reload contains exactly one `voice-load.js?v=24.0.2` script element.

## B7 — can the executing script set differ between first load and SW-controlled reload?

**CONFIRMED — yes.** Evidence, both from the same live session:

First load (no SW controlling yet) — every `script[src]` in the DOM:
```json
["app.js?v=24.0.2", "voice-load.js?v=24.0.2", "sw-bridge.js?v=24.0.2"]
```

After the SW installed, activated, claimed, and the page reloaded through it
(`navigator.serviceWorker.controller` truthy):
```json
["app.js?v=24.0.2", "voice-load.js?v=24.0.2", "sw-bridge.js?v=24.0.2",
 "admin-driver-ui.js?v=24.0.2", "midwest-stack-authority.js?v=24.0.2"]
```
and `typeof window.FreightLogicMidwestStack` went from `undefined` to `"object"`.

Root cause: `grep -n "admin-driver-ui\|midwest-stack" index.html` returns **no matches** —
neither script is in the served HTML. They exist only as
`service-worker.js:7-8` string constants injected by `injectEnhancementScripts()`
(`:37-38`), which only runs for responses the SW itself serves. On a first visit, an
uninstalled/unregistered SW, or a browser where SW registration failed
(`app.js:20369` `.catch(()=>{})` swallows it silently), the TRUE_RPM advisory overlay and
the entire admin UI are simply absent, with no error surfaced.

This is also why `midwest-stack-authority.js`'s own DZ gate has a fail-closed branch for
the reverse ordering (`midwest-stack-authority.js:331-335`: *"app.js not loaded yet /
injection-order issue — fail closed"*).

---

# BLOCK C — DECISION ENGINE: UNKNOWN-INPUT HANDLING

## C1 — `naLookupMarket('')`

`naLookupMarket()` still exists, at `app.js:7795`. Verbatim, with its normalizer:

```js
// app.js:7787-7810
/** Normalize Canadian city names */
function caNormCity(s){
  return (s || '').trim().toLowerCase()
    .replace(/,?\s*(on|qc|bc|ab|mb|sk|nb|ns|pe|nl|nt|yt|nu|ont|que|canada)\s*$/i, '')
    .replace(/[.,;]/g, '').replace(/\s+/g, ' ').trim();
}

/** Lookup a city — check Canada first, then USA. Returns { city, ...data, country } */
function naLookupMarket(city){
  const norm = caNormCity(city);
  // Direct match in Canada
  if (CA_MARKETS[norm]) return { city: norm, ...CA_MARKETS[norm] };
  // Fuzzy match in Canada
  for (const [key, data] of Object.entries(CA_MARKETS)){
    if (norm.includes(key) || key.includes(norm)) return { city: key, ...data };
  }
  // Fall through to USA
  const usNorm = usaNormCity(city);
  if (USA_MARKETS[usNorm]) return { city: usNorm, ...USA_MARKETS[usNorm], country: 'US' };
  for (const [key, data] of Object.entries(USA_MARKETS)){
    if (usNorm.includes(key) || key.includes(usNorm)) return { city: key, ...data, country: 'US' };
  }
  return null;
}
```

**Hand trace of `naLookupMarket('')`:**

1. `norm = caNormCity('')`. `('' || '')` → `''`; `.trim().toLowerCase()` → `''`; both
   `.replace()` calls are no-ops on `''`; final `.trim()` → **`norm === ''`**.
2. `CA_MARKETS['']` → `undefined`, falsy → the direct-match branch does not fire.
3. Fuzzy loop, **first** iteration. `CA_MARKETS`' first key (`app.js:7724`) is
   `'toronto'`.
   - `norm.includes(key)` → `''.includes('toronto')` → `false`.
   - **`key.includes(norm)` → `'toronto'.includes('')` → `true`** — every string contains
     the empty string. Short-circuit `||` fires on the very first key.
4. Returns `{ city: 'toronto', ...CA_MARKETS['toronto'] }`.

**Return value for the empty string — CONFIRMED, verified by executing the extracted
source:** `"" -> toronto / zone=ON_CORE / country=CA`, i.e.
```js
// app.js:7724
'toronto':      { zone:'ON_CORE', role:'anchor',       country:'CA', province:'ON', bias:'very_strong', lat:43.6532, lng:-79.3832 },
```
The market key is **`toronto`**. Whitespace behaves identically: `"   " -> toronto`.

There is **no guard**. Its USA sibling has one — `app.js:7946` `if (!city) return null;` —
and `usaLookupMarket('')` correctly returns `null`. `naLookupMarket` lacks it, and
`naLookupMarket` is called **first** at every site (`app.js:7971-7972`, `:9673-9674`,
`:16495`), so its result always wins.

**Corridor bonus for an empty-origin + empty-destination load.** Both ends resolve to
`toronto` → `origZone = destZone = 'ON_CORE'` (`app.js:7973-7974`) →
`naFindCorridor('ON_CORE','ON_CORE')` (`app.js:7975`) matches the first CA corridor whose
zones fit. Verified by execution:
`EMPTY+EMPTY corridor -> on_on "Ontario ↔ Ontario" bonus=8 laneClass=favorable`. Table
entry verbatim:

```js
// app.js:7778
{ id:'on_on',    name:'Ontario ↔ Ontario',            orZones:['ON_CORE'],                 deZones:['ON_CORE'],    laneClass:'favorable',     bonus: 8,  crossBorder: false },
```

**A load with no origin and no destination receives a `+8` "favorable" corridor bonus for a
fabricated Toronto→Toronto lane.** Neither `app.js:7971-7972` (`usaScoreLoad`) nor
`app.js:9673-9674` (`mwEvaluateLoad`) guards the call.

## C2 — one-character input

**CONFIRMED.** `naLookupMarket('a')` → **`mississauga`** (`zone: 'ON_CORE'`, `role:'anchor'`,
`bias:'very_strong'`, `app.js:7725`). Trace: `norm = 'a'`; `CA_MARKETS['a']` undefined;
first key `'toronto'` contains no `a`, so iteration 1 fails both tests; iteration 2's key
`'mississauga'` satisfies `key.includes('a')` → returns.

Verified by execution, with a second probe for contrast:
```
"a" -> mississauga / zone=ON_CORE / country=CA
"x" -> halifax     / zone=ATLANTIC_CA / country=CA
```
Any single letter present in some `CA_MARKETS` key resolves to the first such key.

## C3 — `deadhead` `|| 0` coercions

```
$ grep -n "deadhead" app.js | grep "|| 0"
5366:      const dm = Number(parsed.deadheadMiles) || 0;
10556:          deadheadPct: deadheadPct, weeklyGross: weeklyGross || 0,
11803:  if (dhm) result.deadheadMiles = parseInt(dhm[1].replace(/,/g,''), 10) || 0;
14384:      deadMiles:   f.deadheadMiles || 0,
19970:    loadedMiles: base.loadedMiles || 0, emptyMiles: base.deadheadMiles || 0,
```
(A broader sweep for `deadMi` adds `7976: const totalMi = (loadedMi || 0) + (deadMi || 0);`
and `10497: emptyMiles: deadMi || 0,`.)

Site-by-site, with the UI flow that feeds each:

| Line | Code | UI flow | Does it coerce a MISSING deadhead to 0? |
|---|---|---|---|
| `5366` | `const dm = Number(parsed.deadheadMiles) \|\| 0;` | **Quick Evaluate** (`openQuickEvalModal` → `_runQuickEval`, `app.js:5358`), reached from the Home "⚡ Evaluate Load" button (`app.js:5313`) and from its photo/OCR sub-mode (`:5425-5439`) | **YES — and it is written to the evaluator field.** `app.js:5381` `else if (id==='mwDeadMi') el.value = String(dm);` |
| `11803` | `if (dhm) result.deadheadMiles = parseInt(...) \|\| 0;` | `parseLoadTextEnhanced()` — shared parser behind every paste path | No. Guarded by `if (dhm)`; only runs when a `deadhead:` token was actually matched. The `\|\| 0` only catches an unparseable digit run. |
| `14384` | `deadMiles: f.deadheadMiles \|\| 0,` | **F27 Unified Load Intake**, "Save as Trip Draft" (`app.js:14374`) | Writes a **trip draft**, not the evaluator. Does not reach `mwEvaluateLoad`. |
| `19970` | `emptyMiles: base.deadheadMiles \|\| 0,` | `parseLoadTextForInbox()` — **F23 Smart Load Inbox** parse result | Sets `parsed.emptyMiles = 0` for an unknown deadhead — but see `20154` below, which converts that `0` back to blank. |
| `10497` | `emptyMiles: deadMi \|\| 0,` | "Book as Trip" from the evaluator result card (`app.js:10489`) | Post-decision trip prefill only; `deadMi` is already known by then (the guard passed). |
| `7976` | `const totalMi = (loadedMi \|\| 0) + (deadMi \|\| 0);` | `usaScoreLoad()` — the evidence layer | Advisory scoring only; not the canonical verdict. |
| `10556` | `weeklyGross \|\| 0` | not a deadhead coercion (`deadheadPct` is passed through unchanged) | n/a |

Paths that correctly preserve UNKNOWN:
- **F23 Smart Load Inbox "Score Load →"**, `app.js:20154`:
  `const dmEl = $('#mwDeadMi'); if (dmEl) dmEl.value = dh || '';` — because `dh` is `0`
  when unknown, `0 || ''` yields `''` (blank). *Side effect:* the same expression also
  erases a driver's **explicitly typed 0** in the inbox edit field (`app.js:20149`
  `Number(...#f23eDH...) || parsed.emptyMiles`), so F23 cannot record a verified zero.
- **OCR quick-scan**, `app.js:15405`:
  `if (parsed.deadheadMiles) { const el = $('#mwDeadMi'); if (el) el.value = parsed.deadheadMiles; }`
  — leaves the field untouched when unknown.
- **F27 "Score This Load"**, `app.js:14364`:
  `if (dead && f.deadheadMiles){ dead.value = f.deadheadMiles; ... }` — same.
- **Manual entry** — the field is simply whatever the driver typed.

## C4 — the full evaluator's blank-deadhead guard

```js
// app.js:9593-9599
  const loadedMi = Math.max(0, numVal('mwLoadedMi', 0));
  // M1: a blank deadhead field used to become a confident 0, which inflated
  // True RPM and produced a grade the driver never supplied the inputs for.
  // Blank now means UNKNOWN; an explicitly entered 0 is a verified zero.
  const deadMiRaw = ($('#mwDeadMi')?.value ?? '').trim();
  const deadMiKnown = knownNum(deadMiRaw);
  const deadMi = deadMiKnown === null ? null : Math.max(0, deadMiKnown);
```
```js
// app.js:9615-9621
  // M1: deadhead is a material fact. Unknown deadhead cannot yield a precise
  // True RPM, so the evaluator asks for it instead of assuming zero. Entering
  // 0 is one keystroke and records a verified zero.
  if (deadMi === null){
    out.innerHTML = '<div class="muted" style="font-size:13px">Enter deadhead miles — type <b>0</b> if you are already at the pickup.<br><span style="font-size:11px">Leaving it blank used to be treated as zero deadhead, which overstated True RPM.</span></div>';
    return;
  }
```
with `knownNum` at `app.js:428-433`:
```js
function knownNum(v){
  if (v === null || v === undefined) return null;
  if (typeof v === 'string' && v.trim() === '') return null;
  const x = Number(v);
  return Number.isFinite(x) ? x : null;
}
```

**Do Quick Evaluate and paste-preview reach the guard, or bypass it?**
**PARTIALLY CONFIRMED — they reach it, and defeat it.** The call chain is:

```
Home "⚡ Evaluate Load" button        app.js:5313   openQuickEvalModal()
  → #qeSubmitText click               app.js:5420   _runQuickEval(txt)
  → parseLoadTextEnhanced(rawText)    app.js:5363
  → const dm = Number(parsed.deadheadMiles) || 0;          app.js:5366   ← UNKNOWN becomes 0
  → else if (id==='mwDeadMi') el.value = String(dm);        app.js:5381   ← writes the string "0"
  → await mwEvaluateLoad();                                 app.js:5386
  → guard at app.js:9618 sees deadMiRaw === "0" → knownNum("0") === 0 → deadMi === 0 → PASSES
```

The guard is not skipped; it is satisfied with a value the driver never supplied. Quick
Evaluate launders an UNKNOWN into what the guard's own comment calls "a verified zero".

The F23 inbox and OCR paste-preview paths (`app.js:20154`, `:15405`) do **not** do this —
they leave the field blank and the guard fires correctly.

## C5 — Chicago → Detroit, 280 loaded mi, $560, no deadhead supplied

A harness exists (`tests/`, Playwright + real Chromium). It was used: the real
unmodified app was served from this working tree and driven through its actual UI.

**Full evaluator, deadhead field left blank** (`#mwOrigin`=`Chicago, IL`,
`#mwDest`=`Detroit, MI`, `#mwLoadedMi`=`280`, `#mwRevenue`=`560`, `#mwDeadMi`=``):

```
grade element:            null
#mwEvalOutput text:       "Enter deadhead miles — type 0 if you are already at the pickup.
                           Leaving it blank used to be treated as zero deadhead, which
                           overstated True RPM."
```
**No grade, no verdict, no True RPM, no bid range.** The guard works.

**Quick Evaluate, same load, end-to-end through the real modal** — pasted text
`"Chicago, IL to Detroit, MI\n280 miles\n$560"`, then clicked `#qeSubmitText`:

```json
{
  "deadheadFieldValueAfterQuickEval": "0",
  "previewGrade": "A",
  "askedForDeadhead": false,
  "previewFirst300": "🟢 PREMIUM WIN A ACCEPT Take it — premium rate, strong reload market ahead
                      Min / Accept $550.00 Professional $550.00 Strong Ask $600.00
                      📊 Show Details RPM · costs · intelligence 🟢 PREMIUM WIN A
                      True RPM: $2.00 • Premium A PREMIUM WIN ≥ $1.75 CURRENT B STRONG
                      ACCEPT $1.60–$1.74 C CONDITIONAL $1.50–"
}
```

**Verdict: CONFIRMED.** On identical inputs and identical missing information, the two
entry points disagree completely:

| | Full evaluator (blank field) | Quick Evaluate |
|---|---|---|
| Grade | *(none — refuses)* | **A** |
| Verdict | *(none)* | **ACCEPT** — "Take it — premium rate, strong reload market ahead" |
| True RPM | *(none)* | **$2.00** |
| Bid | *(none)* | Min/Accept $550 · Professional $550 · Strong Ask $600 |
| Asks for deadhead | **yes** | **no** |

The `$2.00` is `560 / (280 + 0)`. Any real deadhead makes it lower — e.g. 40 mi of
deadhead gives `560/320 = $1.75`, and 80 mi gives `$1.56`, which is below the `$1.60`
grade-B floor. The A/ACCEPT is an artifact of `app.js:5366`, not of the load.

---

# BLOCK D — BID AUTHORITY CONFLICT

## D1 — overlay rate ladder verbatim

```js
// midwest-stack-authority.js:19-92
    modes: {
      PROTECT_FLOOR: {
        id: 'PROTECT_FLOOR',
        label: 'Protect Floor',
        description: 'Normal business-health pricing. Use when not under pressure.',
        floor: 1.40,
        preferred: 1.50,
        target: 1.65
      },
      REALISTIC_WIN: {
        id: 'REALISTIC_WIN',
        label: 'Realistic Win',
        description: 'DispatchLand/Sylectus compressed clearing logic. Use when the board proves $1.40-$1.50 is not winning.',
        floor: 1.15,
        preferred: 1.25,
        target: 1.35
      },
      ESCAPE_RECOVERY: {
        id: 'ESCAPE_RECOVERY',
        label: 'Escape / Recovery',
        description: 'Accept lower pricing only when position clearly improves toward stronger Midwest density.',
        floor: 1.10,
        preferred: 1.25,
        target: 1.40
      },
      DEAD_ZONE: {
        id: 'DEAD_ZONE',
        label: 'Dead Zone Exit',
        description: 'Survival gate only. Requires 1000+ miles from home, no reloads above $1.25 nearby, and meaningful move toward density.',
        floor: 0.90,
        preferred: 1.00,
        target: 1.10
      }
    },
    grades: [
      { grade: 'A', min: 1.75, label: 'Premium' },
      { grade: 'B', min: 1.60, label: 'Strong' },
      { grade: 'C', min: 1.50, label: 'Healthy' },
      { grade: 'D', min: 1.40, label: 'Normal floor' },
      { grade: 'E', min: 1.25, label: 'Strategic only' },
      { grade: 'F', min: 0, label: 'Below floor' }
    ],
    ...
    regionCompression: {
      northeast: { multiplier: 0.90, note: '...' },
      minnesota: { multiplier: 0.88, note: '...' },
      kansasCity: { multiplier: 0.92, note: '...' },
      southeast: { multiplier: 0.90, note: '...' },
      coreMidwest: { multiplier: 1.00, note: '...' }
    },
    ...
    hardStops: {
      absoluteTrueRpmReject: 0.90,
      deadheadWarningMiles: 150,
      deadheadPremiumMiles: 200,
      transitPayloadCautionLbs: 2500,
      transitPayloadHardCheckLbs: 3000
    }
```

```js
// midwest-stack-authority.js:106-115  (realisticWin bands)
    compressedBands: {
      shortLocal: { totalMiles: [0, 200], realisticWin: [1.80, 2.40], note: 'Urgency premiums rising; bid/call fast, counter high first.' },
      mediumFeeder: { totalMiles: [200, 600], realisticWin: [1.35, 1.65], note: 'Sub-1.40 acceptance is now positional-only, no longer a market default. Counter toward floor before conceding.' },
      longRecovery: { totalMiles: [600, 1000], realisticWin: [1.40, 1.70], note: 'Tier 1/Tier 2 destination still required for the low end.' },
      longDisplacement: { totalMiles: [1000, 1800], realisticWin: [1.35, 1.55], note: 'Weak-destination long-locks require premium; capacity scarcity is negotiating leverage.' },
      extremeLongLock: { totalMiles: [1800, 9999], realisticWin: [1.50, 1.90], note: 'Westbound/border/rural must clear premium; do not discount into displacement.' }
    }
```

## D2 — values permitting a decision below $1.25/mi

Canonical reference used: all-in cost $0.60/mi · hard reject $1.25/mi · DZ unlock
$0.90–$1.24 with grade cap C · target band $1.55–$1.70/mi.

| Overlay value | Location | Below $1.25? | Effect |
|---|---|---|---|
| `hardStops.absoluteTrueRpmReject: 0.90` | `:86` | yes | The overlay's only auto-PASS is `trueRpm <= 0.90` (`:353`). **Everything from $0.91 to $1.24 is not rejected by the overlay at all.** |
| `REALISTIC_WIN.floor: 1.15` | `:32` | yes | Feeds `floorRpm` at `:283`. This is the **default** mode (`modeDefaults` falls back to `REALISTIC_WIN`, `:188`; the `<select>` marks it `selected`, `:407`). |
| `ESCAPE_RECOVERY.floor: 1.10` | `:40` | yes | Same. |
| `DEAD_ZONE.floor: 0.90` / `preferred: 1.00` / `target: 1.10` | `:48-50` | yes | Gated by `isDeadZoneEligible` (`:321-345`) — but see the gate-failure path below. |
| `grades` `E min 1.25`, `F min 0` | `:58-59` | F yes | `gradeFor()` returns a grade for any RPM; there is no "reject" grade. |
| `regionCompression` multipliers `0.88 / 0.90 / 0.92` | `:68-71` | multiply bands **down** | Applied to `realisticBand[0]` at `:283` and to `askRpm` at `:289`. |
| `mediumFeeder` / `longDisplacement` `realisticWin[0] = 1.35` | `:108`, `:110` | ×0.88 → **1.188** | The binding term in `floorRpm`. |
| `ESCAPE_RECOVERY` clamp `Math.max(1.10, Math.min(floorRpm, 1.25))` | `:299` | yes | Caps `floorRpm` at exactly `1.25` for tier1/tier2 destinations, i.e. exactly the hard-reject boundary. |
| `DEAD_ZONE` gate-pass clamps `floorRpm = 0.90`, `winRpm ≥ 1.00`, `askRpm ≥ 1.10` | `:337-339` | yes | Intended survival mode; correctly gated. |
| Verdict rule `trueRpm >= floorRpm && (tier1\|\|tier2) → TAKE_IF_LIVE` | `:355` | — | **This is the line that converts any sub-$1.25 `floorRpm` into an acceptance.** |

**Worst case — lowest `floorRpm` the overlay can output after the region multiplier.**

Arithmetic. From `midwest-stack-authority.js:281-283`:
```js
    let floorRpm = staleProtectiveGuard
      ? Math.max(CONFIG.hardStops.absoluteTrueRpmReject, baseFloor, protective.floor)
      : Math.max(CONFIG.hardStops.absoluteTrueRpmReject, baseFloor, realisticBand[0] * regionOverlay.multiplier);
```
with `staleProtectiveGuard` from `:275-276`:
```js
    const overrideStale = rateFreshness.status === 'STALE';
    const staleProtectiveGuard = overrideStale && mode.id !== 'DEAD_ZONE';
```

Minimise `Math.max(0.90, mode.floor, realisticBand[0] × multiplier)`:
- smallest `realisticBand[0]` = **1.35** (`mediumFeeder` `:108` and `longDisplacement` `:110`)
- smallest `multiplier` = **0.88** (`minnesota`, `:69`)
- `1.35 × 0.88 = 1.188`
- smallest `mode.floor` reachable with the stale guard OFF = `DEAD_ZONE.floor` = **0.90**
- `max(0.90, 0.90, 1.188)` = **1.188 → rounds to $1.19/mi**

`staleProtectiveGuard` excludes `DEAD_ZONE` by construction, so the stale-band protection
that today forces every other mode up to `1.40` does **not** apply to `DEAD_ZONE` — even
when its own eligibility gate has **failed**. On the gate-failure branch (`:341-344`) the
floor is deliberately left at its pre-DEAD_ZONE value, which is `1.188`, not `1.40`.

**Verified by executing the real unmodified overlay.** In Node (worst-case sweep):
```json
{ "mode": "DEAD_ZONE", "oc": "Minneapolis MN", "dc": "Chicago IL", "lm": 400,
  "floorRpm": 1.19, "winRpm": 1.32, "region": "minnesota", "destRole": "tier1" }
```
and a concrete probe at that floor:
```
trueRpm= 1.19  grade= F  verdict= TAKE_IF_LIVE  floorRpm= 1.19  floorBid= 475
```

**Verified again in the real running app**, with `app.js` loaded so the genuine gate
functions were present (`typeof window.isDeadZoneEligible === "function"`,
`typeof window.flDzGeoCheck === "function"`), overlay mode set to `DEAD_ZONE` via its own
on-screen `#mwBidMode` dropdown:
```json
{ "trueRpm": 1.19, "grade": "F", "verdict": "TAKE_IF_LIVE",
  "floorRpm": 1.19, "winRpm": 1.32, "floorBid": 475,
  "flags": [
    "Rate override STALE (56d old) — static July bands cannot relax protective pricing; refresh market evidence.",
    "DZ gate: 397mi from home (1000+ required)",
    "DZ gate: saves only ?mi toward stronger freight (200+ required)",
    "DZ gate: manual no-viable-reload confirmation not given",
    "Dead Zone Exit gate not satisfied — using the standard floor, not the survival floor."
  ] }
```

**CONFIRMED: the overlay emits `TAKE_IF_LIVE` at a True RPM of $1.19 — below the $1.25
hard reject — on a load whose Dead Zone gate failed all three of its checks.** The flags
correctly say the gate was not satisfied; the *signal* says take it anyway. The
grade rendered alongside is `F`.

Second reachable path, today suppressed only by band staleness: with the clock inside the
override's CURRENT window (effective `2026-07-09`, `:102`; `CURRENT <= 14d`, `:122`), the
same load produces:
```
REALISTIC_WIN    floorRpm= 1.19   winRpm= 1.32   verdict= TAKE_IF_LIVE   grade= F  trueRpm= 1.19
ESCAPE_RECOVERY  floorRpm= 1.19   winRpm= 1.32   verdict= TAKE_IF_LIVE   grade= F  trueRpm= 1.19
PROTECT_FLOOR    floorRpm= 1.4    winRpm= 1.5    verdict= NEGOTIATE      grade= F  trueRpm= 1.19
DEAD_ZONE        floorRpm= 1.19   winRpm= 1.32   verdict= TAKE_IF_LIVE   grade= F  trueRpm= 1.19
```
i.e. the **default** mode also reaches $1.19 whenever the bands are fresh. As of
2026-09-03 the bands are 56 days old (STALE), so only `DEAD_ZONE` reaches it — the sub-$1.25
path is currently gated by an *expiry timer*, not by the DZ gate.

## D3 — does the overlay render dollar figures into the DOM?

**CONFIRMED — yes.** `midwest-stack-authority.js:447-455`:

```js
    box.innerHTML = '<div class="row">' +
      '<div class="pill"><span class="muted">Floor</span><b>' + money(result.recommendation.floorBid) + '</b></div>' +
      '<div class="pill"><span class="muted">Win</span><b>' + money(result.recommendation.winBid) + '</b></div>' +
      '<div class="pill"><span class="muted">Ask</span><b>' + money(result.recommendation.askBid) + '</b></div>' +
      '</div>' +
      '<div style="margin-top:10px;font-weight:800;color:' + verdictColor + '">Signal: ' + escapeHtml(result.recommendation.verdict) + '</div>' +
      '<div class="muted" style="font-size:12px;margin-top:4px">' + escapeHtml(result.recommendation.action) + '</div>' +
      '<div class="muted" style="font-size:12px;margin-top:8px">→ ' + escapeHtml(result.market.destination.label) + ' · ' + escapeHtml(result.market.region) + ' region</div>' +
      (flags ? '<ul style="font-size:12px;margin:8px 0 0 18px;padding:0;color:var(--warn)">' + flags + '</ul>' : '');
```

It renders three dollar figures **and** a verdict word, and it exposes data as well
(`window.FreightLogicMidwestStack`, `:462-470`).

## D4 — DOM target and simultaneity with the canonical Bid Range

DOM target — `midwest-stack-authority.js:412-413`:
```js
      '<div id="mwStackAuthorityResult" style="margin-top:12px"></div>';
    evalOutput.parentNode.insertBefore(panel, evalOutput.nextSibling);
```
where `evalOutput` is `document.getElementById('mwEvalOutput')` (`:394`) — the canonical
evaluator's own output container. The advisory panel is inserted as the **immediate next
sibling of the canonical result**.

**CONFIRMED — they are on screen at the same time.** Live check on the same DOM,
`o.nextElementSibling === p` where `o = #mwEvalOutput`, `p = #mwStackAuthorityPanel`:
`overlayPanelAfterEvalOutput: true`. Rendered content, same instant, same load
(Minneapolis→Chicago, 400 loaded mi, 0 deadhead, $476):

```
#mwEvalOutput          : "🔴 REJECT F PASS Skip — trap lane, low reload probability
                          Min / Accept $475.00 Professional $550.00 Strong Ask $600.00 …"
#mwStackAuthorityResult: "Floor$475 Win$530 Ask$580 Signal: TAKE_IF_LIVE
                          Call/accept only after pickup, delivery, weight, and commodity
                          are confirmed live. → Tier 1 density · minnesota region …"
```

A driver sees **REJECT / PASS** and **TAKE_IF_LIVE** stacked vertically, with two
different dollar ladders. The only reconciliation shipped is a static disclaimer at
`:404`: `'Canonical decision above is authoritative; this panel is supporting market/bid
evidence.'`

**Adjacent finding inside the canonical layer** (raised because it appears in the same
screenshot, not because Block D asked for it): the canonical hero's "Min / Accept" figure
is **not derived from any floor**. `app.js:9961`:
```js
  const _quickAcceptH = _roundTo25h(revenue);
```
rendered at `app.js:9975-9976` under the label `Min / Accept`. It is the **posted revenue
rounded to $25**. On the REJECT-F load above it therefore reads `Min / Accept $475.00` —
labelling a $1.19/mi rate as an accept figure on a load the same card calls PASS. The
separate `Bid Range` block (`app.js:4819-4824`) does use real floors
(`minimum: { rpm: 1.40 }` … `premium: { rpm: 2.00 }`), so the two coexist in one card.

## D5 — `admin-driver-ui.js`

**REFUTED / NOT PRESENT.** It does not touch rates or verdicts at all.
`grep -ni "rpm\|verdict\|grade\|floor\|bid\|rate" admin-driver-ui.js` returns exactly one
line, and it is a comment about credential migration:
```
12:// Earlier builds persisted this token to localStorage. Migrate any surviving value into
```
The file's entire surface is the admin driver-account API
(`const API='https://freightlogic-backup.fimseitef.workers.dev'`, `:2`) and session-scoped
token handling (`const TOK_KEY='fl_admin_tok'`, `:14`). It renders no dollar figures and
writes nothing into `#mwEvalOutput`.

---

# BLOCK E — DATA MODEL & EXPORT SECURITY

## E1 — object stores and `DB_VERSION`

`app.js:132` — `const DB_VERSION = 15;`

Every `createObjectStore` call with its keyPath:

```js
// app.js:2376
      const ensureStore = (name, opts) => { if (!d.objectStoreNames.contains(name)) d.createObjectStore(name, opts); };
// app.js:2392
        const tripStore = d.createObjectStore('trips', { keyPath: 'orderNo' });
// app.js:2396
        ['fuel','expenses','gpsLogs'].forEach(name => d.createObjectStore(name, { keyPath:'id', autoIncrement:true }));
// app.js:2397
        d.createObjectStore('settings', { keyPath:'key' });
// app.js:2405
          const a = d.createObjectStore('auditLog', { keyPath:'id' });
// app.js:2433
          const mb = d.createObjectStore('marketBoard', { keyPath:'id' });
// app.js:2449
          const lh = d.createObjectStore('laneHistory', { keyPath: 'id' });
// app.js:2455
          d.createObjectStore('weeklyReports', { keyPath: 'weekId' });
// app.js:2459
          const ro = d.createObjectStore('reloadOutcomes', { keyPath: 'id' });
// app.js:2466
          const bh = d.createObjectStore('bidHistory', { keyPath: 'id' });
// app.js:2473
          const dv = d.createObjectStore('documents', { keyPath: 'id' });
```
plus the `ensureStore` catch-alls (`app.js:2400-2401`, `:2411-2416`, `:2481`, `:2487`, `:2503`):
```js
        ensureStore('receipts', { keyPath:'tripOrderNo' });
        ensureStore('receiptBlobs', { keyPath:'id' });
      ensureStore('settings', { keyPath:'key' });
      ensureStore('auditLog', { keyPath:'id' });
      ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
      ensureStore(EVIDENCE_STORE, { keyPath:'evidenceId' });
      if (old < 12) { ensureStore('gpsLogs', { keyPath: 'id', autoIncrement: true }); }
```
`EVIDENCE_STORE` is `'normalizedEvidence'` (`app.js:1327`). **16 stores total.**

## E2 — trips / receipts keyPaths and the UUID blast radius

```js
// app.js:2392
        const tripStore = d.createObjectStore('trips', { keyPath: 'orderNo' });
// app.js:2400 (and identically at :2412)
        ensureStore('receipts', { keyPath:'tripOrderNo' });
```

A UUID migration would have to touch **7 stores** (2 by primary key, 4 by foreign-key
field, 1 by embedded settings-key string):

| # | Store | How it is bound to the order number |
|---|---|---|
| 1 | `trips` | **primary key** — `keyPath: 'orderNo'` (`app.js:2392`) |
| 2 | `receipts` | **primary key** — `keyPath: 'tripOrderNo'` (`app.js:2400`); written at `app.js:3022` `stores.receipts.put({ tripOrderNo: orderNo, files: filesArr });` |
| 3 | `documents` | field `tripOrderNo` — `app.js:17327` `..., expiresAt: expiresAt\|\|'', tripOrderNo: tripOrderNo\|\|'' }` |
| 4 | `bidHistory` | field `orderNo` — `app.js:15917` `ws.bidHistory.put({ id: 'brev_' + now, broker: bk, ..., orderNo: trip.orderNo\|\|'', created: now });` |
| 5 | `loadLifecycle` | indexed field `orderNo` — `app.js:2496` `['orderNo', 'orderNo'],` |
| 6 | `normalizedEvidence` | field `orderNo` and derived id — `app.js:1720` `orderNo: norm.orderNo,`; `app.js:1732` `sourceId: norm.orderNo \|\| norm.lifecycleId,`; `app.js:1677` uses `norm.orderNo` in the fingerprint input |
| 7 | `settings` | order number embedded in the key — `app.js:15789` / `:15803` `const reviewKey = 'laneReviewDone_' + (trip.orderNo \|\| '');`, allowlisted by prefix at `app.js:3454` |

Not affected: `expenses` and `fuel` carry no trip linkage (`sanitizeExpense`,
`app.js:2829-2847`, has no order field); `gpsLogs` links via `tripTrackingId`
(`app.js:18910`), not `orderNo`.

## E3 — export payload builders

Three builders. Verbatim:

**(a) Local JSON export** — `app.js:3287-3326`
```js
async function exportJSON(){
  const trips = await dumpStore('trips');
  const expenses = await dumpStore('expenses');
  const fuel = await dumpStore('fuel');
  const exportableSettings = (await dumpStore('settings')).filter(s => s.key !== 'fmcsaApiKey' && s.key !== 'eiaApiKey');
  const loadLifecycle = await dumpStore('loadLifecycle');
  const normalizedEvidence = await dumpStore(EVIDENCE_STORE);
  const checksum = await computeExportChecksum(trips, expenses, fuel);
  const checksumFull = await computeExportChecksumFull(trips, expenses, fuel, exportableSettings);
  const checksumProtected = await computeExportChecksumProtected(trips, expenses, fuel, exportableSettings, loadLifecycle, normalizedEvidence);
  const gpsLogs = await dumpStore('gpsLogs');
  const payload = {
    meta: { app: 'Freight Logic', version: APP_VERSION, exportedAt: new Date().toISOString(), checksum, checksumFull, checksumProtected, recordCounts: { ... } },
    trips,
    expenses,
    fuel,
    receipts: await dumpStore('receipts'),
    settings: exportableSettings,
    auditLog: await dumpStore('auditLog'),
    laneHistory: await dumpStore('laneHistory'),
    weeklyReports: await dumpStore('weeklyReports'),
    reloadOutcomes: await dumpStore('reloadOutcomes'),
    bidHistory: await dumpStore('bidHistory'),
    documents: await dumpStore('documents'),
    loadLifecycle,
    [EVIDENCE_STORE]: normalizedEvidence,
    gpsLogs,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
```

**(b) Cloud full backup and (c) delta** — one construction, one endpoint switch.
`app.js:14753`:
```js
    const settings = (await dumpStore('settings')).filter(s => s.key !== 'fmcsaApiKey' && s.key !== 'eiaApiKey');
```
`app.js:14807-14810`:
```js
    const payload = JSON.stringify({ meta: { app: 'FreightLogic', version: APP_VERSION, savedAt: new Date().toISOString(), counts, isDelta, lastSynced }, trips, expenses, fuel, settings, receipts, laneHistory: lh, weeklyReports: wr, reloadOutcomes: ro, bidHistory: bh, documents: docs, loadLifecycle: lc, [EVIDENCE_STORE]: ev, gpsLogs: gl });
    const { encrypted, iv, salt } = await cloudEncrypt(payload, config.pass);
    const endpoint = isDelta ? config.url + '/backup/delta' : config.url + '/backup';
    const res = await cloudFetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Device-Id': cloudGetDeviceId(), 'X-Backup-Token': config.token }, body: JSON.stringify({ encrypted, iv, salt }) });
```
`settings` is **never delta-filtered** — the full settings dump goes on every push,
delta or not. The cloud payload is AES-encrypted before leaving the device
(`cloudEncrypt`, `:14808`); the local JSON export is **plaintext**.

## E4 — is the settings object filtered? `ALLOWED_SETTINGS_KEYS` scope

`ALLOWED_SETTINGS_KEYS` is declared at `app.js:3427` as a **local `const` inside
`importJSON()`** (which begins at `app.js:3376`). Its only consumer is `isAllowedSettingsKey`:

```js
// app.js:3451-3457
    const isAllowedSettingsKey = k => {
      if (ALLOWED_SETTINGS_KEYS.has(k)) return true;
      if (k.startsWith('broker_note_') && k.length <= 80) return true;
      if (k.startsWith('laneReviewDone_') && k.length <= 80) return true;
      return false;
    };
    const safeSettingsArr = arr(data.settings).filter(s => s && typeof s === 'object' && typeof s.key === 'string' && isAllowedSettingsKey(s.key) && JSON.stringify(s.value ?? '').length < 50000).map(s => ({
```

Its members include, verbatim from `app.js:3427`:
`'cloudBackupUrl','cloudBackupToken','lastCloudSync','vehicleClass','appLockEnabled','appLockPin',…`
and from `:3429`: `'fmcsaApiKey','eiaApiKey','localUserId',`.

**Answer: applied on IMPORT ONLY.** Both export builders use a different, two-key filter —
`app.js:3297` and `app.js:14753`, identically:
`.filter(s => s.key !== 'fmcsaApiKey' && s.key !== 'eiaApiKey')`. **CONFIRMED:
`ALLOWED_SETTINGS_KEYS` has no role in export whatsoever; export is deny-two-keys, not
allow-listed.**

## E5 — what an unencrypted export actually contains

Determined by running the real app, writing the credentials through the real
`setSetting`, and rebuilding the export payload with `exportJSON()`'s exact filter
(`app.js:3297`) over the real `dumpStore('settings')`:

```json
{
  "exportedSettingKeys": ["appLockEnabled","appLockFailCount","appLockLockedUntil",
                          "appLockPin","cloudBackupToken","insuranceSplitMigrationDone",
                          "legacyMigrated","localUserCreatedAt","localUserId","uiMode"],
  "appLockPin_present": true,
  "appLockPin_value": "pbkdf2v1:e8/alsc5+WUrS/9OzCxEkw==:PdZOw9",
  "cloudBackupToken_present": true,
  "cloudBackupToken_value": "flk_0123456789abcdef0123456789abcdef",
  "appLockFailCount_present": true,
  "appLockLockedUntil_present": true,
  "fmcsaApiKey_present": false,
  "eiaApiKey_present": false,
  "fl_device_id_localStorage": null,
  "fl_device_id_inSettings": false
}
```

| Item | In an unencrypted export? | Evidence |
|---|---|---|
| **`appLockPin` (PIN hash)** | **YES** | Stored in `settings` — `app.js:7324` `if (enabled) await setSetting('appLockPin', await hashPin(pin));`. Not in the two-key export filter (`app.js:3297`). Observed value `pbkdf2v1:<salt_b64>:<hash_b64>` per `hashPin`, `app.js:375-382` (PBKDF2-SHA256, 310,000 iterations, 16-byte random salt). It is a hash, not a plaintext PIN — but an offline brute force against a 4–8 digit numeric PIN (`maxlength="8"`, `app.js:7364`) is bounded by 10⁸ candidates, and the export ships salt, iteration scheme and digest together. |
| **`flk_` backup token** | **YES** | Stored in `settings` — `app.js:14733` `await setSetting('cloudBackupToken', token);`. Exported verbatim. This token is the per-driver cloud credential sent as `X-Backup-Token` (`app.js:14810`). |
| **`fl_device_id`** | **NO** | It lives only in `localStorage` — `app.js:14632-14635` `let id = localStorage.getItem('fl_device_id'); … localStorage.setItem('fl_device_id', id);`. No export builder reads `localStorage`; all three read `dumpStore(...)` (IndexedDB). Confirmed absent from the exported key list. |
| **Lockout state (`appLockFailCount`, `appLockLockedUntil`)** | **YES** | Written to `settings` at `app.js:7424` / `:7428`. `CLAUDE.md`-adjacent comment `app.js:7345-7349` says *"State (appLockFailCount / appLockLockedUntil) persists in settings so a reload doesn't reset the counter … Deliberately NOT added to ALLOWED_SETTINGS_KEYS"* — that exclusion governs **import only**. Both keys are present in the export. |
| `fmcsaApiKey`, `eiaApiKey` | **NO** | Explicitly stripped, `app.js:3297`. |

**Verdict: CONFIRMED for `appLockPin`, `cloudBackupToken` and lockout state; REFUTED for
`fl_device_id`.** The same three items also travel in the cloud payload
(`app.js:14753` uses the identical two-key filter), though that payload is encrypted before
transmission and the local `.json` export is not.

## E6 — the export checksum

```js
// app.js:3254-3285
/** SHA-256 (with FNV-1a fallback) over an arbitrary JSON-serialisable object. */
async function _computeChecksum(data){
  const raw = JSON.stringify(data);
  const buf = new TextEncoder().encode(raw);
  try {
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  } catch {
    let h = 0x811c9dc5;
    for (let i = 0; i < raw.length; i++) { h ^= raw.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return 'fnv1a-' + (h >>> 0).toString(16).padStart(8, '0');
  }
}
async function computeExportChecksum(trips, expenses, fuel){
  return _computeChecksum({ trips, expenses, fuel });
}
async function computeExportChecksumFull(trips, expenses, fuel, settings){
  return _computeChecksum({ trips, expenses, fuel, settings });
}
async function computeExportChecksumProtected(trips, expenses, fuel, settings, loadLifecycle, normalizedEvidence){
  return _computeChecksum({ trips, expenses, fuel, settings, loadLifecycle, normalizedEvidence });
}
```

**Plain SHA-256, not keyed/HMAC — CONFIRMED.** No secret enters the digest; the input is
purely the payload arrays. Three tiers exist and import prefers the strongest present
(`app.js:3385`, `:3395`, `:3403`).

**What it actually detects:** accidental corruption, truncation, and field drift between
the checksum input and the payload (the X-05 class of bug). It **cannot** detect deliberate
tampering: the algorithm is public, unkeyed, and deterministic over data present in the
file, so an editor changes a record and recomputes the digest in one step. Coverage gaps
even against accidents: only `trips`, `expenses`, `fuel`, `settings`, `loadLifecycle` and
`normalizedEvidence` are hashed. The payload also ships `receipts`, `auditLog`,
`laneHistory`, `weeklyReports`, `reloadOutcomes`, `bidHistory`, `documents` and `gpsLogs`
(`app.js:3309-3324`) — **eight stores covered by no checksum at all.** And a mismatch is
not fatal: `app.js:3391-3392` shows a `confirm()` and imports anyway if the user proceeds;
a thrown error in the verifier is swallowed (`:3394` `catch(e){ console.warn("[FL]", e); }`).

---

# BLOCK F — ECONOMICS & VEHICLE TRUTHFULNESS

## F1 — `opCostPerMile` unset or 0

Read path — `app.js:9683`:
```js
  const opCPM = Number(await getSetting('opCostPerMile', 0) || 0);
```
Economics path — `app.js:8659`, `:8665-8668`:
```js
  const opCPM = Math.max(0, Number(f.opCPM || 0));
  ...
  const operatingCost = roundCents(totalMi * opCPM);
  const totalCost = roundCents(fuel + operatingCost + borderAdminCost);
  const operationalProfit = netAfterFuel;
  const trueProfit = roundCents(effectiveRevenue - totalCost);
```

**What it does:** an unset operating cost becomes a **hard 0**, not UNKNOWN. Note the
asymmetry with the same release's own M1 doctrine — revenue, loaded miles and deadhead read
through `knownNum()` (`app.js:428`, and `deriveUnifiedEconomics` returns
`{ available:false, unknownFacts:[…] }` for those), but `opCPM` is read through
`Number(x || 0)`, the exact pattern `app.js:422-427` names as the defect M1 fixed. With
`opCPM = 0`, `operatingCost = 0` and `trueProfit` collapses to `effectiveRevenue − fuel −
border`, i.e. it becomes `netAfterFuel`.

**Does any UI string say "True Profit" while cost is unknown? CONFIRMED — yes.**
`app.js:10140-10143`:
```js
      <div style="text-align:center;padding:10px;border-radius:var(--r-sm);background:${trueProfit >= 0 ? 'var(--good-muted)' : 'var(--bad-muted)'};border:1px solid ${trueProfit >= 0 ? 'var(--good-border)' : 'var(--bad-border)'}">
        <div style="font-family:var(--font-mono);font-size:20px;font-weight:700;color:${trueProfit >= 0 ? 'var(--good)' : 'var(--bad)'}">${fmtMoney(trueProfit)}</div>
        <div style="font-size:10px;color:var(--text-secondary);margin-top:2px">True Profit</div>
        <div style="font-size:9px;color:var(--text-tertiary)">${opCPM > 0 ? 'Revenue − All Costs' : 'Set op cost/mi →'}</div>
      </div>
```
The **label "True Profit" is unconditional**, as is the figure. Only the 9px sub-caption
changes, from `Revenue − All Costs` to `Set op cost/mi →`.

Two sibling elements *do* degrade honestly, which makes the inconsistency internal:
`app.js:10058` `const profitVal = opCPM > 0 ? trueProfit : netAfterFuel;` and
`app.js:10069` `${opCPM > 0 ? 'True Profit (after all costs)' : 'Operational Profit (fuel only — set op cost/mi in settings)'}`;
and the cost breakdown simply omits the operating-cost row, `app.js:10154`
`${opCPM > 0 ? \`<div class="muted">Operating Cost (…)\` : ''}` — so `Total Cost` and
`Net Profit` are printed with a silently missing line item.

## F2 — F26 wizard: is monthly mileage collected?

Step definitions — `app.js:5462-5468`:
```js
  const STEPS = [
    { id:'home',     title:'Where do you home out of?',            hint:'City, State — e.g. "Indianapolis, IN"' },
    { id:'vehicle',  title:'Tell us about your vehicle',           hint:'' },
    { id:'costs',    title:'Your weekly goal & fuel cost',         hint:'' },
    { id:'monthly',  title:'Monthly fixed expenses',               hint:'We\'ll auto-log these each month so your P&L stays accurate' },
    { id:'prefs',    title:'Operating preferences',                hint:'' },
  ];
```
Complete value set — `app.js:5470-5475`:
```js
  const vals = {
    homeBase:'', vehicleType:'Cargo Van', vehicleYear:'', vehicleMake:'',
    avgMpg:'', fuelCost:'', weeklyGoal:'', region:'',
    payloadLimit:'',
    mIns:0, mVan:0, mPhone:0, mDispatch:0, mParking:0, mSubs:0, mMaint:0,
  };
```
`_saveSetupWizardResults()` in full — `app.js:5645-5680`:
```js
async function _saveSetupWizardResults(vals){
  const tasks = [];
  if (vals.homeBase)     tasks.push(setSetting('homeLocation',   clampStr(vals.homeBase, 80)));
  if (vals.vehicleType)  tasks.push(setSetting('vehicleClass',   vals.vehicleType));
  if (vals.vehicleYear)  tasks.push(setSetting('vehicleYear',    clampStr(vals.vehicleYear, 10)));
  if (vals.vehicleMake)  tasks.push(setSetting('vehicleMake',    clampStr(vals.vehicleMake, 60)));
  if (vals.avgMpg)       tasks.push(setSetting('vehicleMpg',     posNum(vals.avgMpg)));
  if (vals.fuelCost){    tasks.push(setSetting('fuelPrice',      posNum(vals.fuelCost)));
                         tasks.push(setFuelPriceProvenance(FUEL_PRICE_SOURCE.OPERATOR)); }
  if (vals.weeklyGoal)   tasks.push(setSetting('weeklyGoal',     posNum(vals.weeklyGoal)));
  if (vals.region)       tasks.push(setSetting('preferredRegion', clampStr(vals.region, 40)));
  if (vals.payloadLimit) tasks.push(setSetting('payloadLimitLbs', posNum(vals.payloadLimit)));

  // Build monthly expense config (all non-zero items)
  const monthlyItems = [
    { id:'ins',      label:'Insurance',            category:'Insurance',        amount: vals.mIns },
    { id:'van',      label:'Van Payment',          category:'Vehicle Payment',  amount: vals.mVan },
    { id:'phone',    label:'Phone & Data',         category:'Phone / Data',     amount: vals.mPhone },
    { id:'dispatch', label:'Dispatch Fees',        category:'Other',            amount: vals.mDispatch },
    { id:'parking',  label:'Parking / Storage',   category:'Other',            amount: vals.mParking },
    { id:'subs',     label:'Subscriptions',        category:'Other',            amount: vals.mSubs },
    { id:'maint',    label:'Maintenance Reserve',  category:'Maintenance',      amount: vals.mMaint },
  ].filter(x => x.amount > 0);
  tasks.push(setSetting('monthlyExpensesConfig', monthlyItems));

  // Legacy compat: keep old individual keys in sync
  tasks.push(setSetting('monthlyInsurance', vals.mIns || 0));
  tasks.push(setSetting('monthlyVehicle',   vals.mVan || 0));
  tasks.push(setSetting('monthlyMaintenance', vals.mMaint || 0));
  const otherTotal = (vals.mPhone||0) + (vals.mDispatch||0) + (vals.mParking||0) + (vals.mSubs||0);
  tasks.push(setSetting('monthlyOther', otherTotal));

  tasks.push(setSetting('f26SetupComplete', true));
  tasks.push(setSetting('autoRecurringExpenses', monthlyItems.length > 0));
  await Promise.all(tasks);
}
```

**Does F26 collect monthly miles? NO — CONFIRMED.** There is no `monthlyMiles` key in
`vals` (`:5470-5475`), no corresponding input in `readVals()` (`:5511-5537`, which reads
only `wz_home`, `wz_vtype`, `wz_vyear`, `wz_vmake`, `wz_mpg`, `wz_goal`, `wz_fuel`,
`wz_ins`, `wz_van`, `wz_phone`, `wz_disp`, `wz_park`, `wz_subs`, `wz_maint`, `wz_region`,
`wz_payload`), and `_saveSetupWizardResults` writes neither `monthlyMiles` nor
`opCostPerMile`.

**Can `opCostPerMile` be derived at the end of onboarding? NO — CONFIRMED.** The only
derivation in the codebase requires monthly miles, `app.js:12724-12730`:
```js
  const mMiles = Number($('#monthlyMiles')?.value || 0);
  ...
  // Auto-calculate per-mile cost if monthly data is filled in
  if (mMiles > 0 && (mIns + mVeh + mMaint + mOther) > 0){
    const autoOpCost = roundCents((mIns + mVeh + mMaint + mOther) / mMiles);
    $('#opCostPerMile').value = autoOpCost.toFixed(2);
    await setSetting('opCostPerMile', autoOpCost);
  } else {
    await setSetting('opCostPerMile', Number($('#opCostPerMile').value || 0));
  }
```
`#monthlyMiles` exists only in the Settings panel — `index.html:274`
`<label>Est. monthly miles</label><input id="monthlyMiles" type="number" step="1" placeholder="e.g., 8000" />`
— which the wizard never opens. Net effect: a driver who completes the entire first-run
wizard has supplied every input the derivation needs **except** mileage, and therefore
finishes onboarding with `opCostPerMile` unset — which is exactly the F1 state where the UI
prints an unqualified "True Profit".

## F3 — `checkVanFit()` with an empty/unset cargo length

```js
// app.js:9541-9559
function checkVanFit({ lengthIn, widthIn, heightIn, weightLbs }, profile){
  const violations = [];
  const L = finiteNum(lengthIn, null), W = finiteNum(widthIn, null), H = finiteNum(heightIn, null), WT = finiteNum(weightLbs, null);
  if (L !== null && L > profile.cargoLengthIn){
    violations.push({ field: 'length', loadValue: L, limit: profile.cargoLengthIn, limitLabel: `cargo length ${profile.cargoLengthIn}"` });
  }
  if (W !== null){
    if (W > profile.cargoWidthIn) violations.push({ field: 'width', loadValue: W, limit: profile.cargoWidthIn, limitLabel: `cargo width ${profile.cargoWidthIn}"` });
    else if (W > profile.doorWidthIn) violations.push({ field: 'width', loadValue: W, limit: profile.doorWidthIn, limitLabel: `door opening width ${profile.doorWidthIn}"` });
  }
  if (H !== null){
    if (H > profile.cargoHeightIn) violations.push({ field: 'height', loadValue: H, limit: profile.cargoHeightIn, limitLabel: `cargo height ${profile.cargoHeightIn}"` });
    else if (H > profile.doorHeightIn) violations.push({ field: 'height', loadValue: H, limit: profile.doorHeightIn, limitLabel: `door opening height ${profile.doorHeightIn}"` });
  }
  if (WT !== null && WT > profile.payloadLbs){
    violations.push({ field: 'weight', loadValue: WT, limit: profile.payloadLbs, limitLabel: `payload ${profile.payloadLbs.toLocaleString()} lbs` });
  }
  return { fits: violations.length === 0, violations };
}
```

The question has two distinct readings; both are answered.

**(a) The `vanProfile` SETTING has never been saved → a default applies.** `app.js:9526-9529`:
```js
async function getVanProfile(){
  const stored = await getSetting('vanProfile', null);
  return { ...VAN_PROFILE_DEFAULT, ...(stored && typeof stored === 'object' ? stored : {}) };
}
```
with `VAN_PROFILE_DEFAULT` at `app.js:9517-9524` (`cargoLengthIn: 130`, `cargoWidthIn: 65`,
`cargoHeightIn: 56`, `doorWidthIn: 60`, `doorHeightIn: 52`, `payloadLbs: 3800`). So
`profile.cargoLengthIn === 130` and the length branch is live, not skipped.

**(b) The LOAD's `lengthIn` is empty → that one branch is skipped.** `finiteNum('')` returns
`0` (`Number('')` is `0`, which is finite — `app.js:418-421`), so a literal empty string
would give `L === 0` and not `null`; but `checkVanFit` is only reached through
`app.js:9637-9646`, where the caller pre-filters:
```js
    const lengthIn = numVal('mwLoadLengthIn', NaN);
    ...
    const knownDims = dims.filter(v => Number.isFinite(v) && v > 0).length;
    if (knownDims > 0){
      const vanProfile = await getVanProfile();
      const fit = checkVanFit({ lengthIn, widthIn, heightIn, weightLbs }, vanProfile);
```
An empty field yields `NaN`, `finiteNum(NaN, null)` → `null`, and the `L !== null` guard
skips that dimension. With **all four** blank, `knownDims === 0` and `checkVanFit` is never
called at all.

**(c) A hazard found while answering this — the Settings SAVE path.** `app.js:12735`:
```js
    cargoLengthIn: posNum($('#vanCargoLengthIn')?.value, VAN_PROFILE_DEFAULT.cargoLengthIn),
```
`posNum(v, def)` calls `finiteNum(v, def)` (`app.js:434-436`), and `finiteNum` only returns
`def` when `Number(v)` is **not finite**. `Number('')` is `0`, which is finite. Verified:
```
posNum("",130)        = 0
posNum("  ",130)      = 0
posNum(undefined,130) = 130
```
So the `VAN_PROFILE_DEFAULT` fallback is **unreachable for a manually cleared input** — it
only fires if the element is missing entirely. A driver who blanks the cargo-length box and
saves stores `cargoLengthIn: 0`, after which every load with any stated length trips
`L > 0`. In the normal flow this is masked, because `renderInsights` pre-populates the six
inputs from `getVanProfile()` first (`app.js:6860-6869`
`set('#vanCargoLengthIn', vp.cargoLengthIn);` …), so the defaults round-trip. The exposure
is confined to a deliberately cleared field.

## F4 — the "130" in the Van Profile helper text vs. the placeholder

Both strings verbatim.

`index.html:251`:
```html
<div class="muted" style="font-size:11px;margin-bottom:8px">A load exceeding these blocks scoring with "CAN'T TAKE" before any economics are shown. Defaults are published 2016 Ford Transit T250 148" cargo-van figures — verify against your own van's spec sheet or door sticker before relying on this.</div>
```
`index.html:253`:
```html
<div><label>Cargo length (in)</label><input id="vanCargoLengthIn" type="number" step="0.5" placeholder="130" /></div>
```

**Both CONFIRMED present as quoted.**

**Does any code treat 130 as a value rather than a placeholder? NO — REFUTED.** The
placeholder is presentational only; `el.value` on an empty `<input placeholder="130">` is
`''`, never `'130'`. The number the code actually uses is the independent constant
`app.js:9518` `cargoLengthIn: 130,` inside `VAN_PROFILE_DEFAULT`, whose own comment
(`app.js:9514-9516`) reads *"Published 2016 Ford Transit T250 148" WB cargo-van figures — a
reasonable starting point, NOT a substitute for the driver's own spec sheet/door sticker."*
The literal `130` therefore exists in two places that must be kept in sync by hand, but only
the `app.js` constant is ever read. Per instruction, no attempt was made to determine the
correct real-world figure.

---

# BLOCK G — SHELL, CSP, PARITY

## G1 — CSP

`index.html:17`:
```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://freightlogic-backup.fimseitef.workers.dev https://cdn.jsdelivr.net https://api.eia.gov https://api.weather.gov https://mobile.fmcsa.dot.gov https://bwt.cbp.gov; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" />
```

`_headers:11-12`:
```
/*
  Content-Security-Policy: default-src 'self'; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://freightlogic-backup.fimseitef.workers.dev https://cdn.jsdelivr.net https://api.eia.gov https://api.weather.gov https://mobile.fmcsa.dot.gov https://bwt.cbp.gov; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
```

**Byte-identical: CONFIRMED.** Both extracted policy strings are 496 bytes and `diff`
reports no difference.

```
$ node scripts/verify-cloudflare-parity.mjs
PASS  index.html and _headers CSP are byte-identical
FAIL  live deployment checks reached the deployed origins — fetch failed — run this from a network that can reach https://freightlogic.pages.dev and https://freightlogic-backup.fimseitef.workers.dev

1 parity check(s) failed.
EXIT CODE: 1
```

The single failure is network reachability from this sandbox, not a source defect. The
static half passed; the live half is unverified here.

## G2 — is the parity script enforced automatically?

**NOT ENFORCED.**

- **CI:** `.github/workflows/` contains exactly two files. `tests.yml` runs
  `node tests/run-all.mjs` and nothing else (`:40-41`). `lanes.yml` runs only
  `scripts/lane-guard.mjs` in three jobs (`:32`, `:50`, `:74`). Neither mentions
  `verify-cloudflare-parity.mjs`.
- **git hooks:** `.githooks/pre-commit` execs `lane-guard.mjs precommit`;
  `.githooks/prepare-commit-msg` execs `lane-guard.mjs trailer`. Neither invokes the parity
  script. Furthermore `git config --get core.hooksPath` is **unset** in this clone and
  `.git/hooks` contains no non-sample hook, so **even the lane-guard hooks are inactive
  here** — as `.githooks/pre-commit:5-6` itself states: *"This is NOT the enforcement
  boundary. `git commit --no-verify` bypasses it and hooks are not distributed by clone."*
- **npm scripts:** there is **no `package.json`** in the repo, so there is no npm script
  surface at all.
- The only automated invocation anywhere is from another manually-run script:
  `scripts/m7-certify.mjs:138`
  `execSync('node scripts/verify-cloudflare-parity.mjs --static-only', …)` — and `m7-certify.mjs`
  is itself not wired into CI or any hook. Every other reference
  (`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md:20`, `:35`, `:112`, `CLAUDE.md`, `_headers:3`,
  `index.html:16`) is prose instructing a human to run it.

## G3 — Google Fonts offline behavior

`index.html:26-29`:
```html
  <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:ital,wght@0,400;0,500;1,400&display=swap">
  <link rel="stylesheet" href="styles.css">
```

**Are the fonts referenced in `styles.css`? CONFIRMED — yes**, `styles.css:50-51`:
```css
      --font:      'Syne', -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI Variable Display', system-ui, sans-serif;
      --font-mono: 'DM Mono', 'SF Mono', 'Cascadia Code', 'Menlo', ui-monospace, monospace;
```

**Is there a local fallback stack? CONFIRMED — yes**, and it is a good one: `Syne` falls
back through `-apple-system` / `BlinkMacSystemFont` / `SF Pro Display` /
`Segoe UI Variable Display` / `system-ui` to `sans-serif`; `DM Mono` falls back through
`SF Mono` / `Cascadia Code` / `Menlo` / `ui-monospace` to `monospace`. Both chains
terminate in a generic family, so text always renders.

**Are any font files precached by the SW? REFUTED — no.**
`grep -n "woff\|font" service-worker.js` returns nothing; the `CORE` array
(`service-worker.js:9-24`) contains no font entry, and
`find . -iname "*.woff*" -o -iname "*.ttf" -o -iname "*.otf"` finds no font file anywhere in
the repo. The SW also cannot cache them opportunistically: its fetch handler bails out at
`service-worker.js:125` `if (url.origin !== self.location.origin) return;`.

**Offline behavior:** the `fonts.googleapis.com` stylesheet request fails (verified live:
`{"url":"https://fonts.googleapis.com/css2?family=Syne","error":"Failed to fetch"}`), so
neither `Syne` nor `DM Mono` is available and every `font-family: var(--font)` /
`var(--font-mono)` rule resolves to the next entry in its stack — the platform system font
and the platform monospace font. **The app remains fully legible offline; only the brand
typefaces are lost, with a metric shift in the mono-set numerics (`.pill b`
`styles.css:131`, the `.eval-grade-badge` at 60px `styles.css:420`, and the
`.eval-rpm-hero` at 22px `styles.css:422`).** Note this is a *first-visit-online*
dependency in either case: the browser's own HTTP cache is what makes the fonts survive a
later offline session, and nothing in the app guarantees it.

## G4 — `env(safe-area-inset-*)`

```
$ grep -n "safe-area-inset" styles.css
100:      padding: 14px 14px calc(84px + env(safe-area-inset-bottom));
365:      padding: 0 8px env(safe-area-inset-bottom);
524:      padding: 0 16px calc(16px + env(safe-area-inset-bottom));
540:      position: fixed; bottom: calc(90px + env(safe-area-inset-bottom));
```

Every rule, with its selector:

| Line | Selector | Rule |
|---|---|---|
| 100 | `.app` (`styles.css:98`) | `padding: 14px 14px calc(84px + env(safe-area-inset-bottom));` |
| 365 | `.bottom` (`styles.css:363`) | `padding: 0 8px env(safe-area-inset-bottom);` |
| 524 | `.modal` (`styles.css:518`) | `padding: 0 16px calc(16px + env(safe-area-inset-bottom));` |
| 540 | `.toast` (`styles.css:539`) | `position: fixed; bottom: calc(90px + env(safe-area-inset-bottom));` |

`grep -n "safe-area-inset" index.html` returns **nothing**. `app.js` has exactly one, also
bottom-only: `app.js:20347` `bottom:calc(72px + env(safe-area-inset-bottom))` on the SW
update banner.

**Does `#mainHeader` receive top safe-area padding? REFUTED — NO.** `#mainHeader`
(`index.html:32` `<header id="mainHeader">`) is styled by the bare element selector
`styles.css:105-113`:
```css
    header {
      position: sticky; top: 0; z-index: 30;
      padding: 10px 16px;
      background: rgba(7,7,16,0.92);
      -webkit-backdrop-filter: saturate(180%) blur(20px);
      backdrop-filter: saturate(180%) blur(20px);
      border-bottom: 1px solid var(--border);
      transition: box-shadow .2s;
    }
```
A flat `padding: 10px 16px` and `top: 0`. Confirmed by computed style in a live browser:
`{"paddingTop":"10px","position":"sticky","top":"0px"}`, and
`env(safe-area-inset-top)` appears **zero times** in the entire repository.

The two meta tags that make this consequential, verbatim:
```html
index.html:5
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
index.html:8
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
```

`viewport-fit=cover` extends the layout viewport into the display cutout area, and
`black-translucent` makes the iOS status bar overlay the web content rather than reserve
space above it. With `top: 0` and no top inset compensation, `#mainHeader` — and therefore
the logo (`index.html:35`), the "Freight Logic" / `#appMeta` title block (`:36`), the theme
toggle (`:39`) and the `Week` / `AR` KPI pills (`:42-43`) — renders underneath the status
bar and notch on a notched iPhone in standalone PWA mode. **CONFIRMED.**

## G5

**CANNOT DETERMINE — the prompt is truncated.** Item G5 arrives as the two words
`G5. Count` with no object, predicate, or acceptance criterion. No verdict is possible and
none is guessed. Re-issue G5 and it will be executed against this same tree.

---

# Summary of verdicts

| Item | Verdict |
|---|---|
| A2 `LANES.md` / `MIDWEST_STACK_CANONICAL_v7.md` / both `rate-overrides-*.json` at root | NOT PRESENT |
| A4 checklist locations 1–6, 8–14 | no drift |
| A4 location 7 (index.html design-system comment) | **DRIFT** — comment absent from `index.html`; lives in `styles.css` reading `24.0.0` |
| A4 uncovered: `styles.css` header | **DRIFT** — `24.0.0` |
| A4 uncovered: `midwest-stack-config.json` `appTarget` | **DRIFT** — `FreightLogic v24.0.0` |
| Premise "CLAUDE.md describes v23.8.2" | **REFUTED** — reads `v24.0.2` |
| Premise "CLAUDE.md omits vendor/" | **REFUTED** |
| Premise "CLAUDE.md omits styles.css" | **CONFIRMED** — zero matches; `CLAUDE.md:18` still claims index.html holds "all CSS" |
| B2 CORE `?v=` vs index.html | no mismatch at HEAD |
| B3 `ignoreSearch` on the app-logic cache fallback | **CONFIRMED ABSENT**; HTML-for-JS fallback demonstrated; **PARTIALLY CONFIRMED** as a defect — latent, not armed at 24.0.2 |
| B4 unbounded same-origin `.js` caching | **CONFIRMED** — proven by cache growth 25 → 26 |
| B6 `sw-bridge.js` injects `voice-load.js` | **REFUTED / NOT PRESENT** — loaded once, by `index.html:576` |
| B7 script set differs pre/post SW control | **CONFIRMED** — 3 scripts vs 5 |
| C1 `naLookupMarket('')` → `toronto`, `+8` favorable corridor | **CONFIRMED** |
| C2 `naLookupMarket('a')` → `mississauga` | **CONFIRMED** |
| C4 Quick Evaluate defeats the blank-deadhead guard | **PARTIALLY CONFIRMED** — reaches it, satisfies it with a fabricated `"0"` |
| C5 Chicago→Detroit 280mi $560, no deadhead | **CONFIRMED** — full evaluator refuses; Quick Evaluate returns **A / ACCEPT / $2.00** |
| D2 overlay decision below $1.25/mi | **CONFIRMED** — `TAKE_IF_LIVE` at `$1.19` (floor `1.35 × 0.88 = 1.188`), DZ gate failed |
| D3 overlay renders dollar figures | **CONFIRMED** |
| D4 simultaneous with canonical Bid Range | **CONFIRMED** — inserted as `#mwEvalOutput.nextSibling`; REJECT/PASS above TAKE_IF_LIVE |
| D5 `admin-driver-ui.js` touches rates/verdicts | **REFUTED / NOT PRESENT** |
| E4 `ALLOWED_SETTINGS_KEYS` applied on export | **REFUTED** — import only |
| E5 `appLockPin` in unencrypted export | **CONFIRMED** (PBKDF2 hash, not plaintext) |
| E5 `flk_` token in unencrypted export | **CONFIRMED** (verbatim) |
| E5 `fl_device_id` in unencrypted export | **REFUTED** — localStorage only |
| E5 lockout state in unencrypted export | **CONFIRMED** |
| E6 checksum keyed/HMAC | **REFUTED** — plain SHA-256; 8 exported stores uncovered; mismatch is a bypassable `confirm()` |
| F1 "True Profit" shown with unknown op cost | **CONFIRMED** |
| F2 F26 collects monthly miles | **REFUTED** — cannot derive `opCostPerMile` at end of onboarding |
| F3 `checkVanFit` skipped vs. defaulted | **PARTIALLY CONFIRMED** — per-dimension skip via `null`; profile default applies; separate `posNum('')→0` hazard on a cleared Settings field |
| F4 code treats the `130` placeholder as a value | **REFUTED** |
| G1 CSP byte-identical | **CONFIRMED** (496 B, `diff` clean) |
| G2 parity script automatically enforced | **NOT ENFORCED** |
| G3 fonts precached by SW | **REFUTED** — none; local fallback stack present; app legible offline |
| G4 `#mainHeader` top safe-area padding | **REFUTED** — none, with `viewport-fit=cover` + `black-translucent` |
| G5 | **CANNOT DETERMINE** — prompt truncated |
