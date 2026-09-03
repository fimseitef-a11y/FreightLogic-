/* FreightLogic v24.0.4 — Browser Hardened Service Worker */
const SW_VERSION = '24.0.4';
const CACHE_NAME = `freightlogic-${SW_VERSION}`;
const RECEIPT_CACHE = 'freightlogic-receipts-v2';
const SHARE_CACHE = 'freightlogic-share-v2';
const APP_SHELL = './index.html';
const ADMIN_UI_TAG = '<script src="admin-driver-ui.js?v=24.0.4"></script>';
const MIDWEST_STACK_TAG = '<script src="midwest-stack-authority.js?v=24.0.4"></script>';
const CORE = [
  './', APP_SHELL,
  './app.js?v=24.0.4',
  './voice-load.js?v=24.0.4',
  './styles.css',
  './admin-driver-ui.js?v=24.0.4',
  './midwest-stack-authority.js?v=24.0.4',
  './manifest.json?v=24.0.4',
  './midwest-stack-config.json',
  // X-10: SheetJS is now bundled (no CDN fallback) — precache it so Excel
  // import works fully offline from the very first install.
  './vendor/xlsx.full.min.js',
  './icon64.png','./icon128.png','./icon192.png','./icon256.png','./icon512.png',
  './icon180.png','./icon167.png','./icon152.png','./icon120.png','./icon1024.png','./favicon32.png','./favicon16.png',
  './sw-bridge.js?v=24.0.4'
];

// v24.0.4 item 4: the finite set of assets this worker will serve from cache,
// derived from CORE itself so the fetch policy cannot drift from what install()
// actually precaches. Queries are stripped: identity is the PATH, and the `?v=`
// generation is handled separately (a known asset may fall back to a
// query-insensitive cache hit; an unknown path may not).
function normalizeAssetPath(pathname) {
  // './app.js?v=24.0.4' and '/app.js' must resolve to the same identity.
  return new URL(pathname, self.location.href).pathname;
}
const KNOWN_ASSET_PATHS = new Set(
  CORE.map(u => normalizeAssetPath(u.split('?')[0]))
);

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

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Critical shell — one failure here is acceptable to abort install.
    // X-08: midwest-stack-authority.js was only in the broader, non-blocking
    // CORE list — a first offline install could complete and serve the app
    // shell before the TRUE_RPM decision layer was actually cached, with no
    // error surfaced. X-10: the bundled SheetJS vendor file is critical too,
    // for the same "must work on the very first offline install" reason.
    const critical = ['./', APP_SHELL, './app.js?v=24.0.4', './voice-load.js?v=24.0.4', './styles.css', './sw-bridge.js?v=24.0.4', './manifest.json?v=24.0.4', './midwest-stack-authority.js?v=24.0.4', './vendor/xlsx.full.min.js'];
    await cache.addAll(critical);
    // Optional assets — failure does not abort install
    const optional = CORE.filter(u => !critical.includes(u));
    await Promise.allSettled(optional.map(url =>
      cache.add(url).catch(e => console.warn('[FL-SW] Optional asset skipped:', url, e))
    ));
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    const keep = new Set([CACHE_NAME, RECEIPT_CACHE, SHARE_CACHE]);
    await Promise.all(keys.map(k => keep.has(k) ? null : caches.delete(k)));
    try {
      const shareCache = await caches.open(SHARE_CACHE);
      const metaRes = await shareCache.match('/shared-meta');
      if (metaRes) {
        const meta = await metaRes.json().catch(() => null);
        if (!meta || !meta.ts || (Date.now() - meta.ts > 300000)) await caches.delete(SHARE_CACHE);
      }
    } catch {}
    await self.clients.claim();
    const clients = await self.clients.matchAll({ type: 'window' });
    for (const client of clients) {
      try { client.postMessage({ type: 'SW_ACTIVATED', version: SW_VERSION }); } catch {}
    }
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data || {};
  if (msg.type === 'GET_VERSION') {
    try { event.ports?.[0]?.postMessage({ version: SW_VERSION }); } catch {}
  }
  if (msg.type === 'SKIP_WAITING' && event.source) self.skipWaiting();
});

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

  // ── v24.0.4 item 4: finite asset authority, and never HTML for a subresource ──
  //
  // The previous handler classified EVERY same-origin `.js` as "app logic" and,
  // on network failure, fell back to `cache.match(req) || cache.match(APP_SHELL)`.
  // Two defects followed from that:
  //
  //   1. The shell fallback applied to scripts. `cache.match(req)` does NOT pass
  //      { ignoreSearch: true }, so any `?v=` drift between index.html and the
  //      precache was a hard miss, and the handler answered a <script src> with
  //      index.html — HTTP 200, Content-Type: text/html. The browser refuses to
  //      execute it, with no 404 and no console error: the script silently
  //      vanishes. Demonstrated against the shipped worker by killing the origin.
  //   2. Wildcard `.js` matching meant any same-origin script — including ones
  //      never precached — was cached on success with no bound.
  //
  // The rules below are: a finite set of known app assets derived from CORE
  // (single source of truth, so it cannot drift from what install() precaches);
  // query-insensitive fallback ONLY for those known assets, so a version-query
  // drift self-heals to the right file instead of poisoning the response; and
  // HTML is served only to something that actually asked to navigate.
  const isNavigation = req.mode === 'navigate' || url.pathname.endsWith('.html');
  const isKnownAppAsset = KNOWN_ASSET_PATHS.has(normalizeAssetPath(url.pathname));
  const isStatic = /\.(json|png|ico|md)$/i.test(url.pathname);
  const isScript = req.destination === 'script' || url.pathname.endsWith('.js');

  /** A failure response that is never mistaken for content. Critically it is NOT
   *  the app shell: returning HTML here is the defect this release removes. */
  const offlineFailure = (what) => new Response(
    `Offline — ${what} is not available in this cache generation.`,
    { status: 504, headers: { 'Content-Type': 'text/plain', 'X-FL-Offline': '1' } }
  );

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);

    // 1. Navigations. HTML is correct here, and only here.
    if (isNavigation) {
      try {
        const res = await fetch(req);
        const out = await injectEnhancementScripts(res.clone());
        if (res && res.ok) cache.put(req, out.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
        return out;
      } catch {
        const cached = (await cache.match(req)) || (await cache.match(req, { ignoreSearch: true })) || (await cache.match(APP_SHELL));
        if (!cached) return new Response('Offline — no cached page available', { status: 503, headers: { 'Content-Type': 'text/plain' } });
        return await injectEnhancementScripts(cached);
      }
    }

    // 2. Known app assets (scripts, styles, the manifest, icons, bundled vendor).
    //    Network-first so a fresh generation wins; on failure fall back to the
    //    exact cache key, then — for these known assets only — to a
    //    query-insensitive match so `?v=` drift self-heals to the real file.
    if (isKnownAppAsset) {
      try {
        const res = await fetch(req);
        if (res && res.ok) cache.put(req, res.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
        return res;
      } catch {
        const cached = (await cache.match(req)) || (await cache.match(req, { ignoreSearch: true }));
        return cached || offlineFailure(url.pathname);
      }
    }

    // 3. Static data/media that is not a known app asset — cache-first, but a
    //    miss is a miss. Never the shell.
    if (isStatic) {
      const cached = await cache.match(req, { ignoreSearch: true });
      if (cached) return cached;
      try {
        const res = await fetch(req);
        if (res && res.ok) cache.put(req, res.clone()).catch(e => console.warn('[FL-SW] Cache put failed:', e));
        return res;
      } catch {
        return offlineFailure(url.pathname);
      }
    }

    // 4. Everything else same-origin. No wildcard caching, and a script that is
    //    not a known app asset still must never be answered with HTML.
    try {
      return await fetch(req);
    } catch {
      const cached = await cache.match(req);
      if (cached) return cached;
      if (isScript) return offlineFailure(url.pathname);
      return offlineFailure(url.pathname);
    }
  })());
});
