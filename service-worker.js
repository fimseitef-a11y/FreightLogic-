/* Freight Logic v18.2.0 — Browser Hardened Service Worker */
const SW_VERSION = '18.2.0';
const CACHE_NAME = `freightlogic-${SW_VERSION}`;
const RECEIPT_CACHE = 'freightlogic-receipts-v2';
const SHARE_CACHE = 'freightlogic-share-v2';
const APP_SHELL = './index.html';
const CORE = [
  './', APP_SHELL, './app.js', './manifest.json',
  './icon64.png','./icon128.png','./icon192.png','./icon256.png','./icon512.png',
  './icon180.png','./icon167.png','./icon152.png','./icon120.png','./icon1024.png','./favicon32.png','./favicon16.png',
  './sw-bridge.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(CORE);
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
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data || {};
  if (msg.type === 'GET_VERSION') {
    try { event.ports?.[0]?.postMessage({ version: SW_VERSION }); } catch {}
  }
  if (msg.type === 'SKIP_WAITING') self.skipWaiting();
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
          await shareCache.put('/shared-meta', new Response(JSON.stringify({ count: files.length, ts: Date.now() })));
          for (let i = 0; i < files.length; i++) {
            const file = files[i];
            await shareCache.put(`/shared-file-${i}`, new Response(file, { headers: { 'Content-Type': file.type, 'X-Filename': file.name } }));
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
        if (res && res.ok) cache.put(req, res.clone());
        return res;
      } catch {
        return (await cache.match(req)) || (await cache.match(APP_SHELL));
      }
    }
    if (isStatic) {
      const cached = await cache.match(req, { ignoreSearch: true });
      if (cached) return cached;
      try {
        const res = await fetch(req);
        if (res && res.ok) cache.put(req, res.clone());
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
