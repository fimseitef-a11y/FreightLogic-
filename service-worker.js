/* FreightLogic v23.5.1 — Browser Hardened Service Worker */
const SW_VERSION = '23.5.1';
const CACHE_NAME = `freightlogic-${SW_VERSION}`;
const RECEIPT_CACHE = 'freightlogic-receipts-v2';
const SHARE_CACHE = 'freightlogic-share-v2';
const APP_SHELL = './index.html';
const ADMIN_UI_TAG = '<script src="admin-driver-ui.js?v=23.5.0"></script>';
const MIDWEST_STACK_TAG = '<script src="midwest-stack-authority.js?v=23.5.1"></script>';
const CORE = [
  './', APP_SHELL,
  './app.js?v=23.5.0',
  './voice-load.js?v=23.5.0',
  './admin-driver-ui.js?v=23.5.0',
  './midwest-stack-authority.js?v=23.5.1',
  './manifest.json?v=23.5.0',
  './midwest-stack-config.json',
  './rate-overrides-2026-05.json',
  './icon64.png','./icon128.png','./icon192.png','./icon256.png','./icon512.png',
  './icon180.png','./icon167.png','./icon152.png','./icon120.png','./icon1024.png','./favicon32.png','./favicon16.png',
  './sw-bridge.js?v=23.5.0'
];

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
    return new Response(text, { status: res.status, statusText: res.statusText, headers: res.headers });
  } catch (err) {
    console.warn('[FL-SW] Enhancement script injection failed:', err);
    return res;
  }
}

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
