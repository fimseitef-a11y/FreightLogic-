// Fixture service worker for the update-handshake regression.
//
// Committed as the "v1" generation. The spec rewrites this exact path with
// different bytes to trigger a real update, then restores this content — the
// script URL has to stay identical for the browser to treat it as an update
// rather than a separate registration.
const FIXTURE_GENERATION = 'v1';

self.addEventListener('install', () => {
  // Deliberately NO self.skipWaiting() here: the whole point is to produce a
  // worker that sits in `waiting` until the page asks it to take over.
});
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
self.addEventListener('fetch', () => {});
