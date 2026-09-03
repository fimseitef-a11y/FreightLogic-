/* FreightLogic v24.0.4 — service worker update bridge */
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
