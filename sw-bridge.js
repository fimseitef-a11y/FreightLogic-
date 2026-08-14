/* FreightLogic v23.8.2 — service worker update bridge */
(function(){
  if (!('serviceWorker'in navigator)) return;

  let reloading = false;
  let skipWaitingRequested = false;

  const reloadOnce = () => {
    if (!skipWaitingRequested || reloading) return;
    reloading = true;
    window.location.reload();
  };

  // Only reload when we triggered SKIP_WAITING — not on first-install controllerchange
  navigator.serviceWorker.addEventListener('controllerchange', reloadOnce);

  // Expose for app.js "New version available" banner
  window._flRequestSWUpdate = () => {
    const ctrl = navigator.serviceWorker.controller;
    if (ctrl) { skipWaitingRequested = true; ctrl.postMessage({ type: 'SKIP_WAITING' }); }
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
