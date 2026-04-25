/* FreightLogic v23.2.0 — service worker update bridge */
(function(){
  if (!('serviceWorker'in navigator)) return;

  let reloading = false;
  const reloadOnce = () => {
    if (reloading) return;
    reloading = true;
    window.location.reload();
  };

  // Reload once the new SW takes control — triggered by app.js banner "Reload" button
  navigator.serviceWorker.addEventListener('controllerchange', reloadOnce);

  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.getRegistration();
      if (!registration) return;
      await registration.update();
      setInterval(() => {
        registration.update().catch((e) => console.warn('[FL] periodic SW update failed:', e));
      }, 5 * 60 * 1000);
    } catch (e) {
      console.warn('[FL] service worker bridge init failed:', e);
    }
  });
})();
