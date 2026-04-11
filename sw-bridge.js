/* Freight Logic v23.1.0 — service worker update bridge + voice-load bootstrap */
(function(){
  if (!('serviceWorker' in navigator)) return;

  let reloading = false;
  const reloadOnce = () => {
    if (reloading) return;
    reloading = true;
    window.location.reload();
  };

  const ensureVoiceModule = () => {
    try {
      if (document.querySelector('script[data-voice-load="1"]')) return;
      const script = document.createElement('script');
      script.src = 'voice-load.js?v=23.1.0';
      script.defer = true;
      script.dataset.voiceLoad = '1';
      script.addEventListener('error', (e) => {
        console.warn('[FL] voice-load bootstrap failed:', e);
      });
      document.body.appendChild(script);
    } catch (e) {
      console.warn('[FL] voice-load bootstrap failed:', e);
    }
  };

  navigator.serviceWorker.addEventListener('controllerchange', reloadOnce);

  const pingWaiting = (registration) => {
    try {
      if (registration && registration.waiting) {
        registration.waiting.postMessage({ type: 'SKIP_WAITING' });
      }
    } catch (e) {
      console.warn('[FL] skipWaiting bridge failed:', e);
    }
  };

  const attachUpdateListener = (registration) => {
    if (!registration) return;
    if (registration.waiting) pingWaiting(registration);
    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      if (!worker) return;
      worker.addEventListener('statechange', () => {
        if (worker.state === 'installed' && navigator.serviceWorker.controller) {
          pingWaiting(registration);
        }
      });
    });
  };

  window.addEventListener('load', async () => {
    ensureVoiceModule();
    try {
      const registration = await navigator.serviceWorker.getRegistration();
      if (!registration) return;
      attachUpdateListener(registration);
      await registration.update();
      pingWaiting(registration);
      setInterval(() => {
        registration.update().catch((e) => console.warn('[FL] periodic SW update failed:', e));
      }, 5 * 60 * 1000);
    } catch (e) {
      console.warn('[FL] service worker bridge init failed:', e);
    }
  });
})();
