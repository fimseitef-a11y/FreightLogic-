(() => {
'use strict';

/** Freight Logic v20.2.0 USA ENGINE
 *  Market Feed + Tomorrow Signal + Strategic Floor (A–E)
 *  v18.2: OpenAI load evaluation, auto-update bridge, session-scoped credentials,
 *         user namespace, FreightLogic_v18 DB with XpediteOps_v1 migration
 */

const APP_VERSION = '20.2.0';

// escapeHtml is the canonical XSS-safe escape function — see line ~74

// csvSafeCell is the canonical CSV injection guard — see line ~91

const _listeners = new Map();
function addManagedListener(el, evt, handler) {
  if (!el) return;
  el.addEventListener(evt, handler);
  const key = el.id || 'anon';
  if (!_listeners.has(key)) _listeners.set(key, []);
  _listeners.get(key).push({el, evt, handler});
}
function cleanupListeners() {
  _listeners.forEach(list => {
    list.forEach(({el, evt, handler}) => el?.removeEventListener(evt, handler));
  });
  _listeners.clear();
}
window.addEventListener('beforeunload', cleanupListeners);
window.addEventListener('pagehide', cleanupListeners);


const DB_NAME = 'FreightLogic_v18';
const DB_NAME_LEGACY = 'XpediteOps_v1';
const SETTINGS_CACHE = new Map();
function getCachedSetting(key, fallback=null){ return SETTINGS_CACHE.has(key) ? SETTINGS_CACHE.get(key) : fallback; }
