/* FreightLogic v24.0.23 — modern five-surface navigation adapter
 * Structural navigation; presentation is owned by styles.css.
 * Canonical routing, state, evaluation and data ownership remain in app.js.
 */
(() => {
  'use strict';

  const PRIMARY_ROUTES = new Set(['home', 'loads', 'omega', 'trips', 'money']);
  const ROUTE_ALIASES = { today: 'home', evaluate: 'omega' };
  let installed = false;

  const icon = {
    today: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
    loads: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>',
    trips: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="1" y="3" width="15" height="13"/><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/></svg>',
    money: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M16 8.5c-.9-.7-2.1-1-3.5-1-2 0-3.5 1-3.5 2.5 0 3.5 7 1.5 7 5 0 1.5-1.5 2.5-3.5 2.5-1.5 0-2.9-.4-4-1.3M12 5v14"/></svg>'
  };


  function canonicalRoute(route) {
    const raw = String(route || 'home').replace(/^#/, '');
    return ROUTE_ALIASES[raw] || raw;
  }

  function syncActiveFromHash() {
    const route = canonicalRoute(window.location.hash || 'home');
    document.querySelectorAll('.bottom .nav [data-nav]').forEach((link) => {
      const active = link.dataset.nav === route;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  }

  function rebuildPrimaryNav() {
    const nav = document.querySelector('.bottom .nav');
    if (!nav) return;
    const badge = nav.querySelector('#navUnpaidBadge');
    nav.innerHTML = `
      <a href="#home" data-nav="home" data-modern-route="home" aria-label="Today"><div class="ni">${icon.today}</div><div class="nl">Today</div></a>
      <a href="#loads" data-nav="loads" data-modern-route="loads" aria-label="Loads"><div class="ni">${icon.loads}</div><div class="nl">Loads</div></a>
      <a href="#omega" data-nav="omega" data-modern-route="evaluate" aria-label="Evaluate load" class="nav-eval-center"><div class="ni" aria-hidden="true">⚡</div><div class="nl">Evaluate</div></a>
      <a href="#trips" data-nav="trips" data-modern-route="trips" aria-label="Trips"><div class="ni" data-badge-slot style="position:relative">${icon.trips}</div><div class="nl">Trips</div></a>
      <a href="#money" data-nav="money" data-modern-route="money" aria-label="Money"><div class="ni">${icon.money}</div><div class="nl">Money</div></a>`;
    const slot = nav.querySelector('[data-badge-slot]');
    if (slot) {
      if (badge) slot.appendChild(badge);
      else {
        const fresh = document.createElement('span');
        fresh.id = 'navUnpaidBadge';
        fresh.style.cssText = 'display:none;position:absolute;top:-4px;right:-6px;min-width:16px;height:16px;padding:0 4px;border-radius:8px;background:var(--bad);color:#fff;font-size:10px;font-weight:700;line-height:16px;text-align:center';
        slot.appendChild(fresh);
      }
    }
  }

  function addSecondaryMenuAccess() {
    if (document.getElementById('modernMoreBtn')) return;
    const headerActions = document.querySelector('#mainHeader .hdr-row .row');
    if (!headerActions) return;
    const button = document.createElement('button');
    button.id = 'modernMoreBtn';
    button.className = 'theme-btn';
    button.type = 'button';
    button.setAttribute('aria-label', 'More tools and settings');
    button.title = 'More';
    button.textContent = '•••';
    button.addEventListener('click', () => { navigate('more'); });
    headerActions.insertBefore(button, headerActions.firstChild);
  }

  function navigate(requested) {
    const route = canonicalRoute(requested);
    if (window.location.hash.replace(/^#/, '') !== route) window.location.hash = route;
  }

  function normalizeAliasHash() {
    const raw = window.location.hash.replace(/^#/, '');
    if (ROUTE_ALIASES[raw]) window.location.hash = ROUTE_ALIASES[raw];
  }

  function install() {
    if (installed) return;
    installed = true;
    const home = document.getElementById('view-home');
    if (home) home.setAttribute('aria-label', 'Today');
    rebuildPrimaryNav();
    addSecondaryMenuAccess();
    window.addEventListener('hashchange', normalizeAliasHash);
    normalizeAliasHash();
    syncActiveFromHash();
  }

  window.FreightLogicModernShell = { install, navigate, primaryRoutes: () => [...PRIMARY_ROUTES] };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install, { once: true });
  else install();
})();
