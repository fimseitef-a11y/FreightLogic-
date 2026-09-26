/* FreightLogic v24.0.45 — modern five-surface navigation adapter
 * Structural navigation; presentation is owned by styles.css.
 * Canonical routing, state, evaluation and data ownership remain in app.js.
 */
(() => {
  'use strict';

  const PRIMARY_ROUTES = new Set(['home', 'loads', 'omega', 'trips', 'money']);
  const ROUTE_ALIASES = { today: 'home', evaluate: 'omega' };
  const ROUTE_TITLES = {
    home: 'Today', loads: 'Loads', omega: 'Evaluate', trips: 'Trips', money: 'Money',
    expenses: 'Expenses', fuel: 'Fuel', intel: 'Market Intel', insights: 'Settings', more: 'More'
  };
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

    // The header behaves like an iPhone screen title, not a permanent marketing
    // banner. The brand still lives in the install icon/about surface.
    const title = document.querySelector('#mainHeader .brand .title strong');
    if (title) title.textContent = ROUTE_TITLES[route] || 'FreightLogic';
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

  function installA11yRepairs() {
    const buttonIds = ['fuelNudgeCard', 'maintAlertBanner', 'f22TaxToggle'];
    const disclosureBodies = { evalAdvToggle: 'evalAdvBody', advSettingsToggle: 'advSettingsBody', f22TaxToggle: 'f22TaxBody' };

    const isExpanded = (body) => {
      if (!body) return false;
      const style = getComputedStyle(body);
      return style.display !== 'none' && style.visibility !== 'hidden' && !body.hidden;
    };

    const makeKeyboardButton = (el) => {
      if (!el || el.dataset.flA11yButton === '1') return;
      if (el.tagName !== 'BUTTON' && el.tagName !== 'A') {
        el.setAttribute('role', 'button');
        el.setAttribute('tabindex', '0');
        el.addEventListener('keydown', (event) => {
          if (event.key !== 'Enter' && event.key !== ' ') return;
          event.preventDefault();
          el.click();
        });
      }
      el.dataset.flA11yButton = '1';
    };

    const syncDisclosure = (el, bodyId) => {
      if (!el) return;
      makeKeyboardButton(el);
      const update = () => el.setAttribute('aria-expanded', isExpanded(document.getElementById(bodyId)) ? 'true' : 'false');
      el.setAttribute('aria-controls', bodyId);
      update();
      if (el.dataset.flA11yDisclosure !== '1') {
        el.addEventListener('click', () => setTimeout(update, 0));
        el.dataset.flA11yDisclosure = '1';
      }
    };

    const repair = () => {
      for (const id of buttonIds) makeKeyboardButton(document.getElementById(id));
      for (const [id, bodyId] of Object.entries(disclosureBodies)) syncDisclosure(document.getElementById(id), bodyId);

      const start = document.getElementById('f21StartBtn');
      const info = document.getElementById('f21InfoBtn');
      if (start && info && start.contains(info)) start.insertAdjacentElement('afterend', info);
      makeKeyboardButton(start);
      makeKeyboardButton(info);
      if (start) start.setAttribute('aria-label', start.getAttribute('aria-label') || 'Start trip');
      if (info) info.setAttribute('aria-label', info.getAttribute('aria-label') || 'GPS tracking information');

      // Dynamic report/lane rows use pointer affordance for activation. Give any
      // such visible non-native row keyboard semantics without changing its click contract.
      document.querySelectorAll('[data-weekly-report-action], [data-lane-action], #laneList [onclick]').forEach(makeKeyboardButton);
    };

    repair();
    const observer = new MutationObserver(repair);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function install() {
    if (installed) return;
    installed = true;
    const home = document.getElementById('view-home');
    if (home) home.setAttribute('aria-label', 'Today');
    rebuildPrimaryNav();
    addSecondaryMenuAccess();
    window.addEventListener('hashchange', () => {
      normalizeAliasHash();
      syncActiveFromHash();
    });
    normalizeAliasHash();
    syncActiveFromHash();
    installA11yRepairs();
  }

  window.FreightLogicModernShell = { install, navigate, primaryRoutes: () => [...PRIMARY_ROUTES] };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install, { once: true });
  else install();
})();
