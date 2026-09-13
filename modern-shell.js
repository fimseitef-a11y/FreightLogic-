/* FreightLogic v24.0.7 — modern five-surface navigation adapter
 *
 * Structural-only layer. It deliberately reuses FreightLogic's canonical
 * renderers/state instead of introducing a second load queue or evaluator.
 * Primary driver surfaces: Today / Loads / Evaluate / Trips / Money.
 */
(() => {
  'use strict';

  const PRIMARY_ROUTES = new Set(['home', 'loads', 'evaluate', 'trips', 'money']);
  const originalNavigate = typeof window.navigate === 'function' ? window.navigate.bind(window) : null;
  let installed = false;

  const icon = {
    today: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
    loads: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>',
    trips: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="1" y="3" width="15" height="13"/><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/></svg>',
    money: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M16 8.5c-.9-.7-2.1-1-3.5-1-2 0-3.5 1-3.5 2.5 0 3.5 7 1.5 7 5 0 1.5-1.5 2.5-3.5 2.5-1.5 0-2.9-.4-4-1.3M12 5v14"/></svg>'
  };

  function currentPrimaryRoute() {
    const hash = window.location.hash.replace(/^#/, '');
    if (hash === 'omega') return 'evaluate';
    if (PRIMARY_ROUTES.has(hash)) return hash;
    const active = document.querySelector('.view.active');
    if (!active) return 'home';
    if (active.id === 'view-omega') return 'evaluate';
    const route = active.id.replace(/^view-/, '');
    return PRIMARY_ROUTES.has(route) ? route : null;
  }

  function setPrimaryActive(route) {
    const nav = document.querySelector('.bottom .nav');
    if (!nav) return;
    nav.querySelectorAll('[data-modern-route]').forEach((link) => {
      const active = link.dataset.modernRoute === route;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  }

  function ensureLoadsSurface() {
    let view = document.getElementById('view-loads');
    if (!view) {
      view = document.createElement('section');
      view.id = 'view-loads';
      view.className = 'view';
      view.style.display = 'none';
      view.setAttribute('aria-label', 'Loads');
      view.innerHTML = `
        <div class="card" style="margin-bottom:12px">
          <div class="fl-card-hdr" style="align-items:flex-start;gap:10px">
            <div>
              <h3 style="margin:0 0 4px">Loads</h3>
              <div class="muted" style="font-size:12px;line-height:1.45">Captured freight waiting for review, evaluation, or action.</div>
            </div>
            <button class="btn primary" id="modernLoadIntake" style="padding:8px 12px;white-space:nowrap">＋ Intake</button>
          </div>
          <button class="btn" id="modernLoadsRefresh" style="width:100%;margin-top:10px">Refresh loads</button>
        </div>
        <div id="modernLoadsSlot"></div>`;

      const trips = document.getElementById('view-trips');
      const parent = trips && trips.parentNode ? trips.parentNode : document.querySelector('main.app');
      if (parent) parent.insertBefore(view, trips || null);
    }

    const slot = view.querySelector('#modernLoadsSlot');
    const inbox = document.getElementById('loadInboxCard');
    if (slot && inbox && inbox.parentNode !== slot) slot.appendChild(inbox);

    const intake = view.querySelector('#modernLoadIntake');
    if (intake && !intake.dataset.bound) {
      intake.dataset.bound = '1';
      intake.addEventListener('click', () => {
        const canonical = document.getElementById('btnLoadIntake');
        if (canonical) canonical.click();
      });
    }

    const refresh = view.querySelector('#modernLoadsRefresh');
    if (refresh && !refresh.dataset.bound) {
      refresh.dataset.bound = '1';
      refresh.addEventListener('click', () => renderLoads());
    }

    return view;
  }

  async function renderLoads() {
    try {
      if (typeof window.renderLoadInbox === 'function') {
        await window.renderLoadInbox();
        return;
      }
      // renderOmega() already owns the inbox render call in the canonical app.
      // Calling it directly is a safe fallback because it updates existing DOM
      // state without creating a second queue or changing the active route.
      if (typeof window.renderOmega === 'function') await window.renderOmega();
    } catch (err) {
      console.warn('[FL modern shell] Loads render failed:', err);
    }
  }

  function rebuildPrimaryNav() {
    const nav = document.querySelector('.bottom .nav');
    if (!nav) return;

    nav.innerHTML = `
      <a href="#home" data-modern-route="home" data-nav="home" aria-label="Today">
        <div class="ni">${icon.today}</div><div class="nl">Today</div>
      </a>
      <a href="#loads" data-modern-route="loads" data-nav="loads" aria-label="Loads">
        <div class="ni">${icon.loads}</div><div class="nl">Loads</div>
      </a>
      <a href="#evaluate" data-modern-route="evaluate" data-nav="evaluate" aria-label="Evaluate load" class="nav-eval-center">
        <div class="ni" aria-hidden="true">⚡</div><div class="nl">Evaluate</div>
      </a>
      <a href="#trips" data-modern-route="trips" data-nav="trips" aria-label="Trips">
        <div class="ni" style="position:relative">${icon.trips}<span id="navUnpaidBadge" style="display:none;position:absolute;top:-4px;right:-6px;min-width:16px;height:16px;padding:0 4px;border-radius:8px;background:var(--bad);color:#fff;font-size:10px;font-weight:700;line-height:16px;text-align:center"></span></div><div class="nl">Trips</div>
      </a>
      <a href="#money" data-modern-route="money" data-nav="money" aria-label="Money">
        <div class="ni">${icon.money}</div><div class="nl">Money</div>
      </a>`;

    nav.addEventListener('click', (event) => {
      const link = event.target.closest('[data-modern-route]');
      if (!link || !nav.contains(link)) return;
      event.preventDefault();
      // The legacy shell may also have a delegated nav handler on this same
      // container. This adapter is now authoritative for the five top-level
      // routes, so do not let both routers run for the same tap.
      event.stopImmediatePropagation();
      modernNavigate(link.dataset.modernRoute, link).catch((err) => {
        console.warn('[FL modern shell] Navigation failed:', err);
      });
    }, true);
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
    button.addEventListener('click', () => {
      if (originalNavigate) originalNavigate('more', button);
    });
    headerActions.insertBefore(button, headerActions.firstChild);
  }

  async function modernNavigate(requested, targetEl) {
    if (!originalNavigate) return;
    let route = String(requested || 'home').replace(/^#/, '');
    if (route === 'today') route = 'home';

    if (route === 'omega' || route === 'evaluate') {
      await originalNavigate('omega', targetEl);
      // Keep the canonical Omega implementation underneath while exposing the
      // driver-facing route/name. replaceState avoids an omega→evaluate loop.
      const url = new URL(window.location.href);
      url.hash = 'evaluate';
      window.history.replaceState(window.history.state, '', url);
      setPrimaryActive('evaluate');
      return;
    }

    if (route === 'loads') {
      ensureLoadsSurface();
      await originalNavigate('loads', targetEl);
      await renderLoads();
      setPrimaryActive('loads');
      return;
    }

    await originalNavigate(route, targetEl);
    setPrimaryActive(PRIMARY_ROUTES.has(route) ? route : null);
  }

  function handleHashRoute() {
    const route = window.location.hash.replace(/^#/, '');
    if (route === 'omega' || route === 'evaluate') {
      const omegaActive = document.getElementById('view-omega')?.classList.contains('active');
      if (omegaActive && route === 'evaluate') {
        setPrimaryActive('evaluate');
        return;
      }
      modernNavigate('evaluate').catch((err) => console.warn('[FL modern shell] Evaluate route failed:', err));
      return;
    }
    if (route === 'loads') {
      const loadsActive = document.getElementById('view-loads')?.classList.contains('active');
      if (loadsActive) {
        setPrimaryActive('loads');
        renderLoads();
        return;
      }
      modernNavigate('loads').catch((err) => console.warn('[FL modern shell] Loads route failed:', err));
      return;
    }
    setPrimaryActive(PRIMARY_ROUTES.has(route) ? route : currentPrimaryRoute());
  }

  function install() {
    if (installed) return;
    installed = true;
    if (!originalNavigate) {
      console.warn('[FL modern shell] Canonical navigate() was not available; leaving legacy shell untouched.');
      return;
    }

    const home = document.getElementById('view-home');
    if (home) home.setAttribute('aria-label', 'Today');
    ensureLoadsSurface();
    rebuildPrimaryNav();
    addSecondaryMenuAccess();

    // Existing quick actions / legacy links that call navigate('omega') now
    // land on the driver-facing Evaluate route without rewriting their callers.
    window.navigate = modernNavigate;
    window.addEventListener('hashchange', handleHashRoute);

    const initial = window.location.hash.replace(/^#/, '');
    if (initial === 'omega' || initial === 'evaluate' || initial === 'loads') {
      handleHashRoute();
    } else {
      setPrimaryActive(currentPrimaryRoute());
    }
  }

  window.FreightLogicModernShell = {
    install,
    navigate: modernNavigate,
    renderLoads,
    ensureLoadsSurface
  };

  install();
})();
