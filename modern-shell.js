/* FreightLogic v24.0.56 — modern five-surface navigation adapter
 * Structural navigation; presentation is owned by styles.css.
 * Canonical routing, state, evaluation and data ownership remain in app.js.
 */
(() => {
  'use strict';

  const PRIMARY_ROUTES = new Set(['home', 'loads', 'omega', 'trips', 'money']);
  const ROUTE_ALIASES = { today: 'home', evaluate: 'omega', scan: 'omega' };
  const ROUTE_TITLES = {
    home: 'Today', loads: 'Loads', omega: 'Scan', trips: 'History', money: 'Money', current: 'Current Load', reports: 'Reports',
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
    const owner = ['expenses','fuel','reports'].includes(route) ? 'money'
      : route === 'intel' ? 'loads'
      : route === 'current' ? 'home'
      : route;
    document.querySelectorAll('.bottom .nav [data-nav]').forEach((link) => {
      const active = link.dataset.nav === owner;
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
      <a href="#omega" data-nav="omega" data-modern-route="scan" aria-label="Scan load" class="nav-eval-center"><div class="ni" aria-hidden="true">⚡</div><div class="nl">Scan</div></a>
      <a href="#trips" data-nav="trips" data-modern-route="trips" aria-label="History"><div class="ni" data-badge-slot style="position:relative">${icon.trips}</div><div class="nl">History</div></a>
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


  const TODAY_PRESENTATION_SPEC = Object.freeze({
    homeId: 'view-home',
    homeClass: 'today-command-v2',
    primaryCardId: 'homeKPICard',
    positionCardId: 'homePositioningCard',
    positionDisclosureId: 'homePositioningDisclosure',
    moneyCardId: 'homeMoneyCard',
    fuelRoute: 'insights',
    fuelFieldId: 'fuelPrice',
    fuelSectionId: 'settingsCosts'
  });
  let todayObserver = null;
  let todaySyncScheduled = false;
  let fuelRouteBound = false;
  let headerResizeBound = false;

  function installTodayStyles() {
    if (document.getElementById('todayCommandCenterV2Styles')) return;
    const style = document.createElement('style');
    style.id = 'todayCommandCenterV2Styles';
    style.textContent = `
      :root { --fl-header-bottom: 72px; }
      #mainHeader.modern-header-safe { isolation:isolate; z-index:240; }
      #mainHeader.modern-header-safe #modernMoreBtn { position:relative; z-index:3; }
      .toast {
        top:calc(var(--fl-header-bottom, 72px) + 8px) !important;
        max-width:min(420px, calc(100vw - 24px));
      }
      #view-home.today-command-v2 .today-context-rail { margin-top:8px !important; }
      #view-home.today-command-v2 .today-context-rail > * {
        min-height:44px !important;
        padding:9px 11px !important;
        border-radius:14px !important;
        box-shadow:none !important;
        font-size:12px !important;
        line-height:1.35 !important;
      }
      #view-home.today-command-v2 #homeTripTrackCard { margin-top:8px !important; }
      #view-home.today-command-v2 #homeTripTrackCard .card {
        padding:12px !important;
        border-radius:16px !important;
        box-shadow:none !important;
      }
      #view-home.today-command-v2 #homeKPICard {
        margin-top:10px !important;
        box-shadow:none;
      }
      #view-home.today-command-v2 #homeNextMoveBox > * {
        margin-top:10px !important;
        padding:11px 13px !important;
        border-radius:14px !important;
        box-shadow:none !important;
      }
      #view-home.today-command-v2 #homeNextMoveBox {
        font-size:.92em;
      }
      #view-home.today-command-v2 .today-position-disclosure {
        width:100%; min-height:48px; margin:10px 0 0; padding:0 13px;
        display:grid; grid-template-columns:30px 1fr auto; align-items:center; gap:9px;
        border:1px solid var(--border); border-radius:14px;
        background:var(--surface-1); color:var(--text); text-align:left;
        font:inherit; font-weight:750; cursor:pointer;
      }
      #view-home.today-command-v2 .today-position-disclosure[hidden] { display:none !important; }
      #view-home.today-command-v2 .today-position-disclosure-icon {
        width:28px; height:28px; display:grid; place-items:center; border-radius:9px;
        background:var(--surface-2); color:var(--accent); font-size:18px;
      }
      #view-home.today-command-v2 .today-position-disclosure-state {
        color:var(--text-tertiary); font-size:12px; font-weight:650;
      }
      #view-home.today-command-v2 .today-position-collapsed { display:none !important; }
      #view-home.today-command-v2 .today-position-expanded {
        display:block; margin-top:8px !important;
      }
      #view-home.today-command-v2 .today-position-expanded > * {
        box-shadow:none !important;
      }
      /* Today owns the current-day money snapshot. Detailed money and historical
         weekly reports stay on their canonical Money/Reports surfaces so the
         driver does not see two competing financial windows on one screen. */
      #view-home.today-command-v2 #homeMoneyCard {
        display:none !important;
      }
      #view-home.today-command-v2 #homeWeeklyReport {
        display:none !important;
      }
      #view-home.today-command-v2 .today-attention-row { margin-top:10px !important; }
      #view-home.today-command-v2 #maintAlertBanner,
      #view-home.today-command-v2 #fuelNudgeCard {
        min-height:0 !important; padding:10px 12px !important;
        border-radius:14px !important; box-shadow:none !important;
      }
      #view-home.today-command-v2 #maintAlertBanner { border-width:1px !important; }
      #view-home.today-command-v2 .quarterly-nudge,
      #view-home.today-command-v2 .today-flow-reminder {
        position:static !important; inset:auto !important; transform:none !important;
        width:auto !important; max-width:none !important; margin:10px 0 !important;
        z-index:auto !important;
      }
      #view-home.today-command-v2 #homeRecentTripsCard,
      #view-home.today-command-v2 #homeRecentTrips { overflow:visible !important; }
      #view-insights .today-settings-focus {
        outline:2px solid var(--accent) !important; outline-offset:3px;
        box-shadow:0 0 0 4px var(--accent-muted) !important;
      }
      @media (max-width:640px) {
        .toast { left:12px !important; right:12px !important; width:auto !important; }
        #view-home.today-command-v2 .card { border-radius:18px; }
        #view-home.today-command-v2 #homeKPICard { padding:16px !important; }
      }
      @media (prefers-reduced-motion:reduce) {
        #view-insights .today-settings-focus { scroll-behavior:auto; }
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function todayPresentationSpec() {
    return { ...TODAY_PRESENTATION_SPEC };
  }

  function syncHeaderSafeArea() {
    const header = document.getElementById('mainHeader');
    if (!header) return;
    header.classList.add('modern-header-safe');
    const rect = typeof header.getBoundingClientRect === 'function' ? header.getBoundingClientRect() : null;
    const bottom = rect && Number.isFinite(rect.bottom) ? Math.ceil(rect.bottom) : 0;
    if (bottom > 0 && document.documentElement?.style) {
      document.documentElement.style.setProperty('--fl-header-bottom', `${bottom}px`);
    }
  }

  function positionCardIsVisible(position) {
    if (!position || position.hidden) return false;
    // app.js owns whether this slot exists via its inline display state. Do not
    // consult computed display here: our own collapsed class intentionally uses
    // display:none and would otherwise make the disclosure hide itself.
    return position.style?.display !== 'none';
  }

  function setPositionExpanded(expanded) {
    const position = document.getElementById(TODAY_PRESENTATION_SPEC.positionCardId);
    const disclosure = document.getElementById(TODAY_PRESENTATION_SPEC.positionDisclosureId);
    if (!position || !disclosure) return;
    position.classList.toggle('today-position-collapsed', !expanded);
    position.classList.toggle('today-position-expanded', expanded);
    position.setAttribute('aria-hidden', expanded ? 'false' : 'true');
    disclosure.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    const state = disclosure.querySelector?.('.today-position-disclosure-state');
    if (state) state.textContent = expanded ? 'Hide' : 'Why?';
  }

  function ensurePositionDisclosure(home) {
    const position = document.getElementById(TODAY_PRESENTATION_SPEC.positionCardId);
    if (!position || !home) return null;
    let disclosure = document.getElementById(TODAY_PRESENTATION_SPEC.positionDisclosureId);
    if (!disclosure) {
      disclosure = document.createElement('button');
      disclosure.id = TODAY_PRESENTATION_SPEC.positionDisclosureId;
      disclosure.type = 'button';
      disclosure.className = 'today-position-disclosure';
      disclosure.setAttribute('aria-controls', TODAY_PRESENTATION_SPEC.positionCardId);
      disclosure.setAttribute('aria-expanded', 'false');
      disclosure.innerHTML = '<span class="today-position-disclosure-icon" aria-hidden="true">⌖</span><span>Market details</span><span class="today-position-disclosure-state">Why?</span>';
      disclosure.addEventListener('click', () => {
        setPositionExpanded(disclosure.getAttribute('aria-expanded') !== 'true');
      });
      position.insertAdjacentElement('beforebegin', disclosure);
      setPositionExpanded(false);
    }

    const visible = positionCardIsVisible(position);
    disclosure.hidden = !visible;
    if (!visible) setPositionExpanded(false);
    return disclosure;
  }

  function normalizeQuarterlyNudges(home) {
    if (!home) return;
    const recent = document.getElementById('homeRecentTripsCard');
    document.querySelectorAll('.quarterly-nudge').forEach((nudge) => {
      nudge.classList.add('today-flow-reminder');
      // Some app versions insert the CPA nudge inside Recent Trips. Keep it in
      // the Today flow, immediately before the trips card, so it can never
      // cover a trip row or its controls.
      if (recent && recent.contains(nudge) && recent.parentNode === home) {
        home.insertBefore(nudge, recent);
      }
    });
  }

  function syncTodayCommandCenter() {
    const home = document.getElementById(TODAY_PRESENTATION_SPEC.homeId);
    if (!home) return;
    home.classList.add(TODAY_PRESENTATION_SPEC.homeClass);

    const kpi = document.getElementById(TODAY_PRESENTATION_SPEC.primaryCardId);
    const position = document.getElementById(TODAY_PRESENTATION_SPEC.positionCardId);
    const disclosure = ensurePositionDisclosure(home);
    const maintenance = document.getElementById('homeMaintenanceAlert');
    const money = document.getElementById(TODAY_PRESENTATION_SPEC.moneyCardId);
    const recent = document.getElementById('homeRecentTripsCard');

    // Daily money is the stable Today anchor. Market evidence remains available
    // directly below it as progressive disclosure rather than leading the page.
    const positionAnchor = disclosure || position;
    if (kpi && positionAnchor && kpi.parentNode === home && positionAnchor.parentNode === home && kpi.nextElementSibling !== positionAnchor) {
      home.insertBefore(kpi, positionAnchor);
    }

    // Maintenance remains visible but belongs to Attention, not the driver's
    // primary drive/money decision path.
    if (maintenance && recent && maintenance.parentNode === home && recent.parentNode === home && maintenance.nextElementSibling !== recent) {
      home.insertBefore(maintenance, recent);
    }

    document.getElementById('homePositionBanner')?.classList.add('today-context-rail');
    document.getElementById('homeTripTrackCard')?.classList.add('today-trip-control');
    position?.classList.add('today-position-details');
    maintenance?.classList.add('today-attention-row');
    money?.classList.add('today-secondary-money');
    document.getElementById('homeWeeklyReport')?.classList.add('today-report-snapshot');
    document.getElementById('homeFuelNudge')?.classList.add('today-attention-row');
    recent?.classList.add('today-recent-trips');

    normalizeQuarterlyNudges(home);
    syncHeaderSafeArea();
  }

  function scheduleTodaySync() {
    if (todaySyncScheduled) return;
    todaySyncScheduled = true;
    const run = () => {
      todaySyncScheduled = false;
      syncTodayCommandCenter();
    };
    if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(run);
    else setTimeout(run, 0);
  }

  function focusFuelPriceSetting() {
    navigate(TODAY_PRESENTATION_SPEC.fuelRoute);
    let attempts = 0;
    const reveal = () => {
      attempts += 1;
      const field = document.getElementById(TODAY_PRESENTATION_SPEC.fuelFieldId);
      if (!field) {
        if (attempts < 8) setTimeout(reveal, 40);
        return false;
      }

      const body = document.getElementById('advSettingsBody');
      const toggle = document.getElementById('advSettingsToggle');
      let collapsed = false;
      if (body) {
        try { collapsed = getComputedStyle(body).display === 'none'; }
        catch (_) { collapsed = body.style?.display === 'none'; }
      }
      if (collapsed && toggle && typeof toggle.click === 'function') toggle.click();

      const section = document.getElementById(TODAY_PRESENTATION_SPEC.fuelSectionId);
      const settle = () => {
        section?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
        field.focus?.({ preventScroll: true });
        field.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
        field.classList?.add('today-settings-focus');
        setTimeout(() => field.classList?.remove('today-settings-focus'), 1600);
      };
      if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(settle);
      else setTimeout(settle, 0);
      return true;
    };
    setTimeout(reveal, 0);
    return true;
  }

  function bindFuelNudgeRoute() {
    if (fuelRouteBound) return;
    fuelRouteBound = true;
    document.addEventListener('click', (event) => {
      const card = event.target?.closest?.('#fuelNudgeCard');
      if (!card) return;
      // Let the app's own card handler finish first, then guarantee a visible,
      // useful destination for the operator.
      setTimeout(focusFuelPriceSetting, 0);
    }, true);
  }

  function installTodayCommandCenter() {
    const home = document.getElementById(TODAY_PRESENTATION_SPEC.homeId);
    if (!home) return false;
    installTodayStyles();
    bindFuelNudgeRoute();
    syncTodayCommandCenter();

    if (!headerResizeBound) {
      window.addEventListener('resize', syncHeaderSafeArea, { passive: true });
      headerResizeBound = true;
    }
    if (!todayObserver) {
      todayObserver = new MutationObserver(scheduleTodaySync);
      todayObserver.observe(home, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style', 'hidden', 'class']
      });
    }
    return true;
  }

  function install() {
    if (installed) return;
    installed = true;
    const home = document.getElementById('view-home');
    if (home) home.setAttribute('aria-label', 'Today');
    rebuildPrimaryNav();
    addSecondaryMenuAccess();
    installTodayCommandCenter();
    window.addEventListener('hashchange', () => {
      normalizeAliasHash();
      syncActiveFromHash();
    });
    normalizeAliasHash();
    syncActiveFromHash();
    installA11yRepairs();
  }

  window.FreightLogicModernShell = {
    install,
    navigate,
    installTodayCommandCenter,
    focusFuelPriceSetting,
    todayPresentationSpec,
    primaryRoutes: () => [...PRIMARY_ROUTES]
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install, { once: true });
  else install();
})();
