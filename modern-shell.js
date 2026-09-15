/* FreightLogic v24.0.10 — modern five-surface navigation adapter
 * Structural navigation plus the operator-approved presentation overlay.
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

  const REFERENCE_UI_CSS = `
:root{--bg:#090b0d;--bg-grid:none;--surface-0:#0d1012;--surface-1:#14181b;--surface-2:#1a1f23;--surface-3:#22282d;--border:#262c31;--border-subtle:#20262a;--border-focus:#3a4248;--text:#f5f7f8;--text-secondary:#9da5ab;--text-tertiary:#737c83;--accent:#f5a623;--accent-dark:#d98c0d;--accent-muted:rgba(245,166,35,.12);--accent-border:rgba(245,166,35,.34);--accent-text:#f5a623;--good:#34c878;--bad:#ff625d;--warn:#f5a623;--r:15px;--r-sm:12px;--shadow:none;--font:-apple-system,BlinkMacSystemFont,'SF Pro Text','SF Pro Display',system-ui,sans-serif}
body{background:var(--bg);background-image:none;font-family:var(--font);font-size:14px;line-height:1.42;letter-spacing:0}.app{max-width:520px;padding:10px 12px calc(78px + env(safe-area-inset-bottom,0px))}
header#mainHeader{padding:calc(8px + env(safe-area-inset-top,0px)) 14px 7px;background:rgba(9,11,13,.96);border-bottom:0;box-shadow:none;-webkit-backdrop-filter:blur(18px) saturate(150%);backdrop-filter:blur(18px) saturate(150%)}header#mainHeader.scrolled{box-shadow:0 1px 0 var(--border)}header#mainHeader .hdr-row{min-height:40px;gap:8px}.logo{display:none}.brand{gap:7px;min-width:0}.title{min-width:0;line-height:1.08}.title strong{color:var(--accent);font-size:16px;font-weight:800;letter-spacing:-.025em;white-space:nowrap}.title span{max-width:155px;margin-top:3px;color:var(--text-tertiary);font-size:9px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}header#mainHeader .row{gap:4px;flex-wrap:nowrap}.theme-btn{width:38px;height:38px;min-width:38px;min-height:38px;border:1px solid var(--border);border-radius:50%;background:var(--surface-1);box-shadow:none}#pillWeekNet,#pillUnpaid{display:none!important}
.card{padding:14px;border:1px solid var(--border);border-radius:var(--r);background:var(--surface-1);box-shadow:none}.card-hero{border-color:var(--border);background:var(--surface-1);box-shadow:none}.card h3{margin:0 0 10px;color:var(--text-secondary);font-size:11px;font-weight:750;line-height:1.2;letter-spacing:.02em;text-transform:uppercase}.spacer{height:10px}.grid2{gap:9px}
#homeKPICard{padding:15px;border-color:var(--border);background:var(--surface-1)}#homeKPICard>div:first-child{margin-bottom:8px!important}#homeKPICard h3{color:var(--text-secondary);font-size:11px;text-transform:uppercase}.kpi-hero{padding:5px 0 10px;text-align:left}.kpi-hero-value{color:var(--text);font-family:var(--font);font-size:clamp(34px,10vw,44px);font-weight:800;line-height:1;letter-spacing:-.045em}.kpi-hero-label{margin-top:5px;color:var(--text-tertiary);font-size:10px;font-weight:650;text-transform:uppercase;letter-spacing:.03em}.kpi-progress-bar-wrap{height:5px;margin:8px 0 10px;background:var(--surface-3)}.kpi-progress-bar{background:var(--accent)}.fl-kpi-3col{gap:8px;margin-top:10px}.fl-kpi-3col .kpi-cell{padding:9px 7px;border:1px solid var(--border-subtle)!important;border-radius:11px;background:var(--surface-0);text-align:left}.fl-kpi-3col .kpi-cell+.kpi-cell{border-left:1px solid var(--border-subtle)}.kpi-cell-value{font-family:var(--font);font-size:14px;font-weight:780}.kpi-cell-label{margin-top:3px;color:var(--text-tertiary);font-size:9px;text-transform:uppercase}
.fl-next-move{margin-top:10px;padding:11px 12px;border:1px solid var(--accent-border);border-radius:12px;background:var(--accent-muted);box-shadow:none}.fl-nm-label{color:var(--accent-text);font-size:9px;font-weight:800;text-transform:uppercase}.fl-nm-text{font-size:12px;line-height:1.35}.fl-quick-grid{gap:7px;margin-top:11px}.fl-quick-btn{min-height:54px;padding:8px;border:1px solid var(--border);border-radius:12px;background:var(--surface-2);box-shadow:none;font-size:11px;font-weight:700}.fl-quick-btn.primary{background:var(--accent);color:#14100a;border-color:var(--accent);box-shadow:none}.fl-quick-btn .fl-qb-icon{font-size:16px}
.list{gap:7px}.item{padding:12px;border:1px solid var(--border);border-left:1px solid var(--border);border-radius:13px;background:var(--surface-1);box-shadow:none}.item.grade-a,.item.grade-b,.item.grade-c,.item.grade-d,.item.grade-e{border-left:1px solid var(--border)}.item .k{color:var(--text-tertiary);font-size:9px;font-weight:700;text-transform:uppercase}.item .v{font-family:var(--font);font-size:14px;font-weight:780}.item .sub{color:var(--text-secondary);font-size:10px}.tag{padding:3px 7px;border-radius:999px;font-size:9px;font-weight:750}
input,select,textarea{min-height:46px;padding:10px 12px;border:1px solid var(--border);border-radius:11px;background:var(--surface-2);box-shadow:none;color:var(--text);font-family:var(--font);font-size:16px}input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-muted)}label{margin:10px 0 5px;color:var(--text-secondary);font-size:10px;font-weight:700}.btn{min-height:44px;padding:9px 13px;border:1px solid var(--border);border-radius:11px;background:var(--surface-2);box-shadow:none;color:var(--text);font-family:var(--font);font-size:12px;font-weight:750}.btn.primary,.btn.primary:hover{border-color:var(--accent);background:var(--accent);box-shadow:none;color:#151008}.chip{min-height:34px;padding:6px 11px;border:1px solid var(--border);border-radius:999px;background:var(--surface-1);box-shadow:none;font-size:10px;font-weight:750}.chip.active{border-color:var(--accent);background:var(--accent);color:#151008}.pill{padding:5px 9px;border:1px solid var(--border);background:var(--surface-0);box-shadow:none;font-size:10px}
#view-loads>.card:first-child,#view-trips>.card:first-child,#view-expenses>.card:first-child,#view-fuel>.card:first-child{padding:6px 1px 10px;border:0;background:transparent;box-shadow:none}#view-loads>.card:first-child h3,#view-trips>.card:first-child h3,#view-expenses>.card:first-child h3,#view-fuel>.card:first-child h3{color:var(--text);font-size:25px;font-weight:820;letter-spacing:-.035em;text-transform:none}#btnLoadsIntake,#btnTripAdd,#btnAddExp2{min-height:38px;padding:7px 10px!important;border-radius:10px!important;font-size:10px}#loadInboxCard .card{padding:12px;border-radius:13px}.fl-trip-full .fl-tf-origin{font-size:13px;font-weight:760}.fl-trip-full .fl-tf-pay{font-family:var(--font);font-size:14px;font-weight:820}
#view-money>.card:first-child{padding:15px;border:1px solid var(--border);background:var(--surface-1);box-shadow:none}#view-money>.card:first-child h3{color:var(--text);font-size:24px;font-weight:820;letter-spacing:-.035em;text-transform:none}#view-omega>.card{padding:14px;border:1px solid var(--border);box-shadow:none}#view-omega>.card:first-of-type h2{color:var(--text);font-size:24px!important;font-weight:820;letter-spacing:-.035em}#mwRevenue,#mwLoadedMi,#mwDeadMi{min-height:52px!important;border:1px solid var(--border)!important;border-radius:11px!important;background:var(--surface-2)!important;box-shadow:none!important;color:var(--text)!important;font-family:var(--font)!important;font-size:20px!important;font-weight:800!important}.fl-eval-grade{font-family:var(--font);font-size:60px;font-weight:850}.intel-row{min-height:58px;padding:10px 11px;border:1px solid var(--border);border-radius:12px;background:var(--surface-1);box-shadow:none}.settings-collapse-btn{padding:11px 12px;border:1px solid var(--border);border-radius:11px;background:var(--surface-0);font-size:11px}
.bottom{left:0;right:0;bottom:0;padding:0 8px env(safe-area-inset-bottom,0px);border:0;border-top:1px solid var(--border);border-radius:0;background:rgba(10,12,14,.97);box-shadow:none;-webkit-backdrop-filter:blur(20px) saturate(160%);backdrop-filter:blur(20px) saturate(160%)}.nav{max-width:520px;height:62px;justify-content:space-around}.nav a{min-width:0;padding:6px 3px 5px;gap:2px;color:var(--text-tertiary)}.nav a::before{display:none}.nav a .ni{width:34px;height:27px;border-radius:9px;font-size:19px}.nav a .ni svg{width:20px;height:20px}.nav a .nl{font-size:9px;font-weight:700;letter-spacing:0}.nav a.active{color:var(--accent)}.nav a.nav-eval-center{flex:0 0 64px;margin-top:-13px;padding:0 2px 2px}.nav a.nav-eval-center .ni,.nav a.nav-eval-center.active .ni{width:50px;height:50px;border:0;border-radius:17px;background:var(--accent);color:#151008;box-shadow:0 8px 24px rgba(245,166,35,.28),0 0 0 4px var(--bg);font-size:20px}.nav a.nav-eval-center .nl,.nav a.nav-eval-center.active .nl{margin-top:1px;color:var(--accent);font-size:9px}
[data-theme="light"]{--bg:#f3f4f5;--surface-0:#eceff1;--surface-1:#fff;--surface-2:#f2f4f5;--surface-3:#e7eaec;--border:#d9dee1;--border-subtle:#e5e9eb;--text:#111416;--text-secondary:#59636a;--text-tertiary:#78838a;--accent:#d68e16;--accent-text:#9a620c}[data-theme="light"] header#mainHeader{background:rgba(243,244,245,.96)}[data-theme="light"] .bottom{background:rgba(255,255,255,.97);border-top-color:var(--border);box-shadow:none}
@media(max-width:480px){.app{padding-left:11px;padding-right:11px}header#mainHeader{padding-left:12px;padding-right:12px}.card{padding:13px}#homeKPICard{padding:14px}.bottom{left:0;right:0;border-radius:0}.nav{height:61px}}
`;

  function installReferenceUI() {
    if (document.getElementById('flReferenceUI')) return;
    const style = document.createElement('style');
    style.id = 'flReferenceUI';
    style.textContent = REFERENCE_UI_CSS;
    document.head.appendChild(style);
  }

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
    installReferenceUI();
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
