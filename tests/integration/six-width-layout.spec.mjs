// v24.0.9 release certification — six-width responsive geometry gate.
//
// This is intentionally browser geometry, not a screenshot golden. It proves
// the invariants that matter to an iPhone-first PWA without pretending Chromium
// is physical iOS: no page-level horizontal overflow, 44x44 primary controls,
// 16px mobile form controls, realistic long-string containment, a representative
// modal within the viewport, and reduced-motion suppression. Physical safe-area,
// keyboard and Home Screen PWA behavior remain a separate device gate.
import { launchBlank, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/six-width-layout.spec.mjs');
const WIDTHS = [320, 375, 390, 393, 430, 440];
const ROUTES = ['home', 'loads', 'omega', 'trips', 'money'];

async function bootResponsiveApp() {
  const app = await launchBlank();
  await app.page.setViewportSize({ width: 440, height: 900 });
  await app.page.evaluate(async () => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      };
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readwrite');
        txn.objectStore('settings').put({ key: 'f26SetupComplete', value: true });
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  });
  await app.bootApp();
  await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
  await app.page.waitForTimeout(350);
  return app;
}

async function themeSignature(page) {
  return await page.evaluate(() => {
    const html = document.documentElement;
    const body = document.body;
    const hs = getComputedStyle(html);
    const bs = getComputedStyle(body);
    return [html.className, html.getAttribute('data-theme') || '', body.className,
      body.getAttribute('data-theme') || '', hs.backgroundColor, bs.backgroundColor,
      bs.color].join('|');
  });
}

async function routeTo(page, route) {
  await page.evaluate((r) => { location.hash = r; }, route);
  await page.waitForTimeout(260);
}

async function geometrySnapshot(page) {
  return await page.evaluate(() => {
    const isVisible = (el) => {
      if (!el) return false;
      const s = getComputedStyle(el);
      if (s.display === 'none' || s.visibility === 'hidden') return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const rect = (el) => {
      const r = el.getBoundingClientRect();
      return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height };
    };

    const visibleView = [...document.querySelectorAll('main.app > section.view')].find(isVisible) || null;
    const nav = [...document.querySelectorAll('.bottom .nav a')].filter(isVisible).map(el => ({
      label: el.getAttribute('aria-label') || el.textContent.trim(), ...rect(el)
    }));
    const theme = document.getElementById('themeToggle');
    const controls = visibleView
      ? [...visibleView.querySelectorAll('input, select, textarea')].filter(isVisible).map(el => ({
          id: el.id || el.name || el.tagName,
          fontSize: parseFloat(getComputedStyle(el).fontSize) || 0,
          ...rect(el),
        }))
      : [];

    return {
      innerWidth: window.innerWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      viewId: visibleView?.id || null,
      nav,
      theme: theme && isVisible(theme) ? rect(theme) : null,
      controls,
    };
  });
}

async function assertNoRealisticLongStringOverflow(page, label) {
  const result = await page.evaluate(() => {
    const view = [...document.querySelectorAll('main.app > section.view')]
      .find(el => getComputedStyle(el).display !== 'none');
    if (!view) return { noView: true };
    const probe = document.createElement('div');
    probe.id = 'sixWidthLongStringProbe';
    probe.className = 'card';
    probe.innerHTML = '<div class="muted">Milwaukee Mitchell International Airport Industrial Logistics Center → Rancho Cucamonga Regional Distribution Campus · Synthetic Consolidated Expedite Transportation Services LLC · $12,345.67 @ $1.876/mi</div>';
    view.appendChild(probe);
    const out = {
      noView: false,
      innerWidth: window.innerWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      probeRight: probe.getBoundingClientRect().right,
    };
    probe.remove();
    return out;
  });
  ok(!result.noView, `${label}: a visible route surface must exist`);
  ok(result.documentScrollWidth <= result.innerWidth + 1,
    `${label}: realistic long route/broker/money text must not create document overflow (${result.documentScrollWidth} > ${result.innerWidth})`);
  ok(result.bodyScrollWidth <= result.innerWidth + 1,
    `${label}: realistic long text must not create body overflow (${result.bodyScrollWidth} > ${result.innerWidth})`);
}

async function assertModalFits(page, label) {
  await routeTo(page, 'loads');
  await page.click('#btnLoadsIntake');
  await page.waitForFunction(() => document.getElementById('modal')?.classList.contains('open'), null, { timeout: 5000 });
  await page.waitForTimeout(120);
  const metrics = await page.evaluate(() => {
    const modal = document.getElementById('modal');
    const visible = [...modal.querySelectorAll('*')].filter(el => {
      const s = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
    });
    const offenders = visible
      .map(el => ({
        tag: el.tagName,
        id: el.id || '',
        cls: typeof el.className === 'string' ? el.className : '',
        left: el.getBoundingClientRect().left,
        right: el.getBoundingClientRect().right,
      }))
      .filter(r => r.left < -1 || r.right > window.innerWidth + 1);
    return {
      innerWidth: window.innerWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      offenders: offenders.slice(0, 8),
    };
  });
  ok(metrics.documentScrollWidth <= metrics.innerWidth + 1,
    `${label}: open Load Intake modal must not widen the page (${metrics.documentScrollWidth} > ${metrics.innerWidth})`);
  eq(metrics.offenders.length, 0,
    `${label}: visible modal descendants must stay inside the viewport; offenders=${JSON.stringify(metrics.offenders)}`);

  // Geometry is the subject of this test, not close-button behavior. Restore a
  // neutral page state without invoking any save/cancel action that could mutate
  // test data.
  await page.evaluate(() => {
    const m = document.getElementById('modal');
    if (m) m.classList.remove('open');
    document.body.classList.remove('modal-open');
    document.body.style.overflow = '';
  });
}

test('[LAY-01] 320/375/390/393/430/440 pass dark+light mobile geometry', async () => {
  const app = await bootResponsiveApp();
  try {
    const firstTheme = await themeSignature(app.page);
    const observedThemes = [firstTheme];

    for (let themePass = 0; themePass < 2; themePass++) {
      if (themePass === 1) {
        await app.page.click('#themeToggle');
        await app.page.waitForTimeout(180);
        observedThemes.push(await themeSignature(app.page));
        ok(observedThemes[1] !== observedThemes[0],
          'theme toggle must produce a distinct dark/light rendered state before geometry is certified');
      }
      const themeLabel = themePass === 0 ? 'theme-A' : 'theme-B';

      for (const width of WIDTHS) {
        await app.page.setViewportSize({ width, height: 900 });
        await app.page.waitForTimeout(80);

        for (const route of ROUTES) {
          await routeTo(app.page, route);
          const label = `${width}px ${themeLabel} #${route}`;
          const g = await geometrySnapshot(app.page);
          ok(g.viewId, `${label}: a canonical view must be visible`);
          ok(g.documentScrollWidth <= width + 1,
            `${label}: document horizontal overflow ${g.documentScrollWidth}px > viewport ${width}px`);
          ok(g.bodyScrollWidth <= width + 1,
            `${label}: body horizontal overflow ${g.bodyScrollWidth}px > viewport ${width}px`);
          eq(g.nav.length, 5, `${label}: five primary driver nav targets must be visible`);
          for (const n of g.nav) {
            ok(n.width >= 44 && n.height >= 44,
              `${label}: nav target ${n.label} is ${n.width.toFixed(1)}x${n.height.toFixed(1)}, minimum is 44x44`);
          }
          ok(g.theme && g.theme.width >= 44 && g.theme.height >= 44,
            `${label}: theme control must be at least 44x44; got ${JSON.stringify(g.theme)}`);
          for (const c of g.controls) {
            ok(c.fontSize >= 16,
              `${label}: visible ${c.id} font-size ${c.fontSize}px can trigger iOS input zoom; minimum is 16px`);
          }
          await assertNoRealisticLongStringOverflow(app.page, label);
        }

        await assertModalFits(app.page, `${width}px ${themeLabel}`);
      }
    }
  } finally { await app.close(); }
});

test('[LAY-02] prefers-reduced-motion suppresses visible infinite decorative motion', async () => {
  const app = await bootResponsiveApp();
  try {
    await app.page.setViewportSize({ width: 390, height: 900 });
    await app.page.emulateMedia({ reducedMotion: 'reduce' });
    await routeTo(app.page, 'home');
    const offenders = await app.page.evaluate(() => {
      const seconds = (raw) => String(raw || '0s').split(',').map(part => {
        const v = part.trim();
        if (v.endsWith('ms')) return parseFloat(v) / 1000;
        if (v.endsWith('s')) return parseFloat(v);
        return 0;
      });
      return [...document.querySelectorAll('body *')].filter(el => {
        const r = el.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return false;
        const s = getComputedStyle(el);
        if (s.display === 'none' || s.visibility === 'hidden') return false;
        const durations = seconds(s.animationDuration);
        const iterations = String(s.animationIterationCount).split(',').map(x => x.trim());
        return iterations.some((it, i) => it === 'infinite' && (durations[i] ?? durations[0] ?? 0) > 0.02);
      }).slice(0, 10).map(el => ({ id: el.id || '', cls: typeof el.className === 'string' ? el.className : '', animation: getComputedStyle(el).animationName }));
    });
    eq(offenders.length, 0,
      `reduced-motion must suppress visible infinite decorative animation; offenders=${JSON.stringify(offenders)}`);
  } finally { await app.close(); }
});

export async function runSpec() { return await run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
