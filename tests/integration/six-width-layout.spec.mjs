import { createSuite, launchApp, skipFirstRunWizard, ok } from '../lib/harness.mjs';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('integration/six-width-layout.spec.mjs');
const WIDTHS = [320, 375, 390, 393, 430, 440];
const ROUTES = ['home', 'loads', 'omega', 'trips', 'money'];
const HEIGHT = 844;

async function waitForShell(page) {
  await page.waitForFunction(() => document.querySelectorAll('.bottom .nav [data-modern-route]').length === 5, { timeout: 15000 });
}

async function openRoute(page, route) {
  await page.evaluate((r) => { window.location.hash = `#${r}`; }, route);
  await page.waitForFunction((id) => {
    const el = document.getElementById(id);
    return !!el && getComputedStyle(el).display !== 'none';
  }, `view-${route}`, { timeout: 10000 });
  await page.waitForTimeout(40);
}

async function themeFingerprint(page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    const body = document.body;
    const cs = getComputedStyle(body);
    return [root.getAttribute('data-theme') || '', root.className || '', body.className || '', cs.backgroundColor, cs.color].join('|');
  });
}

async function assertGeometry(page, width, route, themeLabel) {
  const result = await page.evaluate(() => {
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
    };

    const nav = [...document.querySelectorAll('.bottom .nav [data-modern-route]')]
      .filter(visible)
      .map((el) => {
        const r = el.getBoundingClientRect();
        return { label: el.getAttribute('aria-label') || el.textContent.trim(), width: r.width, height: r.height };
      });

    const headerTargets = ['#themeToggle', '#modernMoreBtn']
      .map((sel) => document.querySelector(sel))
      .filter(Boolean)
      .filter(visible)
      .map((el) => {
        const r = el.getBoundingClientRect();
        return { id: el.id, width: r.width, height: r.height };
      });

    const activeView = [...document.querySelectorAll('.view')].find(visible) || null;
    const controls = activeView
      ? [...activeView.querySelectorAll('input,select,textarea')].filter(visible).map((el) => ({
          id: el.id || el.name || el.tagName,
          fontSize: parseFloat(getComputedStyle(el).fontSize) || 0,
        }))
      : [];

    return {
      innerWidth: window.innerWidth,
      rootScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      nav,
      headerTargets,
      controls,
      activeViewId: activeView?.id || '',
    };
  });

  const prefix = `${width}px ${themeLabel} #${route}`;
  ok(result.innerWidth === width, `${prefix}: viewport width must be exact (got ${result.innerWidth})`);
  ok(result.rootScrollWidth <= width + 1, `${prefix}: document overflow ${result.rootScrollWidth}px > ${width}px`);
  ok(result.bodyScrollWidth <= width + 1, `${prefix}: body overflow ${result.bodyScrollWidth}px > ${width}px`);
  ok(result.activeViewId === `view-${route}`, `${prefix}: expected view-${route}, got ${result.activeViewId || 'none'}`);
  ok(result.nav.length === 5, `${prefix}: five primary nav targets must be visible`);
  for (const target of result.nav) {
    ok(target.width >= 44 && target.height >= 44,
      `${prefix}: nav target ${target.label} is ${target.width.toFixed(1)}x${target.height.toFixed(1)}, below 44x44`);
  }
  for (const target of result.headerTargets) {
    ok(target.width >= 44 && target.height >= 44,
      `${prefix}: ${target.id} is ${target.width.toFixed(1)}x${target.height.toFixed(1)}, below 44x44`);
  }
  for (const control of result.controls) {
    ok(control.fontSize >= 16,
      `${prefix}: visible control ${control.id} computes to ${control.fontSize}px, below iOS-safe 16px`);
  }
}

async function injectLongContentProbe(page) {
  await page.evaluate(() => {
    document.querySelector('[data-six-width-probe]')?.remove();
    const active = [...document.querySelectorAll('.view')].find((el) => {
      const r = el.getBoundingClientRect();
      return getComputedStyle(el).display !== 'none' && r.width > 0 && r.height > 0;
    });
    const host = active?.querySelector('.card') || active;
    if (!host) return;
    const probe = document.createElement('div');
    probe.dataset.sixWidthProbe = '1';
    probe.className = 'muted';
    probe.textContent = 'Saint Clair Shores Industrial Distribution Center → International Falls Regional Logistics Annex • Great Lakes Expedited Transportation Brokerage Incorporated • $123,456,789.00 • 1,234.56 true miles';
    host.appendChild(probe);
  });
}

test('all six release widths pass five-surface geometry in both theme states', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await skipFirstRunWizard(page);
    await page.waitForTimeout(900);
    await waitForShell(page);

    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: HEIGHT });
      await page.waitForTimeout(40);

      const firstTheme = await themeFingerprint(page);
      for (const route of ROUTES) {
        await openRoute(page, route);
        await injectLongContentProbe(page);
        await assertGeometry(page, width, route, 'theme-A');
      }

      await page.locator('#themeToggle').click();
      await page.waitForTimeout(80);
      const secondTheme = await themeFingerprint(page);
      ok(secondTheme !== firstTheme, `${width}px: theme toggle must produce a distinct rendered theme state`);

      for (const route of ROUTES) {
        await openRoute(page, route);
        await injectLongContentProbe(page);
        await assertGeometry(page, width, route, 'theme-B');
      }

      await page.locator('#themeToggle').click();
      await page.waitForTimeout(50);
    }
  } finally {
    await app.close();
  }
});

test('320px reduced-motion mode suppresses long-running animation and a representative trip modal stays inside the viewport', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await skipFirstRunWizard(page);
    await page.waitForTimeout(900);
    await waitForShell(page);
    await page.setViewportSize({ width: 320, height: HEIGHT });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.waitForTimeout(80);

    const motion = await page.evaluate(() => {
      const offenders = [];
      for (const el of document.querySelectorAll('*')) {
        const s = getComputedStyle(el);
        const animationNames = s.animationName.split(',').map(x => x.trim()).filter(x => x && x !== 'none');
        const durations = s.animationDuration.split(',').map(x => parseFloat(x) || 0);
        const iterations = s.animationIterationCount.split(',').map(x => x.trim());
        if (animationNames.length && animationNames.some((_, i) => (durations[i] ?? durations[0] ?? 0) > 0.02 || (iterations[i] ?? iterations[0]) === 'infinite')) {
          offenders.push({ tag: el.tagName, id: el.id, cls: el.className, animation: s.animationName, duration: s.animationDuration, iterations: s.animationIterationCount });
        }
      }
      return offenders.slice(0, 10);
    });
    ok(motion.length === 0, `reduced-motion still has long/decorative animations: ${JSON.stringify(motion)}`);

    // Use the Trips page's always-visible Add Trip action. The Today quick-trip
    // button is intentionally hidden for some empty/new-user states, so it is a
    // poor geometry probe even though the modal it eventually opens is valid.
    await openRoute(page, 'trips');
    const addTrip = page.locator('#btnTripAdd');
    await addTrip.waitFor({ state: 'visible', timeout: 10000 });
    await addTrip.click();
    await page.waitForTimeout(120);

    const dialog = await page.evaluate(() => {
      const visible = (el) => {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
      };
      const selectors = '[role="dialog"],dialog,.modal,.modal-overlay,[class*="modal"],[class*="sheet"]';
      const candidates = [...document.querySelectorAll(selectors)].filter(visible);
      if (!candidates.length) return null;
      const el = candidates.sort((a, b) => {
        const ar = a.getBoundingClientRect(), br = b.getBoundingClientRect();
        return (ar.width * ar.height) - (br.width * br.height);
      })[0];
      const r = el.getBoundingClientRect();
      return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height };
    });

    ok(!!dialog, 'Add Trip must expose a representative modal/sheet/dialog surface');
    ok(dialog.left >= -1 && dialog.right <= 321, `320px modal overflows horizontally: ${JSON.stringify(dialog)}`);
    ok(dialog.width <= 321, `320px modal width ${dialog.width}px exceeds viewport`);
    ok(dialog.top >= -1 && dialog.bottom <= HEIGHT + 1, `320px modal escapes viewport vertically: ${JSON.stringify(dialog)}`);
  } finally {
    await app.close();
  }
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
