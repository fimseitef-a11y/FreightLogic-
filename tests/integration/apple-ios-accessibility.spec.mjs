import { createSuite, launchApp, skipFirstRunWizard, ok } from '../lib/harness.mjs';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('integration/apple-ios-accessibility.spec.mjs');

async function ready(page) {
  await skipFirstRunWizard(page);
  await page.waitForTimeout(900);
}

test('header statuses are non-interactive status semantics and GPS target is Apple-safe', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await ready(page);
    const result = await page.evaluate(() => {
      const read = (id) => {
        const el = document.getElementById(id);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { role: el.getAttribute('role'), aria: el.getAttribute('aria-label'), cursor: getComputedStyle(el).cursor, width: r.width, height: r.height };
      };
      return { sync: read('syncIndicator'), cloud: read('cloudIndicator'), gps: read('mwGpsBtn') };
    });
    for (const [name, status] of [['sync', result.sync], ['cloud', result.cloud]]) {
      ok(!!status, `${name} indicator must exist`);
      ok(status.role === 'status', `${name} indicator must expose role=status, got ${status.role}`);
      ok(status.cursor !== 'pointer', `${name} indicator must not imply click behavior`);
    }
    ok(result.gps.width >= 44 && result.gps.height >= 44,
      `GPS target must be >=44x44, got ${result.gps.width}x${result.gps.height}`);
  } finally { await app.close(); }
});

test('visible Evaluate, Money/Settings and Omega form controls have deterministic accessible names', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await ready(page);
    const routes = ['omega', 'insights'];
    const failures = [];
    for (const route of routes) {
      await page.evaluate((r) => { location.hash = '#' + r; }, route);
      await page.waitForTimeout(120);
      const missing = await page.evaluate(() => {
        const visible = (el) => {
          const r = el.getBoundingClientRect(), s = getComputedStyle(el);
          return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
        };
        const nameOf = (el) => {
          const aria = el.getAttribute('aria-label') || '';
          const by = el.getAttribute('aria-labelledby');
          const labelled = by ? by.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ') : '';
          const explicit = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent || '' : '';
          const wrapped = el.closest('label')?.textContent || '';
          return (aria || labelled || explicit || wrapped || el.getAttribute('title') || '').trim();
        };
        return [...document.querySelectorAll('.view input,.view select,.view textarea')]
          .filter(visible).filter(el => !nameOf(el)).map(el => el.id || el.name || el.tagName);
      });
      failures.push(...missing.map(id => `#${route}:${id}`));
    }
    ok(failures.length === 0, `visible controls missing accessible names: ${failures.join(', ')}`);
  } finally { await app.close(); }
});

test('disclosure controls expose keyboard semantics and state', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await ready(page);
    const ids = ['evalAdvToggle', 'advSettingsToggle'];
    for (const id of ids) {
      const state = await page.locator('#' + id).evaluate((el) => ({
        tag: el.tagName, role: el.getAttribute('role'), tabindex: el.getAttribute('tabindex'),
        expanded: el.getAttribute('aria-expanded')
      }));
      ok(state.tag === 'BUTTON' || (state.role === 'button' && state.tabindex === '0'),
        `#${id} must be keyboard-operable button semantics`);
      ok(state.expanded === 'true' || state.expanded === 'false',
        `#${id} must expose aria-expanded state`);
    }
  } finally { await app.close(); }
});


test('representative controls keep their expected visible/programmatic label text', async () => {
  const app = await launchApp();
  try {
    const { page } = app;
    await ready(page);
    const expected = {
      fuelPrice: 'Fuel price', vehicleMpg: 'Vehicle MPG', weeklyGoal: 'Weekly goal',
      settingsHomeLocation: 'Home Location', vanPayloadLbs: 'Payload',
      mwRevenue: 'Revenue', mwLoadedMi: 'Loaded Miles', mwOrigin: 'Origin',
      omMiles: 'Total miles', mbLocation: 'Current location', mbRpmLow: 'Visible RPM range low'
    };
    const got = await page.evaluate((map) => {
      const out = {};
      for (const id of Object.keys(map)) {
        const el = document.getElementById(id);
        const by = el?.getAttribute('aria-labelledby');
        out[id] = el?.getAttribute('aria-label')
          || (by ? by.split(/\\s+/).map(x => document.getElementById(x)?.textContent || '').join(' ') : '')
          || document.querySelector(`label[for="${CSS.escape(id)}"]`)?.textContent
          || el?.closest('label')?.textContent || '';
      }
      return out;
    }, expected);
    for (const [id, text] of Object.entries(expected)) {
      ok(String(got[id] || '').includes(text), `#${id} accessible name must retain "${text}", got "${got[id] || ''}"`);
    }
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
