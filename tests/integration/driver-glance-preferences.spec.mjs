// v24.0.22 — Driver/Glance display preferences.
//
// This regression is intentionally user-visible. The CSS contract already
// exists in styles.css; these checks prove the shipped Settings controls wire
// that contract to durable device-local preferences without hiding secondary
// functionality or accepting corrupt persisted values.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/driver-glance-preferences.spec.mjs');
async function openDriverDisplaySettings(page) {
  await page.evaluate(() => { location.hash = '#insights'; });
  await page.waitForSelector('#driverTextSize', { state: 'visible', timeout: 15000 });
  await page.waitForSelector('#driverGlanceMode', { state: 'visible', timeout: 15000 });
}

async function rootPrefs(page) {
  return page.evaluate(() => ({
    size: document.documentElement.getAttribute('data-fl-text-size'),
    mode: document.documentElement.getAttribute('data-fl-driver-mode'),
  }));
}

test('[DRIVER DISPLAY] DD-01 Settings exposes all text sizes and Glance Mode with safe defaults', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await openDriverDisplaySettings(app.page);

    const options = await app.page.locator('#driverTextSize option').evaluateAll(nodes =>
      nodes.map(n => ({ value: n.value, text: (n.textContent || '').trim() })));
    eq(options.map(x => x.value).join(','), 'standard,large,xlarge',
      'the shipped text-size preference must expose exactly Standard, Large and Extra Large');
    eq(options.map(x => x.text).join(','), 'Standard,Large,Extra Large',
      'the operator-facing text-size labels must stay explicit and understandable');
    ok(await app.page.locator('#driverGlanceMode').isVisible(),
      'Driver/Glance Mode must be an explicit visible operator control');

    const prefs = await rootPrefs(app.page);
    eq(prefs.size, 'standard', 'a fresh profile must fail to the standard text-size contract');
    eq(prefs.mode, null, 'Glance Mode must be opt-in, never silently enabled');

    const bodySize = await app.page.locator('body').evaluate(el =>
      parseFloat(getComputedStyle(el).fontSize));
    ok(bodySize >= 15,
      `Standard must preserve the shipped 15px body baseline, got ${bodySize}px`);
  } finally { await app.close(); }
});

test('[DRIVER DISPLAY] DD-02 every text-size preference applies immediately and survives reload', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await openDriverDisplaySettings(app.page);

    for (const value of ['large', 'xlarge', 'standard']) {
      await app.page.selectOption('#driverTextSize', value);
      await app.page.waitForFunction(v =>
        document.documentElement.getAttribute('data-fl-text-size') === v, value);
      eq((await rootPrefs(app.page)).size, value, `${value} must apply to <html> immediately`);
    }

    await app.page.selectOption('#driverTextSize', 'xlarge');
    await app.page.reload({ waitUntil: 'load' });
    await app.page.waitForFunction(() =>
      document.documentElement.getAttribute('data-fl-text-size') === 'xlarge');
    eq((await rootPrefs(app.page)).size, 'xlarge',
      'Extra Large must survive a real reload on the same device profile');
    await openDriverDisplaySettings(app.page);
    eq(await app.page.locator('#driverTextSize').inputValue(), 'xlarge',
      'the Settings control must reflect the persisted Extra Large preference after reload');

    const inputSize = await app.page.locator('#mwRevenue').evaluate(el =>
      parseFloat(getComputedStyle(el).fontSize));
    ok(inputSize >= 25,
      `Extra Large must materially enlarge the canonical evaluator input, got ${inputSize}px`);
  } finally { await app.close(); }
});

test('[DRIVER DISPLAY] DD-03 Glance Mode applies immediately, survives reload and keeps secondary navigation reachable', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await openDriverDisplaySettings(app.page);

    await app.page.check('#driverGlanceMode');
    await app.page.waitForFunction(() =>
      document.documentElement.getAttribute('data-fl-driver-mode') === 'glance');
    eq((await rootPrefs(app.page)).mode, 'glance', 'Glance Mode must apply immediately');

    await app.page.reload({ waitUntil: 'load' });
    await app.page.waitForFunction(() =>
      document.documentElement.getAttribute('data-fl-driver-mode') === 'glance');
    eq((await rootPrefs(app.page)).mode, 'glance', 'Glance Mode must survive reload');
    await openDriverDisplaySettings(app.page);
    eq(await app.page.locator('#driverGlanceMode').isChecked(), true,
      'the Settings control must remain checked when persisted Glance Mode is active');

    const primaryTarget = await app.page.locator('.bottom .nav a').first().evaluate(el =>
      parseFloat(getComputedStyle(el).minHeight));
    ok(primaryTarget >= 52,
      `Glance Mode must raise road-use target geometry to at least 52px, got ${primaryTarget}px`);

    ok(await app.page.locator('#modernMoreBtn').isVisible(),
      'Glance Mode must not hide the More/secondary-tools entry point');

    await openDriverDisplaySettings(app.page);
    await app.page.uncheck('#driverGlanceMode');
    await app.page.waitForFunction(() =>
      !document.documentElement.hasAttribute('data-fl-driver-mode'));
    eq((await rootPrefs(app.page)).mode, null, 'turning Glance Mode off must remove the opt-in attribute');
  } finally { await app.close(); }
});

test('[DRIVER DISPLAY / NEGATIVE] DD-04 corrupt persisted display values fail closed to Standard and Glance off', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await app.page.evaluate(() => {
      localStorage.setItem('fl_text_size', 'gigantic');
      localStorage.setItem('fl_driver_mode', 'force-on');
    });
    await app.page.reload({ waitUntil: 'load' });
    await app.page.waitForFunction(() =>
      document.documentElement.getAttribute('data-fl-text-size') === 'standard');
    const prefs = await rootPrefs(app.page);
    eq(prefs.size, 'standard', 'unknown text-size values must normalize to Standard');
    eq(prefs.mode, null, 'unknown Glance values must not enable road mode');
    await openDriverDisplaySettings(app.page);
    eq(await app.page.locator('#driverTextSize').inputValue(), 'standard',
      'the visible text-size control must also normalize corrupt storage to Standard');
    eq(await app.page.locator('#driverGlanceMode').isChecked(), false,
      'the visible Glance control must stay off after corrupt persisted input');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
