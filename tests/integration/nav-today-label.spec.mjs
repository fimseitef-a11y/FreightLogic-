// v24.0.46 (#386): primary driver-navigation presentation regressions.
// Extended 2026-10-02 as the RED contract for the operator-approved final
// visual completion before physical iPhone A1-A14 certification.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/nav-today-label.spec.mjs');
let app;

const MODES = ['standard', 'large', 'xlarge', 'glance'];

const measure = (mode) => app.page.evaluate((mode) => {
  const h = document.documentElement;
  h.removeAttribute('data-fl-driver-mode');
  h.setAttribute('data-fl-text-size', mode === 'glance' ? 'standard' : mode);
  if (mode === 'glance') h.setAttribute('data-fl-driver-mode', 'glance');
  const nl = document.querySelector('.bottom .nav a[data-nav="home"] .nl');
  if (!nl) return { missing: true };
  const cs = getComputedStyle(nl);
  const after = getComputedStyle(nl, '::after');
  return {
    text: nl.textContent.trim(),
    size: parseFloat(cs.fontSize),
    afterContent: after.content,
  };
}, mode);

test('[NTL-01] the Home tab reads "Today" exactly once in standard, large, xlarge and glance', async () => {
  for (const mode of MODES) {
    const r = await measure(mode);
    console.log(`    [evidence] ${mode}: ${JSON.stringify(r)}`);
    ok(!r.missing, 'the Home tab label exists');
    eq(r.text, 'Today', `${mode}: the markup text is Today`);
    ok(r.size > 0, `${mode}: the real label is visible (font-size ${r.size}px)`);
    ok(r.afterContent === 'none' || r.afterContent === 'normal', `${mode}: no ::after pseudo-label — got ${r.afterContent}`);
  }
});

test('[NTL-02] an Intel tab renders exactly one visible label, "Market", in every text mode', async () => {
  for (const mode of MODES) {
    const r = await app.page.evaluate((mode) => {
      const h = document.documentElement;
      h.removeAttribute('data-fl-driver-mode');
      h.setAttribute('data-fl-text-size', mode === 'glance' ? 'standard' : mode);
      if (mode === 'glance') h.setAttribute('data-fl-driver-mode', 'glance');
      const nav = document.querySelector('.bottom .nav');
      const a = document.createElement('a');
      a.setAttribute('data-nav', 'intel');
      a.innerHTML = '<div class="nl">Intel</div>';
      nav.appendChild(a);
      const nl = a.querySelector('.nl');
      const out = {
        text: nl.textContent.trim(),
        size: parseFloat(getComputedStyle(nl).fontSize),
        after: getComputedStyle(nl, '::after').content,
        afterSize: parseFloat(getComputedStyle(nl, '::after').fontSize),
      };
      a.remove();
      return out;
    }, mode);
    console.log(`    [evidence] Intel ${mode}: ${JSON.stringify(r)}`);
    eq(r.text, 'Intel', `${mode}: source label remains Intel`);
    eq(r.size, 0, `${mode}: real Intel label is hidden`);
    eq(r.after, '"Market"', `${mode}: pseudo-label is Market`);
    ok(r.afterSize > 0, `${mode}: Market pseudo-label remains visible`);
  }
});

test('[NTL-03] primary navigation matches the approved five-surface driver vocabulary', async () => {
  const tabs = await app.page.$$eval('.bottom .nav a', (els) => els.map((e) => ({
    label: e.querySelector('.nl')?.textContent?.trim() || '',
    href: e.getAttribute('href'),
    nav: e.dataset.nav,
  })));
  eq(tabs.map(t => t.label).join('/'), 'Today/Loads/Evaluate/Trips/Money',
    'approved primary labels must be Today / Loads / Evaluate / Trips / Money');
  eq(tabs.map(t => t.href).join(','), '#home,#loads,#omega,#trips,#money',
    'visual vocabulary must not break canonical hashes');
  eq(tabs.map(t => t.nav).join(','), 'home,loads,omega,trips,money',
    'visual vocabulary must not create a second router');
});

test('[NTL-04] Evaluate and Trips expose native screen titles, not legacy Scan/History wording', async () => {
  for (const [hash, expected] of [['#omega', 'Evaluate Load'], ['#trips', 'Trips']]) {
    await app.page.evaluate((hash) => { location.hash = hash; }, hash);
    await app.page.waitForTimeout(250);
    const title = await app.page.$eval('#mainHeader .brand .title strong', el => el.textContent.trim());
    eq(title, expected, `${hash} screen title`);
  }
});

test('[NTL-05] installed app typography is system-first with no Google font runtime dependency', async () => {
  const typography = await app.page.evaluate(() => ({
    externalFontLinks: [...document.querySelectorAll('link[href]')]
      .map(link => link.href)
      .filter((href) => href.startsWith('https://fonts.googleapis.com/') || href.startsWith('https://fonts.gstatic.com/')),
    family: getComputedStyle(document.body).fontFamily,
  }));
  eq(typography.externalFontLinks.length, 0,
    `driver shell must not depend on Google-hosted fonts: ${JSON.stringify(typography.externalFontLinks)}`);
  ok(/-apple-system|BlinkMacSystemFont|system-ui/i.test(typography.family),
    `rendered UI must use the iOS/system-first stack: ${typography.family}`);
});

test('[NTL-06] final command palette is flat, near-black, warm-gold and iPhone-targeted', async () => {
  await app.page.setViewportSize({ width: 390, height: 844 });
  await app.page.evaluate(() => { location.hash = '#home'; });
  await app.page.waitForTimeout(250);
  const v = await app.page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    const body = getComputedStyle(document.body);
    const primary = document.querySelector('.btn.primary');
    const progress = document.querySelector('.kpi-progress-bar');
    const hero = document.querySelector('.kpi-hero-value');
    const boxes = [...document.querySelectorAll('.bottom .nav a')].map(a => {
      const r = a.getBoundingClientRect();
      return { w:r.width, h:r.height };
    });
    const center = document.querySelector('.bottom .nav .nav-eval-center');
    const cr = center?.getBoundingClientRect();
    return {
      bg: root.getPropertyValue('--bg').trim(),
      surface1: root.getPropertyValue('--surface-1').trim(),
      surface2: root.getPropertyValue('--surface-2').trim(),
      border: root.getPropertyValue('--border').trim(),
      text: root.getPropertyValue('--text').trim(),
      muted: root.getPropertyValue('--text-secondary').trim(),
      accent: root.getPropertyValue('--accent').trim(),
      good: root.getPropertyValue('--good').trim(),
      bad: root.getPropertyValue('--bad').trim(),
      bodyBgImage: body.backgroundImage,
      primaryBgImage: primary ? getComputedStyle(primary).backgroundImage : 'none',
      progressAnimation: progress ? getComputedStyle(progress).animationName : 'none',
      heroBgImage: hero ? getComputedStyle(hero).backgroundImage : 'none',
      boxes,
      center: cr ? { w:cr.width, h:cr.height } : null,
    };
  });
  eq(v.bg, '#050607', 'approved near-black app background');
  eq(v.surface1, '#11171a', 'approved graphite primary card surface');
  eq(v.surface2, '#151c1f', 'approved secondary graphite surface');
  eq(v.border, '#2a3134', 'approved restrained edge token');
  eq(v.text, '#f5f4ef', 'approved warm off-white text');
  eq(v.muted, '#9ca5a8', 'approved muted text');
  eq(v.accent, '#f3b43f', 'approved FreightLogic warm gold');
  eq(v.good, '#52c77a', 'approved positive token');
  eq(v.bad, '#ff625c', 'approved destructive token');
  eq(v.bodyBgImage, 'none', 'final driver shell must not use a decorative body grid');
  eq(v.primaryBgImage, 'none', 'primary actions use solid gold, not a decorative gradient');
  eq(v.progressAnimation, 'none', 'progress must not shimmer continuously');
  eq(v.heroBgImage, 'none', 'hero numerics use normal text color, not gradient clipping');
  ok(v.boxes.every(b => b.h >= 48), `primary nav targets should be at least 48px tall: ${JSON.stringify(v.boxes)}`);
  ok(v.center && v.center.h >= 48 && v.center.w >= 48,
    `center Evaluate action should be at least 48x48: ${JSON.stringify(v.center)}`);
});

export async function runSpec() {
  app = await launchApp();
  try {
    await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
    await app.page.waitForTimeout(250);
    return await run();
  } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
