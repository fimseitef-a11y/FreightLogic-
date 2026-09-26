// v24.0.46 (#386): the Home tab label renders "Today" exactly once in every text
// size and in Glance mode. The markup already reads "Today"; an older CSS relabel
// hid that text (font-size 0) and drew "Today" again with ::after. Large, Extra
// Large and Glance set the text back to a visible size, so both labels showed
// ("TodayToday"). The first repair (#384 @ 85daac7) only resized the second label.
// This measures computed style, which is where the defect lived. The Intel ->
// Market relabel is a separate rule and must keep working.
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

test('[NTL-02] the Intel tab still relabels to "Market"', async () => {
  const r = await app.page.evaluate(() => {
    const nav = document.querySelector('.bottom .nav');
    const a = document.createElement('a');
    a.setAttribute('data-nav', 'intel');
    a.innerHTML = '<div class="nl">Intel</div>';
    a.id = 'ntlProbe';
    nav.appendChild(a);
    const nl = a.querySelector('.nl');
    const out = { size: parseFloat(getComputedStyle(nl).fontSize), after: getComputedStyle(nl, '::after').content };
    a.remove();
    return out;
  });
  // Only the relabel content is asserted. Inside .bottom the generic label rule
  // outranks the Intel font-size:0 on main too; the five-tab shell has no Intel
  // tab, so that is latent and out of this hotfix's scope.
  eq(r.after, '"Market"', 'Intel -> Market relabel is unchanged');
});

export async function runSpec() {
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
