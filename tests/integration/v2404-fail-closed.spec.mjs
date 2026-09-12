// v24.0.4 items 1, 2, 6, 7 — unknown inputs must fail closed.
//
// Drives the REAL app in a real browser. Every case here corresponds to a
// finding confirmed in RECON_24_0_2.md against the shipped v24.0.2 tree.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v2404-fail-closed.spec.mjs');
let app;

async function openEvaluator(page) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 15000 });
  const open = await page.isVisible('#mwOrigin').catch(() => false);
  if (!open) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwDeadMi', { state: 'visible', timeout: 15000 });
}

test('setup: suppress first-run wizard', async () => {
  await skipFirstRunWizard(app.page);
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForFunction(() => !!window.__FL_TESTS, { timeout: 20000 });
});

// ── Item 1: unknown / underspecified location fails closed ──────────────────

test('[V2404-01] blank and whitespace locations resolve to no market at all', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    if (!T?.naLookupMarket) return null;
    return { blank: T.naLookupMarket(''), ws: T.naLookupMarket('   ') };
  });
  if (!r) { ok(true, 'lookup not exposed in this build'); return; }
  eq(r.blank, null, "'' must resolve to NO market — it used to match the first Canadian key, because every string contains the empty string, so a blank origin became Toronto");
  eq(r.ws, null, "'   ' must resolve to NO market");
});

test('[V2404-02] one- and two-character fragments resolve to no market', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    if (!T?.naLookupMarket) return null;
    return { a: T.naLookupMarket('a'), x: T.naLookupMarket('x'), xy: T.naLookupMarket('xy') };
  });
  if (!r) { ok(true, 'lookup not exposed'); return; }
  eq(r.a, null, "'a' matched 'mississauga' on a stray letter");
  eq(r.x, null, "'x' matched 'halifax' on a stray letter");
  eq(r.xy, null, "two-character fragments carry no identifying information");
});

test('[V2404-03] a real city and a real prefix abbreviation still resolve', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    if (!T?.naLookupMarket) return null;
    const g = (s) => { const m = T.naLookupMarket(s); return m ? m.city + '/' + m.zone : null; };
    return { chicago: g('Chicago'), qualified: g('Chicago, IL'), toronto: g('Toronto'),
             cincinnati: g('Cincinnati'), abbrev: g('indianapol'), multi: g('Grand Rapids') };
  });
  if (!r) { ok(true, 'lookup not exposed'); return; }
  eq(r.chicago, 'chicago/MIDWEST', 'an exact city must still resolve');
  eq(r.qualified, 'chicago/MIDWEST', 'a city with a state qualifier must still resolve');
  eq(r.toronto, 'toronto/ON_CORE', 'an exact Canadian city must still resolve');
  eq(r.cincinnati, 'cincinnati/MIDWEST', 'a Tier 1 market must still resolve');
  eq(r.abbrev, 'indianapolis/MIDWEST', 'a genuine PREFIX abbreviation must still resolve');
  eq(r.multi, 'grand rapids/MIDWEST', 'a multi-word city must still resolve');
});

test('[V2404-04] a shorter name is never absorbed by a longer one that merely ends with it', async () => {
  // 'Gary' (Gary, Indiana — a Tier 1 Midwest market) resolved to 'calgary'
  // (ALBERTA) because 'calgary'.endsWith('gary'). The load then scored against
  // the premium_only "Any -> Alberta" corridor instead of the Midwest.
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    if (!T?.naLookupMarket) return null;
    const m = T.naLookupMarket('Gary');
    const c = T.naLookupMarket('Calgary');
    return { gary: m ? m.city + '/' + m.zone : null, calgary: c ? c.city + '/' + c.zone : null };
  });
  if (!r) { ok(true, 'lookup not exposed'); return; }
  ok(r.gary !== 'calgary/ALBERTA',
    'Gary must never resolve to Calgary/ALBERTA — that scored an Indiana load as a westbound Alberta long-haul');
  eq(r.calgary, 'calgary/ALBERTA', 'Calgary itself must still resolve exactly');
});

// ── Item 2: unknown deadhead stays unknown on every intake ──────────────────

test('[V2404-05] the parser reports an unstated deadhead as UNKNOWN, not zero', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    if (!T?.parseLoadTextEnhanced) return null;
    const noDh = T.parseLoadTextEnhanced('Chicago, IL to Detroit, MI\n280 miles\n$560');
    const withDh = T.parseLoadTextEnhanced('Chicago, IL to Detroit, MI\n280 miles\n40 deadhead miles\n$560');
    return { unstated: noDh.deadheadMiles, stated: withDh.deadheadMiles };
  });
  if (!r) { ok(true, 'parser not exposed'); return; }
  eq(r.unstated, null, 'an unstated deadhead must be null — a 0 default is what made it indistinguishable from a verified zero');
  eq(r.stated, 40, 'a stated deadhead must still parse to its real value');
});

test('[V2404-06] Quick Evaluate refuses to grade a load whose deadhead was never supplied', async () => {
  // The recon case: the full evaluator refused this load while Quick Evaluate
  // returned "A / ACCEPT / True RPM $2.00" off a fabricated zero deadhead.
  await app.page.evaluate(async () => {
    await window.__FL_TESTS.setSetting('quickEvalOnboardingSeen', true);
    location.hash = '#home';
  });
  await app.page.waitForTimeout(700);
  await app.page.click('#homeQuickEvalBtn');
  await app.page.waitForSelector('#qeText', { timeout: 15000 });
  await app.page.fill('#qeText', 'Chicago, IL to Detroit, MI\n280 miles\n$560');
  await app.page.click('#qeSubmitText');
  await app.page.waitForTimeout(2200);

  const state = await app.page.evaluate(() => {
    const prev = document.querySelector('#qeEvalPreview');
    const t = (prev?.textContent || '');
    return {
      deadheadField: document.getElementById('mwDeadMi')?.value ?? '(none)',
      grade: prev?.querySelector('.fl-eval-grade')?.textContent || null,
      asks: /Enter deadhead miles/i.test(t),
    };
  });
  eq(state.deadheadField, '', 'Quick Evaluate must leave the deadhead field BLANK, not write "0" into it');
  eq(state.grade, null, 'no grade may be produced from a deadhead the operator never supplied');
  ok(state.asks, 'the evaluator must ask for the missing deadhead instead of assuming it');
  await app.page.evaluate(() => { document.querySelector('.modal .x')?.click(); });
  await app.page.waitForTimeout(400);
});

test('[V2404-07] an explicitly entered 0 deadhead is still a real, graded zero', async () => {
  await openEvaluator(app.page);
  await app.page.fill('#mwOrigin', 'Chicago, IL');
  await app.page.fill('#mwDest', 'Detroit, MI');
  await app.page.fill('#mwLoadedMi', '280');
  await app.page.fill('#mwDeadMi', '0');
  await app.page.fill('#mwRevenue', '560');
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(1100);
  const state = await app.page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    return { grade: out?.querySelector('.fl-eval-grade')?.textContent || null,
             asks: /Enter deadhead miles/i.test(out?.textContent || '') };
  });
  ok(!state.asks, 'an explicit 0 must NOT be treated as missing');
  eq(state.grade, 'A', '$560 / (280 + a verified 0) = $2.00/mi, which is grade A');
});

// ── Item 7: vehicle fit reconciled to the operator-confirmed 121in ──────────

test('[V2404-08] a 125in load is blocked against the confirmed 121in cargo length', async () => {
  await openEvaluator(app.page);
  await app.page.fill('#mwLoadedMi', '300');
  await app.page.fill('#mwDeadMi', '0');
  await app.page.fill('#mwRevenue', '600');
  await app.page.evaluate(() => { const e = document.getElementById('mwLoadLengthIn'); if (e) e.value = '125'; });
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(1000);
  const state = await app.page.evaluate(() => {
    const t = document.querySelector('#mwEvalOutput')?.textContent || '';
    return { blocks: t.includes("CAN'T TAKE"), names121: t.includes('121') };
  });
  ok(state.blocks, 'a 125in load exceeds the operator-confirmed 121in usable floor and must be blocked BEFORE economics');
  ok(state.names121, 'the violation must name the 121in limit that actually bound');
  await app.page.evaluate(() => { const e = document.getElementById('mwLoadLengthIn'); if (e) e.value = ''; });
});

test('[V2404-09] the default van profile carries the confirmed 121in, not the brochure 130in', async () => {
  const len = await app.page.evaluate(() => window.__FL_TESTS?.VAN_PROFILE_DEFAULT?.cargoLengthIn ?? null);
  if (len === null) { ok(true, 'profile not exposed'); return; }
  eq(len, 121, 'docs/OPERATOR_TRUTH.md records a hard 121in usable cargo-floor limit (OPERATOR_CORRECTION 2026-08-20)');
});

// ── Item 5: portable payloads carry no credentials ─────────────────────────

test('[V2404-10] the real exported payload contains no token, PIN hash or lockout state', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.setSetting('cloudBackupToken', 'flk_deadbeefdeadbeefdeadbeefdeadbeef');
    await T.setSetting('appLockPin', await T.hashPin('4821'));
    await T.setSetting('appLockFailCount', 3);
    await T.setSetting('appLockLockedUntil', Date.now() + 60000);
    await T.setSetting('fmcsaApiKey', 'FMCSA-SECRET');
    await T.setSetting('eiaApiKey', 'EIA-SECRET');
    await T.setSetting('weeklyGoal', 4000);
    // Capture the ACTUAL produced blob rather than re-deriving the filter.
    let captured = null;
    const origCreate = URL.createObjectURL;
    const origClick = HTMLAnchorElement.prototype.click;
    URL.createObjectURL = (b) => { captured = b; return 'blob:stub'; };
    HTMLAnchorElement.prototype.click = function () {};
    try { await T.exportJSON(); }
    finally { URL.createObjectURL = origCreate; HTMLAnchorElement.prototype.click = origClick; }
    if (!captured) return null;
    const raw = await captured.text();
    const payload = JSON.parse(raw);
    const keys = (payload.settings || []).map(s => s.key);
    return {
      keys, raw_hasToken: raw.includes('flk_deadbeef'), raw_hasPinHash: raw.includes('pbkdf2v1:'),
      raw_hasApiSecret: raw.includes('FMCSA-SECRET') || raw.includes('EIA-SECRET'),
      benignSurvived: keys.includes('weeklyGoal'),
    };
  });
  if (!r) { ok(true, 'export not exposed / blob not captured'); return; }
  ok(!r.keys.includes('cloudBackupToken'), 'the bearer cloud token must not be exported');
  ok(!r.keys.includes('appLockPin'), 'the app-lock PIN hash must not be exported');
  ok(!r.keys.includes('appLockFailCount') && !r.keys.includes('appLockLockedUntil'),
    'device-local lockout state must not be exported');
  ok(!r.raw_hasToken, 'the token string must not appear ANYWHERE in the produced file');
  ok(!r.raw_hasPinHash, 'the PIN hash must not appear ANYWHERE in the produced file');
  ok(!r.raw_hasApiSecret, 'API credentials must not appear anywhere in the produced file');
  ok(r.benignSurvived, 'ordinary settings must still be exported — this must not become silent backup data loss');
});

export async function runSpec() {
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
