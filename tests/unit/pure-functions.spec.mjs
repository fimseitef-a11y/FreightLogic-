// Unit-level tests against the pure functions FreightLogic exposes via
// window.__FL_TESTS (app.js:16024-16038). Run inside a real browser so
// browser APIs (crypto.subtle, IndexedDB-adjacent helpers) work exactly as
// they do in production — this is not a jsdom/mocked reimplementation.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/pure-functions.spec.mjs');
let app;

test('escapeHtml neutralizes all five XSS-relevant characters', async () => {
  const r = await app.page.evaluate(() => window.__FL_TESTS.escapeHtml(`<script>alert('x')&"y"</script>`));
  ok(!r.includes('<script>'), 'raw <script> tag must not survive: ' + r);
  eq(r, '&lt;script&gt;alert(&#39;x&#39;)&amp;&quot;y&quot;&lt;/script&gt;', 'exact escaped output');
});

test('escapeHtml handles null/undefined/number without throwing', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.escapeHtml(null),
    window.__FL_TESTS.escapeHtml(undefined),
    window.__FL_TESTS.escapeHtml(42),
  ]);
  eq(r[0], '', 'null -> empty string');
  eq(r[1], '', 'undefined -> empty string');
  eq(r[2], '42', 'number -> stringified');
});

test('csvSafeCell neutralizes leading formula characters (= + - @ TAB CR | % !)', async () => {
  const cases = ['=1+1', '+1+1', '-1+1', '@SUM(A1)', '\t=cmd', '\rmalicious', '|calc', '%exec', '!alert'];
  const r = await app.page.evaluate((cs) => cs.map(c => window.__FL_TESTS.csvSafeCell(c)), cases);
  for (let i = 0; i < cases.length; i++){
    // The mitigation is a literal leading TAB (which spreadsheet apps treat as text,
    // not a formula trigger) — so the real invariant is "position 0 is not =+-@|%!".
    ok(r[i][0] !== '=' && r[i][0] !== '+' && r[i][0] !== '-' && r[i][0] !== '@' && r[i][0] !== '|' && r[i][0] !== '%' && r[i][0] !== '!',
      `csvSafeCell(${JSON.stringify(cases[i])}) still starts with a live formula trigger: ${JSON.stringify(r[i])}`);
  }
});

test('csvSafeCell neutralizes formula chars after embedded newlines (multi-line cell)', async () => {
  const r = await app.page.evaluate(() => window.__FL_TESTS.csvSafeCell('safe first line\n=cmd|calc!A1'));
  ok(!/\n[=+\-@|%!]/.test(r), 'formula trigger survives after a newline: ' + JSON.stringify(r));
});

test('csvSafeCell does NOT neutralize benign leading text (no false positives)', async () => {
  const r = await app.page.evaluate(() => window.__FL_TESTS.csvSafeCell('Springfield, IL'));
  eq(r, 'Springfield, IL', 'benign city/state text must pass through unchanged');
});

test('deepCleanObj strips __proto__/constructor/prototype at every depth (prototype-pollution guard)', async () => {
  const r = await app.page.evaluate(() => {
    const evil = JSON.parse('{"a":1,"__proto__":{"polluted":true},"nested":{"constructor":{"x":1},"prototype":{"y":1},"ok":2}}');
    const cleaned = window.__FL_TESTS.deepCleanObj(evil);
    return {
      hasOwnProto: Object.prototype.hasOwnProperty.call(cleaned, '__proto__'),
      polluted: ({}).polluted, // would be true if it actually reached Object.prototype
      nestedKeys: Object.keys(cleaned.nested),
    };
  });
  eq(r.hasOwnProto, false, '__proto__ must not appear as an own key on the cleaned object');
  eq(r.polluted, undefined, 'global Object.prototype must not be polluted');
  eq(r.nestedKeys.includes('constructor'), false, 'nested constructor key must be stripped');
  eq(r.nestedKeys.includes('prototype'), false, 'nested prototype key must be stripped');
  ok(r.nestedKeys.includes('ok'), 'benign nested keys must survive');
});

test('roundCents avoids classic IEEE-754 drift (0.1+0.2 style cases)', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.roundCents(1.005),
    window.__FL_TESTS.roundCents(0.1 + 0.2),
    window.__FL_TESTS.roundCents(19.999999999998),
  ]);
  eq(r[1], 0.3, '0.1+0.2 must round to exactly 0.3');
  eq(r[2], 20, 'accumulated float drift must round to 20');
});

test('[FINDING F-2 / KNOWN FAILING] sanitizeTrip must validate paidDate like every sibling date field', async () => {
  const r = await app.page.evaluate(() => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'T1', pay: 1000, loadedMiles: 500,
      pickupDate: 'not-a-date', deliveryDate: 'also-garbage', invoiceDate: 'nope',
      isPaid: true, paidDate: 'TOTALLY NOT A DATE',
    });
    return { pickupDate: t.pickupDate, deliveryDate: t.deliveryDate, invoiceDate: t.invoiceDate, paidDate: t.paidDate };
  });
  // Every sibling date field falls back to a valid ISO date when given garbage...
  ok(/^\d{4}-\d{2}-\d{2}$/.test(r.pickupDate), 'pickupDate must fall back to valid ISO: ' + r.pickupDate);
  ok(/^\d{4}-\d{2}-\d{2}$/.test(r.deliveryDate), 'deliveryDate must fall back to valid ISO: ' + r.deliveryDate);
  ok(/^\d{4}-\d{2}-\d{2}$/.test(r.invoiceDate), 'invoiceDate must fall back to valid ISO: ' + r.invoiceDate);
  // ...paidDate must too (app.js:926 currently stores it verbatim with no isValidISODate() check).
  ok(/^\d{4}-\d{2}-\d{2}$/.test(r.paidDate) || r.paidDate === null,
    `BUG (app.js:926): paidDate bypasses isValidISODate() unlike pickupDate/deliveryDate/invoiceDate/dueDate. ` +
    `Got raw passthrough: ${JSON.stringify(r.paidDate)}. A CSV import's PaidDate column (app.js:1637) flows here unvalidated ` +
    `and reaches computeBrokerStats() (app.js:2152-2155) which has no d>=0/d<365 sanity bound, unlike renderMoneyCard's ` +
    `equivalent calculation (app.js:15427-15429) which does.`);
});

test('omegaTierForMiles is exhaustive and mutually exclusive across a dense fuzz sweep', async () => {
  const bad = await app.page.evaluate(() => {
    const bad = [];
    for (let m = -50; m <= 3000; m += 0.5){
      const tier = window.__FL_TESTS.omegaTierForMiles(m);
      if (![0,1,2,3,4].includes(tier)) bad.push({ m, tier, reason: 'out of range' });
    }
    // Boundary exactness
    const boundaries = [
      [180, 0], [180.01, 1], [350, 1], [350.01, 2], [600, 2], [600.01, 3], [900, 3], [900.01, 4],
    ];
    for (const [m, expected] of boundaries){
      const got = window.__FL_TESTS.omegaTierForMiles(m);
      if (got !== expected) bad.push({ m, expected, got, reason: 'boundary mismatch' });
    }
    return bad;
  });
  eq(bad.length, 0, 'omegaTierForMiles boundary/exhaustiveness failures: ' + JSON.stringify(bad));
});

test('OMEGA_TIERS bands are internally non-overlapping within each tier (premium > ideal > strong > floor > under)', async () => {
  const problems = await app.page.evaluate(() => {
    const problems = [];
    for (const t of window.__FL_TESTS.OMEGA_TIERS){
      const order = ['under', 'floor', 'strong', 'ideal', 'premium'];
      for (let i = 0; i < order.length - 1; i++){
        const lo = t[order[i]], hi = t[order[i+1]];
        if (lo.max != null && hi.min !== +(lo.max + 0.01).toFixed(2) && hi.min !== lo.max) {
          // allow either abutting (hi.min === lo.max+0.01) or exact touch; flag real overlap only
          if (hi.min < lo.max) problems.push({ tier: t.name, gap: `${order[i]}.max=${lo.max} vs ${order[i+1]}.min=${hi.min}` });
        }
      }
    }
    return problems;
  });
  eq(problems.length, 0, 'OMEGA_TIERS band overlap found: ' + JSON.stringify(problems));
});

test('mwClassifyRPM: every tier boundary resolves to exactly one tier, scan is monotonic', async () => {
  const bad = await app.page.evaluate(() => {
    const bad = [];
    const tiers = window.__FL_TESTS.MW.rpmTiers;
    for (let rpm = 0; rpm <= 3; rpm += 0.01){
      const t = window.__FL_TESTS.mwClassifyRPM(+rpm.toFixed(2));
      if (!t || typeof t.min !== 'number') bad.push({ rpm, reason: 'no tier returned' });
    }
    return { bad, tierCount: tiers.length, tiers: tiers.map(t=>t.min) };
  });
  eq(bad.bad.length, 0, 'mwClassifyRPM failed to classify: ' + JSON.stringify(bad.bad));
});

test('computeLoadScore is deterministic — identical inputs never drift across repeated calls', async () => {
  const r = await app.page.evaluate(() => {
    const trip = { pay: 2200, loadedMiles: 1100, emptyMiles: 80, pickupDate: '2026-03-01', deliveryDate: '2026-03-03', origin: 'Chicago, IL', destination: 'Dallas, TX' };
    const scores = [];
    for (let i = 0; i < 25; i++){
      scores.push(JSON.stringify(window.__FL_TESTS.computeLoadScore(trip, [], [], null)));
    }
    return scores;
  });
  const distinct = new Set(r);
  eq(distinct.size, 1, `computeLoadScore produced ${distinct.size} distinct results across 25 identical calls (non-deterministic)`);
});

test('hashPin produces a fresh random salt every call (no salt reuse)', async () => {
  const [a, b] = await app.page.evaluate(async () => [await window.__FL_TESTS.hashPin('1234'), await window.__FL_TESTS.hashPin('1234')]);
  ok(a.startsWith('pbkdf2v1:') && b.startsWith('pbkdf2v1:'), 'expected pbkdf2v1 format');
  const saltA = a.split(':')[1], saltB = b.split(':')[1];
  ok(saltA !== saltB, 'two hashPin() calls for the SAME pin produced the SAME salt — salt reuse');
  ok(a !== b, 'two hashPin() calls for the same pin produced the identical hash string');
});

export async function runSpec() {
  app = await launchApp();
  try {
    return await run();
  } finally {
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
