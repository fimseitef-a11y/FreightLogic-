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

test('[FINDING F-2 / FIXED] sanitizeTrip validates paidDate like every sibling date field', async () => {
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
  // ...paidDate now does too (app.js:926): garbage is treated as "no date given",
  // which for isPaid:true falls back to today's date (matching the pre-existing
  // "auto-stamp today when marking paid" behavior for a genuinely absent paidDate),
  // not stored verbatim.
  ok(/^\d{4}-\d{2}-\d{2}$/.test(r.paidDate),
    `EXPECTED paidDate to validate like its siblings (garbage -> fallback ISO date since isPaid:true), GOT ${JSON.stringify(r.paidDate)}`);
});

test('[FINDING F-2] valid paidDate values pass through unchanged', async () => {
  const r = await app.page.evaluate(() => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'T2', pay: 1000, loadedMiles: 500, isPaid: true, paidDate: '2026-02-14',
    });
    return t.paidDate;
  });
  eq(r, '2026-02-14', 'a genuinely valid ISO paidDate must round-trip exactly');
});

test('[FINDING F-2] an unpaid trip with garbage paidDate gets null, not a fabricated date', async () => {
  const r = await app.page.evaluate(() => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'T3', pay: 1000, loadedMiles: 500, isPaid: false, paidDate: 'garbage',
    });
    return t.paidDate;
  });
  eq(r, null, 'an unpaid trip must not get a fabricated paidDate just because garbage was supplied');
});

test('[FINDING F-2b] sanitizeStop.date has the same validation gap as trip.paidDate did — found while auditing F-2', async () => {
  // Lower severity than F-2 itself: grepping app.js finds no computation
  // anywhere that reads stop.date for date-math (unlike paidDate, which fed
  // computeBrokerStats' day-count arithmetic) — it's stored and displayed
  // raw only, today. Still the same bypass pattern, fixed for consistency
  // and to close the gap before anything starts consuming it.
  const r = await app.page.evaluate(() => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'T4', pay: 1000, loadedMiles: 500,
      stops: [{ city: 'Chicago, IL', date: 'not-a-date-either', type: 'stop' }],
    });
    return t.stops[0]?.date;
  });
  ok(r === '' || /^\d{4}-\d{2}-\d{2}$/.test(r),
    `EXPECTED sanitizeStop to reject/blank garbage dates like every other date field, GOT ${JSON.stringify(r)}`);
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

// F-8 (Critical): sanitizeExpense()/sanitizeFuel() used to build a new record's
// key as `id: raw.id ? intNum(raw.id, 0, 1e12) : undefined`. For a brand-new
// record raw.id is absent, so that put an EXPLICIT `id: undefined` property on
// the object handed to store.add(). IndexedDB auto-increment only fills the key
// when the keyPath property is ABSENT — an explicitly-present `id: undefined`
// counts as a real (invalid) key and add() throws DataError synchronously. The
// fix omits the key entirely for new records. These assert the sanitizer output
// shape directly; the end-to-end UI behavior is covered in
// tests/integration/field-resilience.spec.mjs.
test('[FINDING F-8 / FIXED] sanitizeExpense omits the id key entirely for a new record (auto-increment cannot fire otherwise)', async () => {
  const r = await app.page.evaluate(() => {
    const out = window.__FL_TESTS.sanitizeExpense({ amount: 45.5, category: 'Fuel' });
    return { hasIdKey: Object.prototype.hasOwnProperty.call(out, 'id'), keys: Object.keys(out) };
  });
  ok(!r.hasIdKey,
    `a new expense must not carry an 'id' key at all (an explicit id:undefined makes store.add() throw DataError) — keys present: ${JSON.stringify(r.keys)}`);
});

test('[FINDING F-8 / FIXED] sanitizeExpense still sets id on the edit path', async () => {
  const r = await app.page.evaluate(() => {
    const out = window.__FL_TESTS.sanitizeExpense({ id: 7, amount: 45.5, category: 'Fuel' });
    return { hasIdKey: Object.prototype.hasOwnProperty.call(out, 'id'), id: out.id };
  });
  ok(r.hasIdKey, 'an existing expense must keep its id key — updateExpense() throws "Missing id" without it');
  eq(r.id, 7, 'the existing id must be preserved unchanged by the fix');
});

test('[FINDING F-8 / FIXED] sanitizeFuel omits the id key for a new record and keeps it on the edit path', async () => {
  const r = await app.page.evaluate(() => {
    const created = window.__FL_TESTS.sanitizeFuel({ gallons: 18.2, amount: 64.7, state: 'IL' });
    const edited = window.__FL_TESTS.sanitizeFuel({ id: 42, gallons: 18.2, amount: 64.7, state: 'IL' });
    return {
      newHasIdKey: Object.prototype.hasOwnProperty.call(created, 'id'),
      editHasIdKey: Object.prototype.hasOwnProperty.call(edited, 'id'),
      editId: edited.id,
    };
  });
  ok(!r.newHasIdKey, 'a new fuel record must not carry an id key — sanitizeFuel had the byte-for-byte identical bug');
  ok(r.editHasIdKey, 'an existing fuel record must keep its id key');
  eq(r.editId, 42, 'the existing fuel id must be preserved unchanged');
});

// ── v23.9 Phase 1: X-02 (date-keyed mileage rate) ──────────────────────────
test('[X-02] getMileageRate resolves the correct band on both sides of the July 2026 midyear increase', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.getMileageRate('2026-06-30'),
    window.__FL_TESTS.getMileageRate('2026-07-01'),
    window.__FL_TESTS.getMileageRate('2026-01-01'),
    window.__FL_TESTS.getMileageRate('2026-12-31'),
    window.__FL_TESTS.getMileageRate('2025-06-15'),
  ]);
  eq(r[0], 0.725, 'last day of H1 2026 must use the pre-increase rate');
  eq(r[1], 0.76, 'first day of H2 2026 must use the post-increase rate');
  eq(r[2], 0.725, 'Jan 1 2026 must use the pre-increase rate');
  eq(r[3], 0.76, 'Dec 31 2026 must use the post-increase rate');
  eq(r[4], 0.70, '2025 must still resolve to the flat 2025 rate');
});

test('[X-02] getMileageRate never throws on out-of-table dates — clamps to nearest known rate', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.getMileageRate('2020-01-01'),
    window.__FL_TESTS.getMileageRate('2030-01-01'),
    window.__FL_TESTS.getMileageRate(''),
  ]);
  eq(r[0], 0.70, 'a date before the table must clamp to the earliest known rate, not 0 or throw');
  eq(r[1], 0.76, 'a date after the table must clamp to the most recent known rate');
  eq(r[2], 0.70, 'an empty/invalid date must not throw — falls back to the earliest known rate');
});

// ── v23.9 Phase 1: X-03 (tax-method-sensitivity bucket map) ────────────────
test('[X-03] classifyExpenseTaxBucket puts vehicle-operating categories in bucket A', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.classifyExpenseTaxBucket('Fuel'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Repairs & Maintenance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Oil Change'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Registration'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Auto Insurance'),
  ]);
  eq(r[0], 'A', 'Fuel must be bucket A (vehicle-operating)');
  eq(r[1], 'A', 'Repairs & Maintenance must be bucket A');
  eq(r[2], 'A', 'Oil Change must be bucket A');
  eq(r[3], 'A', 'Registration must be bucket A');
  eq(r[4], 'A', 'Auto Insurance must be bucket A — this is the exact double-dip category X-03 describes');
});

test('[X-03] classifyExpenseTaxBucket splits cargo/liability/occ-acc insurance into bucket B, never A', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.classifyExpenseTaxBucket('Cargo Insurance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Liability Insurance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Occupational Accident Insurance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Parking'), window.__FL_TESTS.classifyExpenseTaxBucket('Tolls'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Phone / Data'),
  ]);
  eq(r[0], 'B', 'Cargo Insurance must never be suppressed by vehicle method');
  eq(r[1], 'B', 'Liability Insurance must never be suppressed by vehicle method');
  eq(r[2], 'B', 'Occupational Accident Insurance must never be suppressed by vehicle method');
  eq(r[3], 'B', 'Parking is always deductible');
  eq(r[4], 'B', 'Tolls is always deductible');
  eq(r[5], 'B', 'Phone is always deductible');
});

test('[X-03] classifyExpenseTaxBucket puts bare/unresolved "Insurance" in bucket C, and never auto-includes it', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.classifyExpenseTaxBucket('Insurance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('insurance'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Insurance (Unspecified)'),
  ]);
  eq(r[0], 'C', 'bare "Insurance" must be bucket C (ambiguous), not silently folded into A or B');
  eq(r[1], 'C', 'matching must be case-insensitive');
  eq(r[2], 'C', 'an unrecognized insurance sub-type string must also land in bucket C');
});

test('[X-03] classifyExpenseTaxBucket defaults unrelated (non-vehicle) categories to bucket B, not C', async () => {
  // Regression guard: an earlier draft of this function bucketed EVERY
  // unrecognized category as ambiguous/excluded, which would have silently
  // dropped ordinary Schedule C deductions like Meals/Supplies/Software from
  // every total — a new correctness bug, not a fix for X-03.
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.classifyExpenseTaxBucket('Meals'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Software / Apps'),
    window.__FL_TESTS.classifyExpenseTaxBucket('Supplies'),
  ]);
  eq(r[0], 'B', 'Meals is not vehicle-operating — must stay always-deductible, not excluded');
  eq(r[1], 'B', 'Software/Apps is not vehicle-operating — must stay always-deductible');
  eq(r[2], 'B', 'Supplies is not vehicle-operating — must stay always-deductible');
});

test('[X-03] sanitizeExpense derives/preserves insuranceBucket only for A/B/C values', async () => {
  const r = await app.page.evaluate(() => [
    window.__FL_TESTS.sanitizeExpense({ amount: 100, category: 'Auto Insurance', insuranceBucket: 'A' }).insuranceBucket,
    window.__FL_TESTS.sanitizeExpense({ amount: 100, category: 'Fuel' }).insuranceBucket,
    window.__FL_TESTS.sanitizeExpense({ amount: 100, category: 'Insurance', insuranceBucket: 'not-a-bucket' }).insuranceBucket,
  ]);
  eq(r[0], 'A', 'a valid A/B/C insuranceBucket must round-trip through sanitizeExpense');
  eq(r[1], undefined, 'insuranceBucket must be absent for a non-insurance category, not defaulted to some value');
  eq(r[2], undefined, 'an invalid insuranceBucket value must be dropped, not passed through');
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
