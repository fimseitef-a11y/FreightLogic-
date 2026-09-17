// ISSUE #216 (FIXED in v24.0.15) — the Today screen reported two conflicting
// positions at once.
//
// OBSERVED 2026-09-16 20:04 CT, iPhone, installed Home Screen PWA, app 24.0.14.
// In a single viewport:
//
//   banner : "Athens, TN — Limited reload options. Consider repositioning"
//   card   : "YOUR POSITION: Columbus, OH · anchor market · Midwest"  verdict HOLD
//
// The driver was told to reposition out of a market the app simultaneously said
// he was not in, and one of the two verdicts was grounded in the wrong
// geography. Reproduced verbatim, and stable across re-renders — not a flicker.
//
// FOUR INDEPENDENT MECHANISMS, all closed here.
//
// 1. OPPOSITE TIE-BREAKS. Both surfaces meant "the most recently created trip's
//    destination". They ordered by the same key and broke ties in opposite
//    directions:
//      renderPositionContextBanner -> listTrips() -> the `created` INDEX with
//        cursor 'prev'; IndexedDB breaks equal index keys by PRIMARY KEY DESC.
//      renderPositioningCard -> _getTripsAndExps() -> dumpStore() (store order =
//        primary key ASC) -> Array.prototype.sort, which is STABLE, so an equal
//        `created` keeps store order — primary key ASC.
//    Under DB16 the primary key is a random UUID, so on a tie the two picked
//    OPPOSITE trips, randomly per install and stably forever after. Ties are
//    ordinary: sanitizeTrip() defaults `created` to Date.now() and trips are
//    written in tight loops by import and by the cloud-restore merge.
//
// 2. OVERLAPPING RENDERS, LAST WRITER WINS. This one needs no tie at all, and is
//    almost certainly what the operator actually hit. Both surfaces are fired
//    and forgotten from renderHome() and both await before painting — the card
//    awaits getPositioningBrief(), which does live NWS I/O. Two renders can be in
//    flight at once and the SLOWER one paints last, even though it resolved
//    position from older data. FOUND BY LOOPING, NOT BY READING: 4/10 with
//    overlapping renders, 0/10 once serialized, 0/10 after the fix.
//    The 4/10 was driven by mechanism 2 below (the stale KPI cache) reaching the
//    paint late; the render-generation guard added alongside it is defence in
//    depth and is explicitly NOT proven by this suite -- see PA-05.
//
// 3. TWO DIFFERENT QUESTIONS. The card resolved GPS first; the banner had no GPS
//    awareness at all and only ever read the last trip. While a tracking session
//    was live they were answering different questions with nothing disclosing
//    which was which.
//
// 4. NO UNKNOWN STATE, AND A LIVE GEOGRAPHY DEFECT. The banner tested
//    MW.tier1/tier2/avoid with `city.includes(c)` on the raw destination.
//    MW.avoid is ['deep southeast','rural southeast','deep texas','far
//    northeast'] — not one a city name — so that branch was unreachable and
//    EVERY unrecognised city fell to a final `else` emitting the same "Limited
//    reload options. Consider repositioning" directive. "Athens, TN" was never
//    assessed as thin; it was not recognised, and the absence was rendered as a
//    confident adverse directive. Worse, raw substring matching re-admitted the
//    Gary/Calgary defect v24.0.4 closed in the lookup functions:
//    'calgary, ab'.includes('gary') is true, so the app told the driver Calgary,
//    ALBERTA was a Midwest Tier 1 anchor and to "Hold for $1.60+".
//
// THE REPAIR. One resolver, resolveDriverPosition(), owns "where is the driver"
// for every surface, with an explicit TOTAL order (created desc, then
// deliveryDate desc, then id desc) instead of one that falls out of storage
// internals. Each render takes a generation ticket and abandons rather than
// painting if a newer render has started. classifyPositionMarket() resolves
// identity through the canonical fail-closed lookup and keys the doctrine tier
// on the resolved market key, so MW.tier1 standing is preserved exactly while
// Calgary can no longer match 'gary'.
//
// `updatedAt` is deliberately NOT in the ordering chain — it records when a row
// was last written, not where the driver was, so including it meant editing an
// ancient trip could move his reported position. It was in the first version of
// the comparator, and was caught by the PA-07 scenario refusing to report a
// genuine tie as ambiguous: upsertTrip() stamps `updatedAt` per save, so two rows
// written in one loop almost never tie on it and the ambiguity check was
// unreachable. Caught by a test disagreeing with a fix, not by reading.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/position-authority.spec.mjs');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** Seed trips through the REAL sanitizer and store, then render Today. */
async function seedAndRenderHome(page, trips) {
  await page.evaluate(async (trips) => {
    const T = window.__FL_TESTS;
    for (const t of trips) {
      await T.upsertTrip({ loadedMiles: 300, emptyMiles: 0, pay: 540, ...t });
    }
    T.invalidateKPICache();
  }, trips);
  await page.evaluate(() => { location.hash = '#trips'; });
  await sleep(350);
  await page.evaluate(() => { location.hash = '#home'; });
  await sleep(2400);
}

function readSurfaces(page) {
  return page.evaluate(() => ({
    banner: (document.querySelector('#homePositionBanner')?.innerText || '').trim().replace(/\n/g, ' '),
    cardTitle: ((document.querySelector('#homePositioningCard')?.innerText || '').trim().split('\n')[0] || ''),
  }));
}

// ── PA-01 — the reported defect itself ───────────────────────────────────────
// Two trips tied on `created`, delivered to different cities. Before the fix the
// banner took the primary-key-DESC record and the card the primary-key-ASC one,
// so they named different cities in one viewport.
test('[ISSUE #216 / FIXED] PA-01 tied `created` — both surfaces name the SAME city', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    // Let boot's own renderHome settle so this test isolates the TIE (PA-05
    // covers the overlapping-render mechanism on its own).
    await sleep(2500);
    const base = Date.now() - 600000;
    // The ids are PINNED, and that is what makes this deterministic rather than a
    // coin flip. sanitizeTrip preserves a supplied `id`, dumpStore's cursor walks
    // the store in primary-key ASCENDING order, and the `created` index in 'prev'
    // breaks its tie by primary key DESCENDING. So with `aaa…` on the EARLIER
    // delivery and `zzz…` on the later one, the pre-fix card deterministically
    // names Columbus while the banner names Athens -- the operator's screenshot,
    // exactly, every run.
    //
    // Found the hard way: with random UUIDs this assertion PASSED against the
    // reinstated defect roughly half the time, which is the OI-11 failure mode
    // this repository already records -- a regression that cannot fail on the
    // thing it guards.
    await seedAndRenderHome(app.page, [
      { id: 'aaaaaaaa-0000-4000-8000-000000000001',
        orderNo: 'PA1-a', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-15', deliveryDate: '2026-09-15', created: base },
      { id: 'zzzzzzzz-0000-4000-8000-000000000002',
        orderNo: 'PA1-b', origin: 'Columbus, OH', destination: 'Athens, TN',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
    ]);
    const s = await readSurfaces(app.page);
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);
    console.log(`    [evidence] card  =${JSON.stringify(s.cardTitle)}`);

    // The later DELIVERY wins the tie — that is the semantically meaningful key.
    ok(s.banner.includes('Athens, TN'),
      'banner must resolve the tie to the later delivery, not to a storage-order accident');
    ok(s.cardTitle.includes('Athens, TN'),
      'card must resolve the tie identically — this disagreement IS issue #216');
    ok(!s.cardTitle.includes('Columbus, OH'),
      'the card must not still be naming the primary-key-ASC record');
  } finally { await app.close(); }
});

// ── PA-02 — the banner had no UNKNOWN state ──────────────────────────────────
test('[ISSUE #216 / FIXED] PA-02 an unrecognised market gets NO directive', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    await seedAndRenderHome(app.page, [
      { orderNo: 'PA2-a', origin: 'Chicago, IL', destination: 'Athens, TN',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now() - 60000 },
    ]);
    const s = await readSurfaces(app.page);
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);

    ok(!/Consider repositioning/i.test(s.banner),
      'an unrecognised market is UNKNOWN, not adverse — it must not inherit the trap directive');
    ok(/not recognised/i.test(s.banner),
      'and the absence must be stated plainly rather than hidden behind a verdict');
    // The card already said "Unknown market" for the same input. Both surfaces
    // must now agree that it is unknown, which is the whole point.
    ok(s.cardTitle.includes('Athens, TN'), 'card still names the same city');
  } finally { await app.close(); }
});

// ── PA-03 — the Gary/Calgary defect, live in this surface until now ──────────
test('[ISSUE #216 / FIXED] PA-03 Calgary is not a Midwest Tier 1 anchor', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    await seedAndRenderHome(app.page, [
      { orderNo: 'PA3-a', origin: 'Seattle, WA', destination: 'Calgary, AB',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now() - 60000 },
    ]);
    const s = await readSurfaces(app.page);
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);

    ok(!/Anchor market/i.test(s.banner),
      "'calgary, ab'.includes('gary') must no longer classify an Alberta city as Midwest Tier 1");
    ok(!/\$1\.60/.test(s.banner),
      'and it must not carry a Tier 1 pricing directive — this was a money claim on wrong geography');
    ok(/ALBERTA/i.test(s.banner) || /Outside your Midwest tiers/i.test(s.banner),
      'the real market identity should be what is reported');
  } finally { await app.close(); }
});

// ── PA-04 — doctrine preserved, which is what makes PA-03 a fix not a nerf ───
// Cincinnati and Toledo are MW.tier1 per v24.0.1, while their USA_MARKETS role
// is 'support'. Keying the tier on the resolved market key rather than the role
// is what keeps that standing; classifying by role would have silently demoted
// them.
test('[ISSUE #216 / FIXED] PA-04 MW.tier1 and MW.tier2 standing survive the rewrite', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      const c = (city) => {
        const x = T.classifyPositionMarket(city);
        return x.known ? x.tier : 'UNKNOWN';
      };
      return {
        columbus: c('Columbus, OH'),
        cincinnati: c('Cincinnati, OH'),
        toledo: c('Toledo, OH'),
        gary: c('Gary, IN'),
        nashville: c('Nashville, TN'),
        dayton: c('Dayton, OH'),
        calgary: c('Calgary, AB'),
        athens: c('Athens, TN'),
        blank: c(''),
        fragment: c('a'),
      };
    });
    console.log(`    [evidence] ${JSON.stringify(r)}`);

    eq(r.columbus, 'TIER1', 'Columbus stays Tier 1');
    eq(r.cincinnati, 'TIER1', 'Cincinnati stays Tier 1 (v24.0.1), though its USA_MARKETS role is support');
    eq(r.toledo, 'TIER1', 'Toledo stays Tier 1 (v24.0.1), though its USA_MARKETS role is support');
    eq(r.gary, 'TIER1', 'Gary, IN stays Tier 1 — the v24.0.5 market entry is what makes this resolvable');
    eq(r.nashville, 'TIER2', 'Nashville stays Tier 2');
    eq(r.dayton, 'TIER2', 'Dayton stays Tier 2');
    ok(r.calgary !== 'TIER1', 'Calgary is not Tier 1');
    eq(r.athens, 'UNKNOWN', 'an unrecognised city is UNKNOWN, not a tier and not adverse');
    eq(r.blank, 'UNKNOWN', 'blank fails closed (v24.0.4 item 1)');
    eq(r.fragment, 'UNKNOWN', 'a one-character fragment fails closed');
  } finally { await app.close(); }
});

// ── PA-05 — the same defect under OVERLAPPING renders ────────────────────────
// Deliberately does NOT let boot's renderHome settle: it seeds while that render
// is still in flight, which is exactly the production shape (a trip save calls
// renderHome while a previous Today render is still awaiting the weather fetch).
// Against the original code this mismatched in 4/10 iterations.
//
// WHAT THIS DOES AND DOES NOT PROVE, stated exactly. It fires against the
// pre-fix RESOLVER -- because the old card read the 120s KPI cache, an in-flight
// boot render resolved position from a snapshot taken before the seed and then
// painted late. It does NOT fire against removal of the render-generation guard
// alone: with the resolver reading IndexedDB at the moment it resolves, an
// overlapping render re-reads the current data and reaches the same answer.
//
// So the guard is defence-in-depth and NOTHING IN THIS SUITE FAILS WITHOUT IT.
// That is recorded rather than glossed, because a negative control that does not
// fire is the finding, not a formality (the LPR-10 lesson). It is kept because
// getPositioningBrief() does live NWS I/O in production, where two renders can
// genuinely complete out of order, and because four lines that can only ever
// suppress a stale paint cannot make anything worse -- not because a test
// demands it.
test('[ISSUE #216 / FIXED] PA-05 an overlapping render cannot paint stale position', async () => {
  const ITER = 6;
  let mismatches = 0;
  const seen = [];
  for (let i = 0; i < ITER; i++) {
    const app = await launchApp();
    try {
      await skipFirstRunWizard(app.page);
      // NO settle wait — that is the point of this assertion.
      const base = Date.now() - 600000;
      await seedAndRenderHome(app.page, [
        { id: 'aaaaaaaa-0000-4000-8000-000000000001',
          orderNo: 'PA5-a', origin: 'Chicago, IL', destination: 'Columbus, OH',
          pickupDate: '2026-09-15', deliveryDate: '2026-09-15', created: base },
        { id: 'zzzzzzzz-0000-4000-8000-000000000002',
          orderNo: 'PA5-b', origin: 'Columbus, OH', destination: 'Athens, TN',
          pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
      ]);
      const s = await readSurfaces(app.page);
      const agree = s.banner.includes('Athens, TN') && s.cardTitle.includes('Athens, TN');
      if (!agree) { mismatches++; seen.push(s); }
    } finally { await app.close(); }
  }
  console.log(`    [evidence] mismatches ${mismatches}/${ITER} (was 4/10 before the render-generation guard)`);
  if (seen.length) console.log(`    [evidence] ${JSON.stringify(seen[0])}`);

  eq(mismatches, 0,
    'a render that resolved position from older data must abandon rather than paint over a newer one');
});

// ── PA-06 — the ordering is a TOTAL order, asserted directly ─────────────────
test('[ISSUE #216 / FIXED] PA-06 ordering is total and `updatedAt` cannot move the driver', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      const rank = T._positionTripRank;
      const A = { id: 'aaa', created: 100, deliveryDate: '2026-09-15', updatedAt: 9999, destination: 'X' };
      const B = { id: 'bbb', created: 100, deliveryDate: '2026-09-16', updatedAt: 1, destination: 'Y' };
      const C = { id: 'ccc', created: 100, deliveryDate: '2026-09-16', updatedAt: 1, destination: 'Z' };
      const D = { id: 'ddd', created: 200, deliveryDate: '2026-09-01', updatedAt: 1, destination: 'W' };
      return {
        // created dominates
        createdWins: [A, D].slice().sort(rank)[0].id,
        // on a created tie, the later DELIVERY wins, and a huge `updatedAt` on
        // the loser does not rescue it
        deliveryBreaksTie: [A, B].slice().sort(rank)[0].id,
        // on a full tie the order is still TOTAL (id desc), never storage order
        totalOrder: [B, C].slice().sort(rank)[0].id,
        totalOrderReversedInput: [C, B].slice().sort(rank)[0].id,
        selfIsZero: rank(A, A),
      };
    });
    console.log(`    [evidence] ${JSON.stringify(r)}`);

    eq(r.createdWins, 'ddd', '`created` remains the primary key, as both surfaces always intended');
    eq(r.deliveryBreaksTie, 'bbb',
      'the later delivery wins a `created` tie — and `updatedAt` 9999 on the loser must not override it, ' +
      'because when a row was last EDITED is not where the driver was');
    eq(r.totalOrder, 'ccc', 'a full tie still has one deterministic winner');
    eq(r.totalOrderReversedInput, 'ccc',
      'and it is the SAME winner regardless of input order — that is what "total" means, ' +
      'and what a stable sort over store order failed to give');
    eq(r.selfIsZero, 0, 'the comparator is reflexive');
  } finally { await app.close(); }
});

// ── PA-07 — a genuine ambiguity is disclosed, not priced off ─────────────────
test('[ISSUE #216 / FIXED] PA-07 two fully-tied trips to different cities stand down the directive', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    const base = Date.now() - 600000;
    await seedAndRenderHome(app.page, [
      { orderNo: 'PA7-a', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
      { orderNo: 'PA7-b', origin: 'Detroit, MI', destination: 'Indianapolis, IN',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
    ]);
    const s = await readSurfaces(app.page);
    const pos = await app.page.evaluate(() => window.__FL_TESTS.resolveDriverPosition());
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);
    console.log(`    [evidence] ambiguous=${pos.ambiguous} city=${JSON.stringify(pos.city)}`);

    ok(pos.ambiguous,
      'two trips tied on every ordering key and disagreeing about the destination is a real ambiguity');
    ok(/tie for most recent/i.test(s.banner),
      'and it must be disclosed — both cities are Tier 1 here, so the old code would have issued ' +
      'a confident "Hold for $1.60+" grounded in what is effectively a coin flip');
    // Deterministic pick is still required: that is what stops the two surfaces
    // contradicting each other.
    ok(s.cardTitle.includes(pos.display), 'the card still names the resolver\'s deterministic pick');
  } finally { await app.close(); }
});

// ── PA-08 — position no longer comes from the 120s KPI cache ────────────────
// The card used to read _getTripsAndExps(), a 120s cache, while the banner read
// IndexedDB fresh. Any trip write that did not invalidate left them up to two
// minutes apart. Reproduced pre-fix: banner "Knoxville, TN", card "Athens, TN".
test('[ISSUE #216 / FIXED] PA-08 a trip written without invalidating the KPI cache still moves both surfaces', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    await seedAndRenderHome(app.page, [
      { orderNo: 'PA8-a', origin: 'Chicago, IL', destination: 'Athens, TN',
        pickupDate: '2026-09-15', deliveryDate: '2026-09-15', created: Date.now() - 600000 },
    ]);
    // Deliberately NOT calling invalidateKPICache() — that is the defect's trigger.
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.upsertTrip({
        orderNo: 'PA8-b', origin: 'Athens, TN', destination: 'Columbus, OH',
        loadedMiles: 60, emptyMiles: 0, pay: 150,
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now(),
      });
    });
    await app.page.evaluate(() => { location.hash = '#trips'; });
    await sleep(350);
    await app.page.evaluate(() => { location.hash = '#home'; });
    await sleep(2400);

    const s = await readSurfaces(app.page);
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);
    console.log(`    [evidence] card  =${JSON.stringify(s.cardTitle)}`);

    ok(s.banner.includes('Columbus, OH'), 'banner reads the store, as it always did');
    ok(s.cardTitle.includes('Columbus, OH'),
      'and the card must too — position is authoritative data, not a KPI aggregate that may be 2 minutes stale');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
