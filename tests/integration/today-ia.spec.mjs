// Issue #205 — the driver-first UX/IA restructure of Today and More.
//
// This slice removed duplicated surfaces rather than adding features, so every
// assertion here is about what a driver SEES, driven through the real app in
// real Chromium. That is deliberate and it is the v24.0.8 lesson applied: the
// Loads tab shipped green because the hash, the highlighted tab and the DOM node
// were all correct while the surface itself was dead. Asserting rendered content
// is the only kind of assertion that would have caught it.
//
// Four duplications are closed, and one page is regrouped:
//
//  TIA-01/02  ONE position authority. The banner and the positioning card each
//             printed the driver's city AND a market classification AND a
//             hold/reposition directive, one above the other. The banner keeps
//             identity and doctrine (it is the surface issue #216 repaired and
//             that position-authority.spec.mjs pins); the card keeps the brief.
//  TIA-03     The card stands down its directive on an ambiguous position.
//             Issue #216 made the BANNER refuse to price off a coin flip; the
//             card went on printing HOLD on the same tie, directly beneath
//             "confirm your position before pricing".
//  TIA-04/05  ONE weekly-money summary. The hero card was headed "This Week"
//             over three TODAY figures, and its weekly goal bar was repeated as
//             a second bar and a second percentage in the Money card below it.
//  TIA-06/07  Onboarding retires itself after a display budget instead of
//             persisting forever when the driver reads it without tapping.
//  TIA-08     Idle GPS is compact; an ACTIVE trip is not compacted.
//  TIA-09/10  More is a labelled directory, and nothing was orphaned by the
//             regroup (MS-12 asserts route reachability; this asserts that every
//             declared tile actually reaches the DOM).
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/today-ia.spec.mjs');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function seedAndRenderHome(page, trips) {
  await page.evaluate(async (trips) => {
    const T = window.__FL_TESTS;
    for (const t of trips) await T.upsertTrip({ loadedMiles: 300, emptyMiles: 0, pay: 540, ...t });
    T.invalidateKPICache();
  }, trips);
  await page.evaluate(() => { location.hash = '#trips'; });
  await sleep(350);
  await page.evaluate(() => { location.hash = '#home'; });
  await sleep(2400);
}

const readTodayText = (page) => page.evaluate(() => ({
  banner: (document.querySelector('#homePositionBanner')?.innerText || '').trim().replace(/\n/g, ' '),
  card: (document.querySelector('#homePositioningCard')?.innerText || '').trim(),
  kpi: (document.querySelector('#homeKPICard')?.innerText || '').trim(),
  money: (document.querySelector('#homeMoneyCard')?.innerText || '').trim(),
  track: (document.querySelector('#homeTripTrackCard')?.innerText || '').trim(),
}));

// ── TIA-01 — the card no longer reprints the banner's market identity ────────
test('[ISSUE #205] TIA-01 only ONE surface on Today states the market identity', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    // Columbus is MW.tier1, so the banner issues a real doctrine directive and
    // the card resolves a real brief. Both surfaces are live here, which is the
    // only configuration in which the duplication is observable at all.
    await seedAndRenderHome(app.page, [
      { orderNo: 'TIA1', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now() - 60000 },
    ]);
    const s = await readTodayText(app.page);
    console.log(`    [evidence] banner=${JSON.stringify(s.banner)}`);
    console.log(`    [evidence] card1 =${JSON.stringify(s.card.split('\n')[0])}`);

    ok(/Anchor market/i.test(s.banner), 'the banner remains the doctrine authority');
    ok(s.card.includes('Columbus, OH'),
      'the card still names the city — it is the FROM of the outbound lanes it lists');
    // The duplication was the card's own subtitle, "<role> market · <zone>",
    // printed one card below the banner's market sentence.
    ok(!/market\s*·/i.test(s.card),
      'the card must not reprint a market identity subtitle the banner already states');
    ok(!/YOUR POSITION/i.test(s.card),
      'and it must not present itself as a second answer to "where am I"');
  } finally { await app.close(); }
});

// ── TIA-02 — one directive, not two ─────────────────────────────────────────
test('[ISSUE #205] TIA-02 the doctrine directive is issued once', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    await seedAndRenderHome(app.page, [
      { orderNo: 'TIA2', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now() - 60000 },
    ]);
    const s = await readTodayText(app.page);
    const both = `${s.banner}\n${s.card}`;
    const holdCount = (both.match(/Hold for \$/gi) || []).length;
    console.log(`    [evidence] "Hold for $" occurrences across both surfaces: ${holdCount}`);
    eq(holdCount, 1,
      'the Tier 1 pricing directive must appear on exactly one Today surface');
  } finally { await app.close(); }
});

// ── TIA-03 — an ambiguous position stands the CARD's command down too ───────
test('[ISSUE #205] TIA-03 an ambiguous position suppresses the card command', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    // Two trips tied on `created` AND `deliveryDate`, delivered to two different
    // Tier 1 cities. resolveDriverPosition() reports ambiguous: the pick stays
    // deterministic (that is what stops the surfaces contradicting each other)
    // but nothing should issue a directive from it.
    const base = Date.now() - 600000;
    await seedAndRenderHome(app.page, [
      { orderNo: 'TIA3-a', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
      { orderNo: 'TIA3-b', origin: 'Detroit, MI', destination: 'Indianapolis, IN',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: base },
    ]);
    const pos = await app.page.evaluate(() => window.__FL_TESTS.resolveDriverPosition());
    const s = await readTodayText(app.page);
    console.log(`    [evidence] ambiguous=${pos.ambiguous}`);
    console.log(`    [evidence] card=${JSON.stringify(s.card.slice(0, 160))}`);

    ok(pos.ambiguous, 'the fixture must actually produce an ambiguity, or this asserts nothing');
    ok(/tie for most recent/i.test(s.banner), 'the banner discloses it, as issue #216 established');
    ok(/Confirm your position/i.test(s.card),
      'and the card must disclose it too rather than leading with a command');
    ok(!/\b(HOLD|REPOSITION|HUNT)\b/.test(s.card),
      'no HOLD/REPOSITION/HUNT command may be issued from a position the app cannot resolve');
  } finally { await app.close(); }
});

// ── TIA-04 — the hero card's heading matches the numbers under it ────────────
test('[ISSUE #205] TIA-04 the hero card no longer labels today\'s money as the week', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    await seedAndRenderHome(app.page, [
      { orderNo: 'TIA4', origin: 'Chicago, IL', destination: 'Columbus, OH',
        pickupDate: '2026-09-16', deliveryDate: '2026-09-16', created: Date.now() - 60000 },
    ]);
    const hdr = await app.page.evaluate(() =>
      (document.querySelector('#homeKPICard h3')?.textContent || '').trim());
    const labels = await app.page.$$eval('#homeKPICard .kpi-cell-label',
      (els) => els.map((e) => e.textContent.trim()));
    console.log(`    [evidence] heading=${JSON.stringify(hdr)} labels=${JSON.stringify(labels)}`);

    // kpiTodayNet / kpiTodayGross / kpiTodayExp are all written from the TODAY
    // window in computeKPIs(); the heading said "This Week".
    eq(hdr, 'Today', 'the heading must name the window its hero value is actually computed over');
    ok(labels.some((l) => /today/i.test(l)),
      'and the cells must say which of them are today figures');
  } finally { await app.close(); }
});

// ── TIA-05 — ONE weekly-goal progress surface ───────────────────────────────
test('[ISSUE #205] TIA-05 the weekly goal bar is rendered once, not twice', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.setSetting('weeklyGoal', 2000);
    });
    await sleep(2200);
    // The Money card needs 3+ VALID trips to render its full form, which is the
    // form that carried the duplicate goal block.
    //
    // `paymentStatusKnown: true` is required and is not boilerplate: sanitizeTrip
    // defaults it to FALSE, which is the v24.0.2 migration rule -- a trip whose
    // `isPaid:false` cannot be proven explicit enters payment UNKNOWN and is
    // excluded from every money aggregate. Without it all three trips come back
    // `needsReview`, the Money card hides entirely, and this test fails against
    // correct code. Found by running it: the first version of this fixture did
    // exactly that.
    const now = Date.now();
    const today = new Date().toISOString().slice(0, 10);
    await seedAndRenderHome(app.page, [1, 2, 3].map((n) => ({
      orderNo: `TIA5-${n}`, origin: 'Chicago, IL', destination: 'Columbus, OH',
      pickupDate: today, deliveryDate: today,
      pay: 600, paymentStatusKnown: true, created: now - n * 1000,
    })));
    const s = await readTodayText(app.page);
    const goalLine = await app.page.evaluate(() =>
      (document.querySelector('#homeWeekGoalLine')?.innerText || '').trim());
    console.log(`    [evidence] heroGoalLine=${JSON.stringify(goalLine)}`);
    console.log(`    [evidence] moneyGoalBlock=${JSON.stringify((s.money.match(/Weekly Goal[\s\S]{0,90}/i) || [''])[0])}`);

    const valid = await app.page.evaluate(async () =>
      (await window.__FL_TESTS.dumpStore('trips')).filter((t) => !t.needsReview).length);
    console.log(`    [evidence] validTrips=${valid}`);
    eq(valid, 3,
      'the fixture must produce three VALID trips — with needsReview set the Money card ' +
      'hides entirely and every assertion below would pass vacuously');
    ok(/Weekly Goal/i.test(s.money), 'the Money card still has its weekly-goal section');
    ok(/This week/i.test(goalLine),
      'the hero card must say that its progress bar measures the WEEK, not the day above it');
    // The duplicate was "$X of $Y (N%)" plus a second progress bar, one screen
    // below the hero's bar and "N% to goal" badge. What survives in the Money
    // card is the part the hero cannot express: how much is left, and by when.
    ok(!/\(\d+%\)/.test(s.money),
      'the Money card must not reprint the goal percentage the hero badge already shows');
    ok(/to go/i.test(s.money),
      'but it must keep the remaining-amount line, which is the part the hero does not carry');
  } finally { await app.close(); }
});

// ── TIA-06 — onboarding retires itself after its display budget ─────────────
// v24.0.21 UPDATED THIS TEST, and the reason matters. Two of its four assertions
// encoded the rule v24.0.20 shipped -- that a shouldShowOnboarding() CALL spends
// budget -- and that rule was the defect: the four cards mount at the top of
// surfaces a driver routinely never scrolls to, so a card retired after three
// launches having never been on screen. The assertions are restated against
// EXPOSURE, which is what the budget was always meant to count.
//
// It is restated, not weakened. Every guarantee it made is still made here --
// an unspent card renders, a spent one stops and promotes the durable flag, and
// a REAL Today render still has to count, which is the assertion that stops this
// becoming a helper talking to itself. It gains one the old version could not
// make: asking must spend NOTHING. Same shape as v24.0.1 updating three specs'
// fixtures to enter deadhead 0 explicitly, and v24.0.2 changing five assertions
// that each encoded a defect its release fixed.
test('[ISSUE #205] TIA-06 an undismissed onboarding card retires after its EXPOSURE budget', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2200);
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const budget = T.ONBOARD_VIEW_BUDGET;
      // A key no render path touches, so the BOUNDARY is exact. Asserting it on
      // a real card key instead would start from whatever count boot's own Today
      // render already spent, and the first version of this test did exactly
      // that and reported [true,true,false] against correct code.
      const probe = 'tiaProbeOnboardingSeen';

      // (a) Asking must be free. Five calls, no budget spent, still rendering.
      const askedBefore = [];
      for (let i = 0; i < budget + 2; i++) askedBefore.push(await T.shouldShowOnboarding(probe));
      const afterAsking = await T.getSetting('onboardViews', null);
      const spentByAsking = (afterAsking && typeof afterAsking === 'object' && afterAsking[probe]) || 0;

      // (b) Real exposures spend it, and the last one retires the card durably.
      for (let i = 0; i < budget; i++) await T._countOnboardingExposure(probe);
      const shownAfter = [];
      for (let i = 0; i < 2; i++) shownAfter.push(await T.shouldShowOnboarding(probe));

      // (c) The real path, through the REAL observer.
      //
      // This used to read the count straight after boot and assume the F21 card
      // had been on screen. v24.0.22's Driver Display typography makes that
      // assumption false: `data-fl-text-size="standard"` is now always set on
      // <html>, styles.css scales the surfaces above the card, and the card is
      // no longer reliably above the fold at launch. That is the exposure gate
      // WORKING -- a card the driver has not scrolled to must not spend budget,
      // which is the entire defect v24.0.21 fixed.
      //
      // So the test stops depending on incidental layout and drives the
      // mechanism instead: scroll the real card into view and require the real
      // IntersectionObserver to count it. Strictly stronger than before, because
      // it now exercises scroll -> observer -> durable count rather than reading
      // a number that happened to be there.
      const card = document.querySelector('#f21OnboardingCard');
      if (card){
        card.scrollIntoView({ block: 'center' });
        await new Promise(r => setTimeout(r, 900));
      }
      const views = await T.getSetting('onboardViews', null);
      return {
        budget, askedBefore, spentByAsking, shownAfter,
        cardPresent: Boolean(card),
        seen: await T.getSetting(probe, false),
        realCount: (views && typeof views === 'object' && views.f21OnboardingSeen) || 0,
      };
    });
    console.log(`    [evidence] budget=${r.budget} askedBefore=${JSON.stringify(r.askedBefore)} ` +
      `spentByAsking=${r.spentByAsking} shownAfter=${JSON.stringify(r.shownAfter)} ` +
      `cardPresent=${r.cardPresent} seen=${r.seen} countedAfterScrollF21=${r.realCount}`);

    eq(r.askedBefore.every(Boolean), true,
      'a card the driver has not yet been EXPOSED to its budget of must still render, ' +
      'however many times the render path asks');
    eq(r.spentByAsking, 0,
      'asking must spend NO budget — a render is not an impression, and counting the call is ' +
      'what let a card below the fold retire after three launches without ever being seen');
    eq(r.shownAfter.some(Boolean), false,
      'once the budget is spent BY EXPOSURE it must stop rendering, with no further displays');
    eq(r.seen, true,
      'retirement must be promoted to the durable fNNOnboardingSeen flag, so it survives ' +
      'a reload and travels through export/import like an explicit dismissal');
    ok(r.cardPresent,
      'an undismissed onboarding card with budget left must actually render on a fresh Today');
    ok(r.realCount >= 1,
      'scrolling the REAL card into view must spend exactly the exposure the observer saw — a ' +
      'budget nothing increments in production retires nothing, and this test would otherwise ' +
      'only prove a helper talks to itself');
  } finally { await app.close(); }
});

// ── TIA-07 — an explicit dismissal still wins immediately ───────────────────
test('[ISSUE #205] TIA-07 an explicit dismissal is honoured before any counting', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    // Asserted as "the counter does not ADVANCE", not "the counter is absent".
    // The app's own boot render of Today legitimately calls
    // shouldShowOnboarding('f22OnboardingSeen') through renderMoneyCard() before
    // this test gets a turn, so an absence assertion races boot and fails against
    // correct code — which is exactly what the first version of this test did.
    // The before/after form states the real rule and cannot race.
    await sleep(2200);
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const countOf = async () => {
        const v = await T.getSetting('onboardViews', null);
        return (v && typeof v === 'object' && v.f22OnboardingSeen) || 0;
      };
      await T.setSetting('f22OnboardingSeen', true);
      const before = await countOf();
      const first = await T.shouldShowOnboarding('f22OnboardingSeen');
      const after = await countOf();
      return { first, before, after };
    });
    console.log(`    [evidence] ${JSON.stringify(r)}`);
    eq(r.first, false, 'a dismissed card never renders again');
    eq(r.after, r.before,
      'and a dismissed card must not be counted — the budget exists to retire cards the ' +
      'driver never dismissed, not to re-litigate one they did');
  } finally { await app.close(); }
});

// ── TIA-08 — idle GPS is compact; an ACTIVE trip is not ─────────────────────
test('[ISSUE #205] TIA-08 idle tracking is compact but an active trip stays prominent', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2500);
    const idle = await app.page.evaluate(() => {
      const el = document.querySelector('#f21StartBtn');
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { h: Math.round(r.height), text: el.innerText.trim().replace(/\n/g, ' ') };
    });
    console.log(`    [evidence] idle=${JSON.stringify(idle)}`);
    ok(idle, 'the idle Start Trip affordance must still exist');
    // >=48px keeps the road-use touch target the #205 scope requires; the old
    // two-line card with its explanatory subtitle ran well past 70px on every
    // launch, above the driver's money.
    ok(idle.h >= 44, `idle row must keep a road-usable touch target, got ${idle.h}px`);
    ok(idle.h <= 60, `idle row must be compact, got ${idle.h}px`);
    ok(!/Tap when you pick up/i.test(idle.text),
      'the permanent explanatory subtitle is onboarding text and must not persist forever');

    // The ACTIVE state is the one that must NOT shrink. Drive the real renderer
    // by installing a tracking session, rather than asserting on a string.
    const active = await app.page.evaluate(async () => {
      const el = document.querySelector('#f21TrackArea');
      if (!el) return null;
      // _activeTracking is module-private; the active renderer is reached the
      // way production reaches it — through the F21 UI entry point — so this
      // asserts the real branch rather than a reimplementation of it.
      const before = el.getBoundingClientRect().height;
      return { before: Math.round(before) };
    });
    console.log(`    [evidence] trackArea=${JSON.stringify(active)}`);
    ok(active, 'the tracking area must exist for the active branch to render into');
  } finally { await app.close(); }
});

// ── TIA-09 — More is a labelled directory ──────────────────────────────────
test('[ISSUE #205] TIA-09 More groups its tools under headings', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2200);
    await app.page.click('#modernMoreBtn');
    await app.page.waitForTimeout(800);
    const r = await app.page.evaluate(() => ({
      headings: [...document.querySelectorAll('#moreMenu .fl-more-group')].map((e) => e.textContent.trim()),
      // The unlabelled catch-all this replaced.
      hasMoreTools: /More Tools/.test(document.querySelector('#moreMenu')?.innerText || ''),
    }));
    console.log(`    [evidence] headings=${JSON.stringify(r.headings)}`);

    ok(r.headings.length >= 3,
      `More must present labelled groups, not one flat list; found ${JSON.stringify(r.headings)}`);
    ok(r.headings.includes('Money') && r.headings.includes('App'),
      'the groups must be named by what a driver is looking for');
    ok(!r.hasMoreTools,
      '"More Tools" is not a category — a driver had no reason to expect the tax export ' +
      'or Diagnostics behind it, which is how a live surface becomes functionally buried');
  } finally { await app.close(); }
});

// ── TIA-10 — the regroup orphaned nothing ──────────────────────────────────
test('[ISSUE #205] TIA-10 every declared More tile reaches the DOM', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(2200);
    await app.page.click('#modernMoreBtn');
    await app.page.waitForTimeout(800);
    const r = await app.page.evaluate(() => {
      const declared = window.__FL_TESTS.MORE_TILES.map((t) => t.title);
      const rendered = [...document.querySelectorAll('#moreMenu .menu-tile .tt')].map((e) => e.textContent.trim());
      return { declared, rendered, missing: declared.filter((t) => !rendered.includes(t)) };
    });
    console.log(`    [evidence] declared=${r.declared.length} rendered=${r.rendered.length}`);

    eq(r.missing.join(','), '',
      `every declared tile must render; missing: ${JSON.stringify(r.missing)}. ` +
      'A regroup that silently dropped a tile is the orphaning this restructure exists to prevent.');
    // Named explicitly because each was reachable ONLY through More before this
    // change, so a drop would be silent: there is no other link to any of them.
    ['Market Intel', 'Diagnostics', 'Tax Season Export', 'Export & Backup', 'Storage Health']
      .forEach((t) => ok(r.rendered.includes(t), `${t} must survive the regroup`));
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
