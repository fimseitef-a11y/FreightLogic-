// Issue #278 — DEACTIVATED/WITHDRAWN is its own opportunity outcome class.
//
// Evidence basis: the operator's 2026-09-19 DispatchLand auction history
// (quote #1173654, Villa Rica GA -> Baltimore MD, bid $1,000, platform outcome
// DEACTIVATED), recorded on the issue. Both independent audits converge on this
// item with no disagreement — ChatGPT's 2026-09-20 evidence pass calls it "a
// data-semantics requirement, not a public-market inference", and the Claude
// independent audit of 2026-09-22 agrees and supplies the exact addresses where
// getting it wrong would do damage. The disputed long-haul item is NOT touched
// here.
//
// The defect a naive implementation produces is specific and quiet: mapping a
// deactivation onto LOST for convenience puts it in the WIN-RATE DENOMINATOR
// and trains the clearing-price model with a loss that never happened. A
// deactivated bid is CENSORED evidence — nobody outbid the operator, the
// platform withdrew the auction — so it is neither a win, nor a loss, nor a
// clearing-price observation.
//
// Every assertion drives the real exported function on the real record shape,
// not a helper standing in for it.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/deactivated-outcome.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

/* ═══════════ the vocabulary ═══════════ */

test('[DEACT-01] DEACTIVATED is a distinct member of the opportunity vocabulary', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return {
      members: [...T.LIFECYCLE_OPPORTUNITY],
      // CANCELLED already exists and means the LOAD was cancelled. A broker
      // deactivating the OPERATOR'S BID is a different event with a different
      // subject, so folding one into the other loses the distinction that makes
      // the separate dimensions worth having at all.
      cancelledStillPresent: T.LIFECYCLE_OPPORTUNITY.includes('CANCELLED'),
    };
  });
  ok(r.members.includes('DEACTIVATED'), `DEACTIVATED must be a member — got ${JSON.stringify(r.members)}`);
  ok(r.cancelledStillPresent, 'CANCELLED must survive: a cancelled load is not a deactivated bid');
});

test('[DEACT-02] sanitizeLifecycle preserves DEACTIVATED instead of silently downgrading it to SEEN', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return {
      kept: T.sanitizeLifecycle({ opportunity: 'DEACTIVATED' }).opportunity,
      // The fallback must still fail closed for a value that is genuinely not
      // in the vocabulary — widening the enum must not weaken the guard.
      garbage: T.sanitizeLifecycle({ opportunity: 'NOT_A_REAL_STATE' }).opportunity,
    };
  });
  eq(r.kept, 'DEACTIVATED', 'a deactivated opportunity must survive sanitization');
  eq(r.garbage, 'SEEN', 'an unrecognized opportunity must still fall back to SEEN');
});

test('[DEACT-03] the driver-visible stage label names the deactivation rather than reading as never-seen', async () => {
  const label = await evalIn(() => window.__FL_TESTS.lifecycleDisplayStage({
    opportunity: 'DEACTIVATED', execution: 'NOT_STARTED', settlement: 'NOT_INVOICED',
  }));
  eq(label, 'DEACTIVATED', 'a deactivated bid must not render as SEEN');
});

/* ═══════════ the denominators — the part that would do the damage ═══════════ */

test('[DEACT-04] a deactivation does not move the lifecycle win-rate denominator', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const base = [
      { opportunity: 'WON' }, { opportunity: 'WON' }, { opportunity: 'LOST' },
    ];
    const withDeact = [...base, { opportunity: 'DEACTIVATED' }, { opportunity: 'DEACTIVATED' }];
    const a = T.lifecycleWinRate(base);
    const b = T.lifecycleWinRate(withDeact);
    return {
      denomBefore: a.denominator, denomAfter: b.denominator,
      rateBefore: a.rate, rateAfter: b.rate,
      lostBefore: a.lost, lostAfter: b.lost,
      excludedDeactivated: b.excludedDeactivated,
      excludedCancelled: b.excludedCancelled,
    };
  });
  eq(r.denomAfter, r.denomBefore, 'two deactivations must not enter the win-rate denominator');
  eq(r.rateAfter, r.rateBefore, 'the reported win rate must be unchanged by a deactivation');
  eq(r.lostAfter, r.lostBefore, 'a deactivation is not a loss');
  // Reporting the exclusion is what makes it auditable rather than merely absent.
  eq(r.excludedDeactivated, 2, 'the exclusion must be counted and reported, like EXPIRED and CANCELLED are');
  eq(r.excludedCancelled, 0, 'a deactivation must not be counted as a cancellation');
});

test('[DEACT-05] a deactivation is not a clearing-price observation', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const rows = [
      { lifecycleId: 'lc_w', opportunity: 'WON' },
      { lifecycleId: 'lc_d', opportunity: 'DEACTIVATED' },
    ];
    const lookup = (id) => ({ rpm: id === 'lc_w' ? 1.60 : 1.25, observedAt: Date.now() });
    const out = T.calibrateFromLifecycle(rows, lookup);
    return { winDenominator: out.winDenominator, wonCount: out.wonCount, lostCount: out.lostCount };
  });
  // The deactivated row carries a real RPM and a real timestamp, so it is only
  // excluded if the OUTCOME CLASS excludes it — not because the data was thin.
  eq(r.winDenominator, 1, `only the WON row may become a calibration observation — got ${JSON.stringify(r)}`);
  eq(r.wonCount, 1, 'the genuine win must still count');
  eq(r.lostCount, 0, 'a deactivation must never be counted as a loss');
});

/* ═══════════ the bidHistory half ═══════════ */

test('[DEACT-06] logBid records a deactivation as itself rather than coercing it to expired', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const rec = await T.logBid({
      loadId: '', broker: 'Deact Test Broker', origin: 'Villa Rica, GA', destination: 'Baltimore, MD',
      miles: 800, postedTarget: 1000, bidAmount: 1000, outcome: 'deactivated',
    });
    const junk = await T.logBid({
      loadId: '', broker: 'Deact Test Broker', origin: 'A', destination: 'B',
      miles: 100, postedTarget: 100, bidAmount: 100, outcome: 'nonsense-value',
    });
    return { outcome: rec.outcome, junkOutcome: junk.outcome };
  });
  eq(r.outcome, 'deactivated', 'a deactivated bid outcome must be stored as itself');
  // Widening the accepted set must not turn the validator into a pass-through.
  eq(r.junkOutcome, 'expired', 'an unrecognized outcome must still fail closed to expired');
});

test('[DEACT-07] getBidWinRateStats excludes deactivations from adjudicated, and does not miscount them as expired', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const mk = (outcome) => T.logBid({
      loadId: '', broker: 'Deact Stats Broker', origin: 'X', destination: 'Y',
      miles: 400, postedTarget: 800, bidAmount: 700, outcome,
    });
    await mk('won'); await mk('rejected'); await mk('expired');
    const before = await T.getBidWinRateStats(30);
    await mk('deactivated'); await mk('deactivated');
    const after = await T.getBidWinRateStats(30);
    return {
      adjBefore: before.adjudicatedBids, adjAfter: after.adjudicatedBids,
      rateBefore: before.winRate, rateAfter: after.winRate,
      expiredBefore: before.excludedExpired, expiredAfter: after.excludedExpired,
      deactBefore: before.excludedDeactivated, deactAfter: after.excludedDeactivated,
    };
  });
  eq(r.adjAfter, r.adjBefore, 'deactivations must not enter the adjudicated denominator');
  eq(r.rateAfter, r.rateBefore, 'the bid win rate must be unchanged by a deactivation');
  // excludedExpired was `recent.length - adjudicated.length`, which silently
  // absorbs any future non-adjudicated outcome. A deactivation counted as an
  // expiry is the same conflation this issue exists to remove, one layer down.
  eq(r.expiredAfter, r.expiredBefore, 'a deactivation must not be reported as an expired bid');
  // Stated as a DELTA, not an absolute: bidHistory is shared page state and an
  // earlier test in this spec also logs a deactivation, so an absolute count
  // would be asserting other tests' bookkeeping rather than this rule.
  eq(r.deactAfter - r.deactBefore, 2, 'deactivations must be counted and reported on their own');
});

/* ═══════════ the input path ═══════════ */

test('[DEACT-08] the operator can actually record a deactivation from the evaluator result card', async () => {
  // An outcome class with no way to enter it is the X-11 dead-claim shape: a
  // vocabulary the app documents and nobody can reach. This drives the REAL
  // evaluator so the REAL result card renders, then reads what it offers.
  await app.page.evaluate(() => { location.hash = '#omega'; });
  await app.page.waitForSelector('#mwEvalOutput');
  const rendered = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const set = (id, value) => { const el = document.getElementById(id); if (el) el.value = value; };
    set('mwOrigin', 'Villa Rica, GA');
    set('mwDest', 'Baltimore, MD');
    set('mwLoadedMi', '709');
    set('mwDeadMi', '91');
    set('mwRevenue', '1600');
    await T.mwEvaluateLoad();
    const slot = document.getElementById('mwBidOutcomeSlot');
    return {
      found: !!slot,
      outcomes: slot ? Array.from(slot.querySelectorAll('[data-outcome]')).map(b => b.dataset.outcome) : [],
      text: slot ? (slot.textContent || '').trim() : '',
    };
  });
  ok(rendered.found, 'the bid-outcome control must render with the canonical bid range');
  ok(rendered.outcomes.includes('deactivated'),
    `the result card must offer a Deactivated outcome — got ${JSON.stringify(rendered)}`);
  // The three existing outcomes must survive the addition.
  for (const o of ['won', 'rejected', 'expired']) {
    ok(rendered.outcomes.includes(o), `existing outcome "${o}" must survive — got ${JSON.stringify(rendered.outcomes)}`);
  }
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
