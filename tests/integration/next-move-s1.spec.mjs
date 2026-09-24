// Next Move S1 (v24.0.36) — evidence integrity of the positioning brief.
//
// docs/NEXT_MOVE_LAYER_SPEC.md §6 S1. The Today "Next Move" card is built from
// getPositioningBrief(), and Next Move will read the same evidence, so three
// existing defects in it are fixed first:
//
//   1. Lane RPM and day patterns summed Number(t.emptyMiles || 0): a trip whose
//      deadhead was never stated reported a loaded-only rate as a lane average,
//      and needsReview trips were not excluded.
//   2. Day-of-week parsed a bare YYYY-MM-DD as UTC midnight, the previous local
//      day in every US timezone, so "best day" was off by one. This spec runs in
//      America/Chicago because CI runs in UTC, where the defect is invisible.
//   3. Reload averages read hoursToReload || 0, so a missing value counted as an
//      instant reload ("Hot market").
//
// Every assertion drives the real brief against real IndexedDB records.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/next-move-s1.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

async function seedTrips(trips) {
  return evalIn(async (list) => {
    const T = window.__FL_TESTS;
    for (const t of list) await T.upsertTrip(T.sanitizeTrip(t));
    T._clearPositioningCache();
  }, trips);
}

const base = { customer: 'NM-S1', isPaid: true, paymentStatusKnown: true };

test('[NM1-01] an unstated deadhead never enters a lane average or its count', async () => {
  await seedTrips([
    // Known: $1000 / 500 true miles = $2.00
    { ...base, orderNo: 'NM1-A', origin: 'Dayton, OH', destination: 'Toledo, OH', pay: 1000, loadedMiles: 500, emptyMiles: 0,
      pickupDate: '2026-09-01', deliveryDate: '2026-09-02' },
    // Unknown deadhead: loaded-only would read $2.50 and drag the lane to $2.22
    { ...base, orderNo: 'NM1-B', origin: 'Dayton, OH', destination: 'Toledo, OH', pay: 1000, loadedMiles: 400, emptyMiles: null,
      pickupDate: '2026-09-03', deliveryDate: '2026-09-04' },
  ]);
  const lane = await evalIn(async () => {
    const b = await window.__FL_TESTS.getPositioningBrief('Dayton, OH');
    const l = b.outboundLanes.find(x => /toledo/i.test(x.destDisplay));
    return l ? { avgRPM: l.avgRPM, count: l.count, maxRpm: l.maxRpm } : null;
  });
  ok(lane, 'the evidenced lane must still be listed');
  eq(lane.count, 1, 'only the trip with a known deadhead is lane evidence');
  eq(lane.avgRPM, 2, 'the lane average is the true-mile rate of evidenced trips only');
  eq(lane.maxRpm, 2, 'a loaded-only rate must not appear as the lane maximum');
});

test('[NM1-02] a lane backed only by unknown-deadhead trips is not presented as an option', async () => {
  await seedTrips([
    { ...base, orderNo: 'NM1-C', origin: 'Lima, OH', destination: 'Findlay, OH', pay: 900, loadedMiles: 300, emptyMiles: null,
      pickupDate: '2026-09-05', deliveryDate: '2026-09-06' },
  ]);
  const lanes = await evalIn(async () => (await window.__FL_TESTS.getPositioningBrief('Lima, OH')).outboundLanes.length);
  eq(lanes, 0, 'no evidenced trips means no lane');
});

test('[NM1-03] day-of-week reads the local calendar day, not the UTC day', async () => {
  const days = await evalIn(() => {
    const f = window.__FL_TESTS._localDayOfWeek;
    return { thu: f('2026-09-24'), mon: f('2026-09-21'), junk: f('not a date'), empty: f('') };
  });
  eq(days.thu, 4, '2026-09-24 is a Thursday in America/Chicago');
  eq(days.mon, 1, '2026-09-21 is a Monday');
  eq(days.junk, null, 'an unparseable date is unknown, not a weekday');
  eq(days.empty, null, 'a blank date is unknown');
});

test('[NM1-04] the brief names the right best day end to end', async () => {
  await seedTrips([
    // Thursdays: $2.00 true RPM
    { ...base, orderNo: 'NM1-T1', origin: 'Akron, OH', destination: 'Columbus, OH', pay: 400, loadedMiles: 200, emptyMiles: 0, pickupDate: '2026-09-17', deliveryDate: '2026-09-17' },
    { ...base, orderNo: 'NM1-T2', origin: 'Akron, OH', destination: 'Columbus, OH', pay: 400, loadedMiles: 200, emptyMiles: 0, pickupDate: '2026-09-24', deliveryDate: '2026-09-24' },
    // Mondays: $1.00 true RPM
    { ...base, orderNo: 'NM1-M1', origin: 'Akron, OH', destination: 'Columbus, OH', pay: 200, loadedMiles: 200, emptyMiles: 0, pickupDate: '2026-09-14', deliveryDate: '2026-09-14' },
    { ...base, orderNo: 'NM1-M2', origin: 'Akron, OH', destination: 'Columbus, OH', pay: 200, loadedMiles: 200, emptyMiles: 0, pickupDate: '2026-09-21', deliveryDate: '2026-09-21' },
  ]);
  const best = await evalIn(async () => (await window.__FL_TESTS.getPositioningBrief('Akron, OH')).patterns.bestDay);
  ok(best, 'a best day must be reported with four evidenced trips');
  eq(best.name, 'Thu', 'the $2.00 loads picked up on Thursdays, so Thursday is best (a UTC parse reports Wednesday)');
});

test('[NM1-05] a reload outcome with no recorded hours is not an instant reload', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const mk = (id, h) => ({ id, city: 'springfield', date: '2026-09-01', dayOfWeek: 2, hoursToReload: h, updatedAt: Date.now() });
    // Legacy-shaped rows: two missing values and two real 40h reloads.
    await T.mergeRestoreData({ reloadOutcomes: [mk('nm1-r1', null), mk('nm1-r2', undefined), mk('nm1-r3', 40), mk('nm1-r4', 40)] });
    const score = await T.getCityReloadScore('Springfield');
    // Writing a missing value is refused rather than stored as 0.
    await T.recordReloadOutcome({ destination: 'Nowhere Junction' }, '');
    const nowhere = (await T.dumpStore('reloadOutcomes')).filter(x => x.city === 'nowhere junction').length;
    return { avg: score && score.avg, count: score && score.count, grade: score && score.grade, nowhere };
  });
  eq(r.count, 2, 'only the two recorded reloads count');
  eq(r.avg, 40, 'missing values must not pull the average toward zero');
  eq(r.grade, 'C', '40h is a slow reload, not a hot market');
  eq(r.nowhere, 0, 'recordReloadOutcome must not store a blank as 0 hours');
});

test('[NM1-06] a real zero-hour reload is still a verified value', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.recordReloadOutcome({ destination: 'Zero Town' }, 0);
    await T.recordReloadOutcome({ destination: 'Zero Town' }, 0);
    return T.getCityReloadScore('Zero Town');
  });
  ok(r, 'two explicit zero-hour reloads are evidence');
  eq(r.avg, 0, 'an explicit 0 is a verified instant reload');
  eq(r.grade, 'A', 'and grades as a hot market');
});

export async function runSpec() {
  app = await launchApp({ timezoneId: 'America/Chicago' });
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
