// FINDING V-1 (FIXED in v24.0.15) — `ensureVehicleProfiles()` was not safe to
// call concurrently.
//
// HOW IT SURFACED. `main` @ 8f90725 failed CI on Tests run 35084126731 attempt 1
// with four assertions in `tax-export-csv-corruption.spec.mjs`, the first being
// its setup:
//
//     await saveActiveVehicleProfile({ vehicleTaxMethod: STANDARD_MILEAGE, ... });
//     return (await getActiveVehicleProfile()).vehicleTaxMethod;   // !== STANDARD_MILEAGE
//
// The other three are that one setup cascading: X-03 blocks the F30 Schedule C
// export entirely while `vehicleTaxMethod` is UNSET. Attempt 2 on the same SHA
// passed, and that is the green check standing for `8f90725` today.
//
// THE DEFECT. `ensureVehicleProfiles()` (app.js) seeds lazily and is a
// read-modify-write with no serialization:
//
//     let profiles = await getSetting('vehicleProfiles', null);   // (1) absent
//     if (!Array.isArray(profiles) || !profiles.length){
//       ... await Promise.all([getSetting('vehicleYear'), getSetting('vehicleMake')])
//       profiles = [_newVehicleProfile(label)];                   // (2) mint
//       await setSetting('vehicleProfiles', profiles);            // (3) write
//       await setSetting('activeVehicleId', profiles[0].id);
//     }
//
// Two callers can both be parked on (1) before either reaches (3), so both mint
// a profile with its own fresh id and each overwrites the whole array. One of
// the two profiles is silently discarded, and which one survives is decided by
// whichever `setSetting` lands last. `setSetting` populates SETTINGS_CACHE
// synchronously before awaiting its transaction, which narrows the window but
// does not close it — the window is the IndexedDB round trip inside (1).
//
// This is reachable in production, not only under a test harness.
// `refreshVehicleTaxMethodRow()` reads through this function on any render that
// populates Settings, `openVehicleTaxMethodModal()` reads through it, and
// `openTaxSeasonExport()` reads through it. On a fresh install any two of those
// overlapping means a vehicle profile — and the tax-method election attached to
// it — can be dropped.
//
// THE REPAIR (v24.0.15). One module-scope in-flight promise, so concurrent
// callers await the SAME seeding operation instead of each performing their own.
// It is cleared on settle — later calls re-read normally — and it deliberately
// serializes the seed rather than the function's whole lifetime.
//
// Proven by the same reproduction that found it: two concurrent callers minted
// two distinct profiles in 30/30 iterations before, and 0/30 after.
//
// WHAT WAS NEVER CLAIMED, and still is not. The exact CI interleave — the one
// where the LOSING write is the operator's, so the election reads back UNSET —
// was never reproduced. In all 30 pre-fix iterations the surviving write
// happened to be the operator's, and a reader head start of 0-4 event-loop ticks
// did not flip it. The lost update was proven and is now fixed; that this is
// what Tests run 35084126731 hit remains INFERRED from the mechanism and the
// exact failure signature. Same discipline `FIELD_TEST_CHECKLIST.md` B7 applies
// to run 35049015938: a mechanism that fits is not a cause that was observed.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/vehicle-profile-race.spec.mjs');

// Each page.evaluate below resets the two vehicle-profile settings to "absent"
// as `ensureVehicleProfiles()` judges it (`!Array.isArray`), writing through
// `setSetting` so SETTINGS_CACHE agrees with IndexedDB. That isolates the
// CONCURRENCY rather than a cold cache — the defect does not need a cold cache,
// only two callers inside the same seeding branch. It is written inline rather
// than injected as a string because the app's own CSP forbids `unsafe-eval`,
// which is exactly the protection it should be providing.

test('[FINDING V-1 / FIXED] two concurrent ensureVehicleProfiles() resolve one profile, not two', async () => {
  const app = await launchApp();
  try {
    const runs = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const results = [];
      for (let i = 0; i < 8; i++) {
        await T.setSetting('vehicleProfiles', null);
        await T.setSetting('activeVehicleId', null);
        // Exactly the production shape: a Settings-side reader and a
        // tax-method writer, both entering the lazy seed at the same time.
        const [readerProfile, saved] = await Promise.all([
          T.getActiveVehicleProfile(),
          T.saveActiveVehicleProfile({
            vehicleTaxMethod: T.VEHICLE_TAX_METHOD.STANDARD_MILEAGE,
            firstYearElection: T.FIRST_YEAR_ELECTION.STANDARD_MILEAGE,
          }),
        ]);
        const stored = await T.getSetting('vehicleProfiles', []);
        results.push({
          distinctIds: readerProfile.id !== saved.profile.id,
          stored: Array.isArray(stored) ? stored.length : -1,
        });
      }
      return results;
    });

    const minted2 = runs.filter(r => r.distinctIds).length;
    const kept1 = runs.filter(r => r.stored === 1).length;

    console.log(`    [evidence] two distinct profiles minted in ${minted2}/${runs.length} iterations ` +
                `(was ${runs.length}/${runs.length} before the fix); ` +
                `stored array held exactly one profile in ${kept1}/${runs.length}`);

    // The invariant: one lazy seed, one profile, however many callers race for it.
    eq(minted2, 0,
      'concurrent callers must resolve the SAME profile — a second minted id is the ' +
      'lost update, because only one of the two arrays survives the write');
    eq(kept1, runs.length,
      'and exactly one profile is stored, so nothing was created that then vanished');
  } finally { await app.close(); }
});

test('[FINDING V-1 / FIXED] a single, uncontended seed is still correct — the fix did not change the seed', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('vehicleProfiles', null);
      await T.setSetting('activeVehicleId', null);
      // Serialized: exactly what the repair must make the concurrent case
      // equivalent to. This is the control — without it, a failure above could
      // be read as "vehicle profiles are broken" rather than "they race".
      const saved = await T.saveActiveVehicleProfile({
        vehicleTaxMethod: T.VEHICLE_TAX_METHOD.STANDARD_MILEAGE,
        firstYearElection: T.FIRST_YEAR_ELECTION.STANDARD_MILEAGE,
      });
      const after = await T.getActiveVehicleProfile();
      const stored = await T.getSetting('vehicleProfiles', []);
      return { same: after.id === saved.profile.id, method: after.vehicleTaxMethod, n: stored.length };
    });

    ok(r.same, 'an uncontended save and read must resolve the same profile');
    eq(r.method, 'STANDARD_MILEAGE', 'an uncontended election must survive');
    eq(r.n, 1, 'an uncontended seed creates exactly one profile');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
