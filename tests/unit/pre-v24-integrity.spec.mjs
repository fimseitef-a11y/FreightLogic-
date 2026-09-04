// v23.9.1 pre-v24 integrity gate — static source contracts.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const source = p => readFileSync(path.join(ROOT, p), 'utf8');
const { test, run } = createSuite('unit/pre-v24-integrity.spec.mjs');

test('[PRE24-01] normal/preferred RPM floors align with the protective doctrine', () => {
  const app = source('app.js');
  ok(/preferredFloorRPM:\s*1\.50/.test(app), 'preferred floor must be $1.50');
  ok(/normalFloorRPM:\s*1\.40/.test(app), 'normal floor must be $1.40');
  ok(!/normalFloorRPM:\s*1\.35/.test(app), 'the stale $1.35 normal-floor authority must be gone');
});

test('[PRE24-02] stale static rate bands cannot influence pricing at all', () => {
  // v24.0.4 item 3 SUPERSEDES the guard this test used to assert.
  //
  // The original property was "a STALE band table must fall back to protective
  // pricing", enforced by a `staleProtectiveGuard` flag inside the overlay's own
  // rate ladder. That guard existed because the overlay computed its own
  // floorRpm/winRpm/askRpm from the band table — and it leaked: the guard
  // deliberately excluded DEAD_ZONE (`overrideStale && mode.id !== 'DEAD_ZONE'`),
  // so with the bands 56 days stale the overlay still emitted TAKE_IF_LIVE at a
  // $1.19 floor, below the $1.25 hard reject, on a load whose DZ gate had failed.
  //
  // The overlay no longer prices anything, so there is no longer a pricing path
  // for a stale band to relax — protection is now structural rather than a flag
  // that has to remember its own exceptions. That is strictly stronger, so this
  // test now asserts the absence directly. Freshness REPORTING is still required:
  // band age is real evidence and must still reach the driver.
  const auth = source('midwest-stack-authority.js');

  // Freshness is still computed and still surfaced as a flag.
  ok(auth.includes('RATE_OVERRIDE_FRESHNESS'), 'freshness thresholds missing');
  ok(auth.includes("rateFreshness.status === 'STALE'"), 'STALE path missing');
  ok(auth.includes("rateFreshness.status === 'AGING'"), 'AGING path missing');
  ok(/flags\.push\(`Rate override STALE/.test(auth), 'a stale band table must still be reported to the driver as evidence');

  // The stronger property: no pricing computation survives in this file, so a
  // stale band has nothing to relax. Comments may still DISCUSS these names.
  const code = auth.split('\n')
    .filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
  for (const sym of ['floorRpm', 'winRpm', 'askRpm', 'floorBid', 'winBid', 'askBid', 'compressedWinRpm', 'staleProtectiveGuard']) {
    ok(!new RegExp(`\\b${sym}\\b`).test(code),
      `"${sym}" must not exist in executable overlay code — the overlay owns no pricing, so a stale band cannot influence one`);
  }
  ok(!/function gradeFor\b/.test(code), 'the overlay must not carry its own grade ladder');
  ok(!/\brecommendation\s*:/.test(code), 'the overlay must not return a recommendation object');

  // The Dead Zone gate remains a real, separate survival path — and it is
  // DELEGATED to the canonical gate in app.js rather than re-implemented here.
  ok(auth.includes("mode.id === 'DEAD_ZONE'"), 'the explicit DZ survival path must remain');
  ok(auth.includes('window.isDeadZoneEligible'), 'DZ eligibility must be delegated to the single canonical gate in app.js');
  ok(auth.includes('dzGate'), 'the gate OUTCOME must still be reported so X-04 parity remains assertable');
});

test('[PRE24-03] live feeds publish health instead of silently collapsing to null', () => {
  const app = source('app.js');
  for (const name of ['EIA','NWS','FMCSA','CBP']) ok(app.includes(`setLiveSourceHealth('${name}'`), `${name} health instrumentation missing`);
  for (const status of ['UNCONFIGURED','AUTH_ERROR','HTTP_ERROR','TIMEOUT','PARSE_ERROR','OFFLINE']) ok(app.includes(status), `live-source status ${status} missing`);
  ok(app.includes("row('Live Feed Health'"), 'Diagnostics must surface live-feed health');
});

test('[PRE24-04] broker backfill only uses explicit broker-labelled evidence', () => {
  const app = source('app.js');
  const m = app.match(/async function auditBrokerHistoryIntegrity\(\)\{[\s\S]*?\n\}\n\n\/\/ v24\.0\.0: Broker intelligence/);
  ok(m, 'broker integrity gate not found');
  ok(m[0].includes('brokerDisplay'), 'explicit brokerDisplay evidence should be supported');
  ok(m[0].includes('matchedTrip?.broker'), 'explicit trip.broker evidence should be supported');
  ok(!m[0].includes('matchedTrip?.customer'), 'trip.customer is ambiguous and must never be used to infer broker identity');
  ok(m[0].includes('legacyUnkeyed'), 'unresolved legacy rows must remain explicitly quarantined');
});

test('[PRE24-05] CI toolchain is reproducible', () => {
  const wf = source('.github/workflows/tests.yml');
  ok(/npm\s+install\s+-g\s+playwright@1\.62\.1(?:\s|$)/.test(wf), 'Playwright install command must be pinned to the validated version');
  ok(!/npm\s+install\s+-g\s+playwright@latest(?:\s|$)/.test(wf), 'CI install command must never float on Playwright latest');
  ok(wf.includes('actions/checkout@v6'), 'checkout should use a Node24-capable action runtime');
  ok(wf.includes('actions/setup-node@v6'), 'setup-node should use a Node24-capable action runtime');
});

export async function runSpec(){ return await run(); }
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
