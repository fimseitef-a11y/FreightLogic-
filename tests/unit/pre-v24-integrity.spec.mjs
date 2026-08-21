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

test('[PRE24-02] July static rate bands have an enforceable freshness guard', () => {
  const auth = source('midwest-stack-authority.js');
  ok(auth.includes('RATE_OVERRIDE_FRESHNESS'), 'freshness thresholds missing');
  ok(auth.includes("rateFreshness.status === 'STALE'"), 'STALE path missing');
  ok(auth.includes('staleProtectiveGuard'), 'stale bands must fall back to protective pricing');
  ok(auth.includes("!staleProtectiveGuard && (destRole.role === 'tier1' || destRole.role === 'tier2')"), 'ESCAPE_RECOVERY must not reopen a stale-band floor exception');
  ok(auth.includes("mode.id !== 'DEAD_ZONE'"), 'explicit DZ gate must remain a separate survival exception');
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
