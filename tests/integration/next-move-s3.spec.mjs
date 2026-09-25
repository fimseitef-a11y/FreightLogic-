// Next Move S3 (v24.0.38) — TAKE linkage. docs/NEXT_MOVE_LAYER_SPEC.md §6 S3.
//
// The evaluator result carries the Next Move line for the load just scored,
// read from the canonical decision. A complete ACCEPT/STRATEGIC renders TAKE; any
// other verdict says the load is not a take and shows the move from the
// driver's position (the same deriveNextMove() the Today card uses). The line
// sits OUTSIDE the collapsed Show Details, because a directive a driver has to
// dig for is the #252/#205 complaint restated.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/next-move-s3.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

// Score one load through the real evaluator form and wait for the Next Move
// slot to settle (the non-TAKE path resolves position asynchronously).
const score = (load) => evalIn(async (l) => {
  const T = window.__FL_TESTS;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  location.hash = '#omega';
  set('mwOrigin', l.origin); set('mwDest', l.dest);
  set('mwLoadedMi', l.loaded); set('mwDeadMi', l.dead); set('mwRevenue', l.revenue);
  await T.mwEvaluateLoad();
  const deadline = Date.now() + 8000;
  let slot;
  while (Date.now() < deadline) {
    slot = document.getElementById('mwNextMove');
    if (slot && !/Checking your next move/.test(slot.textContent)) break;
    await new Promise(r => setTimeout(r, 100));
  }
  const out = document.getElementById('mwEvalOutput');
  const text = (out?.textContent || '').replace(/\s+/g, ' ');
  const block = slot && slot.querySelector('.nm-block');
  return {
    exists: !!slot,
    count: out ? out.querySelectorAll('#mwNextMove').length : 0,
    insideDetails: !!(slot && slot.closest('details')),
    move: block ? block.dataset.move : null,
    slotText: (slot?.textContent || '').replace(/\s+/g, ' ').trim(),
    verdict: (text.match(/\b(ACCEPT|REJECT|STRATEGIC|DZ-EXIT|UNAVAILABLE)\b/) || [])[1] || null,
  };
}, load);

const GOOD = { origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '20', revenue: '400' };
const BAD = { origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '20', revenue: '150' };

test('[NM3-01] a canonical ACCEPT/STRATEGIC load renders TAKE, visible outside Show Details', async () => {
  const r = await score(GOOD);
  console.log(`    [evidence] verdict=${r.verdict} move=${r.move} slot=${JSON.stringify(r.slotText.slice(0, 120))}`);
  ok(['ACCEPT', 'STRATEGIC'].includes(r.verdict), `fixture must be a take-able load — got ${r.verdict}`);
  ok(r.exists, 'the evaluator result must carry a Next Move line');
  eq(r.move, 'TAKE', 'a complete ACCEPT/STRATEGIC decision is TAKE');
  ok(!r.insideDetails, 'the line must not be buried inside the collapsed Show Details');
  ok(r.slotText.includes(r.verdict), 'the TAKE reason names the canonical verdict it read');
});

test('[NM3-02] a REJECT load never renders TAKE and says why', async () => {
  const r = await score(BAD);
  console.log(`    [evidence] verdict=${r.verdict} move=${r.move} slot=${JSON.stringify(r.slotText.slice(0, 160))}`);
  eq(r.verdict, 'REJECT', 'fixture must be a REJECT');
  ok(r.move && r.move !== 'TAKE', `a REJECT must never be TAKE — got ${r.move}`);
  ok(/Not a take: the canonical decision is REJECT/.test(r.slotText), 'the line names the canonical verdict');
  ok(['WAIT', 'REPOSITION', 'UNKNOWN'].includes(r.move), 'and falls back to a position move');
});

test('[NM3-03] re-scoring leaves exactly one line, owned by the latest evaluation', async () => {
  // Start a REJECT (async position path) and immediately score a take-able
  // load. The REJECT's late resolution must not overwrite the TAKE.
  const r = await evalIn(async ([bad, good]) => {
    const T = window.__FL_TESTS;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    const fill = (l) => { set('mwOrigin', l.origin); set('mwDest', l.dest); set('mwLoadedMi', l.loaded); set('mwDeadMi', l.dead); set('mwRevenue', l.revenue); };
    location.hash = '#omega';
    fill(bad); const first = T.mwEvaluateLoad();
    await first;
    fill(good); await T.mwEvaluateLoad();
    await new Promise(res => setTimeout(res, 1500));
    const out = document.getElementById('mwEvalOutput');
    const slots = out.querySelectorAll('#mwNextMove');
    const block = slots[0] && slots[0].querySelector('.nm-block');
    return { count: slots.length, move: block ? block.dataset.move : null };
  }, [BAD, GOOD]);
  eq(r.count, 1, 'exactly one Next Move line per result');
  eq(r.move, 'TAKE', 'the latest evaluation owns the line');
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
