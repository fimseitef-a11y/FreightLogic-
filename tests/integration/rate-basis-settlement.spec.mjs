// Issue #278 — explicit operating-arrangement / rate-basis semantics.
//
// Both independent audits converge here with HIGH confidence: the ChatGPT
// evidence pass (issue comment 5754460458) and the Claude independent audit
// (5770614303). 49 CFR 376.12 makes the compensation basis a LEASE TERM, not a
// market constant — percentage of gross, flat per-mile, directional, or another
// mutually agreed method — so the app must record which arrangement is in force
// and must never apply a guessed universal "no authority" haircut.
//
// The operator confirmed they currently run WITHOUT their own MC/DOT authority.
// That is a first-class data dimension, not a note, and it is the reason a
// quoted/market amount and the operator's settlement amount cannot be assumed
// to be the same number.
//
// The load-bearing rule, and the one most likely to be "simplified" away later:
// when the arrangement implies a spread but nobody has supplied the actual
// split, the settlement is UNKNOWN. It is NOT the quoted amount scaled by an
// invented percentage, and the quoted amount is NOT silently relabelled as
// settlement. That is the knownNum() doctrine applied to money provenance.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/rate-basis-settlement.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

test('[RB-01] the vocabulary exists and fails closed to UNKNOWN', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return {
      members: Object.keys(T.RATE_BASIS || {}),
      absent: T.deriveRateBasis({}).basis,
      garbage: T.deriveRateBasis({ rateBasis: 'NOT_A_REAL_BASIS' }).basis,
      leased: T.deriveRateBasis({ rateBasis: 'LEASED_SETTLEMENT' }).basis,
    };
  });
  for (const m of ['UNKNOWN', 'LEASED_SETTLEMENT', 'OWN_AUTHORITY_CARRIER_GROSS', 'DIRECT_SHIPPER_GROSS']) {
    ok(r.members.includes(m), `RATE_BASIS must carry ${m} — got ${JSON.stringify(r.members)}`);
  }
  eq(r.absent, 'UNKNOWN', 'an operator who has said nothing is UNKNOWN, never assumed');
  eq(r.garbage, 'UNKNOWN', 'an unrecognized basis must fail closed, not pass through');
  eq(r.leased, 'LEASED_SETTLEMENT', 'a real basis survives');
});

test('[RB-02] the settlement split is validated, and has no default', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const pct = (v) => T.deriveRateBasis({ rateBasis: 'LEASED_SETTLEMENT', settlementPct: v });
    return {
      absent: pct(undefined).settlementPct,
      zero: pct(0).settlementPct,
      negative: pct(-0.5).settlementPct,
      overOne: pct(1.4).settlementPct,
      garbage: pct('seventy percent').settlementPct,
      valid: pct(0.7).settlementPct,
      whole: pct(1).settlementPct,
      invalidReported: pct(1.4).invalid,
    };
  });
  eq(r.absent, null, 'there is NO default split — inventing one is the defect this issue names');
  eq(r.zero, null, 'a zero split is not a fact about a lease');
  eq(r.negative, null, 'a negative split is refused');
  eq(r.overOne, null, 'a split above 100% is refused');
  eq(r.garbage, null, 'a non-numeric split is refused');
  eq(r.valid, 0.7, 'a real split is honoured exactly');
  eq(r.whole, 1, '100% is a legitimate arrangement');
  ok(Array.isArray(r.invalidReported) && r.invalidReported.includes('settlementPct'),
    'a refused split is REPORTED, not silently dropped');
});

test('[RB-03] on a basis where the operator receives the gross, settlement equals quoted exactly', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const run = (rateBasis) => T.deriveSettlement(1000, T.deriveRateBasis({ rateBasis }));
    return { own: run('OWN_AUTHORITY_CARRIER_GROSS'), direct: run('DIRECT_SHIPPER_GROSS') };
  });
  for (const [name, s] of Object.entries(r)) {
    eq(s.settlement, 1000, `${name}: settlement must equal the quoted amount exactly, not be scaled`);
    eq(s.settlementKnown, true, `${name}: this is a known settlement`);
    eq(s.spreadKnown, true, `${name}: there is no spread, and that is known`);
  }
});

test('[RB-04] a leased basis with a KNOWN split applies exactly that split', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return T.deriveSettlement(1000, T.deriveRateBasis({ rateBasis: 'LEASED_SETTLEMENT', settlementPct: 0.7 }));
  });
  eq(r.settlement, 700, 'a supplied 70% split is applied exactly');
  eq(r.quoted, 1000, 'the quoted/market amount stays distinct and intact');
  eq(r.settlementKnown, true, 'a supplied split makes the settlement known');
  eq(r.spreadKnown, true, 'and makes the spread known');
});

test('[RB-05] a leased basis with NO split leaves the settlement UNKNOWN — never a guessed haircut', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const s = T.deriveSettlement(1000, T.deriveRateBasis({ rateBasis: 'LEASED_SETTLEMENT' }));
    const u = T.deriveSettlement(1000, T.deriveRateBasis({}));
    return { s, u };
  });
  eq(r.s.settlement, null, 'an unknown split means an UNKNOWN settlement, not an invented one');
  eq(r.s.settlementKnown, false, 'and it must say so');
  eq(r.s.spreadKnown, false, 'the spread is explicitly not known');
  eq(r.s.quoted, 1000, 'the quoted amount is NOT relabelled or scaled');
  // The whole point: no constant anywhere may turn 1000 into a smaller number.
  ok(r.s.settlement === null, 'settlement must be null rather than any fraction of quoted');
  eq(r.u.settlement, null, 'an UNKNOWN basis is equally unknown');
  eq(r.u.quoted, 1000, 'and equally leaves the quoted amount alone');
});

test('[RB-06] an unknown revenue makes every settlement field unknown', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return T.deriveSettlement(null, T.deriveRateBasis({ rateBasis: 'OWN_AUTHORITY_CARRIER_GROSS' }));
  });
  eq(r.quoted, null, 'no revenue, no quoted amount');
  eq(r.settlement, null, 'and no settlement — not a zero');
  eq(r.settlementKnown, false, 'and it is reported as unknown');
});

test('[RB-07] rate basis is DESCRIPTIVE — it cannot move verdict, grade, True RPM or bid', async () => {
  // Asserts the four things the contract actually names, extracted from the
  // rendered decision, rather than whole-card text equality. The full card also
  // carries live-source evidence rows (weather, market, source freshness) which
  // are network- and time-dependent and legitimately differ between two
  // evaluations on a runner with no outbound access — comparing them would make
  // this spec fail for a reason that has nothing to do with rate basis, which is
  // exactly what it did on its first CI run.
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const decide = async (rateBasis) => {
      await T.setSetting('rateBasis', rateBasis);
      await T.setSetting('settlementPct', null);
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
      location.hash = '#omega';
      set('mwOrigin', 'Chicago, IL'); set('mwDest', 'Indianapolis, IN');
      set('mwLoadedMi', '180'); set('mwDeadMi', '20'); set('mwRevenue', '400');
      await T.mwEvaluateLoad();
      const text = (document.getElementById('mwEvalOutput')?.textContent || '').replace(/\s+/g, ' ');
      const grab = (re) => (text.match(re) || [])[1] ?? null;
      return {
        verdict: grab(/\b(ACCEPT|REJECT|STRATEGIC|DZ-EXIT|UNAVAILABLE)\b/),
        grade: grab(/\b([A-F?])\s+(?:ACCEPT|REJECT|STRATEGIC)\b/),
        trueRPM: grab(/True RPM:?\s*\$?([0-9.]+)/),
        bids: (text.match(/\$[0-9,]+\.[0-9]{2}/g) || []).slice(0, 3).join('|'),
      };
    };
    const unknown = await decide(null);
    const leased = await decide('LEASED_SETTLEMENT');
    const own = await decide('OWN_AUTHORITY_CARRIER_GROSS');
    await T.setSetting('rateBasis', null);
    return { unknown, leased, own };
  });
  ok(r.unknown.verdict, `the evaluator must have produced a verdict — got ${JSON.stringify(r.unknown)}`);
  ok(r.unknown.trueRPM, 'and a True RPM');
  ok(r.unknown.bids, 'and a bid range');
  for (const [name, d] of [['leased', r.leased], ['own authority', r.own]]) {
    eq(d.verdict, r.unknown.verdict, `declaring ${name} must not change the verdict`);
    eq(d.grade, r.unknown.grade, `declaring ${name} must not change the grade`);
    eq(d.trueRPM, r.unknown.trueRPM, `declaring ${name} must not change True RPM`);
    eq(d.bids, r.unknown.bids, `declaring ${name} must not change the canonical bid range`);
  }
});

test('[RB-08] the operator can actually declare the arrangement from Settings', async () => {
  const r = await evalIn(async () => {
    location.hash = '#insights';
    await new Promise(res => setTimeout(res, 400));
    const sel = document.getElementById('rateBasisSelect');
    return {
      present: !!sel,
      options: sel ? Array.from(sel.options).map(o => o.value) : [],
      pctField: !!document.getElementById('settlementPct'),
    };
  });
  ok(r.present, 'Settings must expose a rate-basis control — a field nobody can set is the X-11 dead-claim shape');
  for (const m of ['UNKNOWN', 'LEASED_SETTLEMENT', 'OWN_AUTHORITY_CARRIER_GROSS', 'DIRECT_SHIPPER_GROSS']) {
    ok(r.options.includes(m), `the control must offer ${m} — got ${JSON.stringify(r.options)}`);
  }
  ok(r.pctField, 'and must let an operator record a split they actually know');
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
