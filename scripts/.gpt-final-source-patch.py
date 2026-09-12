from pathlib import Path


def read(p):
    return Path(p).read_text(encoding='utf-8')


def write(p, s):
    Path(p).write_text(s, encoding='utf-8')


def once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'{label}: expected 1 exact match, got {n}')
    return s.replace(old, new, 1)


p = 'app.js'
s = read(p)
s = once(s, "const APP_VERSION = '24.0.4';", "const APP_VERSION = '24.0.5';", 'APP_VERSION')
s = once(s, "invoiceDate:'', dueDate:'', origin:'', destination:'', pay:0, loadedMiles:0, emptyMiles:0,", "invoiceDate:'', dueDate:'', origin:'', destination:'', pay:0, loadedMiles:0, emptyMiles:null,", 'trip template emptyMiles')
s = once(s, "  const empty = Number(raw?.emptyMiles || 0);\n  const total = loaded + empty;", "  const empty = knownNum(raw?.emptyMiles);\n  const total = empty === null ? null : loaded + empty;", 'review unknown deadhead')
s = once(s, "  if (!(total > 0)) reasons.push('Total miles must be greater than 0');", "  if (empty === null) reasons.push('Deadhead miles are unknown');\n  if (total !== null && !(total > 0)) reasons.push('Total miles must be greater than 0');", 'review reason insert')
s = once(s, "  if (empty > 1500) reasons.push('Deadhead exceeds sanity threshold');", "  if (empty !== null && empty > 1500) reasons.push('Deadhead exceeds sanity threshold');", 'review deadhead bound')
s = once(s, "  t.emptyMiles = posNum(raw.emptyMiles, 0, 300000);", "  const deadheadMilesKnown = knownNum(raw.emptyMiles);\n  t.emptyMiles = (deadheadMilesKnown !== null && deadheadMilesKnown >= 0 && deadheadMilesKnown <= 300000) ? deadheadMilesKnown : null;", 'sanitizeTrip deadhead')
old = "            emptyMiles: Number(cellAt(row, 'EmptyMiles','Empty','Deadhead','DeadheadMiles','DH').replace(/[,]/g,'') || 0),"
new = "            emptyMiles: (() => { const v = cellAt(row, 'EmptyMiles','Empty','Deadhead','DeadheadMiles','DH').replace(/[,]/g,'').trim(); return v === '' ? null : Number(v); })(),"
s = once(s, old, new, 'CSV deadhead')
s = once(s, "        emptyMiles: deadMi || 0,", "        emptyMiles: deadMi,", 'book-as-trip deadhead')
s = once(s, "  $('#f_empty', body).value = trip.emptyMiles || '';", "  $('#f_empty', body).value = trip.emptyMiles ?? '';", 'wizard display zero')
s = once(s, "    trip.emptyMiles = Math.max(0, Number($('#f_empty', body).value || 0));", "    trip.emptyMiles = knownNum($('#f_empty', body).value);", 'wizard collect deadhead')
known_fn = """function knownNum(v){
  if (v === null || v === undefined) return null;
  if (typeof v === 'string' && v.trim() === '') return null;
  const x = Number(v);
  return Number.isFinite(x) ? x : null;
}
"""
known_plus = known_fn + """function tripHasKnownDeadhead(trip){
  const x = knownNum(trip?.emptyMiles);
  return x !== null && x >= 0 && x <= 300000;
}
"""
s = once(s, known_fn, known_plus, 'known deadhead helper')
chicago = "  'chicago':       { zone:'MIDWEST', role:'anchor',       bias:'very_strong', lat:41.8781, lng:-87.6298 },"
gary = chicago + "\n  'gary':          { zone:'MIDWEST', role:'anchor',       bias:'very_strong', lat:41.5955922, lng:-87.3452279 },"
s = once(s, chicago, gary, 'Gary USA market')
s = once(s, "// M1: Level X+ doctrine puts Cincinnati and Toledo in Tier 1. Mirrored in", "// M1: Level X+ doctrine puts Gary, Cincinnati and Toledo in Tier 1. Mirrored in", 'tier1 comment')
s = once(s, "tier1: ['chicago','indianapolis','cleveland','columbus','detroit','cincinnati','toledo'],", "tier1: ['chicago','gary','indianapolis','cleveland','columbus','detroit','cincinnati','toledo'],", 'Gary MW tier1')
s = once(s, "    if (t.needsReview) return false;\n    const dt = t.pickupDate || t.deliveryDate;", "    if (t.needsReview || !tripHasKnownDeadhead(t)) return false;\n    const dt = t.pickupDate || t.deliveryDate;", 'score baseline guard')
s = once(s, "function computeBrokerStats(trips, todayIso, windowDays=90){\n  const now = new Date(todayIso).getTime() || Date.now();\n  const minTs = windowDays > 0 ? (now - (windowDays * 86400000)) : 0;\n  const map = new Map();\n  for (const t of trips){\n    if (t.needsReview) continue;", "function computeBrokerStats(trips, todayIso, windowDays=90){\n  const now = new Date(todayIso).getTime() || Date.now();\n  const minTs = windowDays > 0 ? (now - (windowDays * 86400000)) : 0;\n  const map = new Map();\n  for (const t of trips){\n    if (t.needsReview || !tripHasKnownDeadhead(t)) continue;", 'broker stats guard')
s = once(s, "function computeLaneStats(trips){\n  const map = new Map();\n  for (const t of trips){\n    if (t.needsReview) continue;", "function computeLaneStats(trips){\n  const map = new Map();\n  for (const t of trips){\n    if (t.needsReview || !tripHasKnownDeadhead(t)) continue;", 'lane stats guard')
s = once(s, "    const matches = all.filter(t => (t.customer||'').toLowerCase().includes(norm) || norm.includes((t.customer||'').toLowerCase().slice(0,6)));", "    const matches = all.filter(t => ((t.customer||'').toLowerCase().includes(norm) || norm.includes((t.customer||'').toLowerCase().slice(0,6))) && !t.needsReview && tripHasKnownDeadhead(t));", 'broker trip intel guard')
s = once(s, "async function recordLaneHistory(trip){\n  if (!trip || !trip.origin || !trip.destination) return;\n  const pay = Number(trip.pay||0);", "async function recordLaneHistory(trip){\n  if (!trip || !trip.origin || !trip.destination || trip.needsReview || !tripHasKnownDeadhead(trip)) return;\n  const pay = Number(trip.pay||0);", 'lane history guard')
s = once(s, "      return to.includes(origNorm.split(',')[0].trim()) && td.includes(destNorm.split(',')[0].trim());", "      return !t.needsReview && tripHasKnownDeadhead(t) && to.includes(origNorm.split(',')[0].trim()) && td.includes(destNorm.split(',')[0].trim());", 'lane trend guard')
write(p, s)

p = 'tests/integration/v2404-fail-closed.spec.mjs'
t = read(p)
old = """    return { gary: m ? m.city + '/' + m.zone : null, calgary: c ? c.city + '/' + c.zone : null };
  });
  if (!r) { ok(true, 'lookup not exposed'); return; }
  ok(r.gary !== 'calgary/ALBERTA',
    'Gary must never resolve to Calgary/ALBERTA — that scored an Indiana load as a westbound Alberta long-haul');
  eq(r.calgary, 'calgary/ALBERTA', 'Calgary itself must still resolve exactly');
"""
new = """    return { gary: m ? m.city + '/' + m.zone + '/' + m.country + '/' + m.role : null,
             garyTier1: !!T.MW?.tier1?.includes('gary'),
             calgary: c ? c.city + '/' + c.zone : null };
  });
  if (!r) { ok(true, 'lookup not exposed'); return; }
  eq(r.gary, 'gary/MIDWEST/US/anchor', 'Gary, Indiana must resolve canonically as a U.S. Midwest anchor');
  ok(r.garyTier1, 'Gary must be in the canonical Midwest Tier 1 table, matching the operator authority mirror');
  eq(r.calgary, 'calgary/ALBERTA', 'Calgary itself must still resolve exactly');
"""
t = once(t, old, new, 'Gary regression strengthen')
marker = "// ── Item 7: vehicle fit reconciled to the operator-confirmed 121in ──────────"
add = """// ── v24.0.5: persisted deadhead UNKNOWN must survive every trip write ────────

test('[V2405-01] sanitizeTrip preserves UNKNOWN vs explicit zero deadhead', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const base = { orderNo:'V2405-SAN', pay:500, loadedMiles:250, pickupDate:'2026-09-11', deliveryDate:'2026-09-11' };
    const pick = (extra) => { const x = T.sanitizeTrip({ ...base, ...extra }); return { emptyMiles:x.emptyMiles, needsReview:x.needsReview, reasons:x.reviewReasons }; };
    return { missing:pick({}), blank:pick({emptyMiles:'   '}), invalid:pick({emptyMiles:'bogus'}), negative:pick({emptyMiles:-5}), zero:pick({emptyMiles:0}), positive:pick({emptyMiles:25}) };
  });
  for (const k of ['missing','blank','invalid','negative']) {
    eq(r[k].emptyMiles, null, `${k} deadhead must persist as UNKNOWN/null`);
    ok(r[k].needsReview, `${k} deadhead must mark the trip for review so it cannot enter True RPM history`);
  }
  eq(r.zero.emptyMiles, 0, 'an explicit zero deadhead must remain a real zero');
  ok(!r.zero.reasons.includes('Deadhead miles are unknown'), 'explicit zero must not be labeled unknown');
  eq(r.positive.emptyMiles, 25, 'a positive known deadhead must survive unchanged');
});

test('[V2405-02] IDB round-trip never manufactures unknown deadhead as zero', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const stamp = Date.now();
    const unknownId = `V2405-U-${stamp}`;
    const zeroId = `V2405-Z-${stamp}`;
    const base = { customer:'Integrity Test', pay:500, loadedMiles:250, pickupDate:T.isoDate(), deliveryDate:T.isoDate(), origin:'Chicago, IL', destination:'Detroit, MI' };
    await T.upsertTrip({ ...base, orderNo:unknownId, emptyMiles:null });
    await T.upsertTrip({ ...base, orderNo:zeroId, emptyMiles:0 });
    const rows = await T.dumpStore('trips');
    const u = rows.find(x => x.orderNo === unknownId);
    const z = rows.find(x => x.orderNo === zeroId);
    return { unknown:u && { emptyMiles:u.emptyMiles, needsReview:u.needsReview, reasons:u.reviewReasons }, zero:z && { emptyMiles:z.emptyMiles, needsReview:z.needsReview, reasons:z.reviewReasons } };
  });
  ok(r.unknown, 'unknown-deadhead trip must exist after IDB write');
  eq(r.unknown.emptyMiles, null, 'IDB round-trip must preserve UNKNOWN as null, never fabricate 0');
  ok(r.unknown.needsReview, 'unknown-deadhead persisted trip must remain quarantined from RPM intelligence');
  ok(r.zero, 'explicit-zero trip must exist after IDB write');
  eq(r.zero.emptyMiles, 0, 'IDB round-trip must preserve explicit 0 exactly');
});

"""
if marker not in t:
    raise SystemExit('test insertion marker missing')
t = t.replace(marker, add + marker, 1)
write(p, t)

for p in ['service-worker.js', 'index.html', 'manifest.json', 'sw-bridge.js', 'voice-load.js', 'scripts/verify-cloudflare-parity.mjs']:
    x = read(p)
    if '24.0.4' not in x:
        raise SystemExit(f'{p}: no 24.0.4 marker found')
    write(p, x.replace('24.0.4', '24.0.5'))

p = 'midwest-stack-authority.js'
x = read(p)
x = once(x, 'FreightLogic Midwest Stack v11 / Level X+ Advisory Overlay v24.0.4', 'FreightLogic Midwest Stack v11 / Level X+ Advisory Overlay v24.0.5', 'overlay header')
x = once(x, "const VERSION = '24.0.4';", "const VERSION = '24.0.5';", 'overlay version')
write(p, x)

p = 'midwest-stack-config.json'
x = read(p)
x = once(x, '"appTarget": "FreightLogic v24.0.4"', '"appTarget": "FreightLogic v24.0.5"', 'config appTarget')
write(p, x)

p = 'CLAUDE.md'
x = read(p)
x = once(x, '**FreightLogic v24.0.4**', '**FreightLogic v24.0.5**', 'guide current version')
write(p, x)

print('PATCH_APPLIED')
