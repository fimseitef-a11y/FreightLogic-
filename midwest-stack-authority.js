/* FreightLogic Midwest Stack v11 / Level X+ Advisory Overlay v24.0.4
 * Driver-first cargo-van decision intelligence layer.
 * Safe overlay: no app.js rewrite, no external dependencies, no persistent sensitive storage.
 */
(function(){
  'use strict';

  const VERSION = '24.0.4';
  const UPDATED_AT = '2026-08-20';

  const CONFIG = Object.freeze({
    operator: {
      vehicle: 'cargo_van_transit_t250',
      homeBase: 'Oak Creek, WI',
      homeAnchor: 'Milwaukee / Chicago corridor',
      metricAuthority: 'TRUE_RPM',
      trueRpmFormula: 'revenue / (loadedMiles + deadheadMiles)'
    },
    modes: {
      PROTECT_FLOOR: {
        id: 'PROTECT_FLOOR',
        label: 'Protect Floor',
        description: 'Normal business-health pricing. Use when not under pressure.',
        floor: 1.40,
        preferred: 1.50,
        target: 1.65
      },
      REALISTIC_WIN: {
        id: 'REALISTIC_WIN',
        label: 'Realistic Win',
        description: 'DispatchLand/Sylectus compressed clearing logic. Use when the board proves $1.40-$1.50 is not winning.',
        floor: 1.15,
        preferred: 1.25,
        target: 1.35
      },
      ESCAPE_RECOVERY: {
        id: 'ESCAPE_RECOVERY',
        label: 'Escape / Recovery',
        description: 'Accept lower pricing only when position clearly improves toward stronger Midwest density.',
        floor: 1.10,
        preferred: 1.25,
        target: 1.40
      },
      DEAD_ZONE: {
        id: 'DEAD_ZONE',
        label: 'Dead Zone Exit',
        description: 'Survival gate only. Requires 1000+ miles from home, no reloads above $1.25 nearby, and meaningful move toward density.',
        floor: 0.90,
        preferred: 1.00,
        target: 1.10
      }
    },
    grades: [
      { grade: 'A', min: 1.75, label: 'Premium' },
      { grade: 'B', min: 1.60, label: 'Strong' },
      { grade: 'C', min: 1.50, label: 'Healthy' },
      { grade: 'D', min: 1.40, label: 'Normal floor' },
      { grade: 'E', min: 1.25, label: 'Strategic only' },
      { grade: 'F', min: 0, label: 'Below floor' }
    ],
    marketRoles: {
      tier1: ['chicago','gary','indianapolis','cleveland','columbus','detroit','cincinnati','toledo'],
      tier2: ['nashville','louisville','st louis','saint louis','fort wayne','grand rapids','dayton','milwaukee'],
      feeder: ['kansas city','des moines','memphis','atlanta','dallas','houston','pittsburgh','oklahoma city','minneapolis','saint paul','st paul','twin cities','fargo','omaha','charlotte'],
      trap: ['laredo','el paso','odessa','midland','abilene','amarillo','nogales','reno','las vegas','new mexico','west texas','south texas','rural arkansas','rural mississippi','rural alabama','rural georgia','rural south carolina','rural north carolina']
    },
    regionCompression: {
      northeast: { multiplier: 0.90, note: 'Northeast cargo-van clearing can run compressed; use screenshot targets over generic dry-van data.' },
      minnesota: { multiplier: 0.88, note: 'Twin Cities / Minnesota board often clears below Chicago/Milwaukee expectations.' },
      kansasCity: { multiplier: 0.92, note: 'Kansas City is transitional/feeder; prioritize north/east recovery.' },
      southeast: { multiplier: 0.90, note: 'Southeast support market; avoid rural/deeper South cheap long-locks.' },
      coreMidwest: { multiplier: 1.00, note: 'Core Midwest density; protect floor unless flow pressure is active.' }
    },
    premiums: {
      trapDestination: 0.25,
      feederDestination: 0.10,
      highDeadhead: 0.10,
      veryHighDeadhead: 0.20,
      overnightDirect: 0.10,
      multiStop: 0.08,
      heavyTransit: 0.08,
      hazmatCheck: 0.05,
      weekendOrHolidayLock: 0.10
    },
    hardStops: {
      absoluteTrueRpmReject: 0.90,
      deadheadWarningMiles: 150,
      deadheadPremiumMiles: 200,
      transitPayloadCautionLbs: 2500,
      transitPayloadHardCheckLbs: 3000
    }
  });

  // v23.8.3: bands replaced with the July 2026 tightening-market override, which
  // superseded the May compression table. Values are transcribed verbatim from the
  // (now-deleted) rate-overrides-2026-07.json — that file was precached but never
  // read by any code path, so the May numbers below had stayed in force since May.
  // Inner key names (compressedBands / realisticWin / band keys) are deliberately
  // left as-is — they are consumed by bandForMiles() and assessLoad(), and renaming
  // them is structural churn with no behavioural gain.
  const RATE_OVERRIDE_2026_07 = Object.freeze({
    effectiveDate: '2026-07-09',
    supersedes: 'May 2026 cargo-van compression override',
    source: 'July 2026 tightening-market override — dry van spot at record highs, spot above contract (first since Feb 2022), linehaul +39% YoY, capacity contracting',
    rule: 'True RPM remains the calculation authority. Do not import national dry-van gains 1:1 into cargo-van bids; Midwest-to-Midwest lanes lag national (+10-15% YoY). Broker urgency and repost behavior justify firmer counters than in H1.',
    compressedBands: {
      shortLocal: { totalMiles: [0, 200], realisticWin: [1.80, 2.40], note: 'Urgency premiums rising; bid/call fast, counter high first.' },
      mediumFeeder: { totalMiles: [200, 600], realisticWin: [1.35, 1.65], note: 'Sub-1.40 acceptance is now positional-only, no longer a market default. Counter toward floor before conceding.' },
      longRecovery: { totalMiles: [600, 1000], realisticWin: [1.40, 1.70], note: 'Tier 1/Tier 2 destination still required for the low end.' },
      longDisplacement: { totalMiles: [1000, 1800], realisticWin: [1.35, 1.55], note: 'Weak-destination long-locks require premium; capacity scarcity is negotiating leverage.' },
      // Source reads "1800+" and "1.50-1.90+"; the numeric shape has no way to carry
      // the open upper bound, so 9999 keeps the existing sentinel and 1.90 is the
      // stated premium floor, not a cap.
      extremeLongLock: { totalMiles: [1800, 9999], realisticWin: [1.50, 1.90], note: 'Westbound/border/rural must clear premium; do not discount into displacement.' }
    }
  });



  // Pre-v24 integrity gate: static market overrides are evidence with an age,
  // not permanent truth. CURRENT <=14d, AGING <=30d, STALE >30d.
  const RATE_OVERRIDE_FRESHNESS = Object.freeze({ currentDays: 14, agingDays: 30 });
  function getRateOverrideFreshness(asOf = new Date()){
    const effectiveMs = Date.parse(RATE_OVERRIDE_2026_07.effectiveDate + 'T00:00:00Z');
    const asOfMs = asOf instanceof Date ? asOf.getTime() : Date.parse(String(asOf));
    const ageDays = Number.isFinite(effectiveMs) && Number.isFinite(asOfMs) ? Math.max(0, Math.floor((asOfMs - effectiveMs) / 86400000)) : Infinity;
    const status = ageDays <= RATE_OVERRIDE_FRESHNESS.currentDays ? 'CURRENT' : (ageDays <= RATE_OVERRIDE_FRESHNESS.agingDays ? 'AGING' : 'STALE');
    return { status, ageDays, effectiveDate: RATE_OVERRIDE_2026_07.effectiveDate };
  }

  function cleanText(value){ return String(value || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim(); }
  // M1: material operational facts are UNKNOWN unless they parse finite.
  // null/undefined/blank/NaN/Infinity => null, never a silent 0. An explicit
  // 0 the operator actually entered stays a real 0.
  function knownNum(value){
    if (value === null || value === undefined) return null;
    if (typeof value === 'string' && value.trim() === '') return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  // Presentation-only coercion. Never use for a material fact.
  function finite(value, fallback){ const n = Number(value); return Number.isFinite(n) ? n : (fallback || 0); }
  function round2(value){ return Math.round(finite(value) * 100) / 100; }

  function includesAny(haystack, list){
    const h = cleanText(haystack);
    return list.some(x => h.includes(cleanText(x)));
  }

  function classifyMarket(place){
    const p = cleanText(place);
    if (!p) return { role: 'unknown', label: 'Unknown', risk: 0.05 };
    if (includesAny(p, CONFIG.marketRoles.trap)) return { role: 'trap', label: 'Trap / weak exit', risk: 0.30 };
    if (includesAny(p, CONFIG.marketRoles.tier1)) return { role: 'tier1', label: 'Tier 1 density', risk: -0.10 };
    if (includesAny(p, CONFIG.marketRoles.tier2)) return { role: 'tier2', label: 'Tier 2 support', risk: -0.05 };
    if (includesAny(p, CONFIG.marketRoles.feeder)) return { role: 'feeder', label: 'Transitional / feeder', risk: 0.12 };
    return { role: 'neutral', label: 'Neutral / unknown lane', risk: 0.05 };
  }

  function detectRegion(origin, destination){
    const text = cleanText(origin + ' ' + destination);
    if (/(nj|ny|ct|ma|pa|md|de|ri|new jersey|new york|connecticut|massachusetts|pennsylvania|maryland)/.test(text)) return 'northeast';
    if (/(mn|minnesota|twin cities|minneapolis|saint paul|st paul)/.test(text)) return 'minnesota';
    if (/(kansas city|kc|ks|mo 641|mo 640)/.test(text)) return 'kansasCity';
    if (/(ga|al|ms|fl|sc|nc|tn|atlanta|charlotte|augusta|birmingham|jacksonville|orlando|tampa)/.test(text)) return 'southeast';
    return 'coreMidwest';
  }

  // v24.0.4 item 3: gradeFor() is deleted — it WAS the overlay's independent
  // grade ladder. CONFIG.grades survives only as a declared doctrine reference
  // that the parity tests compare against app.js; nothing here derives a grade
  // from it any more. money()/roundMoney() went with the Floor/Win/Ask pills,
  // their only consumers.

  const MODE_LABEL_MAP = {
    'realistic win': 'REALISTIC_WIN',
    'protect floor': 'PROTECT_FLOOR',
    'escape recovery': 'ESCAPE_RECOVERY',
    'escape / recovery': 'ESCAPE_RECOVERY',
    'dead zone exit': 'DEAD_ZONE',
    'dead zone': 'DEAD_ZONE',
  };

  function modeDefaults(modeId){
    const cleaned = cleanText(modeId || '');
    const key = MODE_LABEL_MAP[cleaned] || cleaned.replace(/\s+/g, '_').toUpperCase();
    return CONFIG.modes[key] || CONFIG.modes.REALISTIC_WIN;
  }

  function bandForMiles(totalMiles){
    const bands = RATE_OVERRIDE_2026_07.compressedBands;
    const list = Object.values(bands);
    // Use exclusive upper bound to prevent boundary overlap between adjacent bands
    for (let i = 0; i < list.length; i++) {
      const b = list[i];
      if (totalMiles >= b.totalMiles[0] && (i === list.length - 1 || totalMiles < b.totalMiles[1])) return b;
    }
    return bands.mediumFeeder;
  }

  function hasWeekendLock(pickupDate, deliveryDate){
    const dates = [pickupDate, deliveryDate].filter(Boolean).map(d => new Date(d)).filter(d => !isNaN(d.getTime()));
    // Use getUTCDay() — bare YYYY-MM-DD strings parse as UTC midnight; getDay() would return the prior day in US timezones
    return dates.some(d => d.getUTCDay() === 0 || d.getUTCDay() === 6);
  }

  function assessLoad(input){
    // M1: `a || b || c` collapses a real 0 into the next candidate, so pick the
    // first DEFINED alias rather than the first truthy one.
    const pick = (...vals) => { for (const v of vals){ const n = knownNum(v); if (n !== null) return n; } return null; };
    const revenueK = pick(input.revenue, input.pay, input.rate);
    const loadedMilesK = pick(input.loadedMiles, input.loadedMi, input.loaded);
    const deadheadMilesK = pick(input.deadheadMiles, input.deadMiles, input.deadhead, input.emptyMiles);

    // Missing material facts cannot produce a precise-looking advisory number.
    const unknownFacts = [];
    if (revenueK === null) unknownFacts.push('revenue');
    if (loadedMilesK === null) unknownFacts.push('loadedMiles');
    if (deadheadMilesK === null) unknownFacts.push('deadheadMiles');
    if (unknownFacts.length){
      return {
        version: VERSION,
        updatedAt: UPDATED_AT,
        authorityRole: 'ADAPTER_ONLY',
        available: false,
        unknownFacts,
        // Same shape the UI reads, with nulls where a fact is missing — the
        // caller must never have to guess whether a 0 here was real.
        input: {
          revenue: revenueK, loadedMiles: loadedMilesK, deadheadMiles: deadheadMilesK,
          totalMiles: null, origin: input.origin || input.pickup || '',
          destination: input.destination || input.dest || '', weight: null, stops: null,
        },
        posted: { trueRpm: null },
        trueRpm: null,
        // v24.0.4 item 3: no monetary shape here either. The absence case must not
        // hand a caller a `recommendation` object to read money out of, even nulls.
        dzGate: { requested: false, eligible: false, gradeCap: null, reasons: [] },
        action: 'Enter revenue, loaded miles and deadhead miles. Blank is not zero.',
        risk: { flags: ['Missing: ' + unknownFacts.join(', ') + '. The overlay does not estimate material facts.'] },
      };
    }

    const revenue = revenueK;
    const loadedMiles = loadedMilesK;
    const deadheadMiles = deadheadMilesK;
    const totalMiles = loadedMiles + deadheadMiles;
    const trueRpm = totalMiles > 0 ? revenue / totalMiles : 0;
    const destination = input.destination || input.dest || '';
    const origin = input.origin || input.pickup || '';
    const notes = String(input.notes || input.loadNotes || '');
    const weight = knownNum(input.weight ?? input.weightLbs) ?? 0; // 0 = 'no payload signal', only ever adds a flag
    const stops = finite(input.stops || input.stopCount || 1, 1);
    const mode = modeDefaults(input.mode || input.bidMode || 'REALISTIC_WIN');
    const destRole = classifyMarket(destination);
    const originRole = classifyMarket(origin);
    const region = detectRegion(origin, destination);
    const regionOverlay = CONFIG.regionCompression[region] || CONFIG.regionCompression.coreMidwest;
    const band = bandForMiles(totalMiles || loadedMiles);

    let premium = 0;
    let risk = 0.20 + Math.max(0, destRole.risk || 0);
    const flags = [];

    if (destRole.role === 'trap') { premium += CONFIG.premiums.trapDestination; flags.push('Trap/weak destination requires premium or pass.'); }
    if (destRole.role === 'feeder') { premium += CONFIG.premiums.feederDestination; flags.push('Feeder destination: have reload/exit plan.'); }
    if (deadheadMiles >= CONFIG.hardStops.deadheadPremiumMiles) { premium += CONFIG.premiums.veryHighDeadhead; risk += 0.18; flags.push('200+ deadhead: needs premium or strategic position benefit.'); }
    else if (deadheadMiles >= CONFIG.hardStops.deadheadWarningMiles) { premium += CONFIG.premiums.highDeadhead; risk += 0.10; flags.push('150+ deadhead warning.'); }
    if (stops > 1 || /multi|2 stop|two stop|multiple/i.test(notes)) { premium += CONFIG.premiums.multiStop; risk += 0.08; flags.push('Multi-stop complexity.'); }
    if (weight >= CONFIG.hardStops.transitPayloadHardCheckLbs) { premium += CONFIG.premiums.heavyTransit; risk += 0.15; flags.push('Payload must be verified for Transit T250.'); }
    else if (weight >= CONFIG.hardStops.transitPayloadCautionLbs) { risk += 0.08; flags.push('Heavy cargo-van load; verify payload.'); }
    if (/battery|batteries|hazmat|chemical|paint|lithium/i.test(notes + ' ' + input.commodity)) { premium += CONFIG.premiums.hazmatCheck; risk += 0.05; flags.push('Commodity check: confirm non-hazmat / paperwork.'); }
    if (hasWeekendLock(input.pickupDate, input.deliveryDate) || /weekend|holiday|memorial|hold/i.test(notes)) { premium += CONFIG.premiums.weekendOrHolidayLock; risk += 0.08; flags.push('Weekend/holiday lock risk.'); }

    // v24.0.4 item 3: the rate ladder is DELETED, not merely unrendered.
    //
    // What stood here computed floorRpm/winRpm/askRpm from this file's own mode
    // floors (`CONFIG.modes.*.floor/preferred/target`), the July band table and
    // `regionCompression` multipliers — an independent monetary doctrine. Leaving
    // it as dead-but-present code would keep the doctrine one wiring change away
    // from returning, which is the opposite of the authority boundary this
    // release establishes. app.js owns bid and verdict; this file owns neither.
    //
    // Retained: rate-override FRESHNESS, which is genuine evidence about how much
    // the static band table can still be trusted, and is reported as a flag rather
    // than used to price anything.
    const rateFreshness = getRateOverrideFreshness();
    if (rateFreshness.status === 'STALE') flags.push(`Rate override STALE (${rateFreshness.ageDays}d old) — static July bands are evidence only and cannot be relied on for current pricing.`);
    else if (rateFreshness.status === 'AGING') flags.push(`Rate override AGING (${rateFreshness.ageDays}d old) — use as secondary evidence and verify current market.`);

    let dzGateResult = null;
    if (mode.id === 'DEAD_ZONE') {
      if (typeof window !== 'undefined' && typeof window.isDeadZoneEligible === 'function'){
        const geo = (typeof window.flDzGeoCheck === 'function') ? window.flDzGeoCheck(origin, destination) : { eligible: false };
        const toggleEl = typeof document !== 'undefined' ? document.getElementById('mwDZNoReloadToggle') : null;
        dzGateResult = window.isDeadZoneEligible({
          distanceFromHome: geo.distanceFromHome,
          distanceSaved: geo.distanceSaved,
          trueRPM: trueRpm,
          noReloadConfirmed: !!(toggleEl && toggleEl.checked),
        });
      } else {
        // app.js not loaded yet / injection-order issue — fail closed rather
        // than silently allowing an unguarded survival-mode TAKE_IF_LIVE.
        dzGateResult = { eligible: false, gradeCap: 'C', reasons: ['DZ gate check unavailable (app.js not loaded) — treated as ineligible'] };
      }
      if (dzGateResult.eligible){
        // No floor to lower any more — the gate outcome is reported as `dzGate`
        // and the canonical evaluator applies the survival floor and grade cap.
        flags.push('Dead-zone mode must be manually validated before acceptance.');
      } else {
        flags.push(...dzGateResult.reasons.map(r => 'DZ gate: ' + r));
        flags.push('Dead Zone Exit gate not satisfied — using the standard floor, not the survival floor.');
      }
    }

    // v24.0.4 item 3: no monetary output and no verdict.
    //
    // floorBid/winBid/askBid and the verdict ladder that used to live here were a
    // SECOND monetary doctrine — this file's own mode floors, grade ladder and
    // regional compression multipliers, producing money and a TAKE_IF_LIVE that
    // could and did contradict the canonical decision (True RPM $1.19 -> canonical
    // "REJECT / F", this file "TAKE_IF_LIVE" at a $475 floor, below the $1.25 hard
    // reject, with the Dead Zone gate failed). A file labelled ADAPTER_ONLY must
    // not own money. app.js is the sole owner of grade, verdict, economics and bid.
    //
    // The floorRpm/winRpm/askRpm locals above still exist because the DEAD_ZONE
    // block is what exercises the shared gate; they are no longer returned or
    // rendered anywhere.

    // The X-04 gate outcome IS still reported, because it is the one thing this
    // file genuinely contributes: proof that it and the main evaluator called the
    // SAME canonical window.isDeadZoneEligible() and reached the same answer.
    // Previously this had to be inferred from the verdict string.
    const dzGate = mode.id === 'DEAD_ZONE'
      ? { requested: true,
          eligible: !!(dzGateResult && dzGateResult.eligible),
          gradeCap: (dzGateResult && dzGateResult.gradeCap) || null,
          reasons: (dzGateResult && dzGateResult.reasons) || [] }
      : { requested: false, eligible: false, gradeCap: null, reasons: [] };

    return {
      authorityRole: 'ADAPTER_ONLY',
      available: true,
      unknownFacts: [],
      version: VERSION,
      updatedAt: UPDATED_AT,
      input: { revenue, loadedMiles, deadheadMiles, totalMiles, origin, destination, weight, stops },
      // trueRpm is a restatement of the canonical formula over the same inputs,
      // kept for evidence display. No grade is derived from it here.
      posted: { trueRpm: round2(trueRpm) },
      mode: { id: mode.id, label: mode.label, description: mode.description },
      market: { origin: originRole, destination: destRole, region, regionNote: regionOverlay.note },
      dzGate,
      risk: { score: Math.min(100, Math.round(risk * 100)), flags },
      override: { effectiveDate: RATE_OVERRIDE_2026_07.effectiveDate, bandNote: band.note }
    };
  }

  function readField(id){ const el = document.getElementById(id); return el ? el.value : ''; }
  function ensureUi(){
    const evalOutput = document.getElementById('mwEvalOutput');
    const revenue = document.getElementById('mwRevenue');
    const loaded = document.getElementById('mwLoadedMi');
    if (!evalOutput || !revenue || !loaded || document.getElementById('mwStackAuthorityPanel')) return;

    const panel = document.createElement('div');
    panel.id = 'mwStackAuthorityPanel';
    panel.className = 'card';
    panel.style.marginTop = '12px';
    // v24.0.4 item 3: the bid-mode selector is gone with the bid ladder it drove.
    // Leaving a "Bid mode" control that no longer changes any bid would be a
    // second authority in appearance even after removing it in substance — the
    // driver would reasonably expect picking a mode to change the recommended
    // money. Mode selection for the survival path lives in the canonical
    // evaluator (the Dead Zone gate and its #mwDZNoReloadToggle), which is the
    // only place it ever had real effect.
    panel.innerHTML = '<h3>Market Context · Advisory</h3>' +
      '<div class="muted" style="font-size:11px;margin-bottom:8px">Canonical decision above is authoritative. This panel is market evidence only — it owns no grade, verdict, economics or bid range.</div>' +
      '<div id="mwStackAuthorityResult" style="margin-top:12px"></div>';
    evalOutput.parentNode.insertBefore(panel, evalOutput.nextSibling);

    const ids = ['mwRevenue','mwLoadedMi','mwDeadMi','mwOrigin','mwDest','mwLoadNotes'];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', renderUi, { passive: true });
      if (el) el.addEventListener('change', renderUi, { passive: true });
    });
    renderUi();
  }

  function renderUi(){
    const box = document.getElementById('mwStackAuthorityResult');
    if (!box) return;
    const result = assessLoad({
      revenue: readField('mwRevenue'),
      loadedMiles: readField('mwLoadedMi'),
      deadheadMiles: readField('mwDeadMi'),
      origin: readField('mwOrigin'),
      destination: readField('mwDest'),
      notes: readField('mwLoadNotes'),
      mode: readField('mwBidMode') || 'REALISTIC_WIN'
    });
    if (result.available === false) {
      box.innerHTML = '<div class="muted" style="font-size:12px">Enter revenue, loaded miles and deadhead miles for realistic bid guidance. '
        + 'A blank field is treated as unknown, not zero.</div>';
      return;
    }
    if (!result.input.loadedMiles && !result.input.revenue) {
      box.innerHTML = '<div class="muted" style="font-size:12px">Enter revenue and miles to get realistic bid guidance.</div>';
      return;
    }
    // v24.0.4 item 3: this panel no longer renders money or a verdict.
    //
    // It used to print its own Floor/Win/Ask pills and a "Signal: <verdict>"
    // line, computed from this file's own mode floors, grade ladder and regional
    // compression multipliers — a second monetary authority sitting directly
    // beneath the canonical result, because the panel is inserted as
    // #mwEvalOutput.nextSibling. The two visibly disagreed: on a Minneapolis ->
    // Chicago load at True RPM $1.19 the canonical card read "REJECT / F / PASS"
    // while this panel read "Signal: TAKE_IF_LIVE" with a $475 floor — below the
    // $1.25 hard reject, on a load whose Dead Zone gate had failed all three of
    // its checks. A driver reading the screen had two answers and no way to tell
    // which one was authoritative beyond a one-line disclaimer.
    //
    // What survives is the part that was always genuinely additive and that
    // app.js does not itself compute: destination market role, regional context,
    // and the risk/premium flags. Those are EVIDENCE. app.js remains the sole
    // owner of grade, verdict, economics and bid range.
    const flags = result.risk.flags.length ? result.risk.flags.map(f => '<li>' + escapeHtml(f) + '</li>').join('') : '';
    box.innerHTML =
      '<div class="muted" style="font-size:12px">→ ' + escapeHtml(result.market.destination.label) + ' · ' + escapeHtml(result.market.region) + ' region</div>' +
      (flags ? '<ul style="font-size:12px;margin:8px 0 0 18px;padding:0;color:var(--warn)">' + flags + '</ul>' : '') +
      '<div class="muted" style="font-size:11px;margin-top:10px">Market context only. Grade, verdict and bid range come from the canonical decision above.</div>';
  }

  function escapeHtml(s){
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  window.FreightLogicMidwestStack = Object.freeze({
    authorityRole: 'ADAPTER_ONLY',
    version: VERSION,
    updatedAt: UPDATED_AT,
    config: CONFIG,
    rateOverride: RATE_OVERRIDE_2026_07,
    assessLoad,
    classifyMarket
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensureUi, { once: true });
  else ensureUi();
  setTimeout(ensureUi, 800);
})();
