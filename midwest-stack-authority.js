/* FreightLogic Midwest Stack v2 Authority Overlay v23.5.1
 * Driver-first cargo-van decision intelligence layer.
 * Safe overlay: no app.js rewrite, no external dependencies, no persistent sensitive storage.
 */
(function(){
  'use strict';

  const VERSION = '23.5.1';
  const UPDATED_AT = '2026-05-27';

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
        floor: 0.91,
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
      tier1: ['chicago','gary','indianapolis','cleveland','columbus','detroit'],
      tier2: ['nashville','louisville','st louis','saint louis','toledo','fort wayne','grand rapids','cincinnati','dayton','milwaukee'],
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

  const RATE_OVERRIDE_2026_05 = Object.freeze({
    effectiveDate: '2026-05-25',
    source: 'User-observed DispatchLand/Sylectus/RPP cargo-van clearing behavior and project screenshots',
    rule: 'When user asks realistic or says forget thresholds, prioritize live board targets and observed clearing behavior over healthy-business thresholds.',
    compressedBands: {
      shortLocal: { totalMiles: [0, 200], realisticWin: [1.60, 2.10], note: 'Short local/reposition loads can still show high True RPM but disappear fast.' },
      mediumFeeder: { totalMiles: [200, 600], realisticWin: [1.10, 1.40], note: 'Feeder markets often clear below normal business floor.' },
      longRecovery: { totalMiles: [600, 1000], realisticWin: [1.20, 1.45], note: 'Accept only when direction improves toward Tier 1 / Tier 2 density.' },
      longDisplacement: { totalMiles: [1000, 1800], realisticWin: [1.20, 1.35], note: 'Reject if destination is trap/weak unless premium or recovery logic is clear.' },
      extremeLongLock: { totalMiles: [1800, 9999], realisticWin: [1.35, 1.75], note: 'Premium-only when westbound, border, rural, or multi-day lock.' }
    }
  });

  function cleanText(value){ return String(value || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim(); }
  function finite(value, fallback){ const n = Number(value); return Number.isFinite(n) ? n : (fallback || 0); }
  function roundMoney(value){ return Math.round(finite(value) / 5) * 5; }
  function round2(value){ return Math.round(finite(value) * 100) / 100; }
  function money(value){ return '$' + Math.round(finite(value)).toLocaleString(); }

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

  function gradeFor(rpm){
    const item = CONFIG.grades.find(g => rpm >= g.min) || CONFIG.grades[CONFIG.grades.length - 1];
    return item.grade;
  }

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
    const bands = RATE_OVERRIDE_2026_05.compressedBands;
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
    const revenue = finite(input.revenue || input.pay || input.rate);
    const loadedMiles = finite(input.loadedMiles || input.loadedMi || input.loaded);
    const deadheadMiles = finite(input.deadheadMiles || input.deadMiles || input.deadhead || input.emptyMiles);
    const totalMiles = loadedMiles + deadheadMiles;
    const trueRpm = totalMiles > 0 ? revenue / totalMiles : 0;
    const destination = input.destination || input.dest || '';
    const origin = input.origin || input.pickup || '';
    const notes = String(input.notes || input.loadNotes || '');
    const weight = finite(input.weight || input.weightLbs);
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

    const realisticBand = band.realisticWin;
    const compressedWinRpm = ((realisticBand[0] + realisticBand[1]) / 2) * regionOverlay.multiplier;
    const baseFloor = mode.floor;
    const baseTarget = mode.target;
    let floorRpm = Math.max(CONFIG.hardStops.absoluteTrueRpmReject, baseFloor, realisticBand[0] * regionOverlay.multiplier);
    let winRpm = Math.max(mode.preferred, compressedWinRpm);
    let askRpm = Math.max(baseTarget, realisticBand[1] * regionOverlay.multiplier) + premium;

    if (mode.id === 'PROTECT_FLOOR') {
      floorRpm = Math.max(1.40, floorRpm);
      winRpm = Math.max(1.50, winRpm);
      askRpm = Math.max(1.65, askRpm);
    }
    if (mode.id === 'ESCAPE_RECOVERY') {
      if (destRole.role === 'tier1' || destRole.role === 'tier2') floorRpm = Math.max(1.10, Math.min(floorRpm, 1.25));
      askRpm = Math.max(askRpm, 1.35 + premium);
    }
    if (mode.id === 'DEAD_ZONE') {
      floorRpm = 0.91;
      winRpm = Math.max(1.00, Math.min(winRpm, 1.15));
      askRpm = Math.max(1.10, Math.min(askRpm, 1.35));
      flags.push('Dead-zone mode must be manually validated before acceptance.');
    }

    const floorBid = roundMoney(floorRpm * totalMiles);
    const winBid = roundMoney(winRpm * totalMiles);
    const askBid = roundMoney(askRpm * totalMiles);

    let verdict = 'NEGOTIATE';
    if (!totalMiles || !loadedMiles) verdict = 'NEEDS_DATA';
    else if (trueRpm && trueRpm <= CONFIG.hardStops.absoluteTrueRpmReject) verdict = 'PASS';
    else if (destRole.role === 'trap' && trueRpm < 1.55 && mode.id !== 'DEAD_ZONE') verdict = 'PASS_PREMIUM_ONLY';
    else if (trueRpm >= floorRpm && (destRole.role === 'tier1' || destRole.role === 'tier2')) verdict = 'TAKE_IF_LIVE';
    else if (trueRpm >= winRpm && risk < 0.55) verdict = 'TAKE_IF_LIVE';
    else if (mode.id === 'ESCAPE_RECOVERY' && trueRpm >= floorRpm && (destRole.role === 'tier1' || destRole.role === 'tier2')) verdict = 'STRATEGIC_ONLY';

    const action = verdict === 'PASS' || verdict === 'PASS_PREMIUM_ONLY'
      ? 'Pass unless broker pays premium and timing is live.'
      : verdict === 'TAKE_IF_LIVE'
        ? 'Call/accept only after pickup, delivery, weight, and commodity are confirmed live.'
        : 'Counter once near the ask, then fall back toward realistic win if the lane improves position.';

    return {
      version: VERSION,
      updatedAt: UPDATED_AT,
      input: { revenue, loadedMiles, deadheadMiles, totalMiles, origin, destination, weight, stops },
      posted: { trueRpm: round2(trueRpm), grade: gradeFor(trueRpm) },
      mode: { id: mode.id, label: mode.label, description: mode.description },
      market: { origin: originRole, destination: destRole, region, regionNote: regionOverlay.note },
      recommendation: {
        floorBid, winBid, askBid,
        floorRpm: round2(floorRpm), winRpm: round2(winRpm), askRpm: round2(askRpm),
        verdict, action
      },
      risk: { score: Math.min(100, Math.round(risk * 100)), flags },
      override: { effectiveDate: RATE_OVERRIDE_2026_05.effectiveDate, bandNote: band.note }
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
    panel.innerHTML = '<h3>Midwest Stack v2 Authority</h3>' +
      '<label for="mwBidMode">Bid mode</label>' +
      '<select id="mwBidMode" aria-label="Midwest Stack bid mode">' +
      '<option value="REALISTIC_WIN" selected>Realistic Win — compressed board</option>' +
      '<option value="PROTECT_FLOOR">Protect Floor — business-health pricing</option>' +
      '<option value="ESCAPE_RECOVERY">Escape / Recovery — position first</option>' +
      '<option value="DEAD_ZONE">Dead Zone Exit — manual gate only</option>' +
      '</select>' +
      '<div id="mwStackAuthorityResult" style="margin-top:12px"></div>';
    evalOutput.parentNode.insertBefore(panel, evalOutput.nextSibling);

    const ids = ['mwBidMode','mwRevenue','mwLoadedMi','mwDeadMi','mwOrigin','mwDest','mwLoadNotes'];
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
    if (!result.input.loadedMiles && !result.input.revenue) {
      box.innerHTML = '<div class="muted" style="font-size:12px">Enter revenue and miles to get realistic bid guidance.</div>';
      return;
    }
    const flags = result.risk.flags.length ? result.risk.flags.map(f => '<li>' + escapeHtml(f) + '</li>').join('') : '<li>No major overlay flags yet.</li>';
    box.innerHTML = '<div class="grid2">' +
      '<div class="pill"><span>Posted True RPM</span><b>$' + result.posted.trueRpm.toFixed(2) + '</b></div>' +
      '<div class="pill"><span>Grade</span><b>' + result.posted.grade + '</b></div>' +
      '<div class="pill"><span>Realistic win</span><b>' + money(result.recommendation.winBid) + '</b></div>' +
      '<div class="pill"><span>Ask</span><b>' + money(result.recommendation.askBid) + '</b></div>' +
      '</div>' +
      '<div style="margin-top:10px;font-weight:800">' + escapeHtml(result.recommendation.verdict) + '</div>' +
      '<div class="muted" style="font-size:12px;margin-top:4px">' + escapeHtml(result.recommendation.action) + '</div>' +
      '<div class="muted" style="font-size:12px;margin-top:8px">Destination: ' + escapeHtml(result.market.destination.label) + ' · Region: ' + escapeHtml(result.market.region) + '</div>' +
      '<ul style="font-size:12px;margin:8px 0 0 18px;padding:0">' + flags + '</ul>';
  }

  function escapeHtml(s){
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  window.FreightLogicMidwestStack = Object.freeze({
    version: VERSION,
    updatedAt: UPDATED_AT,
    config: CONFIG,
    rateOverride: RATE_OVERRIDE_2026_05,
    assessLoad,
    classifyMarket
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensureUi, { once: true });
  else ensureUi();
  setTimeout(ensureUi, 800);
})();
