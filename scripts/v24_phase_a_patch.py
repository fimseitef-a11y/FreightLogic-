from pathlib import Path


def replace_once(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {count}")
    p.write_text(text.replace(old, new, 1))


def insert_after(path, anchor, addition, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly 1 anchor, found {count}")
    p.write_text(text.replace(anchor, anchor + addition, 1))


def replace_between(path, start_marker, end_marker, replacement, label):
    p = Path(path)
    text = p.read_text()
    start = text.find(start_marker)
    if start < 0:
        raise SystemExit(f"{label}: start marker not found")
    end = text.find(end_marker, start)
    if end < 0:
        raise SystemExit(f"{label}: end marker not found")
    if text.find(start_marker, start + 1) >= 0:
        raise SystemExit(f"{label}: start marker not unique")
    p.write_text(text[:start] + replacement + text[end:])


# ---------------------------------------------------------------------------
# app.js — v24.0 canonical deterministic decision contract.
# ---------------------------------------------------------------------------
anchor = "if (typeof window !== 'undefined') window.isDeadZoneEligible = isDeadZoneEligible;\n"
engine = r'''

// ================================================================================
// v24.0 — Unified Decision Engine contract
// The client is the single verdict/grade authority. Existing USA/Midwest/AI
// systems are evidence/adapters and must not publish a competing authoritative
// decision. This first v24 slice centralizes the result contract + grade
// authority while the remaining hard-gate math is migrated behind it in-place.
// No timestamps or ambient reads occur here: identical inputs yield identical
// output, which makes this object suitable for regression tests and later
// predicted-vs-actual calibration.
// ================================================================================
const UNIFIED_DECISION_SCHEMA_VERSION = '24.0.0';

function deriveUnifiedGrade(trueRPM, { isDZActive = false, dzSubTier = null } = {}){
  const rpm = Number.isFinite(Number(trueRPM)) ? Number(trueRPM) : 0;
  let raw;
  if (rpm >= 1.75) raw = { grade:'A', gradeLabel:'PREMIUM WIN', gradeColor:'#34d399', gradeEmoji:'🟢' };
  else if (rpm >= 1.60) raw = { grade:'B', gradeLabel:'STRONG ACCEPT', gradeColor:'var(--good)', gradeEmoji:'🟢' };
  else if (rpm >= 1.50) raw = { grade:'C', gradeLabel:'CONDITIONAL', gradeColor:'var(--warn)', gradeEmoji:'🟡' };
  else if (rpm >= 1.40) raw = { grade:'D', gradeLabel:'WEAK — NEGOTIATE', gradeColor:'#fb923c', gradeEmoji:'🟠' };
  else if (rpm >= 1.25) raw = { grade:'E', gradeLabel:'STRATEGIC ONLY', gradeColor:'#f87171', gradeEmoji:'🔴' };
  else raw = { grade:'F', gradeLabel:'REJECT', gradeColor:'var(--bad)', gradeEmoji:'🔴' };

  const display = isDZActive
    ? { grade:'C', gradeLabel:dzSubTier || 'DZ-EXIT', gradeColor:'#f0a500', gradeEmoji:'🟠' }
    : { ...raw };
  return { raw, display };
}

function buildUnifiedDecisionContract(input){
  const economics = Object.freeze({
    trueRPM: input.trueRPM, loadedRPM: input.loadedRPM, totalMi: input.totalMi,
    loadedMi: input.loadedMi, deadMi: input.deadMi, deadheadPct: input.deadheadPct,
    revenue: input.revenue, effectiveRevenue: input.effectiveRevenue,
    fuel: input.fuel, netAfterFuel: input.netAfterFuel,
    operatingCost: input.operatingCost, totalCost: input.totalCost,
    operationalProfit: input.operationalProfit, trueProfit: input.trueProfit,
    profitMarginPct: input.profitMarginPct, breakEvenRPM: input.breakEvenRPM,
    profitPerMile: input.profitPerMile, profitPerHour: input.profitPerHour,
    fuelPerMile: input.fuelPerMile, estHours: input.estHours, opCPM: input.opCPM,
  });
  const deadZone = Object.freeze({
    active: !!input.isDZActive, eligible: !!input.isDZEligible,
    subTier: input.dzSubTier || null, check: input.dzCheck || null,
    floorRPM: input.dzFloor, noReloadConfirmed: !!input.noReloadConfirmed,
  });
  const grades = deriveUnifiedGrade(economics.trueRPM, { isDZActive: deadZone.active, dzSubTier: deadZone.subTier });
  const authority = Object.freeze({
    source: 'CLIENT_UNIFIED_DECISION_ENGINE',
    verdict: input.verdict,
    reason: input.verdictReason || '',
    grade: grades.display.grade,
    gradeLabel: grades.display.gradeLabel,
    gradeColor: grades.display.gradeColor,
    gradeEmoji: grades.display.gradeEmoji,
    rawGrade: grades.raw.grade,
    rawGradeLabel: grades.raw.gradeLabel,
    rawGradeColor: grades.raw.gradeColor,
    rawGradeEmoji: grades.raw.gradeEmoji,
    tier: input.tier,
    floorRPM: input.floorRPM,
  });
  const usaEvidence = input.usaResult ? Object.freeze({ ...input.usaResult, authorityRole: 'EVIDENCE_ONLY' }) : null;
  const decision = {
    schemaVersion: UNIFIED_DECISION_SCHEMA_VERSION,
    authority,
    economics,
    route: Object.freeze({ origin: input.origin || '', destination: input.dest || '', geo: input.geo || null }),
    market: Object.freeze({ usaEvidence, crossBorder: input.crossBorder || null, urgency: input.urgency || null }),
    personalIntel: Object.freeze({
      score: Number(input.usaResult?.personalScore || 0),
      bullets: Array.isArray(input.usaResult?.personalBullets) ? input.usaResult.personalBullets.slice() : [],
    }),
    risk: Object.freeze({
      steps: Array.isArray(input.steps) ? input.steps.slice() : [],
      warnings: Array.isArray(input.warnings) ? input.warnings.slice() : [],
    }),
    bid: Object.freeze({ range: input.bidRange || null }),
    operations: Object.freeze({
      velocityMode: input.velocityMode, velocityDetail: input.velocityDetail,
      velocityFloor: input.velocityFloor, postDeliveryCmd: input.postDeliveryCmd,
      postDeliveryDetail: input.postDeliveryDetail, turnoverType: input.turnoverType,
      repoSuggestion: input.repoSuggestion || '',
    }),
    context: Object.freeze({
      weeklyGross: input.weeklyGross, fatigue: input.fatigue,
      effectiveStrategic: !!input.effectiveStrategic, effectiveReason: input.effectiveReason || '',
      verdictColors: input.verdictColors, verdictLabels: input.verdictLabels,
    }),
    deadZone,
  };
  return Object.freeze(decision);
}

function unifiedDecisionToLegacy(decision){
  const a = decision.authority, e = decision.economics, r = decision.route;
  const m = decision.market, o = decision.operations, c = decision.context, dz = decision.deadZone;
  return {
    trueRPM:e.trueRPM, loadedRPM:e.loadedRPM, totalMi:e.totalMi, loadedMi:e.loadedMi, deadMi:e.deadMi,
    deadheadPct:e.deadheadPct, revenue:e.revenue, effectiveRevenue:e.effectiveRevenue,
    tier:a.tier,
    grade:a.rawGrade, gradeLabel:a.rawGradeLabel, gradeColor:a.rawGradeColor, gradeEmoji:a.rawGradeEmoji,
    verdict:a.verdict, verdictReason:a.reason, verdictColors:c.verdictColors, verdictLabels:c.verdictLabels,
    steps:decision.risk.steps,
    fuel:e.fuel, netAfterFuel:e.netAfterFuel, operatingCost:e.operatingCost, totalCost:e.totalCost,
    operationalProfit:e.operationalProfit, trueProfit:e.trueProfit, profitMarginPct:e.profitMarginPct,
    breakEvenRPM:e.breakEvenRPM, profitPerMile:e.profitPerMile, profitPerHour:e.profitPerHour,
    fuelPerMile:e.fuelPerMile, estHours:e.estHours, opCPM:e.opCPM,
    weeklyGross:c.weeklyGross, repoSuggestion:o.repoSuggestion, geo:r.geo, fatigue:c.fatigue,
    origin:r.origin, dest:r.destination, floorRPM:a.floorRPM,
    effectiveStrategic:c.effectiveStrategic, effectiveReason:c.effectiveReason,
    usaResult:m.usaEvidence, urgency:m.urgency, bidRange:decision.bid.range, crossBorder:m.crossBorder,
    velocityMode:o.velocityMode, velocityDetail:o.velocityDetail, velocityFloor:o.velocityFloor,
    postDeliveryCmd:o.postDeliveryCmd, postDeliveryDetail:o.postDeliveryDetail,
    turnoverType:o.turnoverType, warnings:decision.risk.warnings,
    isDZActive:dz.active, isDZEligible:dz.eligible, dzSubTier:dz.subTier, dzCheck:dz.check, dzFloor:dz.floorRPM,
    dzDisplayGrade:a.grade, dzDisplayGradeLabel:a.gradeLabel, dzDisplayGradeColor:a.gradeColor, dzDisplayGradeEmoji:a.gradeEmoji,
    noReloadConfirmed:dz.noReloadConfirmed,
    _canonicalDecision: decision,
  };
}

function unifiedDecisionForAI(decision){
  if (!decision) return null;
  return {
    schemaVersion: decision.schemaVersion,
    authority: {
      source: decision.authority.source,
      verdict: decision.authority.verdict,
      reason: decision.authority.reason,
      grade: decision.authority.grade,
      gradeLabel: decision.authority.gradeLabel,
      floorRPM: decision.authority.floorRPM,
    },
    economics: {
      trueRPM: decision.economics.trueRPM,
      loadedRPM: decision.economics.loadedRPM,
      totalMi: decision.economics.totalMi,
      deadMi: decision.economics.deadMi,
      profitMarginPct: decision.economics.profitMarginPct,
      breakEvenRPM: decision.economics.breakEvenRPM,
    },
    route: decision.route,
    personalIntel: { score: decision.personalIntel.score },
    risk: { warnings: decision.risk.warnings.slice(0, 6).map(w => w?.text || String(w || '')) },
    deadZone: { active: decision.deadZone.active, subTier: decision.deadZone.subTier },
  };
}
'''
insert_after('app.js', anchor, engine, 'insert unified decision engine')

# Centralize grade authority in deriveUnifiedGrade().
start_marker = "  // ════════════════════════════════════════════════════\n  // DECISION GRADE (A–F based on True RPM)\n"
end_marker = "  // Override display verdict with intelligence engine result\n"
grade_replacement = r'''  // ════════════════════════════════════════════════════
  // DECISION GRADE — v24 canonical grade authority
  // ════════════════════════════════════════════════════
  const gradeState = deriveUnifiedGrade(trueRPM, { isDZActive, dzSubTier });
  const { grade, gradeLabel, gradeColor, gradeEmoji } = gradeState.raw;
  const {
    grade: dzDisplayGrade,
    gradeLabel: dzDisplayGradeLabel,
    gradeColor: dzDisplayGradeColor,
    gradeEmoji: dzDisplayGradeEmoji,
  } = gradeState.display;

'''
replace_between('app.js', start_marker, end_marker, grade_replacement, 'replace grade authority block')

# Mark the legacy USA score/verdict as evidence-only rather than a competing authority.
replace_once(
    'app.js',
    "  return {\n    score, usaGrade, usaVerdict, usaColor,",
    "  return {\n    authorityRole: 'EVIDENCE_ONLY',\n    score, usaGrade, usaVerdict, usaColor,",
    'USA engine evidence role'
)
replace_once(
    'app.js',
    "USA Engine • ${escapeHtml(u.modeConf.label)} Mode",
    "Market Evidence • ${escapeHtml(u.modeConf.label)} Mode",
    'USA panel heading'
)
replace_once(
    'app.js',
    "<span style=\"font-size:12px;font-weight:700;color:${u.usaColor}\">${escapeHtml(u.usaVerdict)}</span>",
    "<span style=\"font-size:12px;font-weight:700;color:${u.usaColor}\">Signal: ${escapeHtml(u.usaVerdict)}</span>",
    'USA panel advisory signal label'
)

# Replace the legacy ad-hoc result assembly with the canonical contract and adapter.
start_marker = "  const _decision = {\n"
end_marker = "  mwRenderWeekStructure(weeklyGross);\n"
contract_block = r'''  const unifiedDecision = buildUnifiedDecisionContract({
    trueRPM, loadedRPM, totalMi, loadedMi, deadMi, deadheadPct, revenue, effectiveRevenue,
    tier, verdict, verdictReason, verdictColors, verdictLabels, steps,
    fuel, netAfterFuel, operatingCost, totalCost, operationalProfit,
    trueProfit, profitMarginPct, breakEvenRPM,
    profitPerMile, profitPerHour, fuelPerMile, estHours, opCPM,
    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,
    floorRPM, effectiveStrategic, effectiveReason,
    usaResult, urgency, bidRange, crossBorder,
    velocityMode, velocityDetail, velocityFloor,
    postDeliveryCmd, postDeliveryDetail,
    turnoverType, warnings,
    isDZActive, isDZEligible, dzSubTier, dzCheck, dzFloor, noReloadConfirmed,
  });
  _mwRenderDecision(out, unifiedDecisionToLegacy(unifiedDecision));
'''
replace_between('app.js', start_marker, end_marker, contract_block, 'canonical result assembly')

# Send a compact canonical decision to Worker AI review.
replace_once(
    'app.js',
    "          strategic: !!effectiveStrategic, strategicReason: effectiveReason || '',\n        };",
    "          strategic: !!effectiveStrategic, strategicReason: effectiveReason || '',\n          canonicalDecision: unifiedDecisionForAI(d?._canonicalDecision),\n        };",
    'attach canonical decision to AI payload'
)

# ---------------------------------------------------------------------------
# midwest-stack-authority.js — explicit adapter/evidence status.
# ---------------------------------------------------------------------------
replace_once(
    'midwest-stack-authority.js',
    "    return {\n      version: VERSION,",
    "    return {\n      authorityRole: 'ADAPTER_ONLY',\n      version: VERSION,",
    'midwest result adapter role'
)
replace_once(
    'midwest-stack-authority.js',
    "    panel.innerHTML = '<h3>Bid Strategy</h3>' +",
    "    panel.innerHTML = '<h3>Bid Strategy · Advisory</h3>' +\n      '<div class=\"muted\" style=\"font-size:11px;margin-bottom:8px\">Canonical decision above is authoritative; this panel is supporting market/bid evidence.</div>' +",
    'midwest advisory heading'
)
replace_once(
    'midwest-stack-authority.js',
    "      '<div style=\"margin-top:10px;font-weight:800;color:' + verdictColor + '\">' + escapeHtml(result.recommendation.verdict) + '</div>' +",
    "      '<div style=\"margin-top:10px;font-weight:800;color:' + verdictColor + '\">Signal: ' + escapeHtml(result.recommendation.verdict) + '</div>' +",
    'midwest signal label'
)
replace_once(
    'midwest-stack-authority.js',
    "  window.FreightLogicMidwestStack = Object.freeze({\n    version: VERSION,",
    "  window.FreightLogicMidwestStack = Object.freeze({\n    authorityRole: 'ADAPTER_ONLY',\n    version: VERSION,",
    'midwest exported adapter role'
)

# ---------------------------------------------------------------------------
# cloud-backup-worker.js — AI reviews/challenges client authority; never owns it.
# ---------------------------------------------------------------------------
replace_once(
    'cloud-backup-worker.js',
    "const SYSTEM_PROMPT = `You are a Midwest Stack freight decision advisor for an expedited cargo van carrier operating in the US.\nYour job is to evaluate a single load using the Midwest Stack operating framework.\n",
    "const SYSTEM_PROMPT = `You are the review/explanation layer for FreightLogic, an expedited cargo van decision app.\nThe client-supplied canonical decision is authoritative for verdict and grade. Your job is to explain it, identify risks, and challenge weak assumptions — never independently recalculate or override the authoritative verdict/grade.\n",
    'worker system authority contract'
)
replace_once(
    'cloud-backup-worker.js',
    "VERDICT DEFINITIONS:\n- ACCEPT: True RPM meets or exceeds professional floor, broker history clean, destination has reload potential\n- NEGOTIATE: Load has merit but rate is soft — provide a specific dollar counter-offer\n- PASS: True RPM below minimum viable, broker unreliable, or destination is a known trap with no exit\n- STRATEGIC_ONLY: Below-floor but tactically justified (reposition, relationship, weather avoidance)\n\n",
    "AUTHORITY RULE:\n- The canonical client decision's verdict and grade are facts for this review, not fields you may replace.\n- If you disagree, set agreement to CHALLENGE and explain the exact assumption/data that should be rechecked.\n- Never manufacture a second authoritative verdict or grade.\n\n",
    'worker remove independent verdict definitions'
)
replace_once(
    'cloud-backup-worker.js',
    "  \"verdict\": \"ACCEPT | NEGOTIATE | PASS | STRATEGIC_ONLY\",\n  \"grade\": \"A | B | C | D | E\",\n  \"trueRpmBand\": \"$X.XX – $X.XX / true mile\",",
    "  \"agreement\": \"AGREE | CHALLENGE\",\n  \"challenge\": \"empty string when AGREE; otherwise the exact assumption/data to recheck\",\n  \"trueRpmBand\": \"$X.XX – $X.XX / true mile\",",
    'worker response schema review-only'
)
replace_once(
    'cloud-backup-worker.js',
    "    field('driver_notes', promptField(p.notes || 'none', 200)),\n  ];",
    "    field('driver_notes', promptField(p.notes || 'none', 200)),\n    field('authoritative_verdict', promptField(p.canonicalDecision?.authority?.verdict || 'missing', 30)),\n    field('authoritative_grade', promptField(p.canonicalDecision?.authority?.grade || 'missing', 10)),\n    field('authoritative_reason', promptField(p.canonicalDecision?.authority?.reason || 'missing', 200)),\n    field('decision_schema', promptField(p.canonicalDecision?.schemaVersion || 'missing', 20)),\n  ];",
    'worker prompt canonical fields'
)

# Add canonical-to-compat mapping helper before output sanitizers.
marker = "// ─── Output sanitizers ────────────────────────────────────────────────────────\n"
helper = r'''
function canonicalVerdictToAi(v){
  const s = String(v || '').toUpperCase();
  if (s === 'ACCEPT') return 'ACCEPT';
  if (s === 'STRATEGIC' || s === 'DZ-EXIT') return 'STRATEGIC_ONLY';
  return 'PASS';
}
function canonicalGrade(g){
  const s = String(g || '').toUpperCase().trim();
  return /^[A-E]$/.test(s) ? s : 'C';
}

'''
insert_after('cloud-backup-worker.js', marker, helper, 'worker canonical mapping helpers')

old_ai = """          ai: {\n            summary:       String(parsed.summary       || '').slice(0, 500),\n            verdict:       validateVerdict(parsed.verdict),\n            grade:         validateGrade(parsed.grade),\n            trueRpmBand:   String(parsed.trueRpmBand   || '').slice(0, 80),\n            bidAdvice:     String(parsed.bidAdvice      || '').slice(0, 300),\n            primaryReason: String(parsed.primaryReason || '').slice(0, 200),\n            risks:         sanitizeList(parsed.risks),\n            positives:     sanitizeList(parsed.positives),\n            nextMove:      String(parsed.nextMove       || '').slice(0, 200)\n          },"""
new_ai = """          ai: {\n            summary:       String(parsed.summary       || '').slice(0, 500),\n            // v24: compatibility fields are projected FROM client authority, never AI-owned.\n            verdict:       canonicalVerdictToAi(payload.canonicalDecision?.authority?.verdict),\n            grade:         canonicalGrade(payload.canonicalDecision?.authority?.grade),\n            authority:     'CLIENT_UNIFIED_DECISION_ENGINE',\n            agreement:     String(parsed.agreement || 'AGREE').toUpperCase() === 'CHALLENGE' ? 'CHALLENGE' : 'AGREE',\n            challenge:     String(parsed.challenge || '').slice(0, 300),\n            trueRpmBand:   String(parsed.trueRpmBand   || '').slice(0, 80),\n            bidAdvice:     String(parsed.bidAdvice      || '').slice(0, 300),\n            primaryReason: String(parsed.primaryReason || '').slice(0, 200),\n            risks:         sanitizeList(parsed.risks),\n            positives:     sanitizeList(parsed.positives),\n            nextMove:      String(parsed.nextMove       || '').slice(0, 200)\n          },"""
replace_once('cloud-backup-worker.js', old_ai, new_ai, 'worker response authority projection')

# Require the canonical decision for v24 AI review. This fails honestly instead
# of falling back to an AI-owned second verdict for stale clients.
replace_once(
    'cloud-backup-worker.js',
    "        if (!payload) {\n          return json({ ok: false, error: 'Invalid JSON payload' }, 400, cors);\n        }\n\n        const model = env.OPENAI_MODEL || 'gpt-4.1-mini';",
    "        if (!payload) {\n          return json({ ok: false, error: 'Invalid JSON payload' }, 400, cors);\n        }\n        if (!payload.canonicalDecision?.authority?.verdict || !payload.canonicalDecision?.authority?.grade) {\n          return json({ ok: false, error: 'Canonical client decision required for AI review. Local evaluation remains authoritative.' }, 400, cors);\n        }\n\n        const model = env.OPENAI_MODEL || 'gpt-4.1-mini';",
    'worker require canonical decision'
)

# ---------------------------------------------------------------------------
# Tests — register static authority-contract guard. Existing integration suite
# exercises the real renderer/AI button paths through the compatibility adapter.
# ---------------------------------------------------------------------------
test_path = Path('tests/unit/v24-unified-decision.spec.mjs')
test_path.write_text(r'''// v24.0 unified-decision architecture guard.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const source = p => readFileSync(path.join(ROOT, p), 'utf8');
const { test, run } = createSuite('unit/v24-unified-decision.spec.mjs');

test('[V24-01] app has one canonical decision contract and compatibility adapter', () => {
  const app = source('app.js');
  ok(app.includes("const UNIFIED_DECISION_SCHEMA_VERSION = '24.0.0'"), 'v24 decision schema missing');
  ok(app.includes('function buildUnifiedDecisionContract(input)'), 'canonical contract builder missing');
  ok(app.includes("source: 'CLIENT_UNIFIED_DECISION_ENGINE'"), 'client authority marker missing');
  ok(app.includes('function unifiedDecisionToLegacy(decision)'), 'legacy adapter missing');
  ok(app.includes('const unifiedDecision = buildUnifiedDecisionContract({'), 'evaluator must build the canonical result');
  ok(app.includes('_mwRenderDecision(out, unifiedDecisionToLegacy(unifiedDecision));'), 'renderer must consume canonical decision through adapter');
});

test('[V24-02] grade authority is centralized and DZ display cap is preserved', () => {
  const app = source('app.js');
  ok(app.includes('function deriveUnifiedGrade(trueRPM'), 'canonical grade function missing');
  ok(app.includes("? { grade:'C', gradeLabel:dzSubTier || 'DZ-EXIT'"), 'DZ C-cap must remain in canonical grade authority');
  ok(!app.includes("if (trueRPM >= 1.75){ grade = 'A';"), 'legacy inline grade ladder must not remain authoritative');
});

test('[V24-03] USA and Midwest engines are explicitly non-authoritative evidence/adapters', () => {
  const app = source('app.js');
  const mw = source('midwest-stack-authority.js');
  ok(app.includes("authorityRole: 'EVIDENCE_ONLY'"), 'USA engine evidence role missing');
  ok(app.includes('Market Evidence •'), 'USA panel must be labelled as evidence');
  ok(mw.includes("authorityRole: 'ADAPTER_ONLY'"), 'Midwest overlay adapter role missing');
  ok(mw.includes('Canonical decision above is authoritative'), 'Midwest UI must identify canonical authority');
});

test('[V24-04] Worker AI cannot own verdict or grade', () => {
  const worker = source('cloud-backup-worker.js');
  ok(worker.includes('canonicalDecision?.authority?.verdict'), 'Worker must receive canonical verdict');
  ok(worker.includes("authority:     'CLIENT_UNIFIED_DECISION_ENGINE'"), 'Worker response authority marker missing');
  ok(worker.includes('canonicalVerdictToAi(payload.canonicalDecision?.authority?.verdict)'), 'Worker compatibility verdict must project client authority');
  ok(worker.includes('canonicalGrade(payload.canonicalDecision?.authority?.grade)'), 'Worker compatibility grade must project client authority');
  ok(worker.includes('Canonical client decision required for AI review'), 'Worker must fail closed when client authority is absent');
  ok(!worker.includes('verdict:       validateVerdict(parsed.verdict)'), 'AI-parsed verdict must not remain authoritative');
  ok(!worker.includes('grade:         validateGrade(parsed.grade)'), 'AI-parsed grade must not remain authoritative');
});

test('[V24-05] AI payload carries a compact canonical decision, not a second calculation request', () => {
  const app = source('app.js');
  ok(app.includes('function unifiedDecisionForAI(decision)'), 'compact AI projection missing');
  ok(app.includes('canonicalDecision: unifiedDecisionForAI(d?._canonicalDecision)'), 'AI payload must carry canonical client decision');
});

export async function runSpec(){ return await run(); }
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
''')

replace_once(
    'tests/run-all.mjs',
    "import { runSpec as preV24Integrity } from './unit/pre-v24-integrity.spec.mjs';\n",
    "import { runSpec as preV24Integrity } from './unit/pre-v24-integrity.spec.mjs';\nimport { runSpec as v24UnifiedDecision } from './unit/v24-unified-decision.spec.mjs';\n",
    'register v24 import'
)
replace_once(
    'tests/run-all.mjs',
    "  preV24Integrity,\n];",
    "  preV24Integrity,\n  v24UnifiedDecision,\n];",
    'register v24 spec'
)

# Roadmap progress note — architecture guard remains unchanged.
replace_once(
    'docs/V24_ROADMAP.md',
    "1. **v24.0 Unified Decision Engine** — one deterministic result object inside `app.js`.\n",
    "1. **v24.0 Unified Decision Engine** — one deterministic result object inside `app.js`. **In progress:** canonical result contract + grade authority + legacy-render adapter + Worker AI authority separation are the first migration slice.\n",
    'roadmap v24 progress note'
)

# Self-remove; the Actions commit stages this deletion so no patch machinery remains.
Path('scripts/v24_phase_a_patch.py').unlink()
