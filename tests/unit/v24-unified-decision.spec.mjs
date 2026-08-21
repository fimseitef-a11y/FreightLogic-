// v24.0 unified-decision architecture guard.
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
  ok(app.includes('function deriveUnifiedAuthority(facts, policy = UNIFIED_DECISION_POLICY)'), 'canonical hard-gate authority function missing');
  ok(app.includes("if (!input?.authorityResult?.verdict) throw new Error('Canonical authorityResult is required')"), 'decision contract must reject legacy verdict injection');
  ok(!app.includes('let verdict = tier.verdict;'), 'legacy inline verdict authority must be removed');
  ok(app.includes('function deriveUnifiedEconomics(facts)'), 'canonical economics function missing');
  ok(app.includes('function deriveUnifiedBid(totalMiles, opts={})'), 'canonical bid function missing');
  ok(app.includes("if (!input?.economicsResult) throw new Error('Canonical economicsResult is required')"), 'contract must reject legacy economics injection');
  ok(app.includes("if (!input?.bidResult) throw new Error('Canonical bidResult is required')"), 'contract must reject legacy bid injection');
  ok(!app.includes('const fuel = mwFuelCost(totalMi);'), 'evaluator must not use fixed-default fuel economics');
  ok(app.includes("getSetting('fuelPrice', MW.fuelBaseline)"), 'evaluator must read current fuelPrice setting');
  ok(app.includes("getSetting('vehicleMpg', MW.mpg)"), 'evaluator must read current vehicleMpg setting');
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
  ok(!worker.includes('Professional floor: $1.60/mi'), 'Worker must not inject a competing generic RPM floor');
  ok(!worker.includes('IRS mileage deduction: $0.725/mi (2026)'), 'Worker review must not carry stale flat tax-rate context');
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
