// Legacy driver-token audit — the classifier that decides whether a v7-minted
// credential is still live, and the workflow's authority. Pure + static; no
// network. The live answer comes from dispatching the workflow.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';
import { classifyUser, legacyIndexIsLive, verdictFor, V14_DEPLOYED_AT }
  from '../../scripts/audit-legacy-tokens.mjs';

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const sha = (s) => createHash('sha256').update(s).digest('hex');
const { test, run } = createSuite('unit/legacy-token-audit.spec.mjs');

test('[LTA-01] a plaintext token on an active record is a live v7 credential', () => {
  eq(classifyUser({ active: true, token: 'flk_' + 'a'.repeat(32), createdAt: '2026-09-20T00:00:00Z' }),
    'LEGACY_PLAINTEXT', 'plaintext outranks any timestamp');
  eq(classifyUser({ active: false, token: 'flk_' + 'a'.repeat(32) }), 'INACTIVE', 'revoked authenticates nothing');
});

test('[LTA-02] the v14 boundary is exact, and a rotation after it clears a pre-v14 account', () => {
  const before = new Date(Date.parse(V14_DEPLOYED_AT) - 1000).toISOString();
  eq(classifyUser({ active: true, tokenHash: 'x', createdAt: before }), 'PRE_V14', 'migrated v7 bytes are still exposed');
  eq(classifyUser({ active: true, tokenHash: 'x', createdAt: V14_DEPLOYED_AT }), 'CURRENT', 'issued by v14');
  eq(classifyUser({ active: true, tokenHash: 'x', createdAt: before, rotatedAt: '2026-09-20T00:00:00Z' }),
    'CURRENT', 'rotated or re-claimed after v14');
  eq(classifyUser({ active: true, tokenHash: 'x', createdAt: before, rotatedAt: '2026-09-01T00:00:00Z' }),
    'PRE_V14', 'a rotation before v14 was still a v7 credential');
});

test('[LTA-03] an unprovable age is reported, never assumed clean', () => {
  eq(classifyUser({ active: true, tokenHash: 'x' }), 'UNKNOWN_AGE', 'missing createdAt');
  eq(classifyUser({ active: true, tokenHash: 'x', createdAt: 'garbage' }), 'UNKNOWN_AGE', 'unparseable createdAt');
  eq(classifyUser(undefined), 'UNKNOWN_AGE', 'unreadable record');
  eq(verdictFor({ legacyPlaintext: [], preV14: [], unknownAge: ['u1'], liveLegacyIndex: 0 }).verdict, 'FINDINGS');
  eq(verdictFor({ legacyPlaintext: [], preV14: [], unknownAge: [], liveLegacyIndex: 0 }).code, 0);
});

test('[LTA-04] a legacy token: index entry is live only if the user record names its hash', () => {
  const t = 'flk_' + 'b'.repeat(32);
  ok(legacyIndexIsLive(t, { userId: 'u1', active: true }, { active: true, tokenHash: sha(t) }), 'current hash → live');
  ok(legacyIndexIsLive(t, { userId: 'u1', active: true }, { active: true, token: t }), 'plaintext on user → live');
  ok(!legacyIndexIsLive(t, { userId: 'u1', active: true }, { active: true, tokenHash: sha('other') }), 'superseded → dead');
  ok(!legacyIndexIsLive(t, { userId: 'u1', active: true }, { active: false, tokenHash: sha(t) }), 'revoked user → dead');
  ok(!legacyIndexIsLive(t, { userId: 'u1', active: true }, null), 'no user → dead');
});

test('[LTA-05] the workflow is manual, read-only, and never writes to KV or prints a credential', () => {
  const wf = read('.github/workflows/audit-legacy-tokens.yml');
  ok(/^on:\s*\n\s+workflow_dispatch:\s*\n\s*\npermissions:/m.test(wf), 'manual dispatch only');
  ok(/permissions:\s*\n\s+contents: read/.test(wf), 'contents: read');
  const script = read('scripts/audit-legacy-tokens.mjs');
  ok(!/method:\s*['"](PUT|POST|DELETE|PATCH)/i.test(script), 'the audit must never write');
  ok(!/console\.log\([^)]*\bkey\b/.test(script), 'a KV key name must never be printed');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
