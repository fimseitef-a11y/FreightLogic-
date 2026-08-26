// Unit coverage for scripts/lane-guard.mjs — the mechanical enforcement of
// /.agents/LANES.md ownership and the /AGENTS.md lock protocol.
//
// Pure functions only: no browser, no git, no network. The CLI wrappers around
// these are thin; the behavior worth protecting is here — fail-closed on an
// unclassifiable path, and a stale lock granting nothing to anyone including
// its own holder.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import {
  parseLanes, ownerForPath, checkOwnership,
  parseLock, lockIsStale, lockCovers, checkLocks,
  namespaceAgent, checkPrefix, REAP_GRACE_MS
} from '../../scripts/lane-guard.mjs';

const { test, run } = createSuite('unit/lane-guard.spec.mjs');

const LANES = [
  '| Top-level path | Owner | Notes |',
  '|---|---|---|',
  '| `.agents/` | SHARED | protocol |',
  '| `AGENTS.md` | SHARED | contract |',
  '| `app.js` | SHARED | serialized |',
  '| `scripts/` | claude | tooling |',
  '| `tests/` | claude | harness |',
  '| `styles.css` | gpt | presentation |',
  '| `docs/` | gpt | docs |'
].join('\n');

const rows = parseLanes(LANES);
const T0 = Date.parse('2026-08-26T12:00:00Z');
const lock = (over = {}) => ({
  name: 'x.lock', owner: 'claude', token: 'tok-1',
  started_utc: '2026-08-26T09:00:00Z',
  expected_release_utc: '2026-08-26T11:00:00Z',
  paths: ['app.js'], task: 't', ...over
});

test('parses every owner row and ignores header/separator lines', () => {
  eq(rows.length, 7, 'expected 7 ownership rows');
});

test('longest-prefix match resolves files, subtrees, and exact rows', () => {
  eq(ownerForPath(rows, 'scripts/lane-guard.mjs'), 'claude', 'subtree row');
  eq(ownerForPath(rows, 'app.js'), 'shared', 'exact row');
  eq(ownerForPath(rows, '.agents/LANES.md'), 'shared', '.agents/ subtree');
});

test('a path with no LANES.md row fails closed instead of being allowed', () => {
  eq(ownerForPath(rows, 'unlisted-file.js'), null, 'unlisted path must not resolve');
  const v = checkOwnership(rows, 'claude', ['unlisted-file.js']);
  eq(v.length, 1, 'one violation');
  eq(v[0].kind, 'unowned', 'must be reported as unowned');
});

test('editing the other agent\'s lane is a violation; editing your own is not', () => {
  const v = checkOwnership(rows, 'claude', ['styles.css']);
  eq(v.length, 1, 'gpt-owned path must be refused for claude');
  eq(v[0].kind, 'foreign-lane', 'kind');
  eq(checkOwnership(rows, 'gpt', ['styles.css']).length, 0, 'owner must not be blocked from its own lane');
});

test('a SHARED path is ownership-clean for both agents (locks decide it)', () => {
  eq(checkOwnership(rows, 'claude', ['app.js']).length, 0, 'claude');
  eq(checkOwnership(rows, 'gpt', ['app.js']).length, 0, 'gpt');
});

test('the five-field record already on agent-coordination still parses', () => {
  const r = parseLock([
    'owner: gpt',
    'token: 9f92c3ab-6a1e-4ec3-a585-d94d3a570823',
    'started_utc: 2026-08-23T22:40:00Z',
    'expected_release_utc: 2026-08-23T23:40:00Z',
    'task: behavior-preserving CSS seam'
  ].join('\n'), 'ui-style-seam.lock');
  eq(r.owner, 'gpt', 'owner');
  eq(r.token, '9f92c3ab-6a1e-4ec3-a585-d94d3a570823', 'token');
  eq(r.paths.length, 0, 'a legacy record declares no paths');
});

test('a lock that declares no paths covers nothing, so SHARED stays blocked', () => {
  const legacy = lock({ paths: [] });
  ok(!lockCovers(legacy, 'app.js'), 'undeclared lock must not cover app.js');
  const v = checkLocks(rows, 'claude', ['app.js'], [legacy], T0);
  eq(v.length, 1, 'one violation');
  eq(v[0].kind, 'no-lock', 'kind');
  ok(v[0].message.includes('declare no paths'), 'message should name the legacy record');
});

test('a held lock of ours covering the path passes', () => {
  eq(checkLocks(rows, 'claude', ['app.js'], [lock()], T0).length, 0, 'own held lock must pass');
});

test('a trailing slash covers a subtree; without one the match is exact', () => {
  ok(lockCovers(lock({ paths: ['.agents/'] }), '.agents/LANES.md'), 'subtree');
  ok(!lockCovers(lock({ paths: ['.agents'] }), '.agents/LANES.md'), 'no slash must be exact');
});

test('the other agent\'s held lock blocks us', () => {
  const v = checkLocks(rows, 'claude', ['app.js'], [lock({ owner: 'gpt' })], T0);
  eq(v.length, 1, 'one violation');
  eq(v[0].kind, 'held-by-other', 'kind');
});

test('staleness begins strictly after expected_release_utc + 2h', () => {
  const l = lock();
  const expiry = Date.parse(l.expected_release_utc);
  ok(!lockIsStale(l, expiry + REAP_GRACE_MS), 'exactly +2h must NOT be stale');
  ok(lockIsStale(l, expiry + REAP_GRACE_MS + 1), '+2h+1ms must be stale');
});

test('an unparseable expiry is treated as stale, not as an open grant', () => {
  ok(lockIsStale(lock({ expected_release_utc: 'soon' }), T0), 'undated lock must not grant coverage');
});

test('a stale lock grants nothing to its own holder and is never auto-stolen', () => {
  const stale = lock({ expected_release_utc: '2026-08-26T05:00:00Z' });
  const v = checkLocks(rows, 'claude', ['app.js'], [stale], T0);
  eq(v.length, 1, 'one violation');
  eq(v[0].kind, 'stale-lock', 'own stale lock must not pass');
  ok(v[0].message.includes('never auto-stolen'), 'message must state the no-steal rule');
});

test('one lock can cover several declared paths', () => {
  const multi = lock({ paths: ['AGENTS.md', '.agents/LANES.md'] });
  eq(checkLocks(rows, 'claude', ['AGENTS.md', '.agents/LANES.md'], [multi], T0).length, 0, 'multi-path lock');
});

test('a claude-owned path needs no lock at all', () => {
  eq(checkLocks(rows, 'claude', ['scripts/lane-guard.mjs'], [], T0).length, 0, 'own lane needs no lock');
});

test('all four declared branch namespaces resolve; a legacy branch does not', () => {
  eq(namespaceAgent('agent/claude/x'), 'claude', 'agent/claude/*');
  eq(namespaceAgent('claude/x'), 'claude', 'claude/* (harness-assigned)');
  eq(namespaceAgent('agent/gpt/x'), 'gpt', 'agent/gpt/*');
  eq(namespaceAgent('chatgpt/x'), 'gpt', 'chatgpt/*');
  eq(namespaceAgent('feat/v22-voice-load-addon'), null, 'legacy branch must not resolve');
});

test('commit prefix must match the branch namespace', () => {
  eq(checkPrefix('claude/x', [{ sha: 'a'.repeat(40), subject: '[claude] do a thing', parents: 1 }]).length, 0, 'correct prefix');
  const bad = checkPrefix('claude/x', [{ sha: 'b'.repeat(40), subject: '[gpt] do a thing', parents: 1 }]);
  eq(bad.length, 1, 'wrong prefix must be caught');
  eq(bad[0].kind, 'bad-prefix', 'kind');
});

test('merge commits are exempt from the prefix rule', () => {
  const v = checkPrefix('claude/x', [{ sha: 'c'.repeat(40), subject: 'Merge PR #99: sync roadmap', parents: 2 }]);
  eq(v.length, 0, 'forge-generated merge subject must not be flagged');
});

test('an undeclared branch namespace fails rather than passing silently', () => {
  const v = checkPrefix('wildcat/experiment', [{ sha: 'd'.repeat(40), subject: '[claude] x', parents: 1 }]);
  eq(v.length, 1, 'one violation');
  eq(v[0].kind, 'unknown-namespace', 'kind');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
