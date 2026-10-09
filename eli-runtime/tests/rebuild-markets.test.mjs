// Rebuild script for evidence_index markets: dry-run report, guarded SQL, idempotency.
import test from 'node:test';
import assert from 'node:assert/strict';
import { aliasMapFromD1, planRebuild, rowsFrom } from '../scripts/rebuild-evidence-markets.mjs';

const aliases = [
  { alias_text: 'Milwaukee, WI', market_cluster: 'MKT-MKE' },
  { alias_text: 'St. Louis, MO', market_cluster: 'MKT-STL' },
  { alias_text: 'Columbus, OH', market_cluster: 'MKT-CMH' },
];
const evidence = [
  { evidence_id: 'ev:1', origin: 'Saint Louis MO', destination: 'Milwaukee WI', origin_market: null, destination_market: 'MKT-MKE', lane_key: null },
  { evidence_id: 'ev:2', origin: 'Unknown Origin', destination: 'Unknown Destination', origin_market: null, destination_market: null, lane_key: null },
  { evidence_id: 'ev:3', origin: 'Columbus, IN', destination: 'Ohio Turnpike', origin_market: null, destination_market: null, lane_key: null },
  { evidence_id: 'ev:4', origin: null, destination: null, origin_market: null, destination_market: null, lane_key: null },
];

test('RB01 dry-run report counts real mentions, matches, flags and changed rows', () => {
  const { report, statements } = planRebuild(evidence, aliasMapFromD1(aliases));
  assert.equal(report.mentions, 6);
  assert.equal(report.realMentions, 4, 'Unknown placeholders are not real mentions');
  assert.equal(report.matchedBefore, 1);
  assert.equal(report.matchedAfter, 2);
  assert.equal(report.bothResolvedBefore, 0);
  assert.equal(report.bothResolvedAfter, 1);
  assert.equal(report.mentionsLost, 0);
  assert.deepEqual(report.flags, { UNKNOWN_PLACEHOLDER: 2, ROAD: 1 });
  assert.equal(statements.length, 1);
  assert.match(statements[0], /origin_market = 'MKT-STL'/);
  assert.match(statements[0], /lane_key = 'MKT-STL\|MKT-MKE'/);
  assert.match(statements[0], /WHERE evidence_id = 'ev:1' AND superseded = 0 AND \(lane_key IS NOT/);
});

test('RB02 idempotent: applying the plan and re-planning yields zero statements', () => {
  const map = aliasMapFromD1(aliases);
  const { statements } = planRebuild(evidence, map);
  assert.ok(statements.length > 0);
  const applied = evidence.map((row) => {
    if (row.evidence_id !== 'ev:1') return row;
    return { ...row, origin_market: 'MKT-STL', lane_key: 'MKT-STL|MKT-MKE' };
  });
  assert.equal(planRebuild(applied, map).statements.length, 0);
});

test('RB03 an unresolvable input is written as NULL, never guessed; Columbus IN stays UNKNOWN', () => {
  const map = aliasMapFromD1(aliases);
  const stale = [{ evidence_id: 'ev:x', origin: 'Columbus, IN', destination: 'Milwaukee WI', origin_market: 'MKT-CMH', destination_market: 'MKT-MKE', lane_key: 'MKT-CMH|MKT-MKE' }];
  const { report, statements } = planRebuild(stale, map);
  assert.equal(report.mentionsLost, 1, 'a wrong stored match is reported, not hidden');
  assert.match(statements[0], /lane_key = NULL, origin_market = NULL/);
});

test('RB04 accepts wrangler d1 --json output and plain arrays', () => {
  assert.deepEqual(rowsFrom('[{"results":[{"a":1}],"success":true}]'), [{ a: 1 }]);
  assert.deepEqual(rowsFrom([{ a: 2 }]), [{ a: 2 }]);
});
