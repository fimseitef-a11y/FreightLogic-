import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeEvidence } from '../normalize.mjs';
import { deriveLaneIntelligence } from '../derive.mjs';
import { classifyFreshness } from '../freshness.mjs';
import { applyFreshnessToConfidence } from '../confidence.mjs';

test('normalizeEvidence preserves missing facts as null instead of zero', () => {
  const result = normalizeEvidence({
    sourceClass: 'STRUCTURAL_PUBLIC',
    component: 'structural',
    sourceId: 'faf6',
  });

  assert.equal(result.value, null);
  assert.equal(result.asOf, null);
  assert.equal(result.freshnessState, 'UNAVAILABLE');
});

test('classifyFreshness distinguishes fresh aging stale and unavailable', () => {
  const now = '2026-09-30T22:00:00Z';
  const policy = { freshForMs: 2 * 60 * 60 * 1000, staleAfterMs: 24 * 60 * 60 * 1000 };

  assert.equal(classifyFreshness({ sourceAsOf: '2026-09-30T21:00:00Z', now, ...policy }), 'FRESH');
  assert.equal(classifyFreshness({ sourceAsOf: '2026-09-30T16:00:00Z', now, ...policy }), 'AGING');
  assert.equal(classifyFreshness({ sourceAsOf: '2026-09-29T20:00:00Z', now, ...policy }), 'STALE');
  assert.equal(classifyFreshness({ sourceAsOf: null, now, ...policy }), 'UNAVAILABLE');
});

test('missing structural evidence remains UNKNOWN and never becomes zero', () => {
  const result = deriveLaneIntelligence([]);

  assert.equal(result.structuralScore, null);
  assert.equal(result.structuralStatus, 'UNKNOWN');
  assert.ok(result.unknownFlags.includes('STRUCTURAL_EVIDENCE_MISSING'));
});

test('operator-private history cannot determine national structural strength', () => {
  const result = deriveLaneIntelligence([
    {
      sourceClass: 'OPERATOR_PRIVATE',
      sourceId: 'load-history',
      component: 'structural',
      value: 0.95,
      asOf: '2026-09-30T20:00:00Z',
      freshnessState: 'FRESH',
    },
  ]);

  assert.equal(result.structuralScore, null);
  assert.equal(result.structuralStatus, 'UNKNOWN');
  assert.equal(result.operatorOverlay.evidenceCount, 1);
});

test('operator-private evidence does not change a supported public structural value', () => {
  const result = deriveLaneIntelligence([
    {
      sourceClass: 'STRUCTURAL_PUBLIC',
      sourceId: 'faf6',
      component: 'structural',
      value: 0.62,
      asOf: '2026-07-31T00:00:00Z',
      freshnessState: 'FRESH',
    },
    {
      sourceClass: 'OPERATOR_PRIVATE',
      sourceId: 'load-history',
      component: 'structural',
      value: 0.99,
      asOf: '2026-09-30T20:00:00Z',
      freshnessState: 'FRESH',
    },
  ]);

  assert.equal(result.structuralScore, 0.62);
  assert.equal(result.structuralStatus, 'KNOWN');
  assert.equal(result.operatorOverlay.evidenceCount, 1);
});

test('conflicting public structural values route to UNKNOWN instead of averaging', () => {
  const result = deriveLaneIntelligence([
    {
      sourceClass: 'STRUCTURAL_PUBLIC', sourceId: 'faf6', component: 'structural', value: 0.62,
      asOf: '2026-07-31T00:00:00Z', freshnessState: 'FRESH',
    },
    {
      sourceClass: 'STRUCTURAL_PUBLIC', sourceId: 'cfs', component: 'structural', value: 0.71,
      asOf: '2026-07-31T00:00:00Z', freshnessState: 'FRESH',
    },
  ]);

  assert.equal(result.structuralScore, null);
  assert.equal(result.structuralStatus, 'UNKNOWN');
  assert.ok(result.conflictFlags.includes('STRUCTURAL_EVIDENCE_CONFLICT'));
});

test('stale structural evidence degrades to UNKNOWN rather than last-seen live', () => {
  const result = deriveLaneIntelligence([
    {
      sourceClass: 'STRUCTURAL_PUBLIC', sourceId: 'faf6', component: 'structural', value: 0.62,
      asOf: '2026-07-31T00:00:00Z', freshnessState: 'STALE',
    },
  ]);

  assert.equal(result.structuralScore, null);
  assert.equal(result.structuralStatus, 'UNKNOWN');
  assert.ok(result.unknownFlags.includes('STRUCTURAL_EVIDENCE_STALE'));
});

test('stale confidence routes to UNKNOWN without inventing a numeric penalty', () => {
  assert.deepEqual(
    applyFreshnessToConfidence({ baseConfidence: 0.8, freshnessState: 'FRESH' }),
    { value: 0.8, status: 'KNOWN', freshnessState: 'FRESH' },
  );
  assert.deepEqual(
    applyFreshnessToConfidence({ baseConfidence: 0.8, freshnessState: 'STALE' }),
    { value: null, status: 'UNKNOWN', freshnessState: 'STALE' },
  );
});

test('audit: future or impossible timestamps cannot be classified as fresh evidence', () => {
  const policy = { freshForMs: 3600000, staleAfterMs: 86400000 };
  const now = '2026-10-02T12:00:00Z';
  for (const sourceAsOf of [
    '2026-10-03T12:00:00Z', '2026-02-30T12:00:00Z',
    '2026-10-02T24:00:00Z', '2026-10-02T12:60:00Z',
    '2026-10-02T12:00:60Z', '2026-10-02T12:00:00+14:30',
    '', false, 0, 'not a date',
  ]) {
    assert.equal(classifyFreshness({ sourceAsOf, now, ...policy }), 'UNAVAILABLE', String(sourceAsOf));
  }
  assert.equal(classifyFreshness({ sourceAsOf: '2024-02-29T12:00:00Z', now: '2024-02-29T12:00:00Z', ...policy }), 'FRESH');
  assert.equal(classifyFreshness({ sourceAsOf: '2026-10-02T08:00:00-04:00', now, ...policy }), 'FRESH');
  assert.equal(classifyFreshness({ sourceAsOf: now, now: '2026-02-30T12:00:00Z', ...policy }), 'UNAVAILABLE');
});
