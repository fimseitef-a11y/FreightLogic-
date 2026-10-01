import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateSourceDegradation } from '../degradation.mjs';

const SOURCE_FIXTURES = Object.freeze([
  { sourceId: 'faf6', sourceClass: 'STRUCTURAL_PUBLIC', components: ['STRUCTURAL_OD'], available: true },
  { sourceId: 'cfs-pums', sourceClass: 'STRUCTURAL_PUBLIC', components: ['SMALL_LOAD_PROPENSITY'], available: true },
  { sourceId: 'qcew', sourceClass: 'STRUCTURAL_PUBLIC', components: ['INDUSTRY_CONTEXT'], available: true },
  { sourceId: 'synthetic-live-provider', sourceClass: 'LICENSED_LIVE_OPTIONAL', components: ['LIVE_OPERATIONAL_SIGNAL'], available: true },
]);

const REQUIRED_COMPONENTS = Object.freeze([
  'STRUCTURAL_OD',
  'SMALL_LOAD_PROPENSITY',
  'INDUSTRY_CONTEXT',
  'LIVE_OPERATIONAL_SIGNAL',
]);

test('T36 optional live-provider removal leaves service queryable and degrades only its component to UNKNOWN', () => {
  const result = evaluateSourceDegradation({
    sources: SOURCE_FIXTURES,
    removedSourceId: 'synthetic-live-provider',
    requiredComponents: REQUIRED_COMPONENTS,
  });

  assert.equal(result.queryable, true);
  assert.equal(result.components.LIVE_OPERATIONAL_SIGNAL.status, 'UNKNOWN');
  assert.equal(result.components.LIVE_OPERATIONAL_SIGNAL.reason, 'SOURCE_UNAVAILABLE');
  assert.equal(result.components.STRUCTURAL_OD.status, 'KNOWN');
  assert.equal(result.syntheticReplacementUsed, false);
});

for (const [sourceId, component] of [
  ['faf6', 'STRUCTURAL_OD'],
  ['cfs-pums', 'SMALL_LOAD_PROPENSITY'],
  ['qcew', 'INDUSTRY_CONTEXT'],
]) {
  test(`T36 removal of ${sourceId} leaves service queryable and ${component} UNKNOWN`, () => {
    const result = evaluateSourceDegradation({
      sources: SOURCE_FIXTURES,
      removedSourceId: sourceId,
      requiredComponents: REQUIRED_COMPONENTS,
    });

    assert.equal(result.queryable, true);
    assert.equal(result.components[component].status, 'UNKNOWN');
    assert.equal(result.components[component].reason, 'SOURCE_UNAVAILABLE');
    assert.equal(result.syntheticReplacementUsed, false);
  });
}

test('T36 never treats an unavailable component as zero confidence or fabricates a replacement source', () => {
  const result = evaluateSourceDegradation({
    sources: SOURCE_FIXTURES,
    removedSourceId: 'faf6',
    requiredComponents: REQUIRED_COMPONENTS,
  });

  assert.equal(result.components.STRUCTURAL_OD.confidence, null);
  assert.equal(result.components.STRUCTURAL_OD.sourceId, null);
  assert.notEqual(result.components.STRUCTURAL_OD.confidence, 0);
});
