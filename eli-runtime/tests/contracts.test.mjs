import test from 'node:test';
import assert from 'node:assert/strict';

import {
  LIFECYCLE_STATES,
  SOURCE_CLASSES,
  validateOutcomeEvent,
} from '../contracts.mjs';
import { buildEvidenceIdentity } from '../identity.mjs';

test('posting identity includes platform id origin destination and pickup', () => {
  const a = buildEvidenceIdentity({ platform: 'dispatchland', postingId: '1131989', origin: 'Jackson, WI', destination: 'Rogers, AR', pickup: '2026-09-14T12:00:00-05:00', lineage: 'quote' });
  const b = buildEvidenceIdentity({ platform: 'dispatchland', postingId: '1131989', origin: 'Jackson, WI', destination: 'Rogers, AR', pickup: '2026-09-15T12:00:00-05:00', lineage: 'quote' });
  assert.notEqual(a, b);
});

test('quote and order lineage never share an identity without explicit linkage', () => {
  const base = { platform: 'dispatchland', postingId: '191679', origin: 'Jackson, WI', destination: 'Rogers, AR', pickup: '2026-09-14' };
  assert.notEqual(buildEvidenceIdentity({ ...base, lineage: 'quote' }), buildEvidenceIdentity({ ...base, lineage: 'order' }));
});

test('lifecycle preserves tracked states', () => {
  for (const state of ['SHOWN','BID','WON','LOST','EXPIRED','REJECTED','DRY_RUN','DEACTIVATED','IN_PROGRESS','COMPLETED','PAID']) assert.ok(LIFECYCLE_STATES.includes(state));
});

test('source classes are explicit', () => {
  assert.deepEqual(SOURCE_CLASSES, ['STRUCTURAL_PUBLIC','OPERATOR_PRIVATE','LICENSED_LIVE_OPTIONAL']);
});

test('outcome allowlist rejects economics fields', () => {
  for (const field of ['rate','rpm','revenue','payout','settlement','fuel','costPerMile','paymentAccount']) {
    assert.throws(() => validateOutcomeEvent({ status: 'BID', [field]: 1 }), /forbidden/i);
  }
});

test('outcome accepts allowlisted lifecycle evidence', () => {
  assert.deepEqual(validateOutcomeEvent({ correlationToken: 'load-1', status: 'COMPLETED', observedAt: '2026-09-30T20:00:00Z' }), { correlationToken: 'load-1', status: 'COMPLETED', observedAt: '2026-09-30T20:00:00Z' });
});
