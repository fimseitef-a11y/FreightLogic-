import test from 'node:test';
import assert from 'node:assert/strict';

import { materializeLane } from '../ingest.mjs';
import { requireWriteSuccess } from '../pipeline.mjs';
import { consumePrimaryBatch } from '../queue.mjs';

function message(body) {
  const calls = [];
  return {
    id: 'msg-audit',
    body,
    attempts: 2,
    calls,
    ack() { calls.push('ack'); },
    retry() { calls.push('retry'); },
  };
}

test('AUD-ELI-05 stale operator evidence is excluded from active counts when a fresh row exists', () => {
  const lane = materializeLane({
    laneKey: 'MKT-ATL|MKT-DTW',
    originMarket: 'MKT-ATL',
    destinationMarket: 'MKT-DTW',
    stage: 'Pilot Candidate',
    unknownFlags: [],
  }, [
    { statusKey: 'COMPLETED', duplicateClass: 'NONE_KNOWN', observedAt: '2026-10-01' },
    { statusKey: 'AWARDED_ACCEPTED', duplicateClass: 'NONE_KNOWN', observedAt: '2026-07-01' },
  ], {
    now: '2026-10-02T12:00:00Z',
    modelRunId: 'run:audit',
    governanceFingerprint: 'gov:audit',
  });

  assert.equal(lane.freshness.OPERATOR_PRIVATE, 'FRESH');
  assert.equal(lane.evidenceCounts.OPERATOR_COMPLETED, 1);
  assert.equal(lane.evidenceCounts.OPERATOR_AWARDED_ACCEPTED, undefined);
  assert.equal(lane.evidenceCounts.OPERATOR_STALE_EXCLUDED, 1);
  assert.ok(lane.unknownFlags.includes('OPERATOR_STALE_EVIDENCE_EXCLUDED'));
});

test('AUD-ELI-06 failed D1 writes are never treated as successful control-plane updates', () => {
  assert.throws(() => requireWriteSuccess({ success: false }, 'replace aliases'), /replace aliases/i);
  assert.deepEqual(requireWriteSuccess({ success: true, meta: { changes: 1 } }, 'replace aliases'), { success: true, meta: { changes: 1 } });
});

test('AUD-ELI-08/09 primary consumer claims a lease before work, completes before ack, and retains retry attempts', async () => {
  const msg = message({ type: 'NORMALIZE_EVIDENCE', idempotencyKey: 'ev:audit', evidenceId: 'ev:audit' });
  const order = [];

  await consumePrimaryBatch({ messages: [msg] }, {
    claimReceipt: async (receipt) => {
      order.push(`claim:${receipt.idempotencyKey}:${receipt.attemptHint}`);
      return { status: 'ACQUIRED', leaseToken: 'lease-audit', attemptCount: 2 };
    },
    processMessage: async () => { order.push('process'); },
    completeReceipt: async (receipt) => { order.push(`complete:${receipt.leaseToken}:${receipt.attemptCount}`); },
    abandonReceipt: async () => { order.push('abandon'); },
    now: () => '2026-10-02T12:00:00Z',
  });

  assert.deepEqual(order, ['claim:ev:audit:2', 'process', 'complete:lease-audit:2']);
  assert.deepEqual(msg.calls, ['ack']);
});

test('AUD-ELI-08/09 an in-flight duplicate retries without running side effects', async () => {
  const msg = message({ type: 'NORMALIZE_EVIDENCE', idempotencyKey: 'ev:inflight', evidenceId: 'ev:inflight' });
  let processed = 0;

  await consumePrimaryBatch({ messages: [msg] }, {
    claimReceipt: async () => ({ status: 'IN_FLIGHT', attemptCount: 3 }),
    processMessage: async () => { processed += 1; },
    completeReceipt: async () => {},
    abandonReceipt: async () => {},
    now: () => '2026-10-02T12:00:00Z',
  });

  assert.equal(processed, 0);
  assert.deepEqual(msg.calls, ['retry']);
});
