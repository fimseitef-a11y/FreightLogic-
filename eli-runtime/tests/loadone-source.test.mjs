import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  LOADONE_CRON,
  LOADONE_LIVE_SOURCE,
  isLoadOneActiveWindow,
  runLoadOneCollection,
} from '../adapters/loadone-live.mjs';

test('L01 Load One is optional, authorization-gated, and requests a 20-minute live cadence', () => {
  assert.equal(LOADONE_CRON, '*/20 * * * *');
  assert.equal(LOADONE_LIVE_SOURCE.sourceId, 'loadone-live');
  assert.equal(LOADONE_LIVE_SOURCE.sourceClass, 'LICENSED_LIVE_OPTIONAL');
  assert.equal(LOADONE_LIVE_SOURCE.desiredCadenceMinutes, 20);
  assert.equal(LOADONE_LIVE_SOURCE.authorizationRequired, true);
  assert.equal(LOADONE_LIVE_SOURCE.allowedCollectionMethod, 'DOCUMENTED_AUTHORIZED_FEED_ONLY');
  assert.equal(LOADONE_LIVE_SOURCE.requiredForServiceLiveness, false);
});

test('L02 active window is 06:00 inclusive to 22:00 exclusive in America/New_York during EDT', () => {
  assert.equal(isLoadOneActiveWindow('2026-10-01T09:59:00Z'), false); // 05:59 EDT
  assert.equal(isLoadOneActiveWindow('2026-10-01T10:00:00Z'), true);  // 06:00 EDT
  assert.equal(isLoadOneActiveWindow('2026-10-01T11:45:00Z'), true);  // 07:45 EDT
  assert.equal(isLoadOneActiveWindow('2026-10-02T01:40:00Z'), true);  // 21:40 EDT
  assert.equal(isLoadOneActiveWindow('2026-10-02T02:00:00Z'), false); // 22:00 EDT
});

test('L03 active window remains 06:00 Eastern after DST ends', () => {
  assert.equal(isLoadOneActiveWindow('2027-01-15T10:59:00Z'), false); // 05:59 EST
  assert.equal(isLoadOneActiveWindow('2027-01-15T11:00:00Z'), true);  // 06:00 EST
  assert.equal(isLoadOneActiveWindow('2027-01-16T02:40:00Z'), true);  // 21:40 EST
  assert.equal(isLoadOneActiveWindow('2027-01-16T03:00:00Z'), false); // 22:00 EST
});

test('L04 disabled ELI never collects Load One data', async () => {
  let fetchCalls = 0;
  const result = await runLoadOneCollection(
    { ELI_ENABLED: 'false', LOADONE_COLLECTION_AUTHORIZED: 'true' },
    {
      now: () => '2026-10-01T11:45:00Z',
      fetchImpl: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
    },
  );

  assert.deepEqual(result, { status: 'SKIPPED', reason: 'ELI_DISABLED' });
  assert.equal(fetchCalls, 0);
});

test('L05 unauthorized Load One collection fails closed without any provider request', async () => {
  let fetchCalls = 0;
  const result = await runLoadOneCollection(
    { ELI_ENABLED: 'true', LOADONE_COLLECTION_AUTHORIZED: 'false' },
    {
      now: () => '2026-10-01T11:45:00Z',
      fetchImpl: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
    },
  );

  assert.deepEqual(result, { status: 'SKIPPED', reason: 'LOADONE_UNAUTHORIZED' });
  assert.equal(fetchCalls, 0);
});

test('L06 overnight cron fails closed before provider authorization/config checks and never requests provider data', async () => {
  let fetchCalls = 0;
  const result = await runLoadOneCollection(
    { ELI_ENABLED: 'true', LOADONE_COLLECTION_AUTHORIZED: 'true' },
    {
      now: () => '2026-10-01T08:00:00Z', // 04:00 EDT
      fetchImpl: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
    },
  );

  assert.deepEqual(result, { status: 'SKIPPED', reason: 'LOADONE_OUTSIDE_ACTIVE_WINDOW' });
  assert.equal(fetchCalls, 0);
});

test('L07 even authorized collection stays fail-closed until a documented adapter is configured', async () => {
  let fetchCalls = 0;
  const result = await runLoadOneCollection(
    { ELI_ENABLED: 'true', LOADONE_COLLECTION_AUTHORIZED: 'true' },
    {
      now: () => '2026-10-01T12:00:00Z',
      fetchImpl: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
    },
  );

  assert.deepEqual(result, { status: 'SKIPPED', reason: 'LOADONE_DOCUMENTED_FEED_NOT_CONFIGURED' });
  assert.equal(fetchCalls, 0);
});

test('L08 Wrangler retains normal ELI ingestion cron and adds the Load One 20-minute trigger', async () => {
  const config = JSON.parse(await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
  const crons = config.triggers?.crons ?? [];
  assert.ok(crons.includes('23 */6 * * *'));
  assert.ok(crons.includes(LOADONE_CRON));
});
