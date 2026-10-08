// Airtable client retry: transient failures (timeout/exception, 429, 5xx) are
// retried with backoff; permanent answers are not. Production ingestion failed
// on 2026-10-05..08 because one timed-out request ended the whole run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchAirtableRecords } from '../airtable.mjs';

const base = { token: 'patSECRET.value', baseId: 'app8nbbqxfyP0uswo', tableId: 'tblp0W75s9pqmrDmA' };
const ok = () => new Response(JSON.stringify({ records: [{ id: 'rec1', fields: {} }] }), { status: 200 });

test('a thrown request (timeout) is retried and then succeeds', async () => {
  let calls = 0; const sleeps = [];
  const records = await fetchAirtableRecords({ ...base, sleepImpl: async (ms) => { sleeps.push(ms); },
    fetchImpl: async () => { calls += 1; if (calls < 3) throw new Error('The operation was aborted'); return ok(); } });
  assert.equal(records.length, 1);
  assert.equal(calls, 3);
  assert.deepEqual(sleeps, [2000, 6000]);
});

test('429 and 5xx are retried', async () => {
  for (const status of [429, 500, 503]) {
    let calls = 0;
    const records = await fetchAirtableRecords({ ...base, sleepImpl: async () => {},
      fetchImpl: async () => { calls += 1; return calls === 1 ? new Response('', { status }) : ok(); } });
    assert.equal(records.length, 1, `status ${status}`);
    assert.equal(calls, 2, `status ${status}`);
  }
});

test('permanent errors are not retried and never leak the token', async () => {
  for (const status of [401, 403, 404, 422]) {
    let calls = 0;
    await assert.rejects(
      fetchAirtableRecords({ ...base, sleepImpl: async () => {}, fetchImpl: async () => { calls += 1; return new Response('', { status }); } }),
      (e) => e.message === `AIRTABLE_HTTP_${status}:tblp0W75s9pqmrDmA` && !/patSECRET/.test(e.message));
    assert.equal(calls, 1, `status ${status}`);
  }
});

test('gives up after the bounded number of attempts with the original error', async () => {
  let calls = 0;
  await assert.rejects(
    fetchAirtableRecords({ ...base, sleepImpl: async () => {}, fetchImpl: async () => { calls += 1; throw new Error('boom'); } }),
    /^AirtableError: AIRTABLE_REQUEST_FAILED:tblp0W75s9pqmrDmA$|AIRTABLE_REQUEST_FAILED:tblp0W75s9pqmrDmA/);
  assert.equal(calls, 3);
});

test('a retry on page 2 keeps page 1 and requests the same offset again', async () => {
  const urls = []; let failedOnce = false;
  const records = await fetchAirtableRecords({ ...base, sleepImpl: async () => {},
    fetchImpl: async (url) => {
      urls.push(new URL(url).searchParams.get('offset'));
      if (!new URL(url).searchParams.get('offset')) return new Response(JSON.stringify({ records: [{ id: 'a' }], offset: 'p2' }));
      if (!failedOnce) { failedOnce = true; throw new Error('reset'); }
      return new Response(JSON.stringify({ records: [{ id: 'b' }] }));
    } });
  assert.deepEqual(records.map((r) => r.id), ['a', 'b']);
  assert.deepEqual(urls, [null, 'p2', 'p2']);
});
