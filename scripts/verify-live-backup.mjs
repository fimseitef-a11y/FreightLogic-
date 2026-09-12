#!/usr/bin/env node
/**
 * FreightLogic — live backup / delta / restore round-trip verification (M7 gate 2).
 *
 *   FL_BACKUP_TOKEN=flk_... node scripts/verify-live-backup.mjs [workerOrigin]
 *
 * WHY THIS EXISTS
 * Gate 2's PASS criteria require that "authenticated /evaluate, /extract where
 * enabled, backup/full-delta/restore smokes preserve the canonical contracts."
 * `verify-cloudflare-parity.mjs` covers the deployed generation, /health and
 * admin denial. `verify-live-authority.mjs` covers the /evaluate + /extract
 * authority boundary. NOTHING covered backup / delta / restore — the half most
 * likely to fail silently, and the half carrying the live X-01 defect.
 *
 * THE CHECK THAT MATTERS: deployed v7 has POST /backup/delta but NO
 * GET /backup/delta. Deltas are written and can never be read back, so
 * cloudPullBackup() can only ever restore the last full snapshot and any delta
 * pruned by the 20-key cap or the 7-day TTL is permanently lost (AUDIT_REPORT.md
 * P-04). A version string in /health does not prove that endpoint exists. A
 * round trip does.
 *
 * SAFETY — READ THIS BEFORE RUNNING.
 * The Worker namespaces every key as `user:<userId>:device:<deviceId>:…`. This
 * script therefore writes ONLY under a freshly generated synthetic device id
 * (`fl-verify-<random>`), so it cannot read, overwrite or delete anything
 * belonging to the operator's real device. It never calls DELETE against a real
 * device id, and it cleans up its own synthetic namespace when finished.
 *
 * DATA. Every payload is synthetic and opaque (the Worker never inspects
 * payload contents — real backups are client-side encrypted). No operator trip,
 * broker, rate or lane data is sent to the network by this script.
 *
 * AUTH. The token is read from FL_BACKUP_TOKEN only, never argv, so it stays
 * out of shell history and process listings. It is never printed.
 *
 * EXIT CODES — matching verify-live-authority.mjs, because an unobserved check
 * is not a product failure and must never be recorded as one:
 *   0  all attempted checks passed
 *   1  a real FAILURE — the deployed Worker does not honour the contract
 *   2  UNOBSERVED — origin unreachable, or no token supplied
 */

const args = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith('-'));
const workerOrigin = (positional[0] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');
const token = process.env.FL_BACKUP_TOKEN || '';

// A synthetic device id, unique per run. This is the isolation boundary: every
// key this script creates lives under it, so nothing the operator owns is
// reachable. The Worker sanitises to [A-Za-z0-9_-] and 64 chars; stay inside that.
const DEVICE = `fl-verify-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

const checks = [];
let unreachable = false;

function pass(name, detail = '') { checks.push({ state: 'PASS', name, detail }); }
function fail(name, detail = '') { checks.push({ state: 'FAIL', name, detail }); }
function skip(name, detail = '') { checks.push({ state: 'SKIP', name, detail }); }
function assert(name, cond, detail = '') { cond ? pass(name) : fail(name, detail); }

/**
 * All requests go through here so the non-Worker-response detection is applied
 * uniformly. An interposed proxy or WAF answers at the HTTP layer, so `fetch`
 * RESOLVES rather than throwing, and a 403 from a corporate egress proxy is
 * indistinguishable from a Worker reply unless the body is inspected. Every
 * real Worker JSON reply carries `ok`; `GET /backup` is the one exception,
 * because it returns the raw stored payload rather than a JSON envelope.
 */
async function req(method, path, { body, raw = false, auth = true, device = DEVICE } = {}) {
  const headers = {};
  if (auth && token) headers['X-Backup-Token'] = token;
  if (device) headers['X-Device-Id'] = device;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  try {
    const res = await fetch(`${workerOrigin}${path}`, {
      method, headers, body,
      signal: AbortSignal.timeout(30000),
    });
    const text = await res.text();
    if (raw) return { ok: res.ok, status: res.status, text };
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    if (!json || typeof json !== 'object' || !('ok' in json)) {
      unreachable = true;
      return { ok: false, status: 0, json: null, text,
        error: `HTTP ${res.status} with a non-Worker body — request did not reach the Worker` };
    }
    return { ok: res.ok, status: res.status, json, text };
  } catch (e) {
    unreachable = true;
    return { ok: false, status: 0, json: null, error: String((e && e.message) || e) };
  }
}

/* ── synthetic payloads ───────────────────────────────────────────────────── */
// Shaped like a real client payload envelope so a Worker that inspects
// structure behaves as it would in production, but carrying no real data.
const stamp = new Date().toISOString();
const fullPayload = JSON.stringify({
  meta: { app: 'FreightLogic', verify: true, kind: 'full', savedAt: stamp },
  synthetic: 'gate-2 backup round-trip probe — not operator data',
  filler: 'x'.repeat(256),
});
const deltaPayloads = [1, 2].map(n => JSON.stringify({
  meta: { app: 'FreightLogic', verify: true, kind: 'delta', seq: n, savedAt: stamp },
  synthetic: `gate-2 delta probe ${n} — not operator data`,
}));

async function run() {
  console.log('== FreightLogic live backup / delta / restore verification (gate 2) ==\n');
  console.log(`Worker:           ${workerOrigin}`);
  console.log(`Synthetic device: ${DEVICE}`);
  console.log('All writes are namespaced to that device id. Operator data is untouched.\n');

  if (!token) {
    skip('every check', 'FL_BACKUP_TOKEN is not set');
    return report();
  }
  if (!/^flk_[a-f0-9]{32}$/.test(token)) {
    console.log('  note: FL_BACKUP_TOKEN is not in flk_+32hex form; v14 rejects it before any KV access.\n');
  }

  /* 1. Baseline — a fresh synthetic device must have no backups. Also the
        cheapest proof that auth works at all. */
  const status0 = await req('GET', '/status');
  if (unreachable) return report();
  assert('GET /status authenticates', status0.json?.ok === true,
         `status ${status0.status}: ${status0.json?.error ?? status0.error ?? 'no body'}`);
  if (status0.json?.ok !== true) return report();
  assert('fresh synthetic device starts with no backups', status0.json.hasBackup === false,
         `hasBackup=${status0.json.hasBackup} — device id collision?`);

  /* 2. Full backup write + read-back, byte-exact. This is "restore" at the
        Worker boundary: whatever bytes went in must come back unchanged, or
        client-side decryption fails on a real payload. */
  const put = await req('POST', '/backup', { body: fullPayload });
  if (unreachable) return report();
  assert('POST /backup accepted', put.json?.ok === true,
         `status ${put.status}: ${put.json?.error ?? 'no body'}`);
  assert('POST /backup reports the stored size', put.json?.size === fullPayload.length,
         `reported ${put.json?.size}, sent ${fullPayload.length}`);

  const got = await req('GET', '/backup', { raw: true });
  if (unreachable) return report();
  assert('GET /backup returns the snapshot', got.status === 200, `status ${got.status}`);
  assert('snapshot round-trips BYTE-EXACT', got.text === fullPayload,
         'returned payload differs from what was stored — restore would corrupt');

  /* 3. THE X-01 / P-04 CHECK. Write two deltas, then read them back. On
        deployed v7 this GET does not exist and the request falls through to a
        404 "Not found" — the defect that makes every synced delta unreadable. */
  for (let i = 0; i < deltaPayloads.length; i++) {
    const d = await req('POST', '/backup/delta', { body: deltaPayloads[i] });
    if (unreachable) return report();
    assert(`POST /backup/delta #${i + 1} accepted`, d.json?.ok === true,
           `status ${d.status}: ${d.json?.error ?? 'no body'}`);
  }

  const deltas = await req('GET', '/backup/delta');
  if (unreachable) return report();
  assert('GET /backup/delta EXISTS (X-01 / P-04)', deltas.json?.ok === true,
         `status ${deltas.status}: ${deltas.json?.error ?? 'no body'} — ` +
         'deployed v7 has no such route, so deltas are write-only and unrecoverable');

  if (deltas.json?.ok === true) {
    const list = Array.isArray(deltas.json.deltas) ? deltas.json.deltas : [];
    assert('both deltas are retained', list.length === deltaPayloads.length,
           `returned ${list.length}, wrote ${deltaPayloads.length}`);

    const bodies = list.map(d => d && d.payload);
    assert('deltas round-trip byte-exact', deltaPayloads.every(p => bodies.includes(p)),
           'a returned delta payload does not match what was written');

    // Order is part of the contract: mergeRestoreData() applies deltas in
    // sequence, so oldest-first is required for a correct restore.
    const seqs = bodies.map(b => { try { return JSON.parse(b)?.meta?.seq; } catch { return null; } });
    const ordered = seqs.filter(s => typeof s === 'number');
    assert('deltas are chronological oldest-first',
           ordered.length === deltaPayloads.length &&
           ordered.every((s, i) => i === 0 || s >= ordered[i - 1]),
           `sequence returned as [${seqs.join(', ')}] — out-of-order application corrupts a restore`);

    // The gap-detection contract: without these two counters the client cannot
    // distinguish a complete restore from one missing pruned deltas, which is
    // the silent-data-loss case X-01 Phase 4 existed to remove.
    assert('retainedCount is reported', Number.isFinite(deltas.json.retainedCount),
           `got ${JSON.stringify(deltas.json.retainedCount)}`);
    assert('totalCreated is reported (gap detection)', Number.isFinite(deltas.json.totalCreated),
           `got ${JSON.stringify(deltas.json.totalCreated)} — without it a pruned-delta gap is invisible`);
    if (Number.isFinite(deltas.json.totalCreated) && Number.isFinite(deltas.json.retainedCount)) {
      assert('totalCreated >= retainedCount', deltas.json.totalCreated >= deltas.json.retainedCount,
             `totalCreated=${deltas.json.totalCreated} < retainedCount=${deltas.json.retainedCount}`);
    }
  }

  /* 4. Listing and status reflect what was written. */
  const listed = await req('GET', '/list');
  if (unreachable) return report();
  assert('GET /list authenticates', listed.json?.ok === true, `status ${listed.status}`);
  if (listed.json?.ok === true) {
    const keys = Array.isArray(listed.json.backups) ? listed.json.backups : [];
    assert('listing is scoped to this synthetic device',
           keys.length > 0 && keys.every(k => String(k).includes(DEVICE)),
           'a key outside the synthetic device namespace appeared — isolation is not holding');
  }

  const status1 = await req('GET', '/status');
  if (!unreachable) {
    assert('GET /status now reports a backup', status1.json?.hasBackup === true,
           `hasBackup=${status1.json?.hasBackup}`);
  }

  /* 5. Auth boundaries on the data plane. A malformed token must be rejected
        BEFORE any KV access (v14) — v7 performs the lookup regardless (P-06). */
  const badTok = await fetch(`${workerOrigin}/status`, {
    method: 'GET',
    headers: { 'X-Backup-Token': 'flk_notavalidtokenatall', 'X-Device-Id': DEVICE },
    signal: AbortSignal.timeout(30000),
  }).then(r => r.status).catch(() => 0);
  if (badTok === 0) skip('malformed token is rejected', 'request did not complete');
  else assert('malformed token is rejected', badTok === 403 || badTok === 401, `status ${badTok}`);

  const noTok = await fetch(`${workerOrigin}/status`, {
    method: 'GET', headers: { 'X-Device-Id': DEVICE },
    signal: AbortSignal.timeout(30000),
  }).then(r => r.status).catch(() => 0);
  if (noTok === 0) skip('tokenless request is denied', 'request did not complete');
  else assert('tokenless request is denied', noTok === 401, `status ${noTok}`);

  /* 6. Clean up THIS SCRIPT'S synthetic namespace only. DELETE /backup removes
        `…:backup:` keys for the supplied device id — here, the synthetic one.
        It does not remove `…:delta:` keys; those expire on their own 7-day TTL. */
  const cleaned = await req('DELETE', '/backup');
  if (!unreachable) {
    assert('synthetic backups cleaned up', cleaned.json?.ok === true,
           `status ${cleaned.status}: ${cleaned.json?.error ?? 'no body'}`);
  }

  return report();
}

function report() {
  console.log('-- results --');
  for (const c of checks) {
    const mark = c.state === 'PASS' ? 'PASS' : c.state === 'FAIL' ? 'FAIL' : 'SKIP';
    console.log(`  ${mark}  ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
  }
  const passed = checks.filter(c => c.state === 'PASS').length;
  const failed = checks.filter(c => c.state === 'FAIL').length;
  const skipped = checks.filter(c => c.state === 'SKIP').length;
  console.log(`\n  ${passed} passed, ${failed} failed, ${skipped} skipped\n`);

  if (!token) {
    console.log('  UNOBSERVED — set FL_BACKUP_TOKEN to a real driver token to run this gate.');
    console.log('  Use a token you can revoke afterwards. Never paste it into a PR or an issue.\n');
    process.exit(2);
  }
  if (unreachable) {
    console.log('  UNOBSERVED — the Worker could not be reached from this network.');
    console.log('  This is evidence about the network, NOT a product failure. Do not record it as one.');
    console.log('  Deltas written before the failure expire on their own 7-day TTL.\n');
    process.exit(2);
  }
  if (failed) {
    console.log('  FAILED — the deployed Worker does not honour the backup/delta/restore contract.');
    console.log('  If "GET /backup/delta EXISTS" is among the failures, the deployed Worker predates');
    console.log('  v11 and X-01 is live: synced deltas are unreadable and pruned ones are already lost.\n');
    process.exit(1);
  }
  console.log('  PASS — backup, delta and restore contracts hold on the deployed Worker.');
  console.log('  Together with verify-cloudflare-parity.mjs and verify-live-authority.mjs,');
  console.log('  this completes the authenticated half of gate 2.\n');
  process.exit(0);
}

run().catch(e => {
  console.error(`\nunexpected error: ${(e && e.message) || e}`);
  process.exit(2);
});
