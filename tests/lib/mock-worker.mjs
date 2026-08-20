// Combined static-file server + in-memory stand-in for cloud-backup-worker.js's
// driver-facing backup/delta/status endpoints, used ONLY by
// tests/integration/backup-restore-parity.spec.mjs (X-01/X-07 E2E).
//
// Why a mock instead of the real deployed Worker: this environment has no
// live Cloudflare account/KV binding to test against (see AUDIT_REPORT.md's
// "What could NOT be tested" — this was already true before v23.9 and
// remains true here). The real Worker is external infrastructure, not app
// logic, so standing in for it here is not the same thing this suite's own
// "no mocks... of app logic" rule is about (see tests/README.md) — every
// assertion in the paired spec still drives the REAL app.js client code
// (cloudPushBackup/cloudPullBackup/mergeRestoreData) against this server
// over real HTTP, real encryption (cloudEncrypt/cloudDecrypt use real
// crypto.subtle in the browser, this server never sees plaintext), and real
// IndexedDB. Only the Cloudflare KV storage layer itself is swapped for an
// in-memory Map, mirroring cloud-backup-worker.js's own key scheme
// (user:<id>:device:<id>:backup:<ts> / :delta:<ts>) and pruning rules
// (keep last 3 full backups, keep last 20 deltas) closely enough that the
// client code being tested can't tell the difference from its own request/
// response contract.
//
// This file is deliberately NOT cloud-backup-worker.js — it doesn't test the
// Worker's own code (rate limiting, admin auth, KV list() migration, etc.);
// it exists so the APP's restore-path logic has something real to talk to.
//
// Why this server ALSO serves the app's static files (unlike every other
// spec, which uses harness.mjs's shared http-server on its own port): the
// app's shipped CSP locks connect-src to the production Worker origin, and
// two different localhost ports are two different origins to both CSP and
// the browser's cross-origin/Private-Network-Access checks — which this
// sandboxed headless environment classifies unpredictably (observed:
// "blocked ... `unknown` address space" even between two loopback ports).
// Serving the app AND the mock API from the exact same origin sidesteps all
// of that: it's a same-origin fetch, already allowed by 'self' in the
// unmodified, shipped CSP — no CSP rewriting, no browser flags, no
// service-worker workarounds needed, and the real index.html is used
// completely unmodified.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8', '.webmanifest': 'application/manifest+json',
};

export function startMockWorker() {
  const kv = new Map(); // key -> string value (mirrors env.BACKUPS)
  const TOKEN = 'flk_' + 'a'.repeat(32);
  const USER_ID = 'u_mockuser';

  function ptrKey(deviceId, type) { return `user:${USER_ID}:device:${deviceId}:${type}ptr`; }
  function getPtr(deviceId, type) {
    const raw = kv.get(ptrKey(deviceId, type));
    return raw ? JSON.parse(raw) : { keys: [], count: 0, totalCreated: 0 };
  }
  function savePtr(deviceId, type, ptr) { kv.set(ptrKey(deviceId, type), JSON.stringify(ptr)); }
  function deltaTsFromKey(key) {
    const raw = key.slice(key.lastIndexOf(':delta:') + ':delta:'.length);
    const m = raw.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/);
    return m ? `${m[1]}T${m[2]}:${m[3]}:${m[4]}.${m[5]}Z` : raw;
  }

  // Test-control knob: when true, GET /backup/delta pretends every delta but
  // the most recent was pruned (simulates TTL/cap eviction) so the
  // confirmedGap path can be exercised deterministically.
  let forceGapOnNextDeltaFetch = false;

  // Test-control knob (7C, Phase 7): the reported /health version, mirroring
  // cloud-backup-worker.js's own version:'11' field. Overridable so
  // tests/integration/health-badge.spec.mjs can exercise the mismatch path.
  let healthVersion = '11';

  const API_PATHS = new Set(['/backup', '/backup/delta', '/status', '/health']);

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    // Everything that isn't one of this mock's own API paths (or its
    // test-control endpoints) is served as a static file, mirroring
    // tests/lib/harness.mjs's http-server for every other spec.
    if (!API_PATHS.has(p) && !p.startsWith('/__test__/')) {
      const rel = p === '/' ? '/index.html' : p;
      const filePath = path.join(REPO_ROOT, decodeURIComponent(rel));
      if (!filePath.startsWith(REPO_ROOT)) { res.writeHead(403); res.end(); return; }
      try {
        const data = await readFile(filePath);
        res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
        res.end(data);
      } catch {
        res.writeHead(404); res.end('Not found');
      }
      return;
    }

    const cors = {
      'Access-Control-Allow-Origin': req.headers.origin || '*',
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Device-Id, X-Backup-Token, X-Admin-Token',
      'Content-Type': 'application/json',
    };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }

    // Test-only control endpoints (not part of the real Worker contract).
    if (p === '/__test__/force-gap') {
      forceGapOnNextDeltaFetch = true;
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true })); return;
    }
    if (p === '/__test__/reset') {
      kv.clear(); forceGapOnNextDeltaFetch = false; healthVersion = '11';
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true })); return;
    }
    if (p === '/__test__/set-health-version') {
      const body = await new Promise((resolve) => { let d = ''; req.on('data', c => d += c); req.on('end', () => resolve(d)); });
      try { healthVersion = JSON.parse(body).version; } catch {}
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, healthVersion })); return;
    }

    // GET /health — unauthenticated liveness check, mirrors the real
    // cloud-backup-worker.js route exactly (no token/device headers required).
    if (req.method === 'GET' && p === '/health') {
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, version: healthVersion, ts: new Date().toISOString() })); return;
    }

    const token = req.headers['x-backup-token'];
    const deviceId = (req.headers['x-device-id'] || 'default');
    if (token !== TOKEN) { res.writeHead(403, cors); res.end(JSON.stringify({ ok: false, error: 'Invalid token' })); return; }

    const body = await new Promise((resolve) => {
      let data = '';
      req.on('data', c => data += c);
      req.on('end', () => resolve(data));
    });

    if (req.method === 'POST' && p === '/backup') {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const key = `user:${USER_ID}:device:${deviceId}:backup:${ts}`;
      kv.set(key, body);
      const ptr = getPtr(deviceId, 'b');
      ptr.keys.push(key);
      if (ptr.keys.length > 3) ptr.keys.splice(0, ptr.keys.length - 3).forEach(k => kv.delete(k));
      ptr.count = ptr.keys.length;
      savePtr(deviceId, 'b', ptr);
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, key, size: body.length })); return;
    }

    if (req.method === 'POST' && p === '/backup/delta') {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const key = `user:${USER_ID}:device:${deviceId}:delta:${ts}`;
      kv.set(key, body);
      const ptr = getPtr(deviceId, 'd');
      ptr.totalCreated = (ptr.totalCreated || ptr.keys.length) + 1;
      ptr.keys.push(key);
      if (ptr.keys.length > 20) ptr.keys.splice(0, ptr.keys.length - 20).forEach(k => kv.delete(k));
      ptr.count = ptr.keys.length;
      savePtr(deviceId, 'd', ptr);
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, key, size: body.length, type: 'delta' })); return;
    }

    if (req.method === 'GET' && p === '/backup') {
      const ptr = getPtr(deviceId, 'b');
      if (!ptr.keys.length) { res.writeHead(404, cors); res.end(JSON.stringify({ ok: false, error: 'No backup found' })); return; }
      const data = kv.get(ptr.keys[ptr.keys.length - 1]);
      res.writeHead(200, cors); res.end(data); return;
    }

    if (req.method === 'GET' && p === '/backup/delta') {
      const ptr = getPtr(deviceId, 'd');
      let keys = ptr.keys;
      let totalCreated = ptr.totalCreated || ptr.keys.length;
      if (forceGapOnNextDeltaFetch) {
        // Simulate every delta but the newest having expired/been evicted.
        keys = ptr.keys.slice(-1);
        forceGapOnNextDeltaFetch = false;
      }
      const deltas = keys.map(k => ({ key: k, ts: deltaTsFromKey(k), payload: kv.get(k) })).filter(d => d.payload);
      res.writeHead(200, cors);
      res.end(JSON.stringify({ ok: true, deltas, retainedCount: keys.length, totalCreated }));
      return;
    }

    if (req.method === 'GET' && p === '/status') {
      const ptr = getPtr(deviceId, 'b');
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, hasBackup: ptr.count > 0, count: ptr.count, user: 'Mock Driver' })); return;
    }

    if (req.method === 'DELETE' && p === '/backup') {
      const ptr = getPtr(deviceId, 'b');
      ptr.keys.forEach(k => kv.delete(k));
      savePtr(deviceId, 'b', { keys: [], count: 0 });
      res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, deleted: ptr.keys.length })); return;
    }

    res.writeHead(404, cors); res.end(JSON.stringify({ ok: false, error: 'Not found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const url = `http://127.0.0.1:${port}`;
      resolve({
        url,
        appUrl: `${url}/index.html`,
        token: TOKEN,
        forceGap: async () => { await fetch(`${url}/__test__/force-gap`); },
        reset: async () => { await fetch(`${url}/__test__/reset`); },
        setHealthVersion: async (version) => { await fetch(`${url}/__test__/set-health-version`, { method: 'POST', body: JSON.stringify({ version }) }); },
        // server.close() alone waits for all open sockets to end, which can
        // hang if the browser is holding a keep-alive connection open —
        // closeAllConnections() (Node 18.2+) forces them shut so tests never
        // stall on teardown.
        close: () => new Promise(r => { server.closeAllConnections?.(); server.close(r); }),
      });
    });
  });
}
