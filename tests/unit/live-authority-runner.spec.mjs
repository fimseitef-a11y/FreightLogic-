// M7 live authority-boundary runner semantics.
//
// scripts/verify-live-authority.mjs is the only automation for the M7 gate that
// proves the DEPLOYED Worker projects the client's canonical decision instead
// of recalculating one. Its verdict feeds a release decision, so the two ways
// it can lie both matter:
//
//   1. calling a blocked network a product failure, and
//   2. calling a broken authority boundary a pass.
//
// (1) is not hypothetical. The first revision of that script only treated a
// THROWN fetch as unreachable. An interposed proxy answers at the HTTP layer,
// so fetch resolved with a 403 and the run printed "FAILED — the deployed
// Worker did not preserve the canonical authority boundary" about a Worker it
// had never contacted. The certification record is explicit that unobserved is
// neither a pass nor a failure, and exit codes are how that reaches an operator
// or a CI job.
//
// These tests execute the real script against a local stub standing in for the
// Worker, so they assert observable behaviour rather than grepping source.
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('unit/live-authority-runner.spec.mjs');

/**
 * Wraps a stub handler with the Worker's real auth behaviour: a request with no
 * `X-Backup-Token` is rejected 401 before anything else. Without this the stubs
 * answer the script's unauthenticated probe with 200 and the script correctly
 * reports a missing 401 — a defect in the stub, not in the Worker or the script.
 */
function authGuarded(handler) {
  return (req, body) => req.headers['x-backup-token']
    ? handler(req, body)
    : [401, { ok: false, error: 'Unauthorized' }];
}

/** Boots a stub on a free port; `handler(req, body)` returns [status, bodyObjOrString]. */
async function withStub(handler, fn) {
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      let parsed = null;
      try { parsed = JSON.parse(raw); } catch { /* leave null */ }
      const [status, body] = handler(req, parsed);
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      res.writeHead(status, { 'Content-Type': typeof body === 'string' ? 'text/html' : 'application/json' });
      res.end(payload);
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try { return await fn(origin); }
  finally { await new Promise(r => server.close(r)); }
}

function runScript(origin, extraArgs = [], env = {}) {
  return new Promise(resolve => {
    execFile('node', ['scripts/verify-live-authority.mjs', origin, ...extraArgs], {
      cwd: ROOT, encoding: 'utf8', timeout: 60000,
      // NO_PROXY keeps the loopback stub from being routed through any proxy
      // the surrounding environment configures.
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost',
             FL_BACKUP_TOKEN: 'flk_stubtoken', ...env },
    }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, out: String(stdout || '') + String(stderr || '') });
    });
  });
}

/** A stub that honours the v13 canonical-absence contract correctly. */
function correctWorker(req, body) {
  if (req.url === '/extract') return [200, { ok: true, fields: { orderNo: 'TEST-9001' } }];
  const d = body?.canonicalDecision;
  const unavailable = !d || String(d?.authority?.verdict || '').toUpperCase() === 'UNAVAILABLE'
    || d?.factsComplete === false || d?.economics?.available === false;
  if (unavailable) {
    return [200, { ok: true, model: null, user: 'stub', ai: {
      verdict: 'UNAVAILABLE', grade: '?', authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
      trueRpmBand: 'UNAVAILABLE — True RPM cannot be computed from the facts provided',
      bidAdvice: 'Bid range suppressed — the canonical facts are incomplete, so no bid figure is defensible.',
    } }];
  }
  if (!d?.bid?.range) return [400, { ok: false, error: 'Canonical client decision, economics, and bid range are required for AI review.' }];
  return [200, { ok: true, model: 'stub-model', user: 'stub', ai: {
    verdict: d.authority.verdict, grade: d.authority.grade, authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
    agreement: 'AGREE',
    trueRpmBand: `$${Number(d.economics.trueRPM).toFixed(2)} / true mile`,
    bidAdvice: 'Minimum $588 @ $1.40/mi • Professional $651 @ $1.55/mi',
  } }];
}

/* ── the failure mode that shipped, and must never ship again ────────────── */

test('[LA-01] an HTTP-layer proxy denial is UNOBSERVED (exit 2), never a product FAILURE', async () => {
  // A proxy that answers 403 with an HTML body. fetch RESOLVES here — this is
  // exactly the case the first revision misread as a broken Worker.
  const r = await withStub(() => [403, '<html><body>Blocked by policy</body></html>'],
    origin => runScript(origin));
  eq(r.code, 2, `expected exit 2 (UNOBSERVED), got ${r.code}\n${r.out}`);
  ok(/UNOBSERVED/.test(r.out), 'the operator must be told the origin was unreachable');
  ok(!/did not preserve the canonical authority boundary/.test(r.out),
     'a blocked network must never be reported as an authority-boundary failure');
  ok(!/\bFAIL\b/.test(r.out), `no check may be marked FAIL on an unreachable origin:\n${r.out}`);
});

test('[LA-02] a 200 that is not a Worker response is also UNOBSERVED', async () => {
  // Captive portals and some CDNs return 200 with an HTML interstitial. A body
  // with no `ok` field did not come from the Worker, whatever its status code.
  const r = await withStub(() => [200, '<html>sign in to continue</html>'], origin => runScript(origin));
  eq(r.code, 2, `expected exit 2, got ${r.code}\n${r.out}`);
  ok(/UNOBSERVED/.test(r.out), 'a non-Worker 200 is not evidence about the product');
});

/* ── the boundary itself ─────────────────────────────────────────────────── */

test('[LA-03] a correct Worker passes the free checks and exits 0', async () => {
  const r = await withStub(authGuarded(correctWorker), origin => runScript(origin));
  eq(r.code, 0, `expected exit 0, got ${r.code}\n${r.out}`);
  ok(/Authority boundary verified/.test(r.out), 'a clean run says so plainly');
  ok(/free checks only/.test(r.out), 'and states that the paid half was not run');
});

test('[LA-04] a Worker that coerces UNAVAILABLE into REJECT/F is a real FAILURE (exit 1)', async () => {
  // The exact v12 defect v13 fixed. If this ever passes, the script is not
  // testing anything.
  const r = await withStub(authGuarded((req, body) => {
    if (req.url === '/extract') return [200, { ok: true, fields: {} }];
    if (!body?.canonicalDecision?.bid?.range) return [400, { ok: false, error: 'bid range required' }];
    return [200, { ok: true, model: 'stub', user: 'stub', ai: {
      verdict: 'REJECT', grade: 'F', authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
      trueRpmBand: '$0.00 / true mile', bidAdvice: 'Minimum $0 @ $0.00/mi',
    } }];
  }), origin => runScript(origin));
  eq(r.code, 1, `a coerced REJECT/F must fail the gate, got exit ${r.code}\n${r.out}`);
  ok(/did not preserve the canonical authority boundary/.test(r.out), 'and must say why');
  ok(/verdict=REJECT/.test(r.out), 'naming the value the Worker substituted');
});

test('[LA-05] a Worker that invents a bid range instead of refusing is a FAILURE', async () => {
  const r = await withStub(authGuarded((req, body) => {
    if (req.url === '/extract') return [200, { ok: true, fields: {} }];
    const d = body?.canonicalDecision;
    const unavailable = !d || String(d?.authority?.verdict || '').toUpperCase() === 'UNAVAILABLE'
      || d?.factsComplete === false || d?.economics?.available === false;
    if (unavailable) {
      return [200, { ok: true, model: null, user: 'stub', ai: {
        verdict: 'UNAVAILABLE', grade: '?', authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
        trueRpmBand: 'UNAVAILABLE — True RPM cannot be computed from the facts provided',
        bidAdvice: 'Bid range suppressed — the canonical facts are incomplete, so no bid figure is defensible.',
      } }];
    }
    // No bid range supplied, yet it answers with one anyway.
    return [200, { ok: true, model: 'stub', user: 'stub', ai: {
      verdict: 'ACCEPT', grade: 'A', authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
      trueRpmBand: '$1.80 / true mile', bidAdvice: 'Minimum $756 @ $1.80/mi',
    } }];
  }), origin => runScript(origin));
  eq(r.code, 1, `inventing a withheld bid range must fail the gate, got exit ${r.code}\n${r.out}`);
});

/* ── operator ergonomics ─────────────────────────────────────────────────── */

test('[LA-06] with no token nothing is attempted and the run is UNOBSERVED', async () => {
  const r = await withStub(authGuarded(correctWorker), origin => runScript(origin, [], { FL_BACKUP_TOKEN: '' }));
  eq(r.code, 2, `expected exit 2, got ${r.code}\n${r.out}`);
  ok(/FL_BACKUP_TOKEN/.test(r.out), 'and says which variable to set');
  ok(!/\bPASS\b/.test(r.out), 'an unattempted gate must not report passes');
});

test('[LA-07] the token never appears in output', async () => {
  const secret = 'flk_supersecrettokenvalue';
  const r = await withStub(authGuarded(correctWorker), origin => runScript(origin, [], { FL_BACKUP_TOKEN: secret }));
  ok(!r.out.includes(secret), 'the backup token must never be echoed, even on success');
});

export async function runSpec() { return run(); }
