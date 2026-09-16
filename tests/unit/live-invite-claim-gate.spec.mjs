// The live invite/claim gate (scripts/verify-live-invite-claim.mjs).
//
// WHY THIS SPEC EXISTS. v24.0.13 shipped zero-token onboarding, and
// tests/unit/worker-invite-claim.spec.mjs proves the contract against the real
// fetch handler with an in-memory KV. That is a strong SOURCE gate and says
// nothing about the deployed Worker. The existing authenticated production gate
// predates those endpoints, so at the moment onboarding went live the only flow
// in the app that MINTS a credential had zero production verification.
//
// This spec guards the gate that closes it. Most assertions SPAWN THE REAL
// VERIFIER and check its real exit code rather than grepping the source for the
// strings that would produce one — the same method live-parity-runner.spec.mjs
// uses, and for the same reason: a verdict you have never seen produced is a
// verdict you cannot rely on.
//
// The three-outcome contract is the substance. An unreachable origin must NOT
// read as a broken product, and a broken product must NOT hide behind an
// unreachable origin. Those are opposite errors and both are dangerous:
// the first writes a network outage into a certification record as evidence the
// Worker is wrong, and the second lets a run that observed nothing be cited as
// though it had looked.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('unit/live-invite-claim-gate.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'verify-live-invite-claim.mjs');
const WORKFLOW = path.join(ROOT, '.github', 'workflows', 'verify-authenticated-worker.yml');

/** Run the real verifier and resolve its real exit code.
 *
 *  Deliberately async: the synchronous form blocks this process's event loop,
 *  so an in-process HTTP server could never accept the connection and the
 *  verifier would time out against a server that is, from its own side,
 *  perfectly up — reporting UNOBSERVED and making a harness deadlock look like
 *  a product defect. That exact trap is recorded in CLAUDE.md for the
 *  live-parity runner; it applies here identically. */
function runVerifier(originArg, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT, originArg], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });
    child.on('close', (code) => resolve({ code, out }));
  });
}

/** A local origin whose responses are supplied per path. */
async function withOrigin(handler, fn) {
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => handler(req, res, body));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try { return await fn(`http://127.0.0.1:${port}`); }
  finally { await new Promise(r => srv.close(r)); }
}

const json = (res, status, obj) => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj ?? {}));
};

// ── The three verdicts, each produced for real ───────────────────────────────

test('[LIC-01] an unreachable origin is UNOBSERVED (exit 2), never a product failure', async () => {
  // .invalid is reserved by RFC 2606 and never resolves, so this is
  // deterministic offline rather than dependent on the sandbox's network.
  const { code, out } = await runVerifier('https://unreachable.invalid');
  eq(code, 2, `an unreachable origin must exit 2, got ${code}`);
  ok(/UNOBSERVED/.test(out), 'the verdict must say UNOBSERVED');
  ok(!/VERDICT: FAILURE/.test(out), 'an unreachable origin must NOT be reported as a failure');
});

test('[LIC-02] an origin that answers WRONGLY is a FAILURE (exit 1)', async () => {
  const result = await withOrigin((req, res) => {
    // Up, and wrong on every axis: the invite endpoint hands out invites with
    // no auth, and an unknown claim code 404s instead of 410.
    if (req.url === '/admin/invites') return json(res, 200, { ok: true, code: 'LEAKED' });
    if (req.url === '/claim') return json(res, 404, { ok: false });
    return json(res, 404, {});
  }, (origin) => runVerifier(origin));

  eq(result.code, 1, `a wrong origin must exit 1, got ${result.code}`);
  ok(/VERDICT: FAILURE/.test(result.out), 'the verdict must say FAILURE');
  ok(/without an admin token is 401/.test(result.out), 'it must name the invite auth boundary it checked');
});

test('[LIC-03] the invite auth boundary is checked without any secret', async () => {
  // This half must work with no admin token and no KV credential, because the
  // gate does not have ADMIN_TOKEN and must never be given it.
  const seen = [];
  const result = await withOrigin((req, res) => {
    seen.push({ url: req.url, admin: req.headers['x-admin-token'] || null });
    if (req.url === '/admin/invites') return json(res, 401, { ok: false, error: 'Unauthorized' });
    if (req.url === '/claim') {
      return json(res, 400, { ok: false });
    }
    return json(res, 404, {});
  }, (origin) => runVerifier(origin));

  const invites = seen.filter(s => s.url === '/admin/invites');
  eq(invites.length, 2, `both invite auth cases must be attempted, saw ${invites.length}`);
  eq(invites[0].admin, null, 'the first case must send NO admin token');
  ok(invites[1].admin && invites[1].admin.length > 0, 'the second case must send a wrong admin token');
  // Every real admin token the app uses is the operator's secret; the gate must
  // never transmit anything that could be one.
  ok(!/^flk_/.test(invites[1].admin), 'the wrong-token probe must not look like a real credential');
  ok(/401/.test(result.out), 'the run must report on the 401 boundary');
});

test('[LIC-04] a correct origin with NO KV credential is UNOBSERVED, never PASS', async () => {
  // THIS TEST PASSED FOR THE WRONG REASON when it was first written, which is the
  // defect it now guards. Its fake origin answered 400 to BOTH claim probes, so
  // the "unknown code is 410" assertion failed and the run was a FAILURE — it
  // never reached the question being asked. The origin below answers every
  // no-state check CORRECTLY, so nothing fails and the only thing standing
  // between this run and a PASS is the missing round trip.
  //
  // Without that guard the gate reports "invite/claim contract verified" having
  // never exercised the half that MINTS a credential.
  let claims = 0;
  const result = await withOrigin((req, res) => {
    if (req.url === '/admin/invites') return json(res, 401, { ok: false });
    if (req.url === '/claim') {
      claims++;
      // Probe 1 is the malformed code (400), probe 2 the unknown code (410).
      return json(res, claims === 1 ? 400 : 410, { ok: false });
    }
    return json(res, 404, {});
  }, (origin) => runVerifier(origin, { FL_CF_API_TOKEN: '', FL_CF_ACCOUNT_ID: '', FL_KV_NAMESPACE_ID: '' }));

  ok(!/VERDICT: FAILURE/.test(result.out),
    'precondition: every no-state check must PASS, or this test is not asking the question');
  ok(!/VERDICT: PASS/.test(result.out),
    'a run that never claimed a seeded invite must NEVER report PASS');
  eq(result.code, 2, `a half-observed contract must exit 2 (UNOBSERVED), got ${result.code}`);
  ok(/no KV credential supplied/.test(result.out), 'the run must say why the round trip did not happen');
  ok(/MINTS a credential/.test(result.out), 'it must say which half went unobserved');
});

test('[LIC-05] a FAILURE outranks unreachability', async () => {
  // An origin that answers the first probe wrongly and then dies. Evidence of a
  // broken contract is evidence regardless of whether later checks could run;
  // reporting UNOBSERVED here would hide a real defect behind a network excuse.
  let n = 0;
  const result = await withOrigin((req, res) => {
    n++;
    if (n === 1) return json(res, 200, { ok: true }); // /admin/invites with no auth -> should be 401
    res.socket.destroy();
  }, (origin) => runVerifier(origin));

  eq(result.code, 1, `a failure plus unreachability must still exit 1, got ${result.code}`);
  ok(/VERDICT: FAILURE/.test(result.out), 'FAILURE must win over UNOBSERVED');
});

// ── The claim budget, which is a real production constraint ─────────────────

test('[LIC-06] the gate spends at most 6 of the 10/hr per-IP claim budget', async () => {
  // The deployed Worker rate-limits /claim to 10 per hour per IP, checked
  // BEFORE the code is parsed. A gate that spent the budget would make every
  // later check in the same run report a rate limit instead of its real answer,
  // and would lock out a real driver claiming from the same egress.
  let claims = 0;
  await withOrigin((req, res) => {
    if (req.url === '/claim') { claims++; return json(res, 400, { ok: false }); }
    if (req.url === '/admin/invites') return json(res, 401, { ok: false });
    return json(res, 404, {});
  }, (origin) => runVerifier(origin));

  ok(claims <= 6, `the gate must spend at most 6 claim requests, spent ${claims}`);

  const src = fs.readFileSync(SCRIPT, 'utf8');
  ok(/does NOT test the 429|deliberately does NOT test the 429/i.test(src),
    'the source must record why the 429 is not tested live');
});

// ── Wiring ──────────────────────────────────────────────────────────────────

test('[LIC-07] the authenticated gate actually runs this verifier', async () => {
  const wf = fs.readFileSync(WORKFLOW, 'utf8');
  const exec = wf.split('\n').filter(l => !l.trim().startsWith('#')).join('\n');

  ok(/node scripts\/verify-live-invite-claim\.mjs/.test(exec),
    'the workflow must invoke the verifier — a script nothing calls is not a gate');
  ok(/FL_CF_API_TOKEN=/.test(exec) && /FL_KV_NAMESPACE_ID=/.test(exec),
    'it must pass the KV credentials, or the claim round trip can never run');
  // The gate must stay read-only toward the repository; it changes production
  // KV only, and only values it created.
  ok(/permissions:\s*\n\s*contents:\s*read/.test(wf),
    'the workflow must remain contents: read');
  ok(!/git\s+push|create-pull-request|gh\s+pr\s+(create|merge)/.test(exec),
    'the gate must never write to the repository');
});

test('[LIC-08] the verifier cleans up every key it creates, on every path', async () => {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  // A claim makes the Worker write user:<id> and tokh:<hash> with no expiry of
  // their own. Without cleanup this gate would accumulate synthetic driver
  // accounts in production KV on every deploy, forever.
  ok(/finally\s*\{[\s\S]*cleanup\(\)/.test(src),
    'cleanup must run in a finally block so a thrown error still cleans up');
  ok(/created\.add\('tokh:'/.test(src), 'every minted token hash must be registered for cleanup');
  ok(/created\.add\('user:'/.test(src), 'every minted user record must be registered for cleanup');
  ok(/expiration_ttl=/.test(src), 'the seeded invite must also carry a TTL as a backstop');
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
