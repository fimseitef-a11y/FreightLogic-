// Live-parity runner — read-only production observation and three-outcome
// verdict semantics. Static + subprocess; no production mutation.
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/live-parity-runner.spec.mjs');
const WORKFLOW = '.github/workflows/verify-live-parity.yml';

function runVerifier(args, timeoutMs = 120000) {
  return new Promise(resolve => {
    execFile('node', ['scripts/verify-cloudflare-parity.mjs', ...args],
      { cwd: REPO_ROOT, encoding: 'utf8', timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ code: err ? (err.code ?? 1) : 0, out: `${stdout || ''}${stderr || ''}` });
      });
  });
}

test('[LPR-01] workflow runs manually and on release-bound main pushes only', () => {
  const wf = read(WORKFLOW);
  ok(/^on:\s*\n\s+workflow_dispatch:/m.test(wf),
    'workflow_dispatch must remain available for an operator re-check');
  ok(/^\s{2}push:\s*$/m.test(wf),
    'a read-only push trigger must close the connected-tooling dispatch gap');
  ok(/^\s{4}branches:\s*\[main\]\s*$/m.test(wf),
    'automatic observation may run only after a push to main');
  ok(/\.github\/workflows\/verify-live-parity\.yml/.test(wf),
    'the push path set must include the workflow itself so the transition gets observed');
  for (const required of ['app.js', 'service-worker.js', 'manifest.json', 'sw-bridge.js', 'modern-shell.js',
                          'scripts/verify-cloudflare-parity.mjs', 'scripts/lib/deploy-assets.mjs']) {
    ok(wf.includes(`'${required}'`), `release-bound push paths must include ${required}`);
  }
  for (const forbidden of ['pull_request', 'issue_comment', 'schedule', 'repository_dispatch', 'workflow_run']) {
    ok(!new RegExp(`^\\s{2}${forbidden}:`, 'm').test(wf),
      `${forbidden} must not trigger production observation`);
  }
});

test('[LPR-02] workflow is read-only and takes no secrets', () => {
  const wf = read(WORKFLOW);
  ok(/^permissions:\s*\n\s+contents:\s*read\s*$/m.test(wf),
    'permissions must be exactly contents: read');
  ok(!/secrets\./.test(wf), 'unauthenticated parity must not reference secrets');
  const body = wf.replace(/^\s*#.*$/gm, '');
  for (const forbidden of [/\bwrangler\b/i, /\bgit\s+push\b/i, /\bgit\s+commit\b/i,
                           /wrangler-action/i, /peter-evans\/create-pull-request/i]) {
    ok(!forbidden.test(body), `verification workflow must not run ${forbidden}`);
  }
});

test('[LPR-11] dispatch inputs never become shell source', () => {
  const wf = read(WORKFLOW);
  const offenders = wf
    .split('\n')
    .filter(l => !/^\s*#/.test(l))
    .filter(l => /\$\{\{\s*inputs\./.test(l))
    .filter(l => !/^\s+[A-Z_][A-Z0-9_]*:\s*\$\{\{\s*inputs\.[a-z_]+\s*\}\}\s*$/.test(l));
  eq(offenders.length, 0,
    'dispatch-controlled input may appear only as an env binding, never directly in run:\n  ' + offenders.join('\n  '));
  ok(/APP_ORIGIN: \$\{\{ inputs\.app_origin \}\}/.test(wf), 'app origin must be env-bound');
  ok(/WORKER_ORIGIN: \$\{\{ inputs\.worker_origin \}\}/.test(wf), 'worker origin must be env-bound');
  ok(/"\$\{ARGS\[@\]\}"/.test(wf), 'verifier args must use a quoted array');
});

test('[LPR-03] workflow runs the real verifier and records the exact SHA', () => {
  const wf = read(WORKFLOW);
  ok(/node scripts\/verify-cloudflare-parity\.mjs/.test(wf), 'must invoke the real verifier');
  ok(!/node scripts\/verify-cloudflare-parity\.mjs[^\n]*--static-only/.test(wf),
    'production workflow must run the live half');
  ok(/rev-parse HEAD/.test(wf), 'must record the exact checked-out SHA');
});

test('[LPR-04] PASS, FAILURE and UNOBSERVED stay distinct and only PASS is green', () => {
  const wf = read(WORKFLOW);
  for (const verdict of ['PASS', 'FAILURE', 'UNOBSERVED']) {
    ok(wf.includes(verdict), `workflow must handle ${verdict}`);
  }
  ok(/verdict != 'PASS'/.test(wf), 'FAILURE and UNOBSERVED must both fail the job');
});

test('[LPR-05] --static-only is PASS/0 and never UNOBSERVED', async () => {
  const r = await runVerifier(['--static-only'], 60000);
  eq(r.code, 0, `--static-only must exit 0 on clean source; got ${r.code}\n${r.out}`);
  ok(/VERDICT: PASS/.test(r.out), 'expected VERDICT: PASS');
  ok(!/VERDICT: UNOBSERVED/.test(r.out), 'static-only cannot be UNOBSERVED');
});

test('[LPR-06] unreachable origins are UNOBSERVED/2, not FAILURE', async () => {
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  eq(r.code, 2, `unreachable must exit 2; got ${r.code}\n${r.out}`);
  ok(/VERDICT: UNOBSERVED/.test(r.out), 'expected VERDICT: UNOBSERVED');
  ok(/No parity claim is made in either direction/.test(r.out),
    'unobserved output must explicitly refuse a parity claim');
});

test('[LPR-07] UNOBSERVED remains non-zero so callers fail closed', async () => {
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  ok(r.code !== 0, 'UNOBSERVED must never be a green exit code');
});

test('[LPR-09] reachable 404 origin is FAILURE, never UNOBSERVED', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const r = await runVerifier([origin, origin]);
    eq(r.code, 1, `reachable-but-wrong must exit 1; got ${r.code}\n${r.out}`);
    ok(/VERDICT: FAILURE/.test(r.out), 'expected VERDICT: FAILURE');
    ok(!/VERDICT: UNOBSERVED/.test(r.out), 'an HTTP response means production was observed');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-10] partial live evidence is FAILURE, not UNOBSERVED', async () => {
  let seen = 0;
  const server = http.createServer((_req, res) => {
    if (++seen === 1) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html></html>');
    } else {
      res.socket.destroy();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const r = await runVerifier([origin, origin]);
    ok(seen > 1, 'precondition: verifier made multiple requests');
    eq(r.code, 1, `partial evidence must be FAILURE; got ${r.code}\n${r.out}`);
    ok(!/VERDICT: UNOBSERVED/.test(r.out), 'seeing any real response makes the run observed');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-08] a static defect outranks network unreachability', () => {
  const script = read('scripts/verify-cloudflare-parity.mjs');
  ok(/staticFailed/.test(script), 'report() must identify static failures');
  ok(/if \(unobserved && !staticFailed\)/.test(script),
    'UNOBSERVED is allowed only when no static defect was already proved');
});

export async function runSpec() { return await run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
