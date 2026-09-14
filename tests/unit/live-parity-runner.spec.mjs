// Live-parity runner — the read-only observation job, and the three-outcome
// verdict it depends on. Static + subprocess; no browser, no network.
//
// The load-bearing part is that the verifier can say "I could not see
// production" distinctly from "production is wrong". The workflow now runs
// automatically on every push to main (and still supports manual dispatch), so
// a merged certification change creates its own exact-SHA live evidence without
// requiring an operator to press a button.
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

test('[LPR-01] the workflow auto-observes main and retains manual dispatch — never PR/comment/schedule', () => {
  const wf = read(WORKFLOW);
  ok(/^on:\s*\n\s+push:\s*\n\s+branches:\s*\n\s+- main\s*\n\s+workflow_dispatch:/m.test(wf),
    'triggers must be push-to-main plus workflow_dispatch');
  for (const forbidden of ['pull_request', 'issue_comment', 'schedule', 'repository_dispatch', 'workflow_run']) {
    ok(!new RegExp(`^\\s{2}${forbidden}:`, 'm').test(wf),
      `"${forbidden}" must not be a trigger — verification may observe main automatically but must not revive comment/PR repair machinery`);
  }
});

test('[LPR-02] the workflow is read-only and takes no secrets', () => {
  const wf = read(WORKFLOW);
  ok(/^permissions:\s*\n\s+contents:\s*read\s*$/m.test(wf),
    'permissions must be exactly `contents: read` — a verification job must not be able to write');
  ok(!/secrets\./.test(wf),
    'this is the UNAUTHENTICATED sweep: it must not reference any secret. Authenticated smokes stay separate.');
  const body = wf.replace(/^\s*#.*$/gm, '');
  for (const forbidden of [/\bwrangler\b/i, /\bgit\s+push\b/i, /\bgit\s+commit\b/i,
                           /wrangler-action/i, /peter-evans\/create-pull-request/i]) {
    ok(!forbidden.test(body),
      `the workflow body must not run ${forbidden} — on FAILURE it reports, never repairs or deploys`);
  }
});

test('[LPR-11] dispatch inputs never reach a shell through ${{ }} interpolation', () => {
  const wf = read(WORKFLOW);
  const offenders = wf
    .split('\n')
    .filter(l => !/^\s*#/.test(l))
    .filter(l => /\$\{\{\s*(inputs|github\.event)\b/.test(l))
    .filter(l => !/^\s+[A-Z_][A-Z0-9_]*:\s*\$\{\{\s*inputs\.[a-z_]+\s*\}\}\s*$/.test(l));

  eq(offenders.length, 0,
    'these lines splice dispatch-controlled text straight into the job:\n  ' +
    offenders.join('\n  ') +
    '\nBind dispatch input through env: and reference the quoted shell variable instead.');

  ok(/^\s+env:\s*$/m.test(wf) && /APP_ORIGIN: \$\{\{ inputs\.app_origin \}\}/.test(wf),
    'the optional origin inputs must be bound through env:');
  ok(/"\$\{ARGS\[@\]\}"/.test(wf),
    'the verifier must be invoked with a quoted argument array, so empty push/manual inputs keep production defaults');
});

test('[LPR-03] the workflow runs the real verifier, not a curated substitute', () => {
  const wf = read(WORKFLOW);
  ok(/node scripts\/verify-cloudflare-parity\.mjs/.test(wf),
    'the workflow must invoke the existing verifier');
  ok(!/--static-only/.test(wf),
    'the whole point is the LIVE half — a --static-only run observes nothing about production');
  ok(/rev-parse HEAD/.test(wf),
    'the workflow must record the exact SHA being verified');
});

test('[LPR-04] the workflow distinguishes all three verdicts and blocks on two of them', () => {
  const wf = read(WORKFLOW);
  for (const verdict of ['PASS', 'FAILURE', 'UNOBSERVED']) {
    ok(wf.includes(verdict), `the workflow must handle the ${verdict} verdict explicitly`);
  }
  ok(/verdict != 'PASS'/.test(wf),
    'anything other than PASS must fail the job — an UNOBSERVED run is not a green run');
});

test('[LPR-05] --static-only is PASS and exit 0, and can never report UNOBSERVED', async () => {
  const r = await runVerifier(['--static-only'], 60000);
  eq(r.code, 0, `--static-only must exit 0 on a clean tree; got ${r.code}\n${r.out}`);
  ok(/VERDICT: PASS/.test(r.out), 'expected VERDICT: PASS');
  ok(!/VERDICT: UNOBSERVED/.test(r.out), '--static-only must never report an UNOBSERVED verdict');
});

test('[LPR-06] an unreachable origin is UNOBSERVED (exit 2), not FAILURE', async () => {
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  eq(r.code, 2,
    `an unreachable origin must exit 2 (UNOBSERVED), not 1 (FAILURE) or 0 (PASS); got ${r.code}\n${r.out}`);
  ok(/VERDICT: UNOBSERVED/.test(r.out), 'expected VERDICT: UNOBSERVED');
  ok(/No parity claim is made in either direction/.test(r.out),
    'the verdict must say plainly that nothing was observed');
});

test('[LPR-07] UNOBSERVED is still non-zero, so every existing caller keeps failing closed', async () => {
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  ok(r.code !== 0, 'UNOBSERVED must never exit 0');
});

test('[LPR-09] a REACHABLE origin that serves nothing is FAILURE, never UNOBSERVED', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const r = await runVerifier([origin, origin]);
    eq(r.code, 1,
      `a reachable-but-empty origin must exit 1 (FAILURE), not 2 (UNOBSERVED); got ${r.code}\n${r.out}`);
    ok(/VERDICT: FAILURE/.test(r.out), 'expected VERDICT: FAILURE');
    ok(!/VERDICT: UNOBSERVED/.test(r.out), 'a reached origin was observed and may not be called UNOBSERVED');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-10] an origin that answers and THEN dies is FAILURE — partial evidence is still evidence', async () => {
  let seen = 0;
  const server = http.createServer((_req, res) => {
    if (++seen === 1) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html></html>');
      return;
    }
    res.socket.destroy();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const r = await runVerifier([origin, origin]);
    ok(seen > 1, 'precondition: the verifier should have made more than one request');
    eq(r.code, 1,
      `an origin that answered at least once must exit 1 (FAILURE), not 2 (UNOBSERVED); got ${r.code}\n${r.out}`);
    ok(!/VERDICT: UNOBSERVED/.test(r.out), 'partial HTTP evidence means the run was observed');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-08] a static defect outranks unreachability and still reports FAILURE', () => {
  const script = read('scripts/verify-cloudflare-parity.mjs');
  ok(/staticFailed/.test(script), 'report() must separate static failures from live ones');
  ok(/if \(unobserved && !staticFailed\)/.test(script),
    'UNOBSERVED may only be reported when no static check failed');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
