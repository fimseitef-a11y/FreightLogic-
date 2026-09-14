// Live-parity runner — the read-only observation job, and the three-outcome
// verdict it depends on. Static + subprocess; no browser, no network.
//
// Why this exists. The live half of scripts/verify-cloudflare-parity.mjs had
// been UNOBSERVED for the whole v24.0.x line: no environment that could run it
// could also reach production. The gpt lane asked for a GitHub-hosted runner to
// close that gap (.agents/inbox/gpt-to-claude-live-parity-runner-2026-09-14.md).
//
// The load-bearing part is not the workflow file — it is that the verifier can
// say "I could not see production" in a way that is distinct from "production is
// wrong". Conflating those is how a network outage gets written into a
// certification record as a parity failure, or, far worse, how a green-looking
// run gets cited as parity evidence when nothing was actually observed. That is
// the same UNKNOWN-is-not-a-value doctrine v24.0.1 applied to the canonical
// decision and v24.0.9 applied to the pickup gate, applied here to the release
// gate itself.
//
// The verdict tests SPAWN the real verifier and assert its real exit code,
// rather than grepping the source for the strings that would produce one.
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/live-parity-runner.spec.mjs');
const WORKFLOW = '.github/workflows/verify-live-parity.yml';

/** Run the verifier and return its real exit code and output.
 *
 *  Deliberately ASYNC. The synchronous form blocks this process's event loop,
 *  so LPR-09's in-process HTTP server could never accept the connection and the
 *  verifier timed out against a server that was, from its own side, perfectly
 *  up — reporting UNOBSERVED and making the test look like a product defect. */
function runVerifier(args, timeoutMs = 120000) {
  return new Promise(resolve => {
    execFile('node', ['scripts/verify-cloudflare-parity.mjs', ...args],
      { cwd: REPO_ROOT, encoding: 'utf8', timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ code: err ? (err.code ?? 1) : 0, out: `${stdout || ''}${stderr || ''}` });
      });
  });
}

test('[LPR-01] the workflow is manual-dispatch only — never push, comment or schedule', () => {
  const wf = read(WORKFLOW);
  ok(/^on:\s*\n\s+workflow_dispatch:/m.test(wf),
    'the only trigger must be workflow_dispatch');
  for (const forbidden of ['pull_request', 'issue_comment', 'schedule', 'repository_dispatch', 'workflow_run']) {
    ok(!new RegExp(`^\\s{2}${forbidden}:`, 'm').test(wf),
      `"${forbidden}" must not be a trigger — CLAUDE.md records the comment-triggered, ` +
      'branch-pushing CI repair machinery as removed on purpose');
  }
  // `push:` needs its own check: the word appears in prose, so anchor on the
  // trigger position rather than anywhere in the file.
  ok(!/^\s{2}push:/m.test(wf), '"push" must not be a trigger');
});

test('[LPR-02] the workflow is read-only and takes no secrets', () => {
  const wf = read(WORKFLOW);
  ok(/^permissions:\s*\n\s+contents:\s*read\s*$/m.test(wf),
    'permissions must be exactly `contents: read` — a verification job must not be able to write');
  ok(!/secrets\./.test(wf),
    'this is the UNAUTHENTICATED sweep: it must not reference any secret. Authenticated ' +
    'smokes are a separate gate needing a dedicated non-published test identity.');
  // Match deploy MECHANICS, not the word: the failure message deliberately says
  // "do not deploy or auto-fix from this workflow", and a check that trips on
  // its own warning would push the next author into deleting the warning.
  const body = wf.replace(/^\s*#.*$/gm, '');
  for (const forbidden of [/\bwrangler\b/i, /\bgit\s+push\b/i, /\bgit\s+commit\b/i,
                           /wrangler-action/i, /peter-evans\/create-pull-request/i]) {
    ok(!forbidden.test(body),
      `the workflow body must not run ${forbidden} — on FAILURE it stops and reports, it never ` +
      'repairs production, and it never writes to the repository');
  }
});

test('[LPR-11] dispatch inputs never reach a shell through ${{ }} interpolation', () => {
  // GitHub Actions script injection. `${{ inputs.x }}` inside a `run:` block is
  // substituted into the script TEXT before the shell parses it, so the input
  // becomes shell source and quoting at the use site cannot help. Untrusted
  // input is handled carefully everywhere else in this repository (CSP,
  // escapeHtml, csvSafeCell, token scoping); a release gate should not be the
  // one place it is waved off because only maintainers can dispatch.
  //
  // Checked per LINE rather than by parsing run: blocks — a block-matching regex
  // silently truncated here and the negative control stopped firing, which is
  // precisely the "test that cannot fail" this suite exists to avoid.
  const wf = read(WORKFLOW);
  const offenders = wf
    .split('\n')
    .filter(l => !/^\s*#/.test(l))                      // comments are not executed
    .filter(l => /\$\{\{\s*(inputs|github\.event)\b/.test(l))
    // The ONLY legitimate place is an `env:` binding: `NAME: ${{ inputs.x }}`.
    .filter(l => !/^\s+[A-Z_][A-Z0-9_]*:\s*\$\{\{\s*inputs\.[a-z_]+\s*\}\}\s*$/.test(l));

  eq(offenders.length, 0,
    'these lines splice dispatch-controlled text straight into the job:\n  ' +
    offenders.join('\n  ') +
    '\nBind them through env: and reference the quoted shell variable instead.');

  ok(/^\s+env:\s*$/m.test(wf) && /APP_ORIGIN: \$\{\{ inputs\.app_origin \}\}/.test(wf),
    'the origin inputs must be bound through env:');
  ok(/"\$\{ARGS\[@\]\}"/.test(wf),
    'the verifier must be invoked with a quoted argument array, so an empty input contributes ' +
    'no argument and a hostile one stays a single literal argument');
});

test('[LPR-03] the workflow runs the real verifier, not a curated substitute', () => {
  const wf = read(WORKFLOW);
  ok(/node scripts\/verify-cloudflare-parity\.mjs/.test(wf),
    'the workflow must invoke the existing verifier');
  ok(!/--static-only/.test(wf),
    'the whole point is the LIVE half — a --static-only run observes nothing about production');
  ok(/rev-parse HEAD/.test(wf),
    'the workflow must record the exact SHA being verified: a PASS is only meaningful against ' +
    'a named candidate, and that is what lets the docs lane cite evidence rather than infer it');
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
  // It deliberately never attempts the live half, so "unreachable" is not a
  // state it can be in. Reporting UNOBSERVED here would make every offline
  // developer run look like a failed production observation.
  const r = await runVerifier(['--static-only'], 60000);
  eq(r.code, 0, `--static-only must exit 0 on a clean tree; got ${r.code}\n${r.out}`);
  ok(/VERDICT: PASS/.test(r.out), 'expected VERDICT: PASS');
  ok(!/UNOBSERVED/.test(r.out), '--static-only must never report UNOBSERVED');
});

test('[LPR-06] an unreachable origin is UNOBSERVED (exit 2), not FAILURE', async () => {
  // THE ASSERTION THAT MATTERS. A runner that cannot reach production must not
  // produce evidence that production is broken. `.invalid` is reserved by
  // RFC 2606 and can never resolve, so this is deterministic offline.
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  eq(r.code, 2,
    `an unreachable origin must exit 2 (UNOBSERVED), not 1 (FAILURE) or 0 (PASS); got ${r.code}\n${r.out}`);
  ok(/VERDICT: UNOBSERVED/.test(r.out), 'expected VERDICT: UNOBSERVED');
  ok(/No parity claim is made in either direction/.test(r.out),
    'the verdict must say plainly that nothing was observed — not that something failed');
});

test('[LPR-07] UNOBSERVED is still non-zero, so every existing caller keeps failing closed', async () => {
  // scripts/deploy-backup-worker.sh, .github/workflows/deploy-backup-worker.yml
  // and m7-certify all treat any non-zero exit as a failure. Introducing a third
  // outcome must not hand any of them a pass they did not earn.
  const r = await runVerifier(['https://unreachable.invalid', 'https://unreachable.invalid']);
  ok(r.code !== 0,
    'UNOBSERVED must never exit 0: an unobserved gate is not a passed gate, and the deploy ' +
    'path reads this exit code directly');
});

test('[LPR-09] a REACHABLE origin that serves nothing is FAILURE, never UNOBSERVED', async () => {
  // The dangerous direction, and the one a text-only check cannot see. If the
  // verifier stopped recording that an HTTP response arrived, an origin that is
  // up but serving 404 for every asset — a deploy that did not land, which is
  // precisely the 2026-09-13 defect — would be reported as "we couldn't look",
  // and a real production failure would be filed as a network problem.
  //
  // So: a server that answers every request with 404. It is reachable; it is
  // also completely wrong. That must be FAILURE.
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
    ok(!/UNOBSERVED/.test(r.out),
      'an origin that answered every request was OBSERVED — reporting UNOBSERVED here would file a ' +
      'failed deploy as a network problem, which is how a real production defect gets excused');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-10] an origin that answers and THEN dies is FAILURE — partial evidence is still evidence', async () => {
  // The mixed case, and the one that decides whether recording "a response
  // arrived" is load-bearing at all. An origin that serves the first request and
  // then drops every connection produces BOTH a real response and real transport
  // errors. Something was observed, so UNOBSERVED would be a lie — and it is the
  // expensive kind, because a half-deployed origin is exactly when a release
  // most needs to be stopped rather than filed as "couldn't look".
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
    ok(!/VERDICT: UNOBSERVED/.test(r.out),
      'a run that received a real HTTP response has observed production, however badly — ' +
      'UNOBSERVED must be reserved for seeing nothing at all');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('[LPR-08] a static defect outranks unreachability and still reports FAILURE', () => {
  // Otherwise a real source defect could hide behind a network excuse: the CSP
  // check needs no network, so its failure is evidence regardless of reachability.
  const script = read('scripts/verify-cloudflare-parity.mjs');
  ok(/staticFailed/.test(script),
    'report() must separate static failures from live ones');
  ok(/if \(unobserved && !staticFailed\)/.test(script),
    'UNOBSERVED may only be reported when no static check failed — a static failure is real ' +
    'evidence of a defect whether or not the network was reachable');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
