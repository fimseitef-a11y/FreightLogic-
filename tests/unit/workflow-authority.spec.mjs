// Every GitHub Actions workflow's authority, checked as a property of the whole
// directory rather than one named file at a time.
//
// WHY THIS EXISTS. CLAUDE.md has recorded since v24.1 that the v24.0.1
// comment-triggered, branch-pushing CI repair machinery "was removed on
// purpose and must not return", and `.github/workflows/deploy-backup-worker.yml`
// repeats the rule in its own header. Nothing enforced either sentence. On
// 2026-09-15 a workflow appeared on a side branch that took `contents: write`,
// triggered on push, auto-applied a 608-line patch advancing APP_VERSION,
// DB_VERSION 15 -> 16 and the Worker to v18, and finished with
// `git push origin HEAD:<its own branch>`. It never ran — it failed to start,
// with zero jobs — so nothing was auto-committed, and the prohibition was
// upheld by a YAML error rather than by a gate.
//
// A prohibition that survives only because the thing violating it happened to
// be broken is not a prohibition. This spec is the gate, and it applies to
// every file in the directory by glob, so a NEW workflow is covered the moment
// it lands rather than when someone remembers to add it to a list.
//
// The checks are pure functions over workflow text so that WFA-06 can run them
// against a synthetic offending workflow and prove they actually reject one —
// a guard nobody has watched fail is the defect this suite exists to catch.
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/workflow-authority.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const WF_DIR = path.join(ROOT, '.github/workflows');

const workflowFiles = () =>
  readdirSync(WF_DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).sort();

const readWorkflow = (f) => readFileSync(path.join(WF_DIR, f), 'utf8');

// Comments are where the rules are explained, so every check reads executable
// lines only. Scrubbing prose would make a workflow pass by deleting the
// paragraph that documents why it is safe.
const code = (text) => text.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

// --- the three pure rules -------------------------------------------------

export function declaresExplicitPermissions(text) {
  return /^permissions:\s*$/m.test(code(text));
}

export function requestsWriteAuthority(text) {
  const src = code(text);
  if (/^permissions:\s*write-all\s*$/m.test(src)) return 'permissions: write-all';
  const m = src.match(/^\s+(contents|packages|id-token|pull-requests|issues|actions):\s*write\s*$/m);
  return m ? m[0].trim() : null;
}

export function performsRepositoryWrite(text) {
  const src = code(text);
  const offenders = [
    [/\bgit\s+push\b/, 'git push'],
    [/\bgit\s+commit\b/, 'git commit'],
    [/\bgit\s+tag\b/, 'git tag'],
    [/peter-evans\/create-pull-request/, 'create-pull-request action'],
    [/stefanzweifel\/git-auto-commit-action/, 'git-auto-commit action'],
    [/ad-m\/github-push-action/, 'github-push-action'],
    [/\bgh\s+pr\s+(create|merge)\b/, 'gh pr create/merge'],
    [/\bgh\s+api\b[^\n]*\b-X\s*(POST|PUT|PATCH|DELETE)\b/, 'gh api write'],
  ];
  for (const [re, label] of offenders) if (re.test(src)) return label;
  return null;
}

export function usesForbiddenTrigger(text) {
  const src = code(text);
  // pull_request_target and issue_comment run privileged against untrusted
  // input; repository_dispatch is the remote-fire surface the removed repair
  // machinery used. workflow_run is allowed: it is already gated on a
  // first-party workflow and verify-authenticated-worker.yml depends on it.
  for (const t of ['issue_comment', 'repository_dispatch', 'pull_request_target']) {
    if (new RegExp(`^\\s{2}${t}:`, 'm').test(src)) return t;
  }
  return null;
}

// --- the assertions -------------------------------------------------------

test('[WFA-01] every workflow declares an explicit top-level permissions block', () => {
  const files = workflowFiles();
  ok(files.length > 0, 'the workflow directory must not be empty');
  for (const f of files) {
    ok(declaresExplicitPermissions(readWorkflow(f)),
      `${f} has no top-level permissions: block — it would inherit the repository default, which may be write`);
  }
});

test('[WFA-02] no workflow requests write authority over the repository', () => {
  for (const f of workflowFiles()) {
    const granted = requestsWriteAuthority(readWorkflow(f));
    ok(!granted, `${f} requests "${granted}" — no workflow in this repository deploys or writes to it`);
  }
});

test('[WFA-03] no workflow commits, tags or pushes — the self-repair surface stays gone', () => {
  for (const f of workflowFiles()) {
    const how = performsRepositoryWrite(readWorkflow(f));
    ok(!how, `${f} performs a repository write via ${how} — CI may verify and deploy, never author commits`);
  }
});

test('[WFA-04] no workflow is fired by a comment or a remote dispatch', () => {
  for (const f of workflowFiles()) {
    const trigger = usesForbiddenTrigger(readWorkflow(f));
    ok(!trigger, `${f} triggers on ${trigger} — the comment-triggered repair path was removed on purpose`);
  }
});

test('[WFA-05] the deploy workflow is still the one exception, and still gated', () => {
  // Deploying the Worker is the only thing CI does that changes the world. It
  // holds no repository write authority: it pushes to Cloudflare, not to git.
  const wf = readWorkflow('deploy-backup-worker.yml');
  ok(/^\s{2}workflow_dispatch:/m.test(code(wf)), 'the deploy must be manual dispatch only');
  for (const t of ['push', 'schedule']) {
    ok(!new RegExp(`^\\s{2}${t}:`, 'm').test(code(wf)), `the deploy must never trigger on ${t}`);
  }
  ok(/DEPLOY/.test(wf), 'the deploy must still require the typed confirmation');
  ok(!requestsWriteAuthority(wf), 'deploying Cloudflare needs no git write authority');
});

test('[WFA-06] the rules actually reject an offender — negative control, always run', () => {
  // This is the workflow that appeared on agent/gpt/full-repair-takeover,
  // reduced to the four properties that made it dangerous. If any rule above
  // were vacuous, this test — not a future incident — is what says so.
  const offender = [
    'name: FreightLogic full repair once',
    '',
    '# This comment claims the workflow is safe. It is not evidence.',
    'on:',
    '  push:',
    '    branches: [agent/gpt/full-repair-takeover]',
    '  issue_comment:',
    '    types: [created]',
    '',
    'permissions:',
    '  contents: write',
    '',
    'jobs:',
    '  repair:',
    '    runs-on: ubuntu-24.04',
    '    steps:',
    '      - name: Remove one-shot workflow and commit exact repair',
    '        run: |',
    '          git add -A',
    '          git commit -m "[gpt] apply full-repair patch"',
    '          git push origin HEAD:agent/gpt/full-repair-takeover',
    '',
  ].join('\n');

  ok(requestsWriteAuthority(offender) === 'contents: write', 'WFA-02 must catch contents: write');
  ok(performsRepositoryWrite(offender) === 'git push', 'WFA-03 must catch the self-push');
  ok(usesForbiddenTrigger(offender) === 'issue_comment', 'WFA-04 must catch the comment trigger');

  // And the inverse: a real, compliant workflow must not be flagged, or the
  // guard is just noise that gets disabled.
  const good = readWorkflow('verify-live-parity.yml');
  ok(declaresExplicitPermissions(good), 'a compliant workflow must satisfy WFA-01');
  ok(!requestsWriteAuthority(good), 'a compliant workflow must satisfy WFA-02');
  ok(!performsRepositoryWrite(good), 'a compliant workflow must satisfy WFA-03');
  ok(!usesForbiddenTrigger(good), 'a compliant workflow must satisfy WFA-04');

  // A comment mentioning the forbidden thing must not fail the gate, or the
  // documentation this repository depends on becomes unwritable.
  const documented = 'permissions:\n  contents: read\n# never run: git push, and never take contents: write\n';
  ok(!requestsWriteAuthority(documented) && !performsRepositoryWrite(documented),
    'prose describing the prohibition must not be read as violating it');
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
