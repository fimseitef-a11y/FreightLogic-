// v24.0.9 — deployment asset coverage. Static, no browser needed.
//
// Why this spec exists. On 2026-09-13, against main c02ed36, the live half of
// `scripts/verify-cloudflare-parity.mjs` reported 24/24 checks PASS while
// `admin-driver-ui.js` returned HTTP 404 from the deployed origin. Two
// independent gaps produced that:
//
//   1. `.assetsignore` (the Cloudflare Workers static-assets exclusion list)
//      named `admin-driver-ui.js`, so the file was never uploaded — while
//      `service-worker.js` precached it in CORE and INJECTED a <script> tag for
//      it into every HTML response. The repository asked for a file the
//      deployment had been told not to publish, and nothing compared the two
//      lists.
//   2. The live parity checks fetched a hand-picked subset of assets (index,
//      service worker, overlay, bridge, shell, manifest). An asset outside that
//      subset can 404 in production with every check still green.
//
// Gap 1 is what this spec closes, statically and offline: every asset the app
// requests at runtime must exist on disk AND survive the exclusion rules. Gap 2
// is closed in the live half of the parity script, which now fetches every
// declared runtime asset rather than a curated handful. Both are needed — the
// exclusion list can be correct while a deploy is stale, and a deploy can be
// current while the exclusion list silently drops a file.
//
// The inventory and the exclusion matcher live in `scripts/lib/deploy-assets.mjs`
// and are shared with the parity gate itself, deliberately: duplicating them
// here would reproduce the defect one level up — two lists that can drift, each
// reporting green about the other's blind spot.
//
// Deliberately offline: per the deploy-asset-coverage handoff, network checks
// stay out of normal suite execution. A gate that needs the internet is a
// network gate, not a code gate.
import { existsSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import {
  REPO_ROOT,
  declaredRuntimeAssets,
  assetsIgnoreMatcher,
} from '../../scripts/lib/deploy-assets.mjs';

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/deploy-asset-coverage.spec.mjs');

/** The inventory, with any unparseable declaration source surfaced as a hard
 *  failure rather than a quietly smaller list. */
function inventory() {
  const { assets, problems } = declaredRuntimeAssets();
  eq(problems.length, 0, 'could not parse a runtime asset declaration source: ' + problems.join('; '));
  return assets;
}
const isExcluded = (p) => assetsIgnoreMatcher()(p);

test('[DAC-01] every asset the app requests at runtime exists in the repository', () => {
  const assets = inventory();
  ok(assets.size >= 20, `expected the runtime asset inventory to be substantial, found ${assets.size}`);
  const missing = [];
  for (const [p, { requesters }] of assets) {
    if (!existsSync(path.join(REPO_ROOT, p))) missing.push(`${p} (requested by ${[...requesters].join(', ')})`);
  }
  eq(missing.length, 0,
    'these assets are requested at runtime but do not exist on disk:\n  ' + missing.join('\n  '));
});

test('[DAC-02] no runtime asset is excluded from deployment by .assetsignore', () => {
  // THE REGRESSION. admin-driver-ui.js was in service-worker.js CORE, injected
  // into every HTML response, and named in .assetsignore — so the deployed
  // origin returned 404 for a script the worker precaches and the page loads,
  // while the parity script (which never fetched it) reported full green.
  const assets = inventory();
  const blocked = [];
  for (const [p, { requesters }] of assets) {
    const { excluded, by } = isExcluded(p);
    if (excluded) blocked.push(`${p} — excluded by .assetsignore pattern "${by}", but requested by ${[...requesters].join(', ')}`);
  }
  eq(blocked.length, 0,
    'these assets would never reach the deployed origin:\n  ' + blocked.join('\n  ') +
    '\nEither remove the .assetsignore entry or stop requesting the asset. A file the ' +
    'service worker precaches and injects, but the deploy excludes, is a silent 404 in ' +
    'production that no version-marker check can see.');
});

test('[DAC-03] .assetsignore still withholds the server-side and repository-only files', () => {
  // The other direction. .assetsignore is not merely inert config: it is what
  // keeps the Worker SOURCE off the public app origin. `assets.directory` in
  // wrangler.jsonc is `.` — the whole repository — so anything not excluded is
  // published verbatim at the app origin. Relaxing an entry here to clear a 404
  // is the wrong repair, and this asserts nobody does it by accident.
  const mustStayExcluded = [
    'cloud-backup-worker.js', // the backup Worker's source, including its auth middleware
    'wrangler.jsonc',         // deployment configuration
    'CLAUDE.md',              // internal architecture/operations context
    '.assetsignore',
    '.gitignore',
  ];
  for (const f of mustStayExcluded) {
    const { excluded } = isExcluded(f);
    ok(excluded, `${f} must stay excluded from the deployed assets — wrangler.jsonc publishes the ` +
      'entire repository directory, so an un-excluded file is served publicly at the app origin');
  }
  ok(isExcluded('.git/config').excluded,
    '.git/ must stay excluded — its contents are the full repository history');
});

test('[DAC-04] the live parity gate sweeps every declared runtime asset, from the same inventory', () => {
  // Gap 2. The live half used to fetch a curated subset — index, service worker,
  // overlay, bridge, shell, manifest — so an asset outside it could 404 with
  // every check green, which is exactly what happened. It must now derive its
  // fetch list from THIS module, not from a second list of its own: two
  // inventories that can drift is the defect one level up.
  const script = read('scripts/verify-cloudflare-parity.mjs');
  // Commented-out code must not satisfy any of these: a call that is present
  // only inside a `//` comment reports nothing at runtime, and a check that
  // accepts it is exactly as blind as the gate it is guarding.
  const live = script.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

  ok(/from\s+'\.\/lib\/deploy-assets\.mjs'/.test(live),
    'scripts/verify-cloudflare-parity.mjs must import its asset inventory from ' +
    'scripts/lib/deploy-assets.mjs — the same module this spec reads — so the release gate ' +
    'and its regression cannot disagree about what the app declares');
  for (const fn of ['declaredRuntimeAssets', 'assetsIgnoreMatcher', 'expectsNonHtml']) {
    ok(live.includes(fn), `the verifier must use ${fn}() from the shared inventory`);
  }
  // Importing it is not enough: it has to be used on the LIVE path, or the
  // sweep is dead code and production misses stay invisible.
  ok(/async function runAssetCoverageChecks/.test(live),
    'the verifier must run a live asset-coverage sweep (runAssetCoverageChecks), not just ' +
    'import the inventory. A local-only check cannot see a stale deploy.');
  ok(/^\s*await runAssetCoverageChecks\(checks\);/m.test(live),
    'runAssetCoverageChecks must actually be CALLED from runLiveChecks — an uncalled sweep ' +
    'reports nothing and every check still passes');
  // And an asset miss must fail the gate rather than be tolerated as optional.
  ok(!/optional/i.test(live.slice(live.indexOf('async function runAssetCoverageChecks'))),
    'the live sweep must not treat any declared asset as optional — an optional miss reported ' +
    'as full production parity is the 2026-09-13 defect restated');
});

test('[DAC-05] admin-driver-ui.js is retired: not requested, not in the repo, not injected (#231 Phase C)', () => {
  // The 2026-09-13 finding was this file 404ing behind an injected tag. Issue
  // #231 Phase C then DELETED it: the admin surface lives on the separate-origin
  // Admin Console. So the pin inverts — it must be gone from every axis at once,
  // because a half-retirement (tag still injected, file gone) is that 404 again.
  const assets = inventory();
  ok(!assets.has('admin-driver-ui.js'),
    'admin-driver-ui.js is back in the runtime asset inventory — the driver app must carry no admin surface');
  ok(!existsSync(path.join(REPO_ROOT, 'admin-driver-ui.js')),
    'admin-driver-ui.js exists again — Phase C deletes it rather than leaving a dormant privileged module');
  const sw = readFileSync(path.join(REPO_ROOT, 'service-worker.js'), 'utf8');
  ok(!/admin-driver-ui\.js\?v=|ADMIN_UI_TAG/.test(sw),
    'service-worker.js still precaches or injects admin-driver-ui.js');
});

test('[DAC-06] internal audit/certification/reference material is never a deployed asset', () => {
  // Issue #228. External verification observed `AUDIT_REPORT.md` and
  // `FIELD_TEST_CHECKLIST.md` returning HTTP 200 on the app origin. That is not
  // a misconfiguration on top of a safe default — `wrangler.jsonc` publishes
  // `assets.directory: "."`, so the repository root IS the document root and
  // every file is served unless `.assetsignore` withholds it. These documents
  // describe how the app is audited and certified, and one of them is the
  // physical-device certification gate itself.
  const mustNotBePublic = [
    'AGENTS.md',
    'AUDIT_REPORT.md',
    'FIELD_TEST_CHECKLIST.md',
    'RECON_24_0_2.md',
    'UI_BRIEF_V24.5.md',
    'FreightLogic_UI_Reference.html',
    '.agents/LANES.md',
    '.agents/STATUS.md',
    '.claude/CLAUDE.md',
    '.github/workflows/tests.yml',
    '.githooks/pre-commit',
    'docs/COMPLETION_RELEASE_PLAN_2026-08-25.md',
    'docs/BACKUP_CONTRACT.md',
    'schemas/broker-memory.schema.json',
    'scripts/lib/deploy-assets.mjs',
    'scripts/verify-cloudflare-parity.mjs',
    'tests/run-all.mjs',
    'tests/lib/harness.mjs',
  ];
  for (const f of mustNotBePublic) {
    const { excluded } = isExcluded(f);
    ok(excluded, `${f} must be withheld from the deployed assets (Issue #228) — it is repository-only ` +
      'material, and wrangler.jsonc publishes the whole repository directory');
  }
});

test('[DAC-07] the #228 exclusions withhold no runtime asset, and keep the device companion served', () => {
  // The failure mode of DAC-06 is over-exclusion: withholding a real asset
  // produces exactly the 2026-09-13 production 404 this spec exists to prevent,
  // in the opposite direction. DAC-02 already asserts the declared inventory is
  // never excluded; this names the two specific things the #228 change had to
  // reason about explicitly, so a later broadening cannot take them out quietly.
  //
  // `field-certification.html` / `.js` are the operator-approved SAME-ORIGIN
  // device companion: A1-A12 are executed against them on the real iPhone, so
  // they must stay fetchable even though they are not in the runtime inventory.
  for (const f of ['field-certification.html', 'field-certification.js']) {
    const { excluded, by } = isExcluded(f);
    eq(excluded, false, `${f} is the physical-device certification companion and must stay served ` +
      `on the app origin; it was excluded by ${by}`);
  }
  // The bundled parser the service worker precaches in its install-blocking shell.
  eq(isExcluded('vendor/xlsx.full.min.js').excluded, false,
    'the bundled SheetJS vendor file is an install-critical precached asset (X-10)');
});

test('[DAC-08] the live parity gate proves the withheld paths are actually non-public', () => {
  // Issue #228 item 1 asked for a regression that REQUESTS every internal path
  // and fails unless the result is non-public. DAC-06 is the static half — it
  // reads `.assetsignore` — and a static check could not have caught the
  // reported defect: `AUDIT_REPORT.md` and `FIELD_TEST_CHECKLIST.md` were
  // observed at HTTP 200 on the live origin, and nothing in this repository
  // noticed. `.assetsignore` being right in the repo says nothing about what
  // the deployed origin serves, which is the 2026-09-13 lesson exactly.
  const script = read('scripts/verify-cloudflare-parity.mjs');
  // Commented-out code must not satisfy this, for the same reason as DAC-04.
  const live = script.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

  ok(/async function runWithheldPathChecks/.test(live),
    'the verifier must implement a live withheld-path sweep (runWithheldPathChecks)');
  ok(/^\s*await runWithheldPathChecks\(checks\);/m.test(live),
    'runWithheldPathChecks must actually be CALLED on the live path — an uncalled sweep ' +
    'reports nothing and every check still passes');

  // The list it requests must cover the documents the issue named as exposed,
  // plus the Worker source, which is the most damaging thing the "." document
  // root could serve.
  for (const p of ['AUDIT_REPORT.md', 'FIELD_TEST_CHECKLIST.md', 'CLAUDE.md', 'cloud-backup-worker.js']) {
    ok(live.includes(`'${p}'`), `the live withheld-path sweep must request ${p} by name`);
  }

  // A 200 must be the failure. If the sweep treated only 404 as interesting and
  // shrugged at everything else, an origin serving these with a 200 would pass.
  const body = live.slice(live.indexOf('async function runWithheldPathChecks'));
  ok(/res\.ok/.test(body) && /served\.push/.test(body),
    'a successful response for a withheld path must be recorded as a failure, not ignored');
  ok(/404/.test(body) && /403/.test(body),
    'the sweep must accept 404 or 403 as non-public and nothing weaker');
});

test('[DAC-09] the driver origin never serves the Admin Console or the native-ios source', () => {
  // Observed 2026-09-23 by external fetch against production: the DRIVER origin
  // answered `/admin-console/` with the Admin Console UI and served
  // `admin-console/worker.js` and `native-ios/README.md`, because neither
  // directory was in the root `.assetsignore` and wrangler.jsonc publishes ".".
  // #231 exists to keep admin capability OFF the driver origin; a copy of the
  // console served from it defeats that separation even though the Worker's
  // exact-origin CORS stops it working. The console has its own origin and its
  // own `admin-console/.assetsignore`; the root file does not govern it.
  // The repository README/CONTRIBUTING docs are repository-only for the same
  // reason as the #228 set.
  const repoOnly = [
    'admin-console/index.html',
    'admin-console/app.js',
    'admin-console/worker.js',
    'admin-console/wrangler.jsonc',
    'native-ios/Package.swift',
    'native-ios/README.md',
    'README.md',
    'CONTRIBUTING.md',
  ];
  for (const f of repoOnly) {
    const { excluded } = isExcluded(f);
    ok(excluded, `${f} must be withheld from the driver origin's deployed assets`);
  }
  // And the live sweep must actually request the two directories, or the static
  // half is the only thing standing between a regression and production.
  const live = read('scripts/verify-cloudflare-parity.mjs')
    .split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  for (const p of ['admin-console/index.html', 'admin-console/worker.js', 'native-ios/Package.swift']) {
    ok(live.includes(`'${p}'`), `the live withheld-path sweep must request ${p} by name`);
  }
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
