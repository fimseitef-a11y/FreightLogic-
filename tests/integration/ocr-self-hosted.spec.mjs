// Issue #220 — no third-party origin may execute code in the FreightLogic origin.
//
// THE DEFECT. `loadTesseract()` fell back to jsDelivr three times over: the
// engine script, `workerPath`, and `corePath`. `loadScriptWithFallback()`
// carried an SRI TODO and never set an `integrity` attribute, so nothing pinned
// the bytes. `cdn.jsdelivr.net` sat in `script-src` and `connect-src` purely to
// permit it — after X-10 bundled SheetJS, OCR was the only reason left.
//
// Third-party script in this origin has the same access to IndexedDB as the
// operator's entire trip history, expenses, receipts, and the locally stored
// cloud backup credential. That is the risk, and it was real.
//
// THE PART WORTH PROVING: the fallback could never have completed anyway, and
// OCR-01/02 establish that from real `securitypolicyviolation` events rather
// than from reading the policy and reasoning about it:
//
//   - `connect-src` has no `tessdata.projectnaptha.com`, and
//     `Tesseract.createWorker('eng', …)` must fetch `eng.traineddata.gz` from
//     its default `langPath` there.
//   - `worker-src 'self' blob:` forbids a cross-origin worker, so a jsDelivr
//     `workerPath` cannot even be constructed.
//
// So the CDN path could load and RUN foreign code in the origin while never
// producing a single character of OCR. Removing it takes away no working
// capability — which is what makes this the honest option of the two the issue
// offers, rather than a feature deletion dressed up as a security fix.
//
// OCR-01 carries its own discriminator: an ALLOWED origin is also unreachable
// in this sandbox, and it produces NO violation event. Without that control, "a
// fetch failed" would prove nothing about the policy.
//
// NEGATIVE CONTROLS, all verified to fire:
//   - restoring either jsDelivr URL in `loadTesseract()` fails OCR-03.
//   - restoring `https://cdn.jsdelivr.net` to `script-src` fails OCR-05, and to
//     `connect-src` fails OCR-06.
//   - making `loadTesseract()` throw instead of returning null fails OCR-04.

import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('integration/ocr-self-hosted.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = f => readFileSync(path.join(ROOT, f), 'utf8');

/** The CSP POLICY STRING from each file — never the file text.
 *
 *  Learned the hard way: the first version of OCR-05/06 grepped the whole file
 *  for `script-src (...)` and matched the explanatory COMMENT that this very
 *  change added above the meta tag ("script-src is now 'self' ONLY ..."). It
 *  reported the prose as the policy. A guard that reads its own documentation
 *  instead of the thing it guards is the same class of defect as a test that
 *  passes with the bug reinstated. */
function cspOf(file) {
  const src = read(file);
  const m = file === '_headers'
    ? src.match(/^\s*Content-Security-Policy:\s*(.+)$/m)
    : src.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
  if (!m) throw new Error(`could not find the CSP policy string in ${file}`);
  return m[1].trim();
}

/** One directive's value, from the policy string only. */
function directive(file, name) {
  const found = cspOf(file).split(';').map(d => d.trim()).find(d => d === name || d.startsWith(name + ' '));
  if (found === undefined) throw new Error(`${file}: no ${name} directive`);
  return found.slice(name.length).trim();
}

// ── Why the removed path was already dead ────────────────────────────────────

test('[OCR-01] the CSP blocks the Tesseract language-data origin outright', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(async () => {
      const viols = [];
      document.addEventListener('securitypolicyviolation', e => viols.push({
        directive: e.effectiveDirective || e.violatedDirective,
        blocked: e.blockedURI,
      }));
      // The exact URL tesseract.js v5 uses for its default langPath.
      let langThrew = false;
      try { await fetch('https://tessdata.projectnaptha.com/4.0.0/eng.traineddata.gz'); }
      catch { langThrew = true; }
      // CONTROL: an origin the CSP *does* allow. It is also unreachable from the
      // test sandbox, so it fails too — but it must produce NO violation. That
      // is what makes the violation above evidence about the POLICY rather than
      // about the network.
      let allowedThrew = false;
      try { await fetch('https://freightlogic-backup.fimseitef.workers.dev/health'); }
      catch { allowedThrew = true; }
      await new Promise(res => setTimeout(res, 400));
      return { langThrew, allowedThrew, viols };
    });

    ok(r.langThrew, 'the language-data fetch must not succeed');
    const langViol = r.viols.find(v => String(v.blocked).includes('tessdata.projectnaptha.com'));
    ok(langViol, `expected a CSP violation naming tessdata, got ${JSON.stringify(r.viols)}`);
    eq(langViol.directive, 'connect-src', 'the block must come from connect-src');

    const allowedViol = r.viols.find(v => String(v.blocked).includes('freightlogic-backup'));
    ok(!allowedViol,
      'CONTROL: an allowed origin must raise no violation — otherwise the assertion above proves nothing about the policy');
  } finally { await app.close(); }
});

test('[OCR-02] the CSP forbids a cross-origin OCR worker', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(() => {
      try {
        new Worker('https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js');
        return { blocked: false, error: null };
      } catch (e) { return { blocked: true, error: e.name }; }
    });
    ok(r.blocked, 'worker-src \'self\' blob: must forbid a cross-origin worker script');
    eq(r.error, 'SecurityError', `expected SecurityError, got ${r.error}`);
  } finally { await app.close(); }
});

// ── The removal itself ───────────────────────────────────────────────────────

test('[OCR-03] no OCR path names a remote origin any more', async () => {
  const src = read('app.js');
  const loader = src.match(/async function loadTesseract\(\)\{[\s\S]*?\n\}/);
  ok(loader, 'could not find loadTesseract()');
  const body = loader[0];

  ok(!/https?:\/\//.test(body),
    `loadTesseract() must reference no remote URL at all:\n${body.split('\n').filter(l => /https?:\/\//.test(l)).join('\n')}`);
  for (const local of ['./vendor/tesseract.min.js', './vendor/worker.min.js', './vendor/tesseract-core-simd-lstm.wasm.js']) {
    ok(src.includes(local), `the self-hosted path ${local} must remain — removal is not the same as deletion`);
  }
  // And the whole file: no jsDelivr anywhere outside explanatory prose.
  const codeLines = src.split('\n').filter(l => l.includes('cdn.jsdelivr.net') && !/^\s*(\/\/|\*|\/\*)/.test(l));
  eq(codeLines.join(' | '), '', `jsDelivr must not appear in executable code: ${codeLines.join(' | ')}`);
});

test('[OCR-04] an absent engine reports itself instead of throwing', async () => {
  // `vendor/tesseract.min.js` is deliberately not committed, so this is the real
  // production state on a fresh install, not a simulated one.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async () => {
      try {
        const w = await window.__FL_TESTS.loadTesseract();
        return { returned: w === null ? 'null' : typeof w, threw: null };
      } catch (e) { return { returned: null, threw: e.name + ': ' + e.message }; }
    });
    eq(r.threw, null, `loadTesseract() must not throw when OCR is absent, got ${r.threw}`);
    eq(r.returned, 'null', 'an absent engine must resolve to null so callers can say "not installed"');
  } finally { await app.close(); }
});

// ── The CSP is what makes the removal stick ──────────────────────────────────

test('[OCR-05] script-src allows no origin but self', async () => {
  for (const f of ['index.html', '_headers']) {
    const value = directive(f, 'script-src');
    eq(value, "'self'",
      `${f}: script-src must be 'self' alone — any other origin may execute code with full access to the operator's IndexedDB (got: ${value})`);
  }
});

test('[OCR-06] connect-src keeps only the data APIs and the backup Worker', async () => {
  const expected = [
    "'self'",
    'https://freightlogic-backup.fimseitef.workers.dev',
    'https://api.eia.gov',
    'https://api.weather.gov',
    'https://mobile.fmcsa.dot.gov',
    'https://bwt.cbp.gov',
  ];
  for (const f of ['index.html', '_headers']) {
    const actual = directive(f, 'connect-src').split(/\s+/);
    eq(actual.join(' '), expected.join(' '), `${f}: connect-src drifted`);
    ok(!actual.includes('https://cdn.jsdelivr.net'),
      `${f}: jsDelivr must not remain in connect-src once no runtime dependency needs it`);
  }
});

test('[OCR-07] the two CSP copies stay byte-identical', async () => {
  // Checklist item 12 already asserts this in the parity script; repeated here
  // because this change edits both files, and a CSP that is tightened in one
  // place only is worse than one that was never tightened — it reads as fixed.
  eq(cspOf('index.html'), cspOf('_headers'),
    'index.html and _headers CSP must be byte-identical');
});

test('[OCR-08] SheetJS is still bundled and is still not a CDN load', async () => {
  // The tightened script-src would break Excel import if anything still reached
  // for jsDelivr. X-10 bundled it; this proves the CSP change did not outrun it.
  const src = read('app.js');
  const loader = src.match(/async function loadSheetJS\(\)\{[\s\S]*?\n\}/);
  ok(loader, 'could not find loadSheetJS()');
  ok(!/https?:\/\//.test(loader[0]), 'loadSheetJS() must load only the bundled vendor file');
  ok(src.includes('./vendor/xlsx.full.min.js'), 'the bundled SheetJS path must remain');
});

export async function runSpec() { return run(); }
