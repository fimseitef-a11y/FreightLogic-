// D-02 — the cloud-backup setup link never delivers its token.
//
// NOT WIRED INTO tests/run-all.mjs. These assert the CORRECT behaviour and so
// FAIL against main today; see AUDIT_REPORT.md D-02 for the captured
// reproduction, and tests/unit/spec-coverage.spec.mjs QUARANTINE (SC-02/SC-04)
// for the mechanism that keeps this temporary. app.js is SHARED and was under
// the gpt lane's lock/app-js when the finding was captured.
//
// The defect, in one line: the admin panel hands the operator a link whose
// token lives in the URL FRAGMENT, but the only code that reads that fragment
// (cloudCheckSetupLink) runs from renderInsights() — and reaching Settings
// rewrites location.hash to '#insights', destroying the token first.
//
// Why it is worse than one dead link: no admin surface ever shows the BARE
// token. cloudAdminCreateUser() renders only the setup link, and
// cloudAdminShowInvite() renders only the setup link and says "shown once".
// So the operator's only available string is a URL, pasting a URL fails the
// Worker's ^flk_[a-f0-9]{32}$ check, and the Worker answers 403 "Invalid
// token" every single time.
import { launchApp, createSuite, ok, eq, skipFirstRunWizard } from '../lib/harness.mjs';
const { test, run } = createSuite('integration/setup-link-token.spec.mjs');
let app;
const TOKEN = 'flk_a1b2c3d4e5f60718293a4b5c6d7e8f90';

test('[SLT-01] opening the setup link puts the token in the token field', async () => {
  const base = app.page.url().split('#')[0];
  await app.page.goto(base + '#token=' + encodeURIComponent(TOKEN), { waitUntil: 'load' });
  await app.page.waitForTimeout(900);
  // Settings is the only screen that reads the fragment. Reaching it is the
  // ordinary thing an operator does, and it is what destroys the token.
  await app.page.evaluate(() => { location.hash = '#insights'; });
  await app.page.waitForFunction(() => !!document.querySelector('#cloudBackupToken'), null, { timeout: 15000 });
  await app.page.waitForTimeout(800);
  const field = await app.page.evaluate(() => document.querySelector('#cloudBackupToken')?.value ?? null);
  eq(field, TOKEN, 'the setup link is the only way an operator receives a token — it must reach the field');
});

test('[SLT-02] a pasted setup link is accepted as the token it contains', async () => {
  // The operator's only artifact is the link, and the field is labelled
  // "Your Token". Pasting the link is the obvious move, so it must work
  // rather than being forwarded verbatim to the Worker to be rejected.
  const base = app.page.url().split('#')[0];
  const link = base + '#token=' + encodeURIComponent(TOKEN);
  await app.page.evaluate(() => { location.hash = '#insights'; });
  await app.page.waitForFunction(() => !!document.querySelector('#cloudBackupToken'), null, { timeout: 15000 });
  const sent = await app.page.evaluate(async (pasted) => {
    const el = document.querySelector('#cloudBackupToken');
    el.value = pasted; el.dispatchEvent(new Event('input', { bubbles: true }));
    const pass = document.querySelector('#cloudBackupPass');
    if (pass) { pass.value = 'passphrase123'; pass.dispatchEvent(new Event('input', { bubbles: true })); }
    let captured = null;
    const realFetch = window.fetch;
    window.fetch = (url, opts) => {
      const h = (opts && opts.headers) || {};
      if (h['X-Backup-Token']) captured = h['X-Backup-Token'];
      return Promise.resolve(new Response(JSON.stringify({ ok: true, user: 'T', count: 0 }), { status: 200 }));
    };
    try { document.querySelector('#btnCloudSave')?.click(); await new Promise(r => setTimeout(r, 1200)); }
    finally { window.fetch = realFetch; }
    return captured;
  }, link);
  ok(sent !== null, 'Connect must actually attempt a verification request');
  eq(sent, TOKEN, 'a pasted setup link must be reduced to the flk_ token, not sent to the Worker verbatim');
});

export async function runSpec(){
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  try { return await run(); } finally { await app.close(); }
}
if (process.argv[1]?.endsWith('setup-link-token.spec.mjs')){ const r = await runSpec(); process.exit(r.fail ? 1 : 0); }
