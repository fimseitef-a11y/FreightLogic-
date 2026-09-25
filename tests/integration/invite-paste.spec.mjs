// v24.0.40 — connecting the INSTALLED iPhone app, reported 2026-09-25.
//
// Screenshot reading needs cloud backup, and cloud backup is connected only by
// an invite link (#i=CODE). On iPhone a link opens in Safari, which keeps
// storage separate from the Home Screen app, so the installed app could never be
// connected and Load Intake answered every screenshot with "Cloud backup is not
// connected". The app now takes a pasted invite link (or code) and opens the
// same claim wizard the link would have.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/invite-paste.spec.mjs');
let app;
const CODE = 'ABCDEFGHJKMNPQRSTUVWXYZ2';

test('[INV-01] an invite link, a bare code and junk are parsed correctly', async () => {
  const r = await app.page.evaluate((code) => {
    const p = window.__FL_TESTS.parseInviteInput;
    return {
      link: p(`https://freightlogic-v2.fimseitef.workers.dev/#i=${code}`),
      lower: p(`  ${code.toLowerCase()}  `),
      spaced: p(code.slice(0, 8) + ' ' + code.slice(8, 16) + '-' + code.slice(16)),
      junk: p('hello'),
      token: p('flk_' + 'a'.repeat(32)),
    };
  }, CODE);
  eq(r.link, CODE, 'a full invite link yields its code');
  eq(r.lower, CODE, 'a pasted code is trimmed and upper-cased');
  eq(r.spaced, CODE, 'spaces and dashes in a typed code are ignored');
  eq(r.junk, null, 'text that is not an invite is refused');
  eq(r.token, null, 'a bearer token is not an invite code');
});

test('[INV-02] Settings offers invite entry, and pasting a link opens the claim wizard', async () => {
  const r = await app.page.evaluate(async (code) => {
    location.hash = '#insights';
    // The Settings render binds the button after its own awaits; poll for it.
    let btn = null, input = null;
    for (let i = 0; i < 30 && !input; i++){
      await new Promise(res => setTimeout(res, 200));
      btn = document.getElementById('btnCloudInvite');
      if (btn && btn.onclick){ btn.click(); await new Promise(res => setTimeout(res, 300)); input = document.getElementById('inviteLinkInput'); }
    }
    if (!btn) return { btn: false };
    if (!input) return { btn: true, input: false };
    input.value = `https://freightlogic-v2.fimseitef.workers.dev/#i=${code}`;
    document.getElementById('inviteLinkGo').click();
    await new Promise(res => setTimeout(res, 600));
    const wiz = document.getElementById('claimWizard');
    const out = { btn: true, input: true, wizard: !!wiz };
    wiz?.remove();
    return out;
  }, CODE);
  ok(r.btn, 'Settings must offer an invite-link button');
  ok(r.input, 'the button opens a paste field');
  ok(r.wizard, 'a valid link opens the claim wizard');
});

test('[INV-03] a bad paste says why and opens nothing', async () => {
  const r = await app.page.evaluate(async () => {
    window.__FL_TESTS.openInviteEntry();
    await new Promise(res => setTimeout(res, 300));
    document.getElementById('inviteLinkInput').value = 'not an invite';
    document.getElementById('inviteLinkGo').click();
    await new Promise(res => setTimeout(res, 300));
    const err = document.getElementById('inviteLinkError');
    return { err: err && err.style.display !== 'none' ? err.textContent : '', wizard: !!document.getElementById('claimWizard') };
  });
  ok(/invite/i.test(r.err), `the driver is told the paste is not an invite — got ${JSON.stringify(r.err)}`);
  ok(!r.wizard, 'no claim wizard for a bad paste');
});

test('[INV-04] a login refusal from the server offers the invite entry', async () => {
  // v24.0.41: with no login the screenshot is read anyway (Worker v25). Only a
  // server refusal (401/403, e.g. a revoked login) is fixable by connecting.
  await app.page.route('**/extract-image', (route) => route.fulfill({
    status: 403, contentType: 'application/json', body: JSON.stringify({ ok: false, error: 'Invalid token' }) }));
  await app.page.evaluate(async () => {
    window.__FL_TESTS.openLoadIntake();
    await new Promise(res => setTimeout(res, 250));
  });
  await app.page.setInputFiles('#liImgFile', {
    name: 's.png', mimeType: 'image/png',
    buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'),
  });
  await new Promise(res => setTimeout(res, 1200));
  const s = await app.page.evaluate(async () => {
    const btn = document.getElementById('liConnectInvite');
    const vis = !!(btn && btn.offsetParent);
    if (btn) btn.click();
    await new Promise(res => setTimeout(res, 500));
    return { vis, entry: !!document.getElementById('inviteLinkInput') };
  });
  await app.page.unroute('**/extract-image');
  ok(s.vis, 'a login refusal carries a visible "connect" button');
  ok(s.entry, 'tapping it opens the invite paste field');
});

export async function runSpec() {
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
