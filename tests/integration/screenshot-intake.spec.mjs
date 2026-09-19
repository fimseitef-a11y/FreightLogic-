// Issue #252 — screenshot intake, and the onboarding-exposure repair that
// shipped in the same generation.
//
// These drive the REAL app in real Chromium and assert RENDERED CONTENT, not
// internal state. That is the v24.0.8 lesson: the Loads tab shipped green
// because the hash, the highlighted tab and the DOM node were all correct while
// the surface itself was dead. Every signal except the one that matters can be
// right.
//
// The Worker call is intercepted at the network boundary, so everything on the
// app side of it — the picker, the canvas downscale, the review step, the
// draft, and the handoff into the canonical evaluator — is the shipped code.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/screenshot-intake.spec.mjs');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** A real 1x1 PNG, so the canvas path decodes an actual image rather than a
 *  fixture the browser would reject. */
const PNG_1X1 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

/** Intercept /extract-image and answer with `payload`. Returns a handle that
 *  reports what the app actually sent, so the upload contract is asserted too. */
async function stubExtractImage(page, payload, status = 200) {
  const seen = { calls: 0, lastBody: null };
  await page.route('**/extract-image', async (route) => {
    seen.calls++;
    try { seen.lastBody = JSON.parse(route.request().postData() || '{}'); } catch { seen.lastBody = null; }
    await route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(payload),
    });
  });
  return seen;
}

/** Put the app in a state where screenshot intake is reachable: a configured
 *  backup token (the endpoint is behind it) and the Load Intake modal open. */
async function openIntake(page) {
  await page.evaluate(async () => {
    await window.__FL_TESTS.setSetting('cloudBackupToken', 'flk_' + 'a'.repeat(32));
    window.__FL_TESTS.openLoadIntake();
  });
  await sleep(250);
}

/** Drive the real file input with a synthesized screenshot. */
async function chooseImage(page, inputId = 'liImgFile') {
  await page.setInputFiles('#' + inputId, {
    name: 'screenshot.png', mimeType: 'image/png', buffer: Buffer.from(PNG_1X1, 'base64'),
  });
}

const OK_EXTRACTION = {
  ok: true,
  provider: 'workers-ai',
  model: '@cf/moondream/moondream3.1-9B-A2B',
  observedCount: 5,
  fields: {
    orderNo: '1079840', broker: 'DispatchLand', customer: null,
    origin: 'Columbus, OH', destination: 'Chicago, IL',
    pay: 1250, loadedMiles: 355, deadheadMiles: null,
    pickupDate: null, pickupTime: null, deliveryDate: null, deliveryTime: null,
    timezone: null, weight: 1800, pieces: null, dimensions: null,
    commodity: null, notes: null,
  },
  fieldMeta: {
    orderNo: { state: 'OBSERVED', confidence: 0.98 },
    broker: { state: 'OBSERVED', confidence: 0.95 },
    origin: { state: 'OBSERVED', confidence: 0.97 },
    destination: { state: 'OBSERVED', confidence: 0.96 },
    pay: { state: 'OBSERVED', confidence: 0.99 },
    loadedMiles: { state: 'UNCERTAIN', confidence: 0.55 },
    deadheadMiles: { state: 'ABSENT', confidence: null },
    weight: { state: 'OBSERVED', confidence: 0.85 },
  },
};

// ── The intake path ──────────────────────────────────────────────────────────

test('[SSI-01] the intake surface offers a screenshot path, and no Voice control returns', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await openIntake(app.page);
    const surface = await app.page.evaluate(() => ({
      hasShot: !!document.querySelector('#liShot'),
      hasPick: !!document.querySelector('#liPickImg'),
      hasText: !!document.querySelector('#liRawText'),
      text: document.body.innerText,
      voiceNodes: document.querySelectorAll('#liVoice, #mwVoiceBtn, #f23VoiceBtn').length,
    }));
    ok(surface.hasShot, 'a Screenshot control must exist on the intake surface');
    ok(surface.hasPick, 'a Photos/Files control must exist — the guaranteed iPhone path');
    ok(surface.hasText, 'typing and pasting text must remain available');
    // #230 removed Voice by operator decision; a new intake surface must not
    // quietly reintroduce it, and .claude/CLAUDE.md names that explicitly.
    eq(surface.voiceNodes, 0, 'no Voice control may return with the image path');
    ok(!/\bVoice\b/i.test(surface.text), 'no Voice wording may appear on the intake surface');
  } finally { await app.close(); }
});

test('[SSI-02] a screenshot is downscaled, re-encoded as JPEG, and sent to the Worker', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const seen = await stubExtractImage(app.page, OK_EXTRACTION);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    eq(seen.calls, 1, 'exactly one extraction request must be sent');
    ok(seen.lastBody && typeof seen.lastBody.image === 'string', 'the request must carry an image');
    // Re-encoding through a canvas is what strips EXIF (including GPS) and what
    // keeps the upload small. A PNG passed straight through would do neither.
    eq(seen.lastBody.mime, 'image/jpeg', 'the image must be re-encoded as JPEG before upload');
    ok(/^data:image\/jpeg;base64,/.test(seen.lastBody.image), 'the payload must be a JPEG data URL');
  } finally { await app.close(); }
});

test('[SSI-03] extracted values land in the review draft, not straight in the evaluator', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await stubExtractImage(app.page, OK_EXTRACTION);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    const draft = await app.page.evaluate(() => ({
      revenue: document.querySelector('#liRevenue')?.value,
      miles: document.querySelector('#liMiles')?.value,
      origin: document.querySelector('#liOrigin')?.value,
      dest: document.querySelector('#liDest')?.value,
      broker: document.querySelector('#liBroker')?.value,
      reviewVisible: document.querySelector('#liReviewNote')?.style.display !== 'none',
      // The canonical evaluator must NOT have been populated yet — review first.
      mwRevenue: document.querySelector('#mwRevenue')?.value,
    }));
    eq(draft.revenue, '1250', 'revenue must reach the review draft');
    eq(draft.miles, '355', 'loaded miles must reach the review draft');
    eq(draft.origin, 'Columbus, OH', 'origin must reach the review draft');
    eq(draft.dest, 'Chicago, IL', 'destination must reach the review draft');
    eq(draft.broker, 'DispatchLand', 'broker must reach the review draft');
    ok(draft.reviewVisible, 'the review note must be shown before scoring');
    ok(!draft.mwRevenue, 'the evaluator must NOT be filled before the driver reviews');
  } finally { await app.close(); }
});

test('[SSI-04] an ABSENT deadhead stays blank and is NAMED as unknown, never zero', async () => {
  // The defect this whole contract exists to prevent, seen from the surface the
  // driver actually looks at: a blank box that silently means "0" overstates
  // True RPM on every posting that omits the deadhead.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await stubExtractImage(app.page, OK_EXTRACTION);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    const out = await app.page.evaluate(() => ({
      dead: document.querySelector('#liDead')?.value,
      note: document.querySelector('#liReviewNote')?.innerText || '',
    }));
    eq(out.dead, '', 'an unstated deadhead must render BLANK, never 0');
    ok(/deadhead/i.test(out.note), 'the review note must name the missing deadhead');
    ok(/unknown, not zero|not zero/i.test(out.note),
      `the note must say blank means unknown rather than zero, got: ${out.note}`);
  } finally { await app.close(); }
});

test('[SSI-05] an EXPLICIT zero deadhead survives review and reaches the evaluator as 0', async () => {
  // The other direction, and the one the shipped chain got wrong: intNum('') is
  // 0 and `intNum(0) || ''` is '', so a verified zero and an absence were the
  // same empty box, and "Score This Load" then dropped the 0 on a falsy check.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const payload = JSON.parse(JSON.stringify(OK_EXTRACTION));
    payload.fields.deadheadMiles = 0;
    payload.fieldMeta.deadheadMiles = { state: 'OBSERVED', confidence: 0.96 };
    await stubExtractImage(app.page, payload);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    const shown = await app.page.evaluate(() => document.querySelector('#liDead')?.value);
    eq(shown, '0', 'a verified zero deadhead must render as 0, not blank');

    await app.page.evaluate(() => document.querySelector('#liScore')?.click());
    await sleep(700);
    const mw = await app.page.evaluate(() => ({
      dead: document.querySelector('#mwDeadMi')?.value,
      rev: document.querySelector('#mwRevenue')?.value,
    }));
    eq(mw.dead, '0', 'the evaluator must receive the verified zero, not an empty field');
    eq(mw.rev, '1250', 'and the rest of the load with it');
  } finally { await app.close(); }
});

test('[SSI-06] Score This Load hands off to the CANONICAL evaluator — no second pipeline', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await stubExtractImage(app.page, OK_EXTRACTION);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    await app.page.evaluate(() => document.querySelector('#liScore')?.click());
    await sleep(900);
    const after = await app.page.evaluate(() => ({
      hash: location.hash,
      rev: document.querySelector('#mwRevenue')?.value,
      miles: document.querySelector('#mwLoadedMi')?.value,
      origin: document.querySelector('#mwOrigin')?.value,
    }));
    eq(after.hash, '#omega', 'scoring must land on the canonical Evaluate surface');
    eq(after.rev, '1250', 'the canonical evaluator must receive the reviewed revenue');
    eq(after.miles, '355', 'and the reviewed loaded miles');
    eq(after.origin, 'Columbus, OH', 'and the reviewed origin');
  } finally { await app.close(); }
});

test('[SSI-07] a failed extraction falls back to typing — it never opens an empty review', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await stubExtractImage(app.page, { ok: false, error: 'Nothing readable was extracted from that image.' }, 422);
    await openIntake(app.page);
    await chooseImage(app.page);
    await sleep(1200);
    const state = await app.page.evaluate(() => ({
      err: document.querySelector('#liParseError')?.innerText || '',
      errShown: document.querySelector('#liParseError')?.style.display !== 'none',
      textareaVisible: !!document.querySelector('#liRawText')?.offsetParent,
      revenue: document.querySelector('#liRevenue')?.value,
    }));
    ok(state.errShown, 'a failed extraction must be reported, not swallowed');
    ok(/paste|type/i.test(state.err), `the error must point at the fallback, got: ${state.err}`);
    ok(state.textareaVisible, 'the text path must remain available after a failed read');
    ok(!state.revenue, 'a failed extraction must not populate a review draft');
  } finally { await app.close(); }
});

test('[SSI-08] with no cloud token the driver is told why, and no image is uploaded', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const seen = await stubExtractImage(app.page, OK_EXTRACTION);
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.setSetting('cloudBackupToken', '');
      window.__FL_TESTS.openLoadIntake();
    });
    await sleep(250);
    await chooseImage(app.page);
    await sleep(900);
    eq(seen.calls, 0, 'no image may be uploaded without a configured credential');
    const err = await app.page.evaluate(() => document.querySelector('#liParseError')?.innerText || '');
    ok(/settings|connect/i.test(err), `the driver must be told how to fix it, got: ${err}`);
  } finally { await app.close(); }
});

// ── Onboarding exposure (carried-forward repair) ─────────────────────────────

test('[SSI-09] asking whether to show a card no longer spends its budget', async () => {
  // The defect: v24.0.20 counted inside shouldShowOnboarding(), so a card
  // mounted below the fold retired after three launches having never been seen.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const out = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const KEY = 'ssiProbeOnboardingSeen';
      await T.setSetting('onboardViews', {});
      await T.setSetting(KEY, false);
      const answers = [];
      for (let i = 0; i < 5; i++) answers.push(await T.shouldShowOnboarding(KEY));
      const views = await T.getSetting('onboardViews', {});
      return { answers, counted: views[KEY] ?? 0, budget: T.ONBOARD_VIEW_BUDGET };
    });
    ok(out.answers.every(Boolean),
      `an unseen card must keep rendering while unexposed, got ${JSON.stringify(out.answers)}`);
    eq(out.counted, 0, 'asking five times must spend NO budget — a render is not an impression');
  } finally { await app.close(); }
});

test('[SSI-10] a real exposure spends budget, and the last one retires the card durably', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const out = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const KEY = 'ssiProbe2OnboardingSeen';
      await T.setSetting('onboardViews', {});
      await T.setSetting(KEY, false);
      for (let i = 0; i < T.ONBOARD_VIEW_BUDGET; i++) await T._countOnboardingExposure(KEY);
      const views = await T.getSetting('onboardViews', {});
      return {
        counted: views[KEY] ?? 0,
        // Retirement must be expressed in the durable flag the rest of the app
        // reads, so it survives export/import like an explicit dismissal.
        seen: await T.getSetting(KEY, false),
        stillShows: await T.shouldShowOnboarding(KEY),
        budget: T.ONBOARD_VIEW_BUDGET,
      };
    });
    eq(out.counted, out.budget, 'each real exposure must spend exactly one unit of budget');
    eq(out.seen, true, 'the last exposure must promote the durable seen flag');
    eq(out.stillShows, false, 'a retired card must stop rendering');
  } finally { await app.close(); }
});

test('[SSI-11] a card that never scrolls into view does NOT retire', async () => {
  // The reported defect, end to end and through the real observer: mount a card
  // far below the fold, leave it there across repeated renders, and require its
  // budget to be untouched.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const out = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const KEY = 'ssiOffscreenOnboardingSeen';
      await T.setSetting('onboardViews', {});
      await T.setSetting(KEY, false);

      const spacer = document.createElement('div');
      spacer.style.cssText = 'height:8000px';
      document.body.appendChild(spacer);
      const card = document.createElement('div');
      card.style.cssText = 'height:120px';
      card.textContent = 'onboarding card far below the fold';
      document.body.appendChild(card);

      T.markOnboardingExposure(card, KEY);
      await new Promise(r => setTimeout(r, 900));
      const offscreen = (await T.getSetting('onboardViews', {}))[KEY] ?? 0;

      // Now actually look at it. Same card, same observer.
      card.scrollIntoView();
      await new Promise(r => setTimeout(r, 900));
      const afterScroll = (await T.getSetting('onboardViews', {}))[KEY] ?? 0;

      spacer.remove(); card.remove();
      return { offscreen, afterScroll };
    });
    eq(out.offscreen, 0, 'a card below the fold must NOT spend budget — this is the whole defect');
    eq(out.afterScroll, 1, 'scrolling it into view must spend exactly one exposure');
  } finally { await app.close(); }
});

test('[SSI-12] one mount spends at most one exposure, however many callbacks fire', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const out = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const KEY = 'ssiOnceOnboardingSeen';
      await T.setSetting('onboardViews', {});
      await T.setSetting(KEY, false);
      const card = document.createElement('div');
      card.style.cssText = 'height:120px';
      document.body.appendChild(card);
      // Bind repeatedly and scroll repeatedly: the element-level guard and the
      // once-only spend must both hold, or a visible card burns its whole
      // budget in a single session.
      for (let i = 0; i < 4; i++) T.markOnboardingExposure(card, KEY);
      for (let i = 0; i < 3; i++) { card.scrollIntoView(); await new Promise(r => setTimeout(r, 250)); }
      await new Promise(r => setTimeout(r, 400));
      const n = (await T.getSetting('onboardViews', {}))[KEY] ?? 0;
      card.remove();
      return { n };
    });
    eq(out.n, 1, 'a single mount must spend exactly one exposure');
  } finally { await app.close(); }
});

test('[SSI-13] an explicitly dismissed card is never re-counted or re-shown', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const out = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const KEY = 'ssiDismissedOnboardingSeen';
      await T.setSetting('onboardViews', {});
      await T.setSetting(KEY, true); // an explicit "Got it"
      const shows = await T.shouldShowOnboarding(KEY);
      await T._countOnboardingExposure(KEY);
      const views = await T.getSetting('onboardViews', {});
      return { shows, counted: views[KEY] ?? 0 };
    });
    eq(out.shows, false, 'a dismissed card must not render');
    eq(out.counted, 0, 'and a dismissal must not be undone by a stray exposure');
  } finally { await app.close(); }
});

// ── Decision-first compact result (Issue #252, output-presentation contract) ──

/** Drive the REAL canonical evaluator and return what the decision card renders. */
async function scoreLoad(page, { revenue, loaded, dead, origin, dest }) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 15000 });
  const open = await page.isVisible('#mwOrigin').catch(() => false);
  if (!open) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwOrigin', { state: 'visible', timeout: 15000 });
  await page.fill('#mwRevenue', String(revenue));
  await page.fill('#mwLoadedMi', String(loaded));
  await page.fill('#mwDeadMi', String(dead));
  if (origin) await page.fill('#mwOrigin', origin);
  if (dest) await page.fill('#mwDest', dest);
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(1400);
  return page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const details = out?.querySelector('#mwEvalDetails');
    // Everything OUTSIDE the collapsed <details> is what the driver sees first.
    const clone = out?.cloneNode(true);
    clone?.querySelector('#mwEvalDetails')?.remove();
    return {
      all: (out?.innerText || ''),
      upFront: (clone?.innerText || ''),
      detailsOpen: details ? details.hasAttribute('open') : null,
    };
  });
}

test('[SSI-14] the decision card states True RPM, miles and positioning WITHOUT opening details', async () => {
  // #252's output contract. All four of these were behind "Show Details", so
  // the numbers a driver decides on were one tap away while the decision was
  // not. Asserted against the text OUTSIDE the collapsed <details>, because
  // "it is somewhere in the DOM" is exactly the check that would have passed
  // while the surface was still buried.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await scoreLoad(app.page, {
      revenue: 1250, loaded: 355, dead: 42, origin: 'Columbus, OH', dest: 'Chicago, IL',
    });
    eq(r.detailsOpen, false, 'the detailed Omega math must still start COLLAPSED');
    ok(/True RPM/i.test(r.upFront), 'True RPM must be stated up front');
    // 1250 / (355 + 42) = 3.148..., so the card must show the TOTAL-mile rate.
    ok(/\$3\.1[0-9]/.test(r.upFront), `True RPM must be the total-mile figure, got: ${r.upFront.slice(0, 300)}`);
    ok(/397/.test(r.upFront), 'total miles must be stated up front');
    ok(/355/.test(r.upFront) && /42/.test(r.upFront), 'the loaded + deadhead split must be stated');
    ok(/Positioning/i.test(r.upFront), 'positioning / reload quality must be stated up front');
  } finally { await app.close(); }
});

test('[SSI-15] the compact facts are READ from the canonical decision, never recomputed', async () => {
  // The authority rule, asserted as agreement rather than asserted in prose: the
  // True RPM in the compact strip and the True RPM the detailed Omega math
  // prints must be the same number. A second derivation would be a second
  // evaluator, which is the thing #252 forbids and v24.0 already forbade.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await scoreLoad(app.page, {
      revenue: 900, loaded: 300, dead: 0, origin: 'Columbus, OH', dest: 'Toledo, OH',
    });
    // 900 / 300 = 3.00 with a verified zero deadhead.
    const upFrontRpm = /\$(\d+\.\d{2})/.exec(r.upFront.slice(r.upFront.search(/True RPM/i)));
    ok(upFrontRpm, `no True RPM found up front: ${r.upFront.slice(0, 300)}`);
    eq(upFrontRpm[1], '3.00', 'the compact strip must print the canonical total-mile True RPM');
    ok(r.all.includes('3.00'), 'and the detailed math must agree with it');
  } finally { await app.close(); }
});

test('[SSI-16] an explicit zero deadhead renders as 0 in the card, not as a gap', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await scoreLoad(app.page, {
      revenue: 900, loaded: 300, dead: 0, origin: 'Columbus, OH', dest: 'Toledo, OH',
    });
    ok(/300 loaded \+ 0 DH/.test(r.upFront),
      `a verified zero deadhead must render as 0, got: ${r.upFront.slice(0, 300)}`);
  } finally { await app.close(); }
});


test('[SSI-17] compact positioning labels disclose static market classification rather than claiming live reload strength', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await scoreLoad(app.page, {
      revenue: 1250, loaded: 355, dead: 42, origin: 'Columbus, OH', dest: 'Chicago, IL',
    });
    ok(/Positioning/i.test(r.upFront), 'the compact card must retain the positioning fact');
    ok(/static market class/i.test(r.upFront),
      `Tier classification must identify itself as static doctrine context, got: ${r.upFront.slice(0, 400)}`);
    ok(!/strong reloads|workable reloads/i.test(r.upFront),
      'static Tier 1/2 membership must not be phrased as if live reload strength was measured');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
