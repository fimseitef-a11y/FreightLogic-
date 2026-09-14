// Six-width browser-layout acceptance — the machine-verifiable half of the
// modern-UI visual gate, at the exact release widths.
//
// Requested by the gpt lane in
// .agents/inbox/gpt-to-claude-six-width-layout-gate-2026-09-14.md: the release
// gate listed six-width visual acceptance (320/375/390/393/430/440 CSS px) as
// wholly manual, while the parts that are real rendered geometry — page-level
// horizontal overflow, touch-target size, mobile font-size, modal containment,
// reduced-motion — are measurable in a real browser.
//
// WHAT THIS DOES NOT DO, and must never be read as doing. It does not replace
// physical-iPhone checks A1-A10. Safari safe-area insets, the iOS software
// keyboard, and Home Screen PWA behavior are device evidence and stay device
// evidence; SWL-06 exercises a real modal at the narrowest width and says
// nothing about a keyboard. There are no pixel-golden screenshots here either —
// those churn on harmless rendering differences and then get muted, which is
// worse than not having them. Every assertion below is structural: a box
// measurement, a computed style, or a page-level overflow fact.
//
// The context is a real coarse-pointer mobile emulation (isMobile + hasTouch),
// because styles.css has a `@media (pointer: coarse)` block that raises several
// controls to 44px. Asserting touch targets in a desktop context would be
// asserting against rules that never applied.
import { launchBlank, stopServer, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/six-width-layout.spec.mjs');

/** The six release widths, in CSS px. */
const WIDTHS = [320, 375, 390, 393, 430, 440];
/** The five primary driver surfaces, by canonical route. */
const SURFACES = [
  ['home', 'Today'], ['loads', 'Loads'], ['omega', 'Evaluate'],
  ['trips', 'Trips'], ['money', 'Money'],
];
const MIN_TARGET = 44;      // WCAG 2.1 AA, and this repo's own accessibility rule
const MIN_MOBILE_FONT = 16; // below this iOS Safari zooms the page on focus

/** Boot the real app in a coarse-pointer mobile context, with the F26 wizard
 *  suppressed so no full-screen modal can sit over the surface being measured.
 *
 *  The suppression is written through the app's own `setSetting` on a first boot
 *  and takes effect on the reload, rather than by pre-creating the database from
 *  the test the way modern-shell-routing.spec.mjs does. That pattern is fine for
 *  a spec that only reads, and a trap for one that writes: opening
 *  `FreightLogic_v18` with no explicit version creates it AT VERSION 1, so when
 *  app.js then upgrades 1 -> 15 its `if (old < 1)` block is skipped — and that
 *  block is the only place `trips`, `expenses` and `fuel` are created. The
 *  database comes up at v15 with those three stores missing and every other one
 *  present, so SWL-05's first `upsertTrip` died on "object store not found".
 *
 *  That gap is NOT reachable in production and app.js was deliberately not
 *  changed for it: a real version-1 database is created BY that block, so it
 *  always has those stores. Only a test that manufactures a v1 database without
 *  them can see it. */
async function bootMobile(width = WIDTHS[0]) {
  const base = await launchBlank();
  const context = await base.browser.newContext({
    viewport: { width, height: 800 },
    isMobile: true, hasTouch: true, deviceScaleFactor: 2,
  });
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.goto(`${base.baseUrl}/index.html`, { waitUntil: 'load' });
  await waitReady(page);
  await page.evaluate(() => window.__FL_TESTS.setSetting('f26SetupComplete', true));
  await page.reload({ waitUntil: 'load' });
  await waitReady(page);
  return { base, context, page, close: async () => { await base.close(); } };
}

/** Wait for the app to be genuinely usable, not merely painted.
 *
 *  `#appMeta` populates before initDB() has finished, which is the race PR #148
 *  fixed inside the shared harness — this spec builds its own mobile context and
 *  so has to honour the same contract itself. Probing `dumpStore('trips')` is
 *  the harness's own readiness test, and it is the right one here: SWL-05 writes
 *  a trip as its first action and otherwise fails with "object store not found"
 *  against an app that is perfectly healthy a moment later. */
async function waitReady(page) {
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  await page.waitForFunction(async () => {
    const T = window.__FL_TESTS;
    if (!T || typeof T.dumpStore !== 'function') return false;
    try { await T.dumpStore('trips'); return true; } catch { return false; }
  }, null, { timeout: 15000 });
  // sw-bridge.js reaches modern-shell.js by dynamic import, so the tab bar
  // exists one microtask-turn after load rather than synchronously.
  await page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
  await page.waitForTimeout(500);
}

/** Dark is the app's default (no attribute); light is `data-theme="light"`.
 *  Set deterministically rather than by clicking the toggle, so a width loop
 *  cannot drift out of sync with what it believes it is measuring. */
async function setTheme(page, theme) {
  await page.evaluate((t) => {
    if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
  }, theme);
  await page.waitForTimeout(60);
}

/** Navigate by canonical hash and wait for that view to actually be displayed —
 *  the hash being right while the surface is dead is exactly how v24.0.8's
 *  Loads tab shipped, so "arrived" means computed visibility, not location. */
async function goSurface(page, route) {
  await page.evaluate((r) => { window.location.hash = r; }, route);
  await page.waitForFunction((r) => {
    const el = document.getElementById(`view-${r}`);
    return !!el && getComputedStyle(el).display !== 'none';
  }, route, { timeout: 8000 });
  await page.waitForTimeout(220); // renderers settle
}

/** Elements laid out in the page flow whose box extends past the viewport.
 *
 *  NOT `documentElement.scrollWidth`, which was this helper's first form and was
 *  VACUOUS: styles.css:95 sets `body { overflow-x: hidden }`, so the body clips
 *  horizontally and the page can never report a scrollWidth wider than the
 *  viewport no matter how far content spills. The assertion could not fail —
 *  injecting `.app { min-width: 900px !important }` left SWL-01 and SWL-05
 *  green. The negative control is the only reason that was caught, and it is the
 *  same defect shape as the rollback verifier's fast-forward "revert check".
 *
 *  `overflow-x: hidden` does not make spilled content harmless, it makes it
 *  UNREACHABLE — the driver simply cannot see the right-hand side of a row. So
 *  the measurement is geometric: does a visible box cross the viewport edge?
 *
 *  An element is skipped when any ancestor below `body` clips or scrolls
 *  horizontally (`overflow-x: auto | scroll | hidden | clip`). Inside such an
 *  ancestor, overflow is that container's business — a deliberate horizontal
 *  tab strip (styles.css:780) scrolls on purpose, and a rounded card clips on
 *  purpose. What remains are boxes sitting directly in the page flow, where
 *  crossing the viewport edge is exactly the defect this gate is for.
 *
 *  `body`'s own `overflow-x: hidden` is deliberately NOT treated as an excuse:
 *  it is the thing hiding the defect.
 *
 *  Measured against the DEVICE width the test set, never `window.innerWidth`.
 *  Under mobile emulation the layout viewport EXPANDS to fit content wider than
 *  the device — with `.app { min-width: 900px }` injected at a 320px device,
 *  `innerWidth` reported 900. Comparing boxes to `innerWidth` therefore compares
 *  them to a viewport that has already grown to accommodate them, and can never
 *  fail. This was the second vacuous form of this same helper; the control
 *  caught it too.
 *
 *  That expansion is itself the cleanest signal available: on a real phone it is
 *  the page zooming out to fit, so `innerWidth > deviceWidth` is reported as
 *  overflow in its own right. */
async function overflow(page, deviceWidth) {
  return await page.evaluate((vw) => {
    const layoutWidth = window.innerWidth;
    const offenders = [];
    if (layoutWidth > vw) {
      offenders.push(`the layout viewport expanded to ${layoutWidth}px to fit the content`);
    }
    const clips = (cs) => ['auto', 'scroll', 'hidden', 'clip'].includes(cs.overflowX);
    const describe = (el) => `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
      `${typeof el.className === 'string' && el.className.trim()
        ? '.' + el.className.trim().split(/\s+/).slice(0, 3).join('.') : ''}`;

    for (const el of document.querySelectorAll('body *')) {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') continue;
      // Screen-reader-only text is positioned and clipped out of view by design.
      if (el.classList.contains('sr-only')) continue;

      const r = el.getBoundingClientRect();
      if (r.width <= 1 || r.height <= 1) continue;
      if (r.right <= vw + 1 && r.left >= -1) continue;

      let contained = false;
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        if (clips(getComputedStyle(p))) { contained = true; break; }
      }
      if (contained) continue;

      offenders.push(`${describe(el)} [${Math.round(r.left)}..${Math.round(r.right)}]`);
    }
    return { vw, layoutWidth, offenders: offenders.slice(0, 6), count: offenders.length };
  }, deviceWidth);
}

test('[SWL-01] no primary surface overflows horizontally at any release width, in either theme', async () => {
  const app = await bootMobile();
  try {
    const failures = [];
    for (const theme of ['dark', 'light']) {
      await setTheme(app.page, theme);
      for (const width of WIDTHS) {
        await app.page.setViewportSize({ width, height: 800 });
        for (const [route, label] of SURFACES) {
          await goSurface(app.page, route);
          const r = await overflow(app.page, width);
          if (r.count > 0) {
            failures.push(`${label} @${width}px/${theme}: ${r.count} box(es) cross the ` +
              `${r.vw}px viewport edge — ${r.offenders.join(' ; ')}`);
          }
        }
      }
    }
    eq(failures.length, 0,
      `page-level horizontal overflow at release widths:\n  ${failures.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-02] every bottom-nav control meets 44x44 at every release width', async () => {
  const app = await bootMobile();
  try {
    const small = [];
    for (const width of WIDTHS) {
      await app.page.setViewportSize({ width, height: 800 });
      await app.page.waitForTimeout(140);
      const boxes = await app.page.$$eval('.bottom .nav a', (els) => els.map((a) => {
        const b = a.getBoundingClientRect();
        return { route: a.dataset.modernRoute, w: b.width, h: b.height };
      }));
      eq(boxes.length, 5, `the tab bar must carry five controls at ${width}px, found ${boxes.length}`);
      for (const b of boxes) {
        // The centre Evaluate action is measured by its real interactive anchor
        // box, as the request specifies — not by the icon circle inside it,
        // which is deliberately smaller than the tap area.
        if (b.w < MIN_TARGET || b.h < MIN_TARGET) {
          small.push(`${b.route} @${width}px: ${b.w.toFixed(1)}x${b.h.toFixed(1)}`);
        }
      }
    }
    eq(small.length, 0, `bottom-nav controls below ${MIN_TARGET}x${MIN_TARGET}:\n  ${small.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-03] the theme control and the More entry meet 44x44 at the <=480 widths', async () => {
  const app = await bootMobile();
  try {
    const small = [];
    for (const width of WIDTHS) {
      ok(width <= 480, 'precondition: every release width is inside the <=480 media query');
      await app.page.setViewportSize({ width, height: 800 });
      await app.page.waitForTimeout(140);
      for (const id of ['themeToggle', 'modernMoreBtn']) {
        const box = await app.page.evaluate((i) => {
          const el = document.getElementById(i);
          if (!el) return null;
          const b = el.getBoundingClientRect();
          return { w: b.width, h: b.height };
        }, id);
        ok(box !== null, `#${id} must exist — it is a primary header control`);
        if (box.w < MIN_TARGET || box.h < MIN_TARGET) {
          small.push(`#${id} @${width}px: ${box.w.toFixed(1)}x${box.h.toFixed(1)}`);
        }
      }
    }
    eq(small.length, 0, `header controls below ${MIN_TARGET}x${MIN_TARGET}:\n  ${small.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-04] every visible evaluator text field resolves to >=16px at mobile widths', async () => {
  // Below 16px iOS Safari zooms the viewport on focus, which on this screen
  // means the driver loses the rest of the load they are pricing.
  const app = await bootMobile();
  try {
    const small = [];
    for (const width of WIDTHS) {
      await app.page.setViewportSize({ width, height: 800 });
      await goSurface(app.page, 'omega');
      // Expand "More Details" first. Collapsed, the evaluator exposes only
      // three fields (revenue, loaded, deadhead) and this test measured just
      // those — while origin, destination, broker, the 7D dimension fields and
      // the v24.0.9 pickup cutoff, 33 in all, went unmeasured behind the
      // toggle. They are typed into just as often, and a sub-16px field there
      // zooms iOS identically. Caught by the negative control: dropping
      // #mwOrigin to 13px did not fail this test until the section was opened.
      await app.page.evaluate(() => {
        const body = document.getElementById('evalAdvBody');
        if (body && getComputedStyle(body).display === 'none') {
          document.getElementById('evalAdvToggle')?.click();
        }
      });
      await app.page.waitForTimeout(250);
      const fields = await app.page.evaluate(() => {
        const TEXTUAL = new Set(['text', 'number', 'tel', 'search', 'url', 'email',
          'date', 'datetime-local', 'time', 'password', '']);
        const out = [];
        for (const el of document.querySelectorAll('#view-omega input, #view-omega select, #view-omega textarea')) {
          if (el.tagName === 'INPUT' && !TEXTUAL.has((el.getAttribute('type') || '').toLowerCase())) continue;
          const cs = getComputedStyle(el);
          if (cs.display === 'none' || cs.visibility === 'hidden') continue;
          if (el.getBoundingClientRect().width === 0) continue;
          out.push({ id: el.id || el.name || el.tagName.toLowerCase(), px: parseFloat(cs.fontSize) });
        }
        return out;
      });
      // A guard against this test quietly shrinking back to three fields if the
      // toggle id or markup changes: the expanded evaluator has dozens.
      ok(fields.length >= 12,
        `the expanded evaluator must expose its full field set at ${width}px; ` +
        `only ${fields.length} were visible — did "More Details" fail to open?`);
      for (const f of fields) {
        if (!(f.px >= MIN_MOBILE_FONT)) small.push(`${f.id} @${width}px: ${f.px}px`);
      }
    }
    eq(small.length, 0, `evaluator fields below ${MIN_MOBILE_FONT}px:\n  ${small.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-05] long route / broker / money strings do not force page-level overflow', async () => {
  const app = await bootMobile();
  try {
    // Seeded through the app's own sanitizing write path, so these are records
    // the app could really hold — not markup injected past validation.
    await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const long = (s, n) => s.repeat(n);
      await T.upsertTrip({
        orderNo: 'SWL-LONG-1',
        customer: long('Transcontinental Expedited Logistics Group International ', 3),
        origin: long('Municipality of Upper Saint Clair Township ', 3),
        destination: long('Sault Sainte Marie Chippewa County ', 3),
        pickupDate: '2026-09-01', deliveryDate: '2026-09-02',
        pay: 9876543.21, loadedMiles: 98765, emptyMiles: 0,
        notes: long('unbroken', 40), // no spaces: the classic word-wrap breaker
      });
      await T.upsertTrip({
        orderNo: long('ORDERNUMBER', 10),
        customer: 'Acme', origin: 'Chicago, IL', destination: 'Toledo, OH',
        pickupDate: '2026-09-03', deliveryDate: '2026-09-04',
        pay: 1234567.89, loadedMiles: 250, emptyMiles: 12,
      });
    });
    await app.page.reload({ waitUntil: 'load' });
    await waitReady(app.page);

    const failures = [];
    for (const theme of ['dark', 'light']) {
      await setTheme(app.page, theme);
      for (const width of WIDTHS) {
        await app.page.setViewportSize({ width, height: 800 });
        for (const [route, label] of SURFACES) {
          await goSurface(app.page, route);
          const r = await overflow(app.page, width);
          if (r.count > 0) {
            failures.push(`${label} @${width}px/${theme}: ${r.count} box(es) cross the ` +
              `${r.vw}px viewport edge — ${r.offenders.join(' ; ')}`);
          }
        }
      }
    }
    eq(failures.length, 0,
      `long real-world strings forced page-level overflow:\n  ${failures.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-06] a real modal stays inside the viewport at the narrowest width', async () => {
  // This is layout containment only. It does not simulate the iOS software
  // keyboard, and nothing here may be read as evidence about it.
  const app = await bootMobile(320);
  try {
    await app.page.setViewportSize({ width: 320, height: 800 });
    await goSurface(app.page, 'home');
    // Opportunity Intake is a real production modal, and an offline one — it
    // needs no provider authorization and makes no network call.
    await app.page.evaluate(() => window.__FL_TESTS.openOpportunityIntake());
    await app.page.waitForFunction(
      () => getComputedStyle(document.getElementById('modal')).display !== 'none',
      null, { timeout: 8000 });
    await app.page.waitForTimeout(350); // the open transition

    const m = await app.page.evaluate(() => {
      const md = document.getElementById('modal');
      const b = md.getBoundingClientRect();
      const de = document.documentElement;
      const wide = [];
      for (const el of md.querySelectorAll('*')) {
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        const r = el.getBoundingClientRect();
        if (r.width > 0 && (r.right > window.innerWidth + 1 || r.left < -1)) {
          wide.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''} [${Math.round(r.left)}..${Math.round(r.right)}]`);
        }
      }
      const close = document.getElementById('modalClose');
      const closeBox = close ? close.getBoundingClientRect() : null;
      return {
        left: b.left, right: b.right, vw: window.innerWidth,
        pageScrollWidth: de.scrollWidth,
        wide: wide.slice(0, 6),
        closePresent: !!close,
        closeW: closeBox ? closeBox.width : 0,
        closeH: closeBox ? closeBox.height : 0,
        actionable: md.querySelectorAll('button, input, select, textarea, [role="button"]').length,
      };
    });

    ok(m.left >= -1 && m.right <= m.vw + 1,
      `the modal must stay inside the viewport horizontally at 320px; it spans ` +
      `${Math.round(m.left)}..${Math.round(m.right)} in a ${m.vw}px viewport`);
    eq(m.wide.length, 0, `modal content spilled past the viewport:\n  ${m.wide.join('\n  ')}`);
    eq(m.pageScrollWidth, m.vw, 'an open modal must not make the page itself scroll sideways');
    ok(m.closePresent, 'the modal close control must be reachable in the DOM');
    ok(m.closeW >= MIN_TARGET && m.closeH >= MIN_TARGET,
      `the modal close control must meet ${MIN_TARGET}x${MIN_TARGET}; measured ` +
      `${m.closeW.toFixed(1)}x${m.closeH.toFixed(1)}`);
    ok(m.actionable > 0, 'the modal must expose its primary controls in the DOM');
  } finally { await app.close(); }
});

test('[SWL-07] reduced motion leaves no decorative element animating indefinitely', async () => {
  const app = await bootMobile();
  try {
    await app.page.emulateMedia({ reducedMotion: 'reduce' });
    await app.page.reload({ waitUntil: 'load' });
    await waitReady(app.page);

    const r = await app.page.evaluate(() => {
      const looping = [];
      let animatedSeen = 0;
      for (const el of document.querySelectorAll('body *')) {
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        const names = cs.animationName.split(',').map((s) => s.trim()).filter((n) => n && n !== 'none');
        if (!names.length) continue;
        animatedSeen++;
        const counts = cs.animationIterationCount.split(',').map((s) => s.trim());
        const durations = cs.animationDuration.split(',').map((s) => s.trim());
        names.forEach((n, i) => {
          const count = counts[i % counts.length];
          const dur = parseFloat(durations[i % durations.length]) || 0;
          // Infinite, or many iterations of something long enough to be seen.
          if (count === 'infinite' || (Number(count) > 1 && dur > 0.05)) {
            looping.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}: ` +
              `${n} x${count} ${durations[i % durations.length]}`);
          }
        });
      }
      return {
        reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
        animatedSeen, looping: looping.slice(0, 8),
      };
    });

    ok(r.reduced, 'precondition: the page must actually see prefers-reduced-motion: reduce');
    // Note what is NOT asserted: nothing here requires a progress indicator to
    // stop conveying progress. The assertion is only that no element is left
    // looping indefinitely, which is what the reduced-motion contract promises.
    eq(r.looping.length, 0,
      `elements still looping under reduced motion:\n  ${r.looping.join('\n  ')}`);
  } finally { await app.close(); }
});

test('[SWL-08] the tertiary text token clears 4.5:1 on surface-1 in both themes', async () => {
  // Optional per the request, and computed from the REAL resolved colors in the
  // page rather than by re-parsing styles.css — a second CSS parser in the test
  // is a second thing to drift.
  const app = await bootMobile();
  try {
    const results = {};
    for (const theme of ['dark', 'light']) {
      await setTheme(app.page, theme);
      results[theme] = await app.page.evaluate(() => {
        const cs = getComputedStyle(document.documentElement);
        const parse = (v) => {
          const probe = document.createElement('span');
          probe.style.color = v.trim();
          document.body.appendChild(probe);
          const rgb = getComputedStyle(probe).color;
          probe.remove();
          const m = rgb.match(/(\d+(?:\.\d+)?)/g);
          return m ? m.slice(0, 3).map(Number) : null;
        };
        const lum = (c) => {
          const [r, g, b] = c.map((v) => {
            const s = v / 255;
            return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
          });
          return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };
        const fg = parse(cs.getPropertyValue('--text-tertiary'));
        const bg = parse(cs.getPropertyValue('--surface-1'));
        if (!fg || !bg) return null;
        const [a, b2] = [lum(fg), lum(bg)].sort((x, y) => y - x);
        return { ratio: (a + 0.05) / (b2 + 0.05) };
      });
    }
    for (const theme of ['dark', 'light']) {
      ok(results[theme] !== null, `--text-tertiary and --surface-1 must both resolve in ${theme}`);
      ok(results[theme].ratio >= 4.5,
        `--text-tertiary on --surface-1 in ${theme} is ${results[theme].ratio.toFixed(2)}:1, ` +
        'below the 4.5:1 required for normal text');
    }
  } finally { await app.close(); }
});

export async function runSpec() {
  const r = await run();
  await stopServer();
  return r;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
