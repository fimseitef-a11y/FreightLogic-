#!/usr/bin/env node
// FreightLogic — physical-certification PRE-FLIGHT.
//
// WHAT THIS IS FOR. FIELD_TEST_CHECKLIST.md A1-A13 is 42 checkpoints, and the
// operator has to perform them on a real iPhone. Most of that work is not the
// tapping — it is CONSTRUCTING each case (what revenue, what miles, what
// cutoff) and then REASONING about whether the answer was right. This script
// does the constructing and the reasoning ahead of time, against the real app,
// so the device pass becomes "type these numbers, expect this answer."
//
// It also front-loads failure. If a doctrine boundary has moved, or an export
// leaks a key, or the two-tab guard regressed, it fails HERE — on a machine,
// with a diff — instead of at a truck stop with a phone.
//
// ── WHAT IT DELIBERATELY DOES NOT DO ─────────────────────────────────────────
// It does not close a row, mark one PASS, or write anything the runner reads.
// Issue #226's evidence rule is not a formality to route around:
//
//     "A desktop browser, Chromium/WebKit emulation, CI, screenshots from
//      another device, or synthetic test harness may pre-validate logic but
//      MUST NEVER mark an A-row PASS when the checklist requires an actual
//      iPhone observation."
//
// The rows below are split by whether a browser can answer them AT ALL. Seven
// of them genuinely cannot be: an installed-PWA update path, a real Airplane
// Mode round trip, ten real minutes of backgrounded GPS, an iOS Settings
// permission revocation, real Safari 27 rendering at arm's length, the
// Safari-vs-Home-Screen storage partition, and whether iOS actually hands a
// file to the picker inside an installed PWA. Those are the reason the gate
// exists. Nothing here shortens them and nothing here may pretend to.
//
// What it DOES shorten is the other six rows, which are logic the operator
// should be CONFIRMING rather than deriving.
//
// USAGE
//   node scripts/preflight-field-certification.mjs              # local copy
//   node scripts/preflight-field-certification.mjs --live       # production origin
//   node scripts/preflight-field-certification.mjs --out card.txt

import { chromium } from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { assetsIgnoreMatcher } from './lib/deploy-assets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LIVE_ORIGIN = 'https://freightlogic-v2.fimseitef.workers.dev';

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.png':'image/png', '.webmanifest':'application/manifest+json' };

/**
 * Serve the working copy on an ephemeral loopback port.
 *
 * NO FILESYSTEM PATH IS EVER BUILT FROM THE REQUEST. The servable set is
 * enumerated once at startup into a Map of url-path → absolute path, and a
 * request is a Map lookup whose key is a plain string. A path that was never
 * enumerated cannot be served however it is spelled, encoded or nested.
 *
 * This replaces an earlier decode + resolve + `path.relative` containment
 * check. That check was sound — verified over a raw socket, where the
 * pre-fix handler leaked /etc/passwd on two vectors and the fixed one answered
 * 403 to all three — but CodeQL kept flagging both sinks, because it does not
 * recognise `path.relative` as a sanitizer and cannot see that `full` is
 * contained.
 *
 * Suppressing the alert would have been the wrong move twice over: it argues
 * with a static analyzer about a claim only a human reviewer could check, and
 * it leaves a constructed path in code whose whole job is to be trustworthy.
 * An allowlist is shorter, strictly tighter than containment, and removes the
 * question instead of answering it.
 */
const SERVABLE_EXT = new Set(Object.keys(MIME));

/**
 * Enumerate what this local origin may serve, through the REAL `.assetsignore`
 * matcher the deploy gate already uses.
 *
 * Sharing that matcher is the point. A hand-written skip list here would be a
 * second copy of the exclusion rules, and two lists that can disagree is the
 * exact shape of the 2026-09-13 defect — `.assetsignore` and the service
 * worker's CORE list disagreeing while every gate read green.
 *
 * It also matters for fidelity. Before this, the local server happily returned
 * `cloud-backup-worker.js` — the Worker source with its auth middleware — which
 * production withholds and DAC-03 exists to keep withheld. A pre-flight origin
 * that serves what production refuses can only produce false confidence.
 */
async function buildServableMap(dir, prefix, map, isIgnored) {
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return map; }
  for (const ent of entries) {
    if (ent.name.startsWith('.') || ent.name === 'node_modules') continue;
    const abs = path.join(dir, ent.name);
    const url = prefix + '/' + ent.name;
    const rel = url.replace(/^\//, '');
    if (ent.isDirectory()) {
      // The matcher reports {excluded, by} — `by` names the pattern that
      // decided it, which is why the shared module returns a reason at all.
      if (isIgnored(rel + '/').excluded) continue;
      await buildServableMap(abs, url, map, isIgnored);
    } else if (ent.isFile() && SERVABLE_EXT.has(path.extname(ent.name)) && !isIgnored(rel).excluded) {
      map.set(url, abs);
    }
  }
  return map;
}

async function serveLocal() {
  const files = await buildServableMap(ROOT, '', new Map(), assetsIgnoreMatcher());
  const index = files.get('/index.html');
  if (!index) throw new Error('index.html not found under ' + ROOT);

  const server = http.createServer(async (req, res) => {
    const deny = (code, msg) => { res.writeHead(code, { 'Content-Type': 'text/plain' }); res.end(msg); };
    let key;
    try { key = decodeURIComponent((req.url || '/').split('?')[0].split('#')[0]); }
    catch { return deny(400, 'bad request'); }
    if (key === '/' || key === '') key = '/index.html';

    // A lookup, not a path. `key` never reaches the filesystem.
    const abs = files.get(key);
    if (!abs) return deny(404, 'not found');
    try {
      const buf = await fs.readFile(abs);
      res.writeHead(200, { 'Content-Type': MIME[path.extname(abs)] || 'application/octet-stream' });
      res.end(buf);
    } catch { deny(404, 'not found'); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

// ─── the split, stated honestly ──────────────────────────────────────────────

/** Rows no browser can answer. Listed so the operator sees WHY each one costs
 *  them a real action, rather than suspecting it is bureaucracy. */
const HARDWARE_ONLY = {
  A1:  'Installed Home Screen PWA update path. A browser tab is not an installed PWA; the update path and the "did data survive" question only exist on the device.',
  A4:  'Real Airplane Mode, plus closing and reopening the app while still offline. The automated gate explicitly declines to claim the offline NAVIGATION — that is this row.',
  A6:  'Ten real minutes of backgrounded/locked GPS across real movement. Nothing emulated reproduces iOS suspending your app in your pocket.',
  A7:  'Revoking Location in iOS Settings while a trip is live. There is no web API that does this to you.',
  A11: 'Real Safari 27 rendering, and readability at phone-mount distance. Pixels in a headless browser are not the question; your eyes at arm\'s length are.',
  A12: 'Whether Safari and the installed Home Screen app share a storage partition. This is the unknown the whole zero-token design hinges on, and only the device answers it.',
  A13: 'Whether iOS actually hands a file to the picker / camera / clipboard INSIDE an installed PWA. The logic half is pre-flighted below; the delivery half is not knowable here.',
};

const results = [];
const record = (row, label, ok_, detail) => results.push({ row, label, ok: ok_, detail });

// ─── the logic rows ──────────────────────────────────────────────────────────

async function evaluateLoad(page, { revenue, loaded, dead, cutoffMins = null }) {
  await page.fill('#mwLoadedMi', String(loaded));
  await page.fill('#mwDeadMi', dead === null ? '' : String(dead));
  await page.fill('#mwRevenue', String(revenue));
  if (cutoffMins !== null) {
    await page.evaluate((mins) => {
      const d = new Date(Date.now() + mins * 60000);
      const pad = (n) => String(n).padStart(2, '0');
      const el = document.querySelector('#mwPickupCutoff');
      if (el) {
        el.value = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        el.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }, cutoffMins);
  }
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(450);
  return page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      blocked: text.includes("CAN'T TAKE"),
      grade: out?.querySelector('.fl-eval-grade')?.textContent?.trim() || null,
      // The compact decision strip carries the canonical True RPM in its own
      // cell (data-fl-rpm, v24.0.22). A loose "$n.nn" regex over the card text
      // matched the REVENUE first and printed it as True RPM — a wrong expected
      // value on a confirmation card is worse than no value at all.
      rpm: (out?.querySelector('[data-fl-rpm]')?.textContent?.match(/\$?(\d+\.\d\d)/) || [])[1] || null,
      asksDeadhead: /deadhead/i.test(text) && /unknown|enter|need/i.test(text),
      text: text.replace(/\s+/g, ' ').slice(0, 400),
    };
  });
}

async function run() {
  const live = process.argv.includes('--live');
  const outArg = process.argv.indexOf('--out');
  const outFile = outArg > -1 ? process.argv[outArg + 1] : null;

  let origin, close = () => {};
  if (live) { origin = LIVE_ORIGIN; }
  else { const s = await serveLocal(); origin = s.origin; close = s.close; }

  console.log(`\n  FreightLogic physical-certification PRE-FLIGHT`);
  console.log(`  origin: ${origin}${live ? '  (LIVE production)' : '  (local working copy)'}\n`);

  const browser = await chromium.launch({
    headless: true,
    ...(process.env.FL_CHROME_PATH ? { executablePath: process.env.FL_CHROME_PATH } : {}),
  });
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await ctx.newPage();

  try {
    await page.goto(`${origin}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#appMeta')?.textContent, { timeout: 20000 });
    await page.waitForTimeout(1200);
    // Dismiss the first-run wizard the same way the suite does, so the
    // evaluator is reachable.
    await page.evaluate(async () => {
      try { await window.__FL_TESTS?.setSetting('f26SetupComplete', true); } catch {}
      document.querySelectorAll('.modal-backdrop, #setupWizard').forEach(n => n.remove());
    });
    // Open the evaluator's advanced section the same way the suite does. The
    // 7D dimension fields and the v24.0.9 pickup cutoff live behind this
    // toggle, which is exactly why they survived several earlier audits.
    await page.evaluate(() => { location.hash = '#omega'; });
    await page.waitForSelector('#evalAdvToggle', { timeout: 15000 });
    if (!(await page.isVisible('#mwOrigin').catch(() => false))) {
      await page.click('#evalAdvToggle');
    }
    await page.waitForSelector('#mwPickupCutoff', { state: 'visible', timeout: 15000 });

    // ── A2 — UNKNOWN deadhead vs explicit zero ──────────────────────────────
    const unknownDH = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: null });
    const zeroDH    = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: 0 });
    record('A2', 'blank deadhead is UNKNOWN, not zero',
      unknownDH.grade !== zeroDH.grade || unknownDH.asksDeadhead || unknownDH.grade === null,
      `blank → grade ${unknownDH.grade ?? '(none)'} · explicit 0 → grade ${zeroDH.grade ?? '(none)'}`);
    record('A2', 'explicit zero is a VERIFIED zero and still grades',
      zeroDH.grade !== null && !zeroDH.blocked,
      `$600 / 300 loaded / 0 deadhead → grade ${zeroDH.grade}, True RPM $${zeroDH.rpm ?? '?'}`);

    // ── A9 — doctrine boundaries, both sides of each ────────────────────────
    // Driven through the REAL evaluator fields rather than by calling
    // checkVanFit() directly. That is not incidental: the function takes a van
    // profile, and calling it with a synthetic one would test a van the
    // operator does not own. Through the UI it reads their configured profile,
    // which is the thing the device pass is actually confirming.
    async function dimBlocks(field, value) {
      await page.evaluate(({ f }) => {
        for (const id of ['mwLoadLengthIn','mwLoadWidthIn','mwLoadHeightIn','mwLoadWeightLbs']) {
          const el = document.querySelector('#' + id);
          if (el && id !== f) { el.value = ''; el.dispatchEvent(new Event('input', { bubbles: true })); }
        }
      }, { f: field });
      await page.fill('#' + field, String(value));
      const r = await evaluateLoad(page, { revenue: 900, loaded: 300, dead: 0 });
      await page.fill('#' + field, '');
      return r.blocked;
    }
    const vanFit = {
      len121: !(await dimBlocks('mwLoadLengthIn', 121)),
      len122: !(await dimBlocks('mwLoadLengthIn', 122)),
      w548:   !(await dimBlocks('mwLoadWidthIn', 54.8)),
      w549:   !(await dimBlocks('mwLoadWidthIn', 54.9)),
      lb3000: !(await dimBlocks('mwLoadWeightLbs', 3000)),
      lb3001: !(await dimBlocks('mwLoadWeightLbs', 3001)),
    };
    record('A9', 'cargo length 121 in passes / 122 in blocks',
      vanFit.len121 === true && vanFit.len122 === false,
      `121" → ${vanFit.len121 ? 'scores' : "CAN'T TAKE"} · 122" → ${vanFit.len122 ? 'scores' : "CAN'T TAKE"}`);
    record('A9', 'wheel-well width 54.8 in passes / 54.9 in blocks',
      vanFit.w548 === true && vanFit.w549 === false,
      `54.8" → ${vanFit.w548 ? 'scores' : "CAN'T TAKE"} · 54.9" → ${vanFit.w549 ? 'scores' : "CAN'T TAKE"}`);
    record('A9', 'payload 3000 lb passes / 3001 lb blocks',
      vanFit.lb3000 === true && vanFit.lb3001 === false,
      `3000 lb → ${vanFit.lb3000 ? 'scores' : "CAN'T TAKE"} · 3001 lb → ${vanFit.lb3001 ? 'scores' : "CAN'T TAKE"}`);

    const geo = await page.evaluate(() => {
      const T = window.__FL_TESTS; if (!T?.naLookupMarket) return null;
      const id = (s) => {
        const m = T.naLookupMarket(s) || T.usaLookupMarket?.(s);
        if (!m) return null;
        // Market records differ in shape between the NA and USA tables, so take
        // the first identifying field that is actually present rather than
        // printing "undefined" onto a card someone is meant to compare against.
        const name = m.key ?? m.name ?? m.city ?? m.market ?? JSON.stringify(m).slice(0, 40);
        const zone = m.zone ?? m.region ?? m.province ?? m.state ?? '?';
        return `${name}/${zone}`;
      };
      return { gary: id('Gary, IN'), calgary: id('Calgary, AB'), blank: id(''), frag: id('x') };
    });
    if (geo) {
      record('A9', 'Gary IN and Calgary AB are different markets',
        geo.gary && geo.calgary && geo.gary !== geo.calgary,
        `Gary → ${geo.gary ?? 'null'} · Calgary → ${geo.calgary ?? 'null'}`);
      record('A9', 'blank / 1-char market text fails closed to UNKNOWN',
        geo.blank === null && geo.frag === null,
        `'' → ${geo.blank ?? 'null'} · 'x' → ${geo.frag ?? 'null'}`);
    }

    // ── A10 — pickup feasibility matrix ─────────────────────────────────────
    await page.evaluate(async () => { await window.__FL_TESTS?.setSetting('planningAvgMph', null); });
    const inert = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: 225, cutoffMins: 20 });
    record('A10', 'no planning speed set → the check stays INERT',
      !inert.blocked, `225 mi deadhead vs a 20-minute window still scored: ${inert.blocked ? 'BLOCKED (wrong)' : 'not blocked'}`);

    await page.evaluate(async () => { await window.__FL_TESTS?.setSetting('planningAvgMph', 55); });
    const impossible = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: 225, cutoffMins: 20 });
    record('A10', 'with speed set, an impossible pickup BLOCKS',
      impossible.blocked, `225 mi @ 55 mph vs 20 min → ${impossible.blocked ? "CAN'T TAKE" : 'not blocked (wrong)'}`);

    const reachable = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: 30, cutoffMins: 600 });
    record('A10', 'a comfortably reachable pickup does NOT block',
      !reachable.blocked, `30 mi @ 55 mph vs 10 h → ${reachable.blocked ? 'BLOCKED (wrong)' : 'scored normally'}`);

    const unknownReach = await evaluateLoad(page, { revenue: 600, loaded: 300, dead: null, cutoffMins: 20 });
    record('A10', 'UNKNOWN deadhead never reads as instantly reachable',
      !(unknownReach.grade && !unknownReach.blocked && unknownReach.rpm),
      `blank deadhead vs a 20-minute window → ${unknownReach.blocked ? "CAN'T TAKE" : `grade ${unknownReach.grade ?? '(none)'}`}`);
    await page.evaluate(async () => { await window.__FL_TESTS?.setSetting('planningAvgMph', null); });

    // ── A5 — export carries no credential ───────────────────────────────────
    // exportSafeSettings is not on __FL_TESTS, and that is fine — the honest
    // probe is the REAL export the operator would take, scanned for sentinels
    // planted in the very settings keys that must never travel.
    const exp = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      if (!T?.exportJSON || !T?.setSetting) return null;
      await T.setSetting('cloudBackupToken', 'flk_PREFLIGHT_SENTINEL_TOKEN');
      await T.setSetting('appLockPin', 'PREFLIGHT_SENTINEL_PINHASH');
      let captured = '';
      const realCreate = URL.createObjectURL;
      URL.createObjectURL = (blob) => { try { blob.text().then(t => { captured = t; }); } catch {} return 'blob:preflight'; };
      const realClick = HTMLAnchorElement.prototype.click;
      HTMLAnchorElement.prototype.click = function () {};
      try { await T.exportJSON(); } catch {}
      await new Promise(r => setTimeout(r, 300));
      URL.createObjectURL = realCreate;
      HTMLAnchorElement.prototype.click = realClick;
      await T.setSetting('cloudBackupToken', null);
      await T.setSetting('appLockPin', null);
      return {
        got: captured.length > 0,
        leaksToken: captured.includes('PREFLIGHT_SENTINEL_TOKEN'),
        leaksPin: captured.includes('PREFLIGHT_SENTINEL_PINHASH'),
        bytes: captured.length,
      };
    });
    if (exp && exp.got) {
      record('A5', 'a real export withholds the backup token and the PIN hash',
        !exp.leaksToken && !exp.leaksPin,
        `${exp.bytes} byte export · token present: ${exp.leaksToken} · PIN hash present: ${exp.leaksPin}`);
    } else {
      record('A5', 'export secret exclusion', false,
        'could not capture an export payload here — confirm this one on the device (it is an A5 checkpoint anyway)');
    }

    await browser.close();
  } catch (err) {
    await browser.close().catch(() => {});
    close();
    console.error(`\n  PRE-FLIGHT ERROR: ${err.message}\n`);
    console.error('  This is the point of running it here: the failure is on a machine, not on a phone.\n');
    process.exit(1);
  }
  close();

  // ─── the card ──────────────────────────────────────────────────────────────
  const lines = [];
  const say = (s = '') => { lines.push(s); console.log(s); };

  say('  ── PRE-FLIGHTED (confirm on device, do not re-derive) ──────────────────');
  say('');
  let failed = 0;
  let lastRow = null;
  for (const r of results) {
    if (r.row !== lastRow) { say(`  ${r.row}`); lastRow = r.row; }
    if (!r.ok) failed++;
    say(`    ${r.ok ? 'ok  ' : 'FAIL'}  ${r.label}`);
    say(`          ${r.detail}`);
  }
  say('');
  say('  ── ONLY YOU CAN DO THESE, AND HERE IS WHY ──────────────────────────────');
  say('');
  for (const [row, why] of Object.entries(HARDWARE_ONLY)) {
    say(`  ${row}  ${why}`);
    say('');
  }
  say('  A3 and A8 are device actions with pre-known answers: A3 is create → reopen →');
  say('  same record; A8 is two Safari tabs where the stale save must not win.');
  say('');
  say('  SUGGESTED ORDER — most of this rides along with a trip you are taking anyway:');
  say('    parked, before you roll   A1, A2, A9, A10, A13-logic, A5, A3, A8');
  say('    during the run            A6 (start parked, drive, pocket the phone 10+ min)');
  say('    still parked, after       A7 (revoke Location mid-trip), A4 (Airplane Mode)');
  say('    any time                  A11 (look at it), A12 (invite → claim → Home Screen)');
  say('');
  say('  NOTHING HERE CLOSES A ROW. Issue #226: a harness may pre-validate logic and');
  say('  may never mark an A-row PASS. This only means you are confirming answers');
  say('  instead of working them out on a phone.');
  say('');

  if (outFile) { await fs.writeFile(outFile, lines.join('\n') + '\n'); console.log(`  written to ${outFile}\n`); }

  if (failed) {
    console.log(`  ${failed} pre-flight check(s) FAILED — fix before the device pass.\n`);
    process.exit(1);
  }
  console.log('  All pre-flightable logic behaves. The device pass is confirmation.\n');
  return 0;
}

run().catch(e => { console.error(e); process.exit(1); });
