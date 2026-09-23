// v24.0.34 — the service worker's Web Push handlers (docs/WEB_PUSH_CONTRACT.md §7).
//
// The REAL service-worker.js is evaluated in a vm sandbox that stands in for
// ServiceWorkerGlobalScope, so the handlers under test are the shipped ones.
// Chromium in the rest of the suite cannot deliver a real push (no push
// service), which is why this is a unit spec: it pins what the handler DOES
// with a payload, not whether Apple delivers it. That second half is the
// physical-device gate.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('unit/sw-push.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SRC = readFileSync(path.join(ROOT, 'service-worker.js'), 'utf8');
const SCOPE = 'https://app.test/';

function loadSW({ windows = [] } = {}) {
  const handlers = {};
  const shown = [];
  const opened = [];
  const self = {
    location: { href: SCOPE + 'service-worker.js' },
    registration: {
      scope: SCOPE,
      showNotification: async (title, opts) => { shown.push({ title, opts }); },
    },
    clients: {
      matchAll: async () => windows,
      openWindow: async (url) => { opened.push(url); },
    },
    addEventListener: (type, fn) => { handlers[type] = fn; },
    skipWaiting() {},
  };
  vm.runInNewContext(SRC, { self, URL, Headers, Response, console, setTimeout });
  return { handlers, shown, opened };
}

function pushEvent(payload) {
  const waits = [];
  const data = payload === undefined ? null : {
    json() { if (typeof payload === 'string') return JSON.parse(payload); return payload; },
  };
  return { event: { data, waitUntil: (p) => waits.push(p) }, waits };
}

function clickEvent(url) {
  const waits = [];
  let closed = false;
  return {
    event: { notification: { data: { url }, close() { closed = true; } }, waitUntil: (p) => waits.push(p) },
    waits, closed: () => closed,
  };
}

test('[SWP-01] a push shows the notification it carries, with its relay link', async () => {
  const sw = loadSW();
  ok(typeof sw.handlers.push === 'function' && typeof sw.handlers.notificationclick === 'function',
    'service-worker.js must register push and notificationclick handlers');
  const { event, waits } = pushEvent({ title: 'FreightLogic', body: 'Expense ready to save — $45.10 Tolls', url: './#do=relay&id=rl_abc12345', tag: 'relay-rl_abc12345' });
  sw.handlers.push(event);
  eq(waits.length, 1, 'the notification promise must be handed to waitUntil, or the worker may be killed first');
  await Promise.all(waits);
  eq(sw.shown.length, 1, 'exactly one notification');
  const n = sw.shown[0];
  eq(n.title, 'FreightLogic'); eq(n.opts.body, 'Expense ready to save — $45.10 Tolls');
  eq(n.opts.tag, 'relay-rl_abc12345');
  eq(n.opts.data.url, SCOPE + '#do=relay&id=rl_abc12345', 'the relative relay link resolves inside the scope');
});

test('[SWP-02] a notification can only ever open this app; text is clamped and cleaned', async () => {
  for (const hostile of ['https://evil.example/#do=expense', 'javascript:alert(1)', '//evil.example/x', 'data:text/html,hi']) {
    const sw = loadSW();
    const { event, waits } = pushEvent({ title: 't', body: 'b', url: hostile });
    sw.handlers.push(event); await Promise.all(waits);
    eq(sw.shown[0].opts.data.url, SCOPE, `${hostile} must fall back to the app scope`);
  }
  const sw = loadSW();
  const { event, waits } = pushEvent({ title: 'X'.repeat(200), body: 'line1\u0000\u0007\nline2 ' + 'y'.repeat(400) });
  sw.handlers.push(event); await Promise.all(waits);
  eq(sw.shown[0].title.length, 60, 'title clamped to 60');
  ok(sw.shown[0].opts.body.length <= 180, 'body clamped to 180');
  ok(!/[\u0000-\u001f]/.test(sw.shown[0].opts.body), 'control characters removed');
});

test('[SWP-03] an empty or malformed push still shows a notification (iOS revokes silent push)', async () => {
  for (const payload of [undefined, 'not json {', { unexpected: true }]) {
    const sw = loadSW();
    const { event, waits } = pushEvent(payload);
    sw.handlers.push(event); await Promise.all(waits);
    eq(sw.shown.length, 1, `payload ${JSON.stringify(payload)} must still display`);
    eq(sw.shown[0].title, 'FreightLogic', 'falls back to the app name');
    eq(sw.shown[0].opts.data.url, SCOPE, 'falls back to the scope');
  }
});

test('[SWP-04] tapping focuses an open app window and hands it the link', async () => {
  const posted = []; let focused = false;
  const win = { url: SCOPE + '#home', focus: async () => { focused = true; }, postMessage: (m) => posted.push(m) };
  const other = { url: 'https://evil.example/', focus: async () => { throw new Error('must not focus'); }, postMessage: () => { throw new Error('must not post'); } };
  const sw = loadSW({ windows: [other, win] });
  const c = clickEvent(SCOPE + '#do=relay&id=rl_abc12345');
  sw.handlers.notificationclick(c.event); await Promise.all(c.waits);
  ok(c.closed(), 'the notification is closed');
  ok(focused, 'the same-origin window is focused');
  eq(JSON.stringify(posted), JSON.stringify([{ type: 'FL_OPEN_URL', url: SCOPE + '#do=relay&id=rl_abc12345' }]), 'the link is posted to the app');
  eq(sw.opened.length, 0, 'no second window is opened');
});

test('[SWP-05] with no app window, tapping opens one — never somewhere else', async () => {
  const sw = loadSW();
  const c = clickEvent(SCOPE + '#do=relay&id=rl_abc12345');
  sw.handlers.notificationclick(c.event); await Promise.all(c.waits);
  eq(JSON.stringify(sw.opened), JSON.stringify([SCOPE + '#do=relay&id=rl_abc12345']));
  const sw2 = loadSW();
  const c2 = clickEvent('https://evil.example/phish');
  sw2.handlers.notificationclick(c2.event); await Promise.all(c2.waits);
  eq(JSON.stringify(sw2.opened), JSON.stringify([SCOPE]), 'a foreign URL in notification data is not opened');
});

test('[SWP-06] the push handlers stay a delivery layer: no storage, credentials or network', async () => {
  const start = SRC.indexOf('// ── v24.0.34: Web Push delivery');
  ok(start > 0, 'push section marker present');
  const section = SRC.slice(start).split('\n').filter(l => !/^\s*\/\//.test(l)).join('\n');
  for (const banned of ['indexedDB', 'caches.', 'fetch(', 'cloudBackupToken', 'X-Backup-Token', 'localStorage', 'importScripts']) {
    ok(!section.includes(banned), `push handlers must not use ${banned}`);
  }
});

export async function runSpec() {
  return await run();
}
