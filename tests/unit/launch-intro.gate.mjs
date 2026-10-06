import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');

const { test, run } = createSuite('unit/launch-intro.gate.mjs');

test('[LI-01] launch intro is decorative, noninteractive, and present before app content', () => {
  const html = read('index.html');
  const marker = html.indexOf('id="launchIntro"');
  ok(marker >= 0, 'index.html must include #launchIntro');
  ok(/id="launchIntro"[^>]*class="[^"]*launch-intro[^"]*"[^>]*aria-hidden="true"/.test(html)
    || /id="launchIntro"[^>]*aria-hidden="true"[^>]*class="[^"]*launch-intro[^"]*"/.test(html),
    '#launchIntro must be decorative (aria-hidden=true)');
  const appMarker = html.search(/id="(?:app|root|shell|page|today)/);
  ok(appMarker < 0 || marker < appMarker,
    '#launchIntro must be declared before the main application surface');
});

test('[LI-02] intro duration stays inside the requested 2–3 second launch window', () => {
  const css = read('styles.css');
  const rule = css.match(/\.launch-intro\s*\{([\s\S]*?)\}/)?.[1] || '';
  const duration = Number(rule.match(/animation-duration:\s*([0-9.]+)s/)?.[1]);
  ok(Number.isFinite(duration), '.launch-intro must declare animation-duration in seconds');
  ok(duration >= 2 && duration <= 3,
    `launch intro duration must be 2–3 seconds; got ${duration || 'missing'}`);
});

test('[LI-03] intro cannot block taps or application readiness', () => {
  const css = read('styles.css');
  const rule = css.match(/\.launch-intro\s*\{([\s\S]*?)\}/)?.[1] || '';
  ok(/pointer-events:\s*none/.test(rule),
    '.launch-intro must use pointer-events:none so it cannot block the app');
  ok(/position:\s*fixed/.test(rule) && /inset:\s*0/.test(rule),
    '.launch-intro must be an isolated fixed overlay');
});

test('[LI-04] reduced-motion users do not receive the launch animation', () => {
  const css = read('styles.css');
  const reduced = css.match(/@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}/)?.[1] || '';
  ok(reduced.includes('.launch-intro'),
    'reduced-motion media query must address .launch-intro');
  ok(/animation:\s*none/.test(reduced),
    'reduced-motion launch intro must disable animation');
  ok(/visibility:\s*hidden/.test(reduced) || /display:\s*none/.test(reduced),
    'reduced-motion launch intro must be immediately hidden');
});

export async function runSpec() {
  return run();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  if (result.fail) process.exitCode = 1;
}
