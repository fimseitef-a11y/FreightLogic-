import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(path.join(here, '..', 'modern-shell.js'), 'utf8');

const documentListeners = new Map();
const document = {
  readyState: 'loading',
  addEventListener(type, fn) { documentListeners.set(type, fn); },
  querySelectorAll() { return []; },
  querySelector() { return null; },
  getElementById() { return null; },
  createElement() { throw new Error('createElement should not run before install'); },
  body: { classList: { add() {}, remove() {}, toggle() {} } },
  documentElement: { style: { setProperty() {} } }
};
const windowListeners = new Map();
const window = {
  location: { hash: '' },
  addEventListener(type, fn) { windowListeners.set(type, fn); },
  requestAnimationFrame(fn) { fn(); }
};

const context = vm.createContext({
  window,
  document,
  console,
  setTimeout,
  clearTimeout,
  MutationObserver: class { observe() {} disconnect() {} },
  getComputedStyle() { return { display: 'block', visibility: 'visible' }; }
});
vm.runInContext(source, context, { filename: 'modern-shell.js' });

const shell = window.FreightLogicModernShell;
assert.ok(shell, 'modern shell API must be exported');
assert.equal(typeof shell.installTodayCommandCenter, 'function', 'Today-v2 installer must be executable');
assert.equal(typeof shell.focusFuelPriceSetting, 'function', 'fuel action must have an executable canonical route repair');
assert.equal(typeof shell.todayPresentationSpec, 'function', 'Today-v2 presentation contract must be inspectable');

const spec = shell.todayPresentationSpec();
assert.equal(spec.homeId, 'view-home');
assert.equal(spec.primaryCardId, 'homeKPICard');
assert.equal(spec.positionCardId, 'homePositioningCard');
assert.equal(spec.moneyCardId, 'homeMoneyCard');
assert.equal(spec.fuelRoute, 'insights');
assert.equal(spec.fuelFieldId, 'fuelPrice');
assert.equal(spec.fuelSectionId, 'settingsCosts');
assert.equal(spec.positionDisclosureId, 'homePositioningDisclosure');
assert.equal(spec.homeClass, 'today-command-v2');

assert.match(source, /--fl-header-bottom/, 'shell must publish measured header bottom for transient UI');
assert.match(source, /quarterly-nudge/, 'shell must normalize CPA reminder flow');
assert.match(source, /fuelNudgeCard/, 'shell must bind the rendered fuel nudge, not a duplicate control');

console.log('Today command center v2 contract: PASS');
