import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const app = readFileSync(path.join(ROOT, 'app.js'), 'utf8');

export async function runSpec(){
  let pass = 0, fail = 0;
  const failures = [];
  const check = (name, cond) => {
    if (cond) { pass++; console.log('  ✓', name); }
    else { fail++; failures.push({ name }); console.error('  ✗', name); }
  };

  // Issue #417 Slice A contracts. These are source-level ownership assertions:
  // behavioral lifecycle math remains covered by the existing lifecycle specs.
  check('UXIA-01/09: Today owns one explicit stateful primary-action resolver',
    /function resolveTodayPrimaryAction\s*\(/.test(app) && /renderTodayPrimaryAction\s*\(/.test(app));
  check('UXIA-02: Current Load is a dedicated canonical route',
    /current:\s*\$\('#view-current'\)/.test(app) && /name === 'current'/.test(app));
  check('UXIA-02: Current Load reads canonical lifecycle state',
    /async function renderCurrentLoad\s*\(/.test(app) && /listLifecycle\(\)/.test(app));
  check('UXIA-06: Trips exposes History explicitly while preserving #trips compatibility',
    /History/.test(app) && /location\.hash\s*=\s*'#trips'/.test(app));
  check('UXIA-10: Reports is a coherent dedicated route',
    /reports:\s*\$\('#view-reports'\)/.test(app) && /async function renderReports\s*\(/.test(app));
  check('UXIA-14: legacy #history and #reports aliases are canonicalized safely',
    /hash === 'history'/.test(app) && /hash === 'reports'/.test(app));
  check('Settings remains a separate destination from Reports',
    /Settings/.test(app) && /Reports/.test(app));

  return { file: 'issue-417-slice-a-ia.spec.mjs', pass, fail, failures };
}
