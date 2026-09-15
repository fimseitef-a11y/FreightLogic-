#!/usr/bin/env node
// A byte change in a deployed app asset must advance the PWA generation.
// Static marker agreement alone cannot detect a release that reused its number.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { declaredRuntimeAssets, REPO_ROOT } from './lib/deploy-assets.mjs';
const git = (...args) => execFileSync('git', args, {cwd:REPO_ROOT, encoding:'utf8', maxBuffer:8*1024*1024}).trim();
export function generationVerdict(before, after, changedRuntime){
  const parse = v => /^\d+\.\d+\.\d+$/.test(v || '') ? v.split('.').map(Number) : null;
  const a = parse(before), b = parse(after);
  if (!a || !b) return {ok:false, reason:'Missing or invalid release generation'};
  const cmp = b[0]-a[0] || b[1]-a[1] || b[2]-a[2];
  if (cmp < 0) return {ok:false, reason:'Release generation moved backwards'};
  if (changedRuntime.length && cmp === 0) return {ok:false, reason:'Runtime assets changed without a new release generation'};
  return {ok:true, reason:changedRuntime.length ? 'Runtime changes advance the release generation' : 'No deployed app bytes changed'};
}
export function verifyGeneration(base){
  if (!base){
    const head = git('rev-parse','HEAD'), main = git('rev-parse','origin/main');
    base = head === main ? git('rev-parse','HEAD^1') : git('merge-base','HEAD','origin/main');
  }
  const previous = git('show',`${base}:app.js`).match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];
  const current = readFileSync(`${REPO_ROOT}/app.js`,'utf8').match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];
  const runtime = new Set([...declaredRuntimeAssets().assets.keys(), 'service-worker.js']);
  const changedRuntime = git('diff','--name-only',base,'--').split('\n').filter(p => runtime.has(p));
  return {...generationVerdict(previous,current,changedRuntime), base, previous, current, changedRuntime};
}
if (process.argv[1] === fileURLToPath(import.meta.url)){
  const result = verifyGeneration(process.argv[2]);
  console.log(JSON.stringify(result,null,2));
  process.exit(result.ok ? 0 : 1);
}
