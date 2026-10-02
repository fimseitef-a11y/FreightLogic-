import { readFileSync } from 'node:fs';
import { createSuite, eq, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/audit-suite-result.spec.mjs');
const source = readFileSync(new URL('../run-all.mjs', import.meta.url), 'utf8');
const start = source.indexOf('function normalizeSpecResult(');
const end = source.indexOf('\nasync function runJob(', start);
if (start < 0 || end < 0) throw new Error('Production result-normalizer boundary missing');
const normalize = new Function(source.slice(start, end) + '\nreturn normalizeSpecResult;')();

test('[ASR-01] legacy passing results preserve counts and gain safe reporting details', () => {
  const result = normalize({ file: 'legacy', pass: 3, fail: 0 }, 'job');
  eq(result.pass, 3);
  eq(result.fail, 0);
  eq(result.failures.length, 0);
});
test('[ASR-02] legacy failing results preserve failure counts and produce a visible diagnostic', () => {
  const result = normalize({ pass: 2, fail: 4 }, 'job');
  eq(result.pass, 2);
  eq(result.fail, 4);
  eq(result.file, 'job');
  ok(result.failures[0].name.includes('4 failed'), 'missing details cannot crash or hide failure');
});
test('[ASR-03] missing, nonfinite, negative and fractional counts cannot yield a green suite', () => {
  for (const input of [undefined, {}, { pass: 1 }, { pass: NaN, fail: 0 },
    { pass: 1, fail: -1 }, { pass: 1.5, fail: 0 }, { pass: 1, fail: Infinity }]) {
    const result = normalize(input, 'bad');
    eq(result.pass, 0);
    eq(result.fail, 1);
    ok(result.failures[0].name.includes('invalid assertion counts'));
  }
});
test('[ASR-04] a spec that executes no assertions fails, and real assertion details survive', () => {
  eq(normalize({ pass: 0, fail: 0 }, 'empty').fail, 1);
  const result = normalize({ pass: 2, fail: 1, failures: [{ name: 'actual regression' }] }, 'job');
  eq(result.fail, 1);
  eq(result.failures[0].name, 'actual regression');
});
export async function runSpec() { return run(); }
