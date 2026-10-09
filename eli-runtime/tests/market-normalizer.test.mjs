// Market-text normalizer regression (ELI FINDING + HANDOFF 2026-10-09, R1 + R3).
// Fixtures are real Load History strings from production D1 freightlogic-eli-runtime-v1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  aliasMapFrom,
  buildAliasRows,
  marketLookupKey,
  resolveMarket,
} from '../ingest.mjs';

const NOW = '2026-10-09T12:00:00Z';
const alias = (id, aliasText, market) => ({
  id,
  fields: { fldKR0KUzl6ozdA0n: aliasText, fldXqOWA6L88MUUpy: market, fldh7mhLR93c2fJ19: 'Verified' },
});
const key = (value) => marketLookupKey(value).key;

test('N01 ZIP suffix and missing comma reduce to the alias key', () => {
  assert.equal(key('Milwaukee WI'), 'milwaukee, wi');
  assert.equal(key('Memphis, TN 38118'), 'memphis, tn');
  assert.equal(key('La Vergne, TN 37086'), 'la vergne, tn');
  assert.equal(key('Lebanon, TN 37087-1234'), 'lebanon, tn', 'ZIP+4');
  assert.equal(key('  MILWAUKEE   WI  53201 '), 'milwaukee, wi', 'case and repeated spaces');
});

test('N02 "City ST" gets the comma form', () => {
  for (const [raw, want] of [
    ['Hartland WI', 'hartland, wi'],
    ['West Bend WI', 'west bend, wi'],
    ['Aurora IL', 'aurora, il'],
    ['Chicago IL', 'chicago, il'],
  ]) assert.equal(key(raw), want, raw);
});

test('N03 Saint / St / St. collapse to one key, and it is the St. Louis alias key', () => {
  const stl = key('St. Louis, MO');
  assert.ok(stl);
  for (const raw of ['Saint Louis MO', 'St Louis MO', 'St. Louis, MO', 'Saint Louis, MO 63132']) {
    assert.equal(key(raw), stl, raw);
  }
  const map = aliasMapFrom(buildAliasRows([alias('stl', 'St. Louis, MO', 'MKT-STL')], NOW));
  assert.equal(resolveMarket('Saint Louis MO', map), 'MKT-STL');
  assert.equal(resolveMarket('St Louis MO', map), 'MKT-STL');
  assert.equal(resolveMarket('Lake Saint Louis, MO 63367', map), null, 'a different city is not merged');
  assert.equal(resolveMarket('Bay Saint Louis, MS 39520', map), null, 'a different state is not merged');
});

test('N04 Mount / Mt / Mt. collapse to one key', () => {
  assert.equal(key('Mt Prospect IL'), key('Mount Prospect, IL'));
  assert.equal(key('Mt. Juliet, TN'), key('Mount Juliet, TN 37122'));
  assert.notEqual(key('Mount Vernon, IL 62864'), key('Mount Prospect, IL'));
});

test('N05 parenthetical notes and a trailing country are noise', () => {
  assert.equal(key('Atlanta, GA (zip unknown)'), 'atlanta, ga');
  assert.equal(key('Doral, FL (ZIP unknown)'), 'doral, fl');
  assert.equal(key('Memphis, TN 38118, USA'), 'memphis, tn');
  assert.equal(key('Memphis, TN, US'), 'memphis, tn');
});

test('N06 placeholders, multi-leg, roads, two-city strings and Canadian addresses stay unresolved and flagged', () => {
  const cases = [
    ['Unknown Origin', 'UNKNOWN_PLACEHOLDER'],
    ['Unknown Destination', 'UNKNOWN_PLACEHOLDER'],
    ['unknown city (Rochester), IN', 'UNKNOWN_PLACEHOLDER'],
    ['Multi-Leg', 'MULTI_LEG'],
    ['Ohio Turnpike', 'ROAD'],
    ['Anderson, IN 46011 -> London, KY 40741', 'MULTI_CITY'],
    ['McCordsville / Indianapolis, IN', 'MULTI_CITY'],
    ['Kitchener, ON N2A 0A1, CA', 'NON_US'],
    ['Thunder Bay, ON P7B 7B8, Canada', 'NON_US'],
    ['Montmagny, QC', 'NON_US'],
    ['Woodstock, ON', 'NON_US'],
    ['Hagerstown', 'NO_STATE'],
  ];
  const map = aliasMapFrom(buildAliasRows([
    alias('a', 'Indianapolis, IN', 'MKT-IND'),
    alias('b', 'London, KY', 'MKT-SDF'),
  ], NOW));
  for (const [raw, flag] of cases) {
    const result = marketLookupKey(raw);
    assert.equal(result.key, null, `${raw} must not produce a lookup key`);
    assert.equal(result.flag, flag, raw);
    assert.equal(resolveMarket(raw, map), null, `${raw} must stay UNKNOWN`);
  }
  assert.deepEqual(marketLookupKey(null), { key: null, flag: null }, 'absent is absent, not a data-quality flag');
  assert.deepEqual(marketLookupKey('   '), { key: null, flag: null });
});

test('N07 state-exact: Columbus IN is not Columbus OH; Springfield MO and Winchester KY keep their state', () => {
  assert.notEqual(key('Columbus, IN'), key('Columbus, OH'));
  const map = aliasMapFrom(buildAliasRows([
    alias('a', 'Columbus, OH', 'MKT-CMH'),
    alias('b', 'Springfield, MO', 'MKT-SGF'),
    alias('c', 'Winchester, KY', 'MKT-LEX'),
  ], NOW));
  assert.equal(resolveMarket('Columbus, IN', map), null);
  assert.equal(resolveMarket('Columbus IN', map), null);
  assert.equal(resolveMarket('Columbus, OH', map), 'MKT-CMH');
  assert.equal(resolveMarket('Springfield MO 65803', map), 'MKT-SGF');
  assert.equal(resolveMarket('Springfield, KY 40069', map), null);
  assert.equal(resolveMarket('Springfield, IL', map), null);
  assert.equal(resolveMarket('Winchester, KY', map), 'MKT-LEX');
  assert.equal(resolveMarket('Winchester, VA', map), null);
  assert.equal(resolveMarket('Columbus', map), null, 'no state is never guessed');
});

test('N08 alias_norm and lookup use the same function', () => {
  const texts = ['St. Louis, MO', 'Mount Juliet, TN', 'Milwaukee, WI', 'La Vergne, TN', 'Oklahoma City OK'];
  const rows = buildAliasRows(texts.map((t, i) => alias(`r${i}`, t, 'MKT-X')), NOW);
  assert.deepEqual(rows.map((r) => r.aliasNorm), texts.map(key), 'alias_norm is exactly marketLookupKey(alias text)');

  // Every lookup path in the runtime goes through marketLookupKey; none keeps a private normalizer.
  const ingest = readFileSync(new URL('../ingest.mjs', import.meta.url), 'utf8');
  const pipeline = readFileSync(new URL('../pipeline.mjs', import.meta.url), 'utf8');
  const fnBody = (src, name) => src.slice(src.indexOf(`function ${name}(`), src.indexOf('\n}\n', src.indexOf(`function ${name}(`)));
  assert.match(fnBody(ingest, 'buildAliasRows'), /marketLookupKey\(aliasText\)/);
  assert.match(fnBody(ingest, 'resolveMarket'), /marketLookupKey\(/);
  assert.match(fnBody(pipeline, 'resolveMarketInDb'), /marketLookupKey\(/);
  for (const [name, src] of [['buildAliasRows', ingest], ['resolveMarket', ingest], ['resolveMarketInDb', pipeline]]) {
    assert.doesNotMatch(fnBody(src, name), /normalizeMarketText\(|toLowerCase\(/, `${name} must not normalize on its own`);
  }
});

test('N09 an alias text that is itself flagged never enters the alias table', () => {
  const rows = buildAliasRows([
    alias('a', 'Unknown Origin', 'MKT-ATL'),
    alias('b', 'Toronto, ON', 'MKT-YYZ'),
    alias('c', 'Atlanta, GA', 'MKT-ATL'),
  ], NOW);
  assert.deepEqual(rows.map((r) => r.aliasNorm), ['atlanta, ga']);
});
