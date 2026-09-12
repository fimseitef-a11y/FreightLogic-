#!/usr/bin/env node
/**
 * FreightLogic — private-history bundle preflight (completion gate C).
 *
 * Gate C (`FIELD_TEST_CHECKLIST.md` section C,
 * `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-12.md`) is
 * SOURCE FILE MISSING / NOT RUN: the raw row-level operator master is not in
 * the repository or any supplied archive, and summaries must not be used to
 * reconstruct it.
 *
 * WHY THIS EXISTS
 * `scripts/m6-import.mjs` is a file-specific adapter, not a general importer.
 * It is hard-wired to five exact filenames and their exact column spellings
 * from the 2026-08-27 bundle, and it fails on the first missing file. Handing
 * it a re-export that is merely *close* produces a crash or — worse — silent
 * row loss, then a round trip, then another. This script front-loads every
 * structural check so the FIRST re-export is the right shape.
 *
 * PRIVACY CONTRACT — THIS IS THE POINT, NOT A DISCLAIMER.
 * Gate C requires that only non-sensitive reconciliation results be recorded
 * publicly. This script therefore prints STRUCTURE ONLY: filenames, column
 * names, row counts, and which required columns are absent. It never prints a
 * cell value, an order number, a broker, a city, a rate, or a date. Its output
 * is safe to paste into an issue, a PR, or a certification record.
 *
 *   node scripts/verify-history-bundle.mjs /path/to/bundle-dir
 *
 * Exit 0 = the bundle satisfies m6-import's input contract.
 * Exit 1 = it does not; every problem is listed.
 * Exit 2 = usage error.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const BUNDLE = process.argv[2];
if (!BUNDLE) {
  console.error('usage: node scripts/verify-history-bundle.mjs <bundle-dir>');
  console.error('\nThe bundle should live OUTSIDE this repository — gate C requires the raw');
  console.error('row-level data stay private. Pass an absolute path.');
  process.exit(2);
}
if (!existsSync(BUNDLE) || !statSync(BUNDLE).isDirectory()) {
  console.error(`not a directory: ${BUNDLE}`);
  process.exit(2);
}

/* ---- CSV reader: byte-identical to m6-import.mjs's, so this preflight agrees
   with the importer about what a row IS (quoted fields, embedded commas and
   newlines). A looser parser here would pass bundles the importer then rejects. */
function parseCSV(text) {
  const rows = []; let i = 0, field = '', row = [], q = false;
  const pushF = () => { row.push(field); field = ''; };
  const pushR = () => { rows.push(row); row = []; };
  while (i < text.length) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } q = false; i++; continue; }
      field += c; i++; continue;
    }
    if (c === '"') { q = true; i++; continue; }
    if (c === ',') { pushF(); i++; continue; }
    if (c === '\r') { i++; continue; }
    if (c === '\n') { pushF(); pushR(); i++; continue; }
    field += c; i++;
  }
  if (field.length || row.length) { pushF(); pushR(); }
  return rows.filter(r => r.some(x => x !== ''));
}

/**
 * The input contract, extracted from scripts/m6-import.mjs.
 * `key` columns are the ones whose absence drops rows silently or crashes the
 * adapter. `valued` columns carry facts the reconciliation needs; a missing one
 * is a WARN because the adapter is designed to keep the value UNKNOWN rather
 * than invent it — that is correct behaviour, but it means a quietly truncated
 * export degrades the result without failing.
 * `expectedRows` is the count recorded in the bundle's own documentation.
 */
const CONTRACT = [
  {
    file: 'All_Trips_App_Import_v1.csv',
    key: ['Order_Number'],
    valued: ['Company', 'Pickup_City', 'Pickup_State', 'Delivery_City', 'Delivery_State',
             'Pickup_Date', 'Delivery_Date', 'Gross_Pay', 'Miles'],
    expectedRows: null,
    note: '`Miles` is treated as a DISPLAYED TOTAL, never as loaded miles — so loaded/deadhead stay UNKNOWN and True RPM is not computable from this file.',
  },
  {
    file: 'text 2.csv',
    key: ['Order_Number'],
    valued: ['Carrier', 'Pickup_City', 'Delivery_City', 'Completed_Date',
             'Gross_Pay', 'Total_Miles', 'RPM'],
    expectedRows: 58,
    note: 'The column is `Carrier`, NOT broker (B6). Canonical broker is deliberately left UNKNOWN. Note the filename contains a SPACE and is lowercase — `text 2.csv` exactly.',
  },
  {
    file: 'COMPLETE-UNIFIED-DATA.csv',
    key: ['Order #', 'Type'],
    valued: ['Broker', 'Origin', 'Destination', 'Pickup Date', 'Delivery Date',
             'Revenue', 'Loaded Miles'],
    expectedRows: null,
    note: 'Rows whose `Type` is not `trip` are skipped by design. Column names here use SPACES (`Order #`, `Loaded Miles`), unlike the underscore spellings in the two files above. An `Empty Miles` of 0 is NOT accepted as proof of zero deadhead.',
  },
  {
    file: 'RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv',
    key: ['id', 'status'],
    valued: ['date', 'origin', 'destination', 'final_rate', 'loaded_miles',
             'deadhead_miles', 'displayed_or_total_miles', 'captured_rpm'],
    expectedRows: 26,
    note: 'AI_SECONDARY authority, status-driven. DRY RUN rows are imported as their own excluded class (B7); an unrecognized status sets no award (B8).',
  },
  {
    file: 'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv',
    key: ['id', 'status'],
    valued: ['date', 'origin', 'destination', 'final_rate', 'loaded_miles',
             'empty_miles', 'displayed_or_total_miles', 'displayed_rpm',
             'submitted_bid', 'target_rate'],
    expectedRows: null,
    note: 'Carries bid/target observations as well as orders.',
  },
];

let failures = 0, warnings = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const bad = (m) => { console.log(`  FAIL  ${m}`); failures++; };
const warn = (m) => { console.log(`  WARN  ${m}`); warnings++; };

console.log('== FreightLogic private-history bundle preflight (gate C) ==\n');
console.log(`Bundle: ${BUNDLE}`);
console.log('Output is STRUCTURE ONLY — no cell values are read out. Safe to share.\n');

// Is the bundle inside the repo? That would risk committing private data.
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
if (path.resolve(BUNDLE).startsWith(repoRoot + path.sep)) {
  warn('the bundle is INSIDE the repository working tree. Gate C requires this data ' +
       'stay private; move it outside before running the importer, or it can be ' +
       'committed by accident.');
}

console.log('-- required files --');
const present = new Set(readdirSync(BUNDLE));
for (const spec of CONTRACT) {
  if (present.has(spec.file)) ok(`${spec.file}`);
  else {
    bad(`${spec.file} — MISSING. m6-import.mjs reads this unconditionally and will throw.`);
    // Offer a near-miss, since the filenames are easy to get subtly wrong.
    const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
    const near = [...present].filter(f => norm(f) === norm(spec.file) ||
      (norm(f).includes(norm(spec.file).slice(0, 12)) && f.endsWith('.csv')));
    if (near.length) console.log(`        near-miss in bundle: ${near.join(', ')}  <- rename to match EXACTLY`);
  }
}

console.log('\n-- columns and row counts --');
let grandTotal = 0;
for (const spec of CONTRACT) {
  if (!present.has(spec.file)) continue;
  let rows;
  try {
    rows = parseCSV(readFileSync(path.join(BUNDLE, spec.file), 'utf8'));
  } catch (e) {
    bad(`${spec.file} — unreadable (${e.code || e.message})`);
    continue;
  }
  if (!rows.length) { bad(`${spec.file} — no parseable rows at all`); continue; }

  const header = rows[0].map(h => h.trim());
  const dataRows = rows.length - 1;
  grandTotal += dataRows;

  const missingKey = spec.key.filter(c => !header.includes(c));
  const missingValued = spec.valued.filter(c => !header.includes(c));

  console.log(`\n  ${spec.file}  —  ${dataRows} data row(s), ${header.length} column(s)`);

  if (missingKey.length) {
    bad(`  ${spec.file}: missing KEY column(s): ${missingKey.join(', ')} — rows will be ` +
        'dropped silently (the adapter skips any row with no id/order number)');
  } else {
    ok(`  all key columns present: ${spec.key.join(', ')}`);
  }

  if (missingValued.length) {
    warn(`  ${spec.file}: missing value column(s): ${missingValued.join(', ')} — these ` +
         'facts will stay UNKNOWN (correct, but the reconciliation is weaker than intended)');
  } else {
    ok(`  all value columns present`);
  }

  if (spec.expectedRows !== null) {
    if (dataRows === spec.expectedRows) ok(`  row count matches the documented ${spec.expectedRows}`);
    else warn(`  row count is ${dataRows}; bundle documentation records ${spec.expectedRows}. ` +
              'Investigate the difference — do NOT pad the file to match.');
  }

  // Duplicate header names silently shadow each other in the adapter's row objects.
  const dupes = header.filter((h, i) => header.indexOf(h) !== i);
  if (dupes.length) bad(`  ${spec.file}: duplicate column name(s): ${[...new Set(dupes)].join(', ')} — ` +
                        'the later column silently overwrites the earlier one');

  // A BOM on the first header breaks an exact-match column lookup.
  if (rows[0][0] && rows[0][0].charCodeAt(0) === 0xFEFF) {
    bad(`  ${spec.file}: starts with a UTF-8 BOM — the first column name will not match. ` +
        'Re-export as UTF-8 without BOM.');
  }

  console.log(`        note: ${spec.note}`);
}

console.log(`\n-- totals --`);
console.log(`  ${grandTotal} data row(s) across ${CONTRACT.filter(s => present.has(s.file)).length} of ${CONTRACT.length} expected files`);
if (grandTotal < 125) {
  warn(`the recovered handoff describes a 125-row master. This bundle totals ${grandTotal} ` +
       'rows across all files (they overlap, so the reconciled count is lower than the sum). ' +
       'If the master is genuinely short, report the gap — do NOT reconstruct rows from summaries.');
}

const extras = [...present].filter(f => f.endsWith('.csv') && !CONTRACT.some(s => s.file === f));
if (extras.length) {
  console.log(`\n  CSVs present but NOT read by m6-import.mjs: ${extras.join(', ')}`);
  console.log('  (the adapter is file-specific; these are ignored entirely)');
}

console.log('\n== gate C preflight verdict ==\n');
if (failures) {
  console.log(`${failures} blocking problem(s), ${warnings} warning(s).`);
  console.log('m6-import.mjs would fail or lose rows on this bundle. Fix the above first.\n');
  process.exit(1);
}
console.log(`0 blocking problems, ${warnings} warning(s).`);
console.log('This bundle satisfies m6-import.mjs\'s input contract. Next:\n');
console.log('  node scripts/m6-import.mjs <bundle-dir> <out-dir>');
// NB: m6-import.mjs's own header comment claims it emits `import-report.md`. It
// does not — the actual artifact is `import-report.json`. Verified by running it.
console.log('\nThen review out-dir/import-report.json and out-dir/withheld.json BEFORE importing.');
console.log('Gate C PASS additionally requires: no invented broker identity, no unsupported');
console.log('WON/completed promotion, no UNKNOWN-to-zero coercion, preserved source');
console.log('timestamps/semantics, and no collapse of distinct shipments sharing an');
console.log('external id. The withheld.json file is the evidence for the last two.\n');
process.exit(0);
