// Issue #219 — an untrusted local import must never replace local credential
// or security state.
//
// THE DEFECT, exactly as it stood on main @ ee07297:
//
//   `ALLOWED_SETTINGS_KEYS` (inside `importJSON()`) admitted `cloudBackupToken`,
//   `cloudBackupUrl`, `appLockPin`, `fmcsaApiKey` and `eiaApiKey`. The import
//   writer then wrote every accepted settings row through a blind `store.put()`.
//   `cloudGetConfig()` reads BOTH `cloudBackupToken` and `cloudBackupUrl` back,
//   so a crafted JSON file — the kind an operator can be handed and will happily
//   feed to "Import Data" — could silently repoint every subsequent backup at an
//   attacker's endpoint using an attacker's bearer token, and replace the
//   app-lock PIN hash on the way past.
//
//   Export-side stripping (`exportSafeSettings`, v24.0.4 item 5) is NOT a
//   defence here and the file's own comment said so: it governs what an export
//   EMITS, never what an import ACCEPTS.
//
//   Second half: the writer's `mode === 'skip'` guard tested `x.id !== undefined`.
//   `settings` has keyPath `key`, not `id`, so NO settings record could ever
//   satisfy it and every one fell through to `put()`. `skip` mode therefore
//   overwrote existing settings on every import — the exact opposite of what the
//   mode means, and the reason the credential overwrite landed even in the mode
//   an operator would pick specifically to avoid clobbering local state.
//
// These assertions drive the REAL `importJSON()` against a real IndexedDB with a
// real pre-existing credential in it, and compare the stored value byte for
// byte. They deliberately do not test the policy function alone: the defect was
// in what reached the store, and a policy that is correct but unreachable is the
// failure mode this repository has recorded four times (OI-11, checklist item 15,
// PR #213's empty function, PA-01).
//
// NEGATIVE CONTROLS, each verified to fire against the reinstated defect:
//   - re-admitting the credential keys to `ALLOWED_SETTINGS_KEYS` alone is NOT
//     enough to fail ICT-01/02, because `isSettingImportSafe()` still denies
//     them — so ICT-06 asserts the gate directly, and reverting the gate alone
//     fails ICT-01/02/03. Both edits are required to reopen the hole and either
//     one alone is caught.
//   - reverting `idbRecordHasOwnKey()` to `x.id !== undefined` fails ICT-05.

import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/import-credential-trust-boundary.spec.mjs');

// The credential/security state a real install holds, and the values an
// attacker-supplied file tries to put in its place.
const LOCAL = {
  cloudBackupToken: 'flk_1111111111111111111111111111aaaa',
  cloudBackupUrl: 'https://freightlogic-backup.fimseitef.workers.dev',
  appLockPin: 'pbkdf2$real-local-pin-hash',
  fmcsaApiKey: 'local-fmcsa-key',
  eiaApiKey: 'local-eia-key',
  appLockEnabled: true,
};
const ATTACKER = {
  cloudBackupToken: 'flk_deadbeefdeadbeefdeadbeefdeadbeef',
  cloudBackupUrl: 'https://attacker.example/collect',
  appLockPin: 'pbkdf2$attacker-pin-hash',
  fmcsaApiKey: 'attacker-fmcsa-key',
  eiaApiKey: 'attacker-eia-key',
  appLockEnabled: false,
};

/** Seeds the local credential state, then imports a payload that also carries a
 *  benign preference and a real trip, and reports what actually landed. */
async function importAttackPayload(page, mode) {
  return await page.evaluate(async ({ LOCAL, ATTACKER, mode }) => {
    const T = window.__FL_TESTS;

    for (const [k, v] of Object.entries(LOCAL)) await T.setSetting(k, v);
    // A benign preference that MUST still import, so a pass cannot be earned by
    // refusing everything.
    await T.setSetting('weeklyGoal', 1000);

    const payload = {
      meta: { app: 'FreightLogic', version: 'attack' },
      trips: [{
        orderNo: 'ICT-IMPORTED-1', customer: 'Legit Broker',
        origin: 'Gary, IN', destination: 'Toledo, OH',
        pay: 900, loadedMiles: 300, emptyMiles: 40,
      }],
      settings: [
        ...Object.entries(ATTACKER).map(([key, value]) => ({ key, value })),
        { key: 'weeklyGoal', value: 2500 },
        { key: 'homeLocation', value: 'Indianapolis, IN' },
      ],
    };

    const file = new File([JSON.stringify(payload)], 'attack.json', { type: 'application/json' });
    await T.importJSON(file, { mode });

    // Read straight out of the store, not the settings cache, so a stale cache
    // cannot make a clobbered value look preserved.
    const rows = await T.dumpStore('settings');
    const stored = {};
    for (const r of rows) stored[r.key] = r.value;
    const trips = await T.dumpStore('trips');
    return { stored, importedTrip: trips.some(t => t.orderNo === 'ICT-IMPORTED-1') };
  }, { LOCAL, ATTACKER, mode });
}

test('[ICT-01] merge import cannot replace the cloud bearer token or endpoint', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const { stored } = await importAttackPayload(app.page, 'merge');

    eq(stored.cloudBackupToken, LOCAL.cloudBackupToken,
      'the local cloud bearer token must survive an untrusted import byte for byte');
    eq(stored.cloudBackupUrl, LOCAL.cloudBackupUrl,
      'the cloud endpoint must survive — cloudGetConfig() reads it, so an imported URL redirects every later backup');
  } finally { await app.close(); }
});

test('[ICT-02] merge import cannot replace app-lock PIN material or third-party API keys', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const { stored } = await importAttackPayload(app.page, 'merge');

    eq(stored.appLockPin, LOCAL.appLockPin, 'the app-lock PIN hash must survive an untrusted import');
    eq(stored.appLockEnabled, LOCAL.appLockEnabled,
      'an import must not be able to switch the device lock off — that is a security downgrade');
    eq(stored.fmcsaApiKey, LOCAL.fmcsaApiKey, 'the FMCSA API credential must survive an untrusted import');
    eq(stored.eiaApiKey, LOCAL.eiaApiKey, 'the EIA API credential must survive an untrusted import');
  } finally { await app.close(); }
});

test('[ICT-03] ordinary non-secret preferences and records still import normally', async () => {
  // The whole point: this is a trust boundary, not a disabled feature. A pass
  // that came from refusing the entire payload would be worthless.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const { stored, importedTrip } = await importAttackPayload(app.page, 'merge');

    eq(stored.weeklyGoal, 2500, 'a permitted non-secret preference must still be imported (merge overwrites it)');
    eq(stored.homeLocation, 'Indianapolis, IN', 'a permitted non-secret preference absent locally must still be added');
    ok(importedTrip, 'the payload\'s ordinary trip record must still import');
  } finally { await app.close(); }
});

test('[ICT-04] replace mode also cannot install a credential', async () => {
  // `replace` clears the settings store first, so "the local value survived" is
  // not the property here — "the attacker's value is absent" is.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const { stored } = await importAttackPayload(app.page, 'replace');

    for (const key of Object.keys(ATTACKER)) {
      ok(stored[key] !== ATTACKER[key],
        `replace mode must not install the attacker value for ${key} (got ${JSON.stringify(stored[key])})`);
    }
    eq(stored.weeklyGoal, 2500, 'replace mode still imports permitted preferences');
  } finally { await app.close(); }
});

test('[ICT-05] skip mode actually skips an existing setting instead of overwriting it', async () => {
  // The keyPath half of the defect, on a key with no security significance at
  // all — so this fails on the `x.id !== undefined` bug specifically, and not
  // as a side effect of the credential gate.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('homeLocation', 'Gary, IN');
      const payload = { settings: [
        { key: 'homeLocation', value: 'OVERWRITTEN' },   // exists locally -> must be skipped
        { key: 'perDiemRate', value: 80 },               // absent locally  -> must be added
      ] };
      const file = new File([JSON.stringify(payload)], 's.json', { type: 'application/json' });
      await T.importJSON(file, { mode: 'skip' });
      const rows = await T.dumpStore('settings');
      const m = {}; for (const x of rows) m[x.key] = x.value;
      return { home: m.homeLocation, perDiem: m.perDiemRate };
    });

    eq(r.home, 'Gary, IN',
      'skip mode must not overwrite an existing settings row — keyPath is `key`, and the old guard tested `id`');
    eq(r.perDiem, 80, 'skip mode must still add a settings row that does not exist locally');
  } finally { await app.close(); }
});

test('[ICT-08] in skip mode one duplicate key does not abort the whole import', async () => {
  // Found by ICT-05 failing against the first version of the #219 fix, and it
  // turned out to be PRE-EXISTING rather than newly introduced: the old guard
  // already sent id-bearing trips through add(), and IndexedDB raises the
  // duplicate-key ConstraintError as an asynchronous request error that bubbles
  // to the transaction and aborts it. So re-importing a file that shared even
  // one record id silently imported NOTHING, with a cheerful "Import complete".
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      // One trip already present, with a pinned id the payload will collide on.
      await T.upsertTrip({ id: 'ict-dup-1', orderNo: 'ICT-DUP', customer: 'X',
        origin: 'Gary, IN', destination: 'Toledo, OH', pay: 500, loadedMiles: 200, emptyMiles: 10 });

      const payload = { settings: [{ key: 'perDiemRate', value: 80 }], trips: [
        { id: 'ict-dup-1', orderNo: 'ICT-DUP', customer: 'COLLIDES', pay: 1, loadedMiles: 1, emptyMiles: 1 },
        { id: 'ict-dup-2', orderNo: 'ICT-FRESH', customer: 'Fresh Broker',
          origin: 'Gary, IN', destination: 'Erie, PA', pay: 800, loadedMiles: 300, emptyMiles: 20 },
      ] };
      const file = new File([JSON.stringify(payload)], 'dup.json', { type: 'application/json' });
      await T.importJSON(file, { mode: 'skip' });

      const trips = await T.dumpStore('trips');
      const rows = await T.dumpStore('settings');
      const m = {}; for (const x of rows) m[x.key] = x.value;
      return {
        collided: (trips.find(t => t.id === 'ict-dup-1') || {}).customer,
        fresh: trips.some(t => t.orderNo === 'ICT-FRESH'),
        perDiem: m.perDiemRate,
      };
    });

    eq(r.collided, 'X', 'the existing record is left alone — that is what skip means');
    ok(r.fresh, 'a non-colliding record in the SAME payload must still import — a duplicate must not abort the transaction');
    eq(r.perDiem, 80, 'a setting written after the collision must also survive — proof the transaction was never aborted');
  } finally { await app.close(); }
});

test('[ICT-06] the import gate is strictly narrower than the export gate', async () => {
  // Asserted on the policy directly as well as through the store, because the
  // asymmetry is the part a future reader is most likely to "simplify" away:
  // `cloudBackupUrl` is deliberately exportable AND deliberately not importable.
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      const keys = ['cloudBackupToken','cloudAdminTokenEnc','appLockPin','appLockFailCount',
                    'appLockLockedUntil','fmcsaApiKey','eiaApiKey','cloudBackupUrl','appLockEnabled',
                    'weeklyGoal','homeLocation','vehicleMpg','broker_note_acme'];
      const out = {};
      for (const k of keys) out[k] = { exp: T.isSettingExportSafe(k), imp: T.isSettingImportSafe(k) };
      return out;
    });

    for (const k of ['cloudBackupToken','cloudAdminTokenEnc','appLockPin','fmcsaApiKey','eiaApiKey']) {
      eq(r[k].imp, false, `${k} must never be import-safe`);
      eq(r[k].exp, false, `${k} must never be export-safe either`);
    }
    // The asymmetric pair — safe to emit, never safe to accept.
    eq(r.cloudBackupUrl.exp, true, 'cloudBackupUrl is not a secret and stays exportable/backed up');
    eq(r.cloudBackupUrl.imp, false, 'cloudBackupUrl carries endpoint authority and must not be importable');
    eq(r.appLockEnabled.imp, false, 'appLockEnabled must not be importable — switching the lock off is a downgrade');

    for (const k of ['weeklyGoal','homeLocation','vehicleMpg','broker_note_acme']) {
      eq(r[k].imp, true, `${k} is an ordinary preference and must remain importable`);
    }

    // Import-safe must be a strict subset of export-safe: anything the gate lets
    // IN must also have been safe to let OUT. A key that is import-safe but not
    // export-safe would mean a secret could round-trip in through a file.
    for (const [k, v] of Object.entries(r)) {
      ok(!(v.imp && !v.exp), `${k} is import-safe but not export-safe — the import gate must be the narrower one`);
    }
  } finally { await app.close(); }
});

test('[ICT-07] the record-has-own-key helper reads the store\'s real keyPath', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      // Stand-ins for the three keyPath shapes the import writer actually meets.
      const idStore = { keyPath: 'id' };
      const keyStore = { keyPath: 'key' };
      const orderStore = { keyPath: 'tripOrderNo' };
      const compound = { keyPath: ['a','b'] };
      const outOfLine = { keyPath: null };
      return {
        settingsRow: T.idbRecordHasOwnKey(keyStore, { key: 'weeklyGoal', value: 1 }),
        settingsRowUnderIdStore: T.idbRecordHasOwnKey(idStore, { key: 'weeklyGoal', value: 1 }),
        receiptRow: T.idbRecordHasOwnKey(orderStore, { tripOrderNo: 'A-1' }),
        idRow: T.idbRecordHasOwnKey(idStore, { id: 7 }),
        autoIncrementRow: T.idbRecordHasOwnKey(idStore, { ts: 1 }),
        compoundBoth: T.idbRecordHasOwnKey(compound, { a: 1, b: 2 }),
        compoundPartial: T.idbRecordHasOwnKey(compound, { a: 1 }),
        outOfLine: T.idbRecordHasOwnKey(outOfLine, { id: 1 }),
        notAnObject: T.idbRecordHasOwnKey(keyStore, null),
      };
    });

    eq(r.settingsRow, true, 'a settings row carries its own key under keyPath `key` — this is what the old `id` test missed');
    eq(r.settingsRowUnderIdStore, false, 'the old guard\'s view: a settings row has no `id`, which is why skip never skipped');
    eq(r.receiptRow, true, 'a receipts row carries its own key under keyPath `tripOrderNo`');
    eq(r.idRow, true, 'an id-keyed row still reports its own key');
    eq(r.autoIncrementRow, false, 'an autoIncrement row with no id must fall through to put(), as before');
    eq(r.compoundBoth, true, 'a compound keyPath needs every component present');
    eq(r.compoundPartial, false, 'a compound keyPath with one component missing is not a complete key');
    eq(r.outOfLine, false, 'an out-of-line store\'s key comes from the caller, never the record');
    eq(r.notAnObject, false, 'a non-object is never a keyed record');
  } finally { await app.close(); }
});

// ---------------------------------------------------------------------------
// Issue #232 — the import ceiling must bind BEFORE materialization.
//
// `LIMITS.MAX_IMPORT_BYTES` (30 MB) was checked before the read in
// `importJSON()` and `importCSVFile()`, but the TXT route ran
// `await file.text()` and the XLSX route ran `await file.arrayBuffer()` plus a
// full SheetJS parse FIRST, and only met the ceiling afterwards, on the
// synthetic CSV they had already built from the resident source. A rejection
// that lands after the whole file is in memory does not bound the spike it
// exists to prevent.
//
// These assertions do not check the limit's VALUE — they check the ORDERING,
// which is the whole defect. Each oversized input reports its size honestly and
// instruments its own readers, so the assertion is "was the byte-producing call
// ever invoked", not "did a toast appear". A guard that rejects only after
// reading would still produce the right toast, which is why a message-level
// assertion could not have caught this.
//
// NEGATIVE CONTROLS, each verified to fire: removing the guard from `importTXTFile`
// fails ICT-11; removing it from `importXLSXFile` fails ICT-12; removing the
// pre-dispatch backstop in `importFile()` alone still leaves both route-level
// guards, so ICT-13 asserts that boundary separately.
// ---------------------------------------------------------------------------

// A File-like object that is honest about its size and records whether anything
// ever asked it for bytes. Deliberately not a real 30 MB File: allocating one
// would make the test cost what the defect costs, and the size property is the
// only thing a correct guard reads.
const OVERSIZED_PROBE = `
  (name, type) => {
    const probe = {
      name, type,
      size: 31 * 1024 * 1024,   // over LIMITS.MAX_IMPORT_BYTES (30 MB)
      read: [],
      // Each reader records the attempt and then throws. Recording alone would
      // be enough for the assertion, but a probe that RETURNS usable bytes
      // sends an unguarded route onward into the real interactive importer,
      // where it waits for operator input and the test hangs instead of
      // failing — a negative control that cannot run is not a control. The
      // route's own try/catch swallows this, so an unguarded route fails fast
      // with the read recorded, which is exactly the evidence wanted.
      text() { this.read.push('text'); throw new Error('probe: no bytes may be produced for an over-ceiling import'); },
      arrayBuffer() { this.read.push('arrayBuffer'); throw new Error('probe: no bytes may be produced for an over-ceiling import'); },
      slice() { this.read.push('slice'); return this; },
      stream() { this.read.push('stream'); return null; },
    };
    return probe;
  }
`;

test('[ICT-11] an oversized TXT import is refused before file.text() is called', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async (mk) => {
      const T = window.__FL_TESTS;
      const probe = eval(mk)('big.txt', 'text/plain');
      await T.importTXTFile(probe);
      return { read: probe.read, limit: T.LIMITS.MAX_IMPORT_BYTES, flagged: T.importExceedsSizeLimit(probe) };
    }, OVERSIZED_PROBE);

    eq(r.read.length, 0,
      `an oversized TXT must be refused before any byte-producing read; the guard let ${JSON.stringify(r.read)} run`);
    eq(r.limit, 30 * 1024 * 1024, 'the operator-facing ceiling is unchanged by this repair');
    eq(r.flagged, true, 'the shared policy must recognise this input as over the ceiling');
  } finally { await app.close(); }
});

test('[ICT-12] an oversized XLSX import is refused before arrayBuffer() and before SheetJS parses', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async (mk) => {
      const T = window.__FL_TESTS;
      // Instrument the parser too: the original defect materialized the buffer
      // AND handed it to SheetJS, so both must stay uninvoked.
      let parsed = 0;
      const priorXLSX = window.XLSX;
      window.XLSX = { read: () => { parsed++; return { SheetNames: [] }; }, utils: { sheet_to_json: () => [] } };
      const probe = eval(mk)('big.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      try {
        await T.importXLSXFile(probe);
      } finally { window.XLSX = priorXLSX; }
      return { read: probe.read, parsed };
    }, OVERSIZED_PROBE);

    eq(r.read.length, 0,
      `an oversized workbook must not be materialized; the guard let ${JSON.stringify(r.read)} run`);
    eq(r.parsed, 0, 'SheetJS must never be handed an over-ceiling workbook');
  } finally { await app.close(); }
});

test('[ICT-13] the dispatcher refuses an oversized file whatever the route, including an unknown type', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async (mk) => {
      const T = window.__FL_TESTS;
      const out = {};
      for (const [label, name, type] of [
        ['txt', 'big.txt', 'text/plain'],
        ['xlsx', 'big.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        ['csv', 'big.csv', 'text/csv'],
        ['json', 'big.json', 'application/json'],
        ['unknown', 'big.bin', ''],
      ]) {
        const probe = eval(mk)(name, type);
        await T.importFile(probe);
        out[label] = probe.read;
      }
      return out;
    }, OVERSIZED_PROBE);

    for (const [label, read] of Object.entries(r)) {
      eq(read.length, 0,
        `routing an oversized file as ${label} must not read it; got ${JSON.stringify(read)}`);
    }
  } finally { await app.close(); }
});

test('[ICT-14] a within-limit import is still read and still imports', async () => {
  // The guard's own failure mode is over-rejection, which would break every
  // ordinary import silently. An explicit 0-byte and a normal-sized file must
  // both still reach their reader.
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const mk = (size) => ({
        name: 'ok.txt', type: 'text/plain', size,
        read: [],
        text() { this.read.push('text'); return Promise.resolve('order,revenue\n'); },
      });
      const small = mk(2048), empty = mk(0);
      await T.importTXTFile(small);
      await T.importTXTFile(empty);
      return {
        small: small.read, empty: empty.read,
        atLimit: T.importExceedsSizeLimit({ size: T.LIMITS.MAX_IMPORT_BYTES }),
        overByOne: T.importExceedsSizeLimit({ size: T.LIMITS.MAX_IMPORT_BYTES + 1 }),
        noSize: T.importExceedsSizeLimit({}),
      };
    });

    ok(r.small.includes('text'), 'a normal-sized TXT must still be read');
    ok(r.empty.includes('text'), 'a 0-byte file is within the limit and must still be read');
    eq(r.atLimit, false, 'exactly at the ceiling is allowed — the limit is a maximum, not an exclusive bound');
    eq(r.overByOne, true, 'one byte over the ceiling is refused');
    eq(r.noSize, false, 'an input with no size is not treated as oversized (unchanged behaviour)');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
