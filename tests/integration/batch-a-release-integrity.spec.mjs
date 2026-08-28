// Issue #119 Batch A — release-integrity hotfix regressions.
//
// Source audit: .agents/inbox/gpt-to-claude-batch-a-source-audit-2026-08-28.md
// Contracts:    docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md
//               docs/EVIDENCE_PROVENANCE.md
//               docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md
//
// Every test here drives the REAL runtime path the defect lives on — the real
// IndexedDB upgrade transaction, the real linker, the real production intake
// surface, the real export/import — because the previous coverage asserted
// helper behaviour and store EXISTENCE, which is exactly why these defects
// shipped green.
import { launchApp, launchBlank, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/batch-a-release-integrity.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

/* ═══════════════ A1 — the v14/v15 index migration ═══════════════ */

// The store was created by the catch-all `ensureStore` BEFORE the versioned
// block that was supposed to create its indexes, so that block's
// `objectStoreNames.contains` guard was already true and the whole index body
// was skipped — on a fresh database as much as on an upgrade. The old M4-01
// asserted the store EXISTED, which was never the failing half.
test('[A-01] a freshly created database actually has the lifecycle indexes', async () => {
  const r = await evalIn(async () => {
    const db = await new Promise((res, rej) => {
      const q = indexedDB.open('FreightLogic_v18');
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
    const txn = db.transaction(['loadLifecycle', 'normalizedEvidence'], 'readonly');
    const lc = [...txn.objectStore('loadLifecycle').indexNames].sort();
    const ev = [...txn.objectStore('normalizedEvidence').indexNames].sort();
    db.close();
    return { lc, ev };
  });
  for (const idx of ['broker', 'orderNo', 'updatedAt']){
    ok(r.lc.includes(idx), `loadLifecycle must have a real '${idx}' index, not just the store — got [${r.lc}]`);
  }
  for (const idx of ['fingerprint', 'lifecycleId', 'observedAt', 'recordedAt']){
    ok(r.ev.includes(idx), `normalizedEvidence must have a real '${idx}' index — got [${r.ev}]`);
  }
});

// The upgrade half: a database that reached v13 (or reached v14 through the
// pre-fix code, with a bare index-less store) must GAIN the indexes.
test('[A-02] a seeded v13 database upgrades and gains the lifecycle indexes', async () => {
  const b = await launchBlank();
  try {
    // Seed a v13 database that already carries an index-less `loadLifecycle`
    // store — the exact shape the pre-fix catch-all produced.
    await b.page.evaluate(async () => {
      await new Promise((res, rej) => { const d = indexedDB.deleteDatabase('FreightLogic_v18'); d.onsuccess = res; d.onerror = () => rej(d.error); d.onblocked = res; });
      await new Promise((res, rej) => {
        const q = indexedDB.open('FreightLogic_v18', 13);
        q.onupgradeneeded = () => {
          const d = q.result;
          d.createObjectStore('trips', { keyPath: 'orderNo' });
          for (const n of ['fuel','expenses','gpsLogs']) d.createObjectStore(n, { keyPath:'id', autoIncrement:true });
          d.createObjectStore('settings', { keyPath:'key' });
          d.createObjectStore('receipts', { keyPath:'tripOrderNo' });
          d.createObjectStore('receiptBlobs', { keyPath:'id' });
          d.createObjectStore('auditLog', { keyPath:'id' });
          for (const n of ['laneHistory','weeklyReports','reloadOutcomes','bidHistory','documents','marketBoard']) d.createObjectStore(n, { keyPath:'id' });
          // index-less, exactly as the buggy path left it
          d.createObjectStore('loadLifecycle', { keyPath:'lifecycleId' });
        };
        q.onsuccess = () => { q.result.close(); res(); };
        q.onerror = () => rej(q.error);
      });
      // A row that must survive the upgrade untouched.
      await new Promise((res, rej) => {
        const q = indexedDB.open('FreightLogic_v18');
        q.onsuccess = () => {
          const d = q.result;
          const t = d.transaction('loadLifecycle', 'readwrite');
          t.objectStore('loadLifecycle').put({ lifecycleId:'lc_pre_upgrade', orderNo:'PRE-13', broker:'acme', revision:1, updatedAt: 1 });
          t.oncomplete = () => { d.close(); res(); };
          t.onerror = () => rej(t.error);
        };
        q.onerror = () => rej(q.error);
      });
    });

    await b.bootApp(); // the real initDB() upgrade path runs here

    const r = await b.page.evaluate(async () => {
      const db = await new Promise((res, rej) => {
        const q = indexedDB.open('FreightLogic_v18');
        q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
      });
      const txn = db.transaction(['loadLifecycle','normalizedEvidence'], 'readonly');
      const store = txn.objectStore('loadLifecycle');
      const lc = [...store.indexNames].sort();
      const ev = [...txn.objectStore('normalizedEvidence').indexNames].sort();
      const survived = await new Promise((res2) => { const g = store.get('lc_pre_upgrade'); g.onsuccess = () => res2(g.result); });
      const version = db.version;
      db.close();
      return { lc, ev, survived: !!survived, order: survived?.orderNo, version };
    });

    for (const idx of ['broker', 'orderNo', 'updatedAt']){
      ok(r.lc.includes(idx), `the v13->current upgrade must create the '${idx}' index — got [${r.lc}]`);
    }
    ok(r.ev.length > 0, 'the durable evidence store is created with its indexes on upgrade');
    ok(r.survived, 'the pre-upgrade lifecycle row must not be dropped');
    eq(r.order, 'PRE-13', 'and its data must be untouched');
    ok(r.version >= 15, 'the database reached the current declared version');
  } finally { await b.close(); }
});

/* ═══════════════ A2 — cloudPushBackup empty-delta path ═══════════════ */

// `lc` was read by the empty-delta guard several lines ABOVE its own `const`
// declaration — a temporal dead zone throw on every delta push. It was
// invisible because cloudPushBackup() wraps its whole body in try/catch, so
// the ReferenceError surfaced only as a generic "Backup failed" retry.
test('[A-03] a delta push with nothing changed no-ops cleanly instead of throwing', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    // Point at an unreachable origin on purpose: if the empty-delta early
    // return works, no request is ever made, so an unreachable URL is harmless.
    // If the guard is skipped, the run fails on the network instead — which
    // this test would also catch, from the other direction.
    await T.setSetting('cloudBackupUrl', 'http://127.0.0.1:9/never');
    await T.setSetting('cloudBackupToken', 'flk_' + '0'.repeat(32));
    sessionStorage.setItem('fl_cloud_pass', 'test-passphrase-12345');
    // Everything currently stored is older than this, so nothing is "changed".
    await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
    await T.setSetting('lastCloudSync', 0);
    let threw = null;
    try { await T.cloudPushBackup(true); } catch(e){ threw = String(e && e.message || e); }
    return { threw, lastSync: await T.getSetting('lastCloudSync', 0) };
  });
  eq(r.threw, null, 'cloudPushBackup must not reject');
  // The early return is the ONLY path that stamps lastCloudSync without a
  // successful HTTP response, so a non-zero value proves the guard was reached.
  ok(Number(r.lastSync) > 0, 'the empty-delta guard must be reached and stamp lastCloudSync (a TDZ throw never gets here)');
});

/* ═══════════════ A3 — background lifecycle concurrency ═══════════════ */

// linkLifecycle read the base record and then called upsertLifecycle WITHOUT
// the revision it had just observed, so a user correction landing in between
// was silently overwritten by the background link's merge of a stale base.
test('[A-05] a background link that read a stale base aborts instead of overwriting', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const saved = await T.upsertLifecycle({ orderNo:'RACE-1', broker:'Acme', origin:'Chicago, IL', destination:'Toledo, OH', opportunity:'BID' });
    // The operator corrects it — this is the write that must survive.
    const corrected = await T.upsertLifecycle({ ...saved, opportunity:'WON' }, { expectedRevision: saved.revision, source:'USER', reason:'operator correction' });

    // Simulate the race deterministically: doctor the FIRST loadLifecycle
    // `get()` — which is linkLifecycle's own base read — to return the record
    // as it was one revision earlier. Every later read (including the one
    // upsertLifecycle does inside its own transaction) sees the real record.
    // That is precisely "the row changed between the link's read and its write".
    const origGet = IDBObjectStore.prototype.get;
    let doctored = false;
    IDBObjectStore.prototype.get = function(...args){
      const req = origGet.apply(this, args);
      if (this.name === 'loadLifecycle' && !doctored){
        doctored = true;
        const origDesc = Object.getOwnPropertyDescriptor(IDBRequest.prototype, 'result');
        Object.defineProperty(req, 'result', {
          configurable: true,
          get(){
            const real = origDesc.get.call(this);
            return real ? { ...real, revision: real.revision - 1, opportunity: 'BID' } : real;
          },
        });
      }
      return req;
    };
    let link;
    try {
      link = await T.linkLifecycle(
        { orderNo:'RACE-1', broker:'Acme', origin:'Chicago, IL', destination:'Toledo, OH', execution:'PICKED_UP' },
        { source:'TRIP', sourceId:'RACE-1', reason:'background trip link' });
    } finally { IDBObjectStore.prototype.get = origGet; }

    const after = await T.getLifecycle(corrected.lifecycleId);
    return { ok: link.ok, conflict: link.conflict === true, opportunity: after.opportunity, revision: after.revision };
  });
  eq(r.ok, false, 'a stale background link must not report success');
  eq(r.conflict, true, 'and must report the conflict rather than swallowing it into a silent no-op');
  eq(r.opportunity, 'WON', "the operator's newer correction survives");
  eq(r.revision, 2, 'and no stale merge was written over it');
});

test('[A-06] a background link with a current base still succeeds', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.upsertLifecycle({ orderNo:'RACE-OK', broker:'Acme', origin:'Gary, IN', destination:'Erie, PA' });
    const link = await T.linkLifecycle(
      { orderNo:'RACE-OK', broker:'Acme', origin:'Gary, IN', destination:'Erie, PA', execution:'DELIVERED' },
      { source:'TRIP', sourceId:'RACE-OK', reason:'normal background link' });
    const rows = await T.listLifecycle();
    const row = rows.find(x => x.orderNo === 'RACE-OK');
    return { ok: link.ok, execution: row.execution, count: rows.filter(x => x.orderNo === 'RACE-OK').length };
  });
  eq(r.ok, true, 'the ordinary link path is unaffected by the concurrency fix');
  eq(r.execution, 'DELIVERED', 'and the link still applies');
  eq(r.count, 1, 'without creating a duplicate');
});

/* ═══════════════ A4 — reused external identifiers ═══════════════ */

test('[A-07] a reused order number with a conflicting route does not auto-link', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const candidates = [{ lifecycleId:'lc_a', orderNo:'Q-4471', broker:'acme logistics', origin:'Chicago, IL', destination:'Toledo, OH' }];
    return T.lifecycleMatchCandidate(
      { orderNo:'Q-4471', broker:'Acme Logistics', origin:'Chicago, IL', destination:'Nashville, TN' }, candidates);
  });
  eq(r.linked, false, 'the same external ID on a different lane is a different shipment');
  eq(r.unresolved, true, 'and the ambiguity is surfaced, not resolved by picking');
});

test('[A-08] a reused order number with a conflicting pickup clock does not auto-link', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const candidates = [{ lifecycleId:'lc_b', orderNo:'Q-9001', broker:'acme', origin:'Gary, IN', destination:'Erie, PA', pickupAt:'2026-05-04T08:15:00Z' }];
    return T.lifecycleMatchCandidate(
      { orderNo:'Q-9001', broker:'Acme', origin:'Gary, IN', destination:'Erie, PA', pickupAt:'2026-05-04T17:45:00Z' }, candidates);
  });
  eq(r.linked, false, 'two different pickup instants on the same day are two different loads');
  eq(r.unresolved, true, 'and stay unresolved');
});

test('[A-09] clock precision is preserved, not truncated to date, when matching', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    // Same instant expressed in two offsets must NOT conflict.
    const same = T.lifecycleFactsConflict(
      { pickupAt:'2026-05-04T12:00:00Z' }, { pickupAt:'2026-05-04T08:00:00-04:00' });
    // Genuinely date-only evidence compares at date resolution only.
    const dateOnly = T.lifecycleFactsConflict(
      { pickupAt:'2026-05-04' }, { pickupAt:'2026-05-04T23:59:00Z' });
    const differentDay = T.lifecycleFactsConflict(
      { pickupAt:'2026-05-04' }, { pickupAt:'2026-05-05T00:01:00Z' });
    return { same, dateOnly, differentDay };
  });
  eq(r.same, false, 'the same instant in a different offset is not a conflict');
  eq(r.dateOnly, false, 'date-only evidence is not widened into a fake midnight instant');
  eq(r.differentDay, true, 'but a genuinely different day still conflicts');
});

test('[A-10] a missing compatibility fact is unknown and never manufactures a conflict', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return T.lifecycleMatchCandidate(
      { orderNo:'Q-1', broker:'Acme', destination:'Toledo, OH' },
      [{ lifecycleId:'lc_c', orderNo:'Q-1', broker:'acme', destination:'Toledo, OH' }]);
  });
  eq(r.linked, true, 'unknown facts do not block a match that nothing contradicts');
});

test('[A-11] the trip chip/editor lookup refuses to pick one of several reused-ID records', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const rows = [
      { lifecycleId:'lc_x', orderNo:'DUP-77', broker:'acme', origin:'Chicago, IL', destination:'Toledo, OH' },
      { lifecycleId:'lc_y', orderNo:'DUP-77', broker:'acme', origin:'Chicago, IL', destination:'Nashville, TN' },
    ];
    // The trip's own route evidence matches NEITHER candidate exactly.
    const ambiguous = T.resolveLifecycleForTrip(
      { orderNo:'DUP-77', broker:'Acme', origin:'Chicago, IL', destination:'Memphis, TN' }, rows);
    // With the trip's real destination, exactly one candidate is compatible.
    const resolved = T.resolveLifecycleForTrip(
      { orderNo:'DUP-77', broker:'Acme', origin:'Chicago, IL', destination:'Nashville, TN' }, rows);
    return {
      ambiguousPicked: ambiguous.lifecycle?.lifecycleId || null,
      ambiguousUnresolved: ambiguous.unresolved,
      resolvedId: resolved.lifecycle?.lifecycleId || null,
    };
  });
  eq(r.ambiguousPicked, null, 'no arbitrary lifecycle record may be chosen for the chip or the editor');
  eq(r.ambiguousUnresolved, true, 'the ambiguity is reported');
  eq(r.resolvedId, 'lc_y', "the trip's own route evidence resolves it correctly when it can");
});

test('[A-12] the lifecycle editor refuses to open on an ambiguous reused ID', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.upsertLifecycle({ lifecycleId:'lc_ed1', orderNo:'EDIT-9', broker:'Acme', origin:'Chicago, IL', destination:'Toledo, OH' });
    await T.upsertLifecycle({ lifecycleId:'lc_ed2', orderNo:'EDIT-9', broker:'Acme', origin:'Chicago, IL', destination:'Nashville, TN' });
    await T.openLifecycleEditor({ orderNo:'EDIT-9', broker:'Acme', origin:'Chicago, IL', destination:'Memphis, TN' });
    return { modalOpen: !!document.querySelector('#lcOpp') };
  });
  eq(r.modalOpen, false, 'opening an arbitrary record would let a correction land on the wrong shipment');
});

/* ═══════════════ A5 — durable normalized evidence ═══════════════ */

test('[A-13] the production intake surface persists durable evidence that survives a reload', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.openOpportunityIntake();
    const set = (id, v) => { const el = document.getElementById(id); el.value = v; };
    set('oiOrder', 'PROD-1'); set('oiBroker', 'Acme Logistics');
    set('oiOrigin', 'Chicago, IL'); set('oiDest', 'Toledo, OH');
    set('oiAmount', '620');
    document.getElementById('oiPriceSem').value = 'BOARD_TARGET_RATE';
    set('oiMiles', '244');
    document.getElementById('oiMileSem').value = 'DISPLAYED_TOTAL_MILES';
    set('oiObserved', '2026-08-02T14:31:07Z');
    set('oiRef', 'msg-id-99@mail');
    set('oiSourceName', 'inbox');
    document.getElementById('oiSave').click();
    await new Promise(r => setTimeout(r, 400));
  });
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  const r = await evalIn(async () => {
    const rows = await window.__FL_TESTS.listEvidence();
    const row = rows.find(x => x.orderNo === 'PROD-1');
    return row ? {
      found: true, priceSemantic: row.priceSemantic, amount: row.amount,
      canonicalRevenue: row.canonicalRevenue, loadedMi: row.loadedMi,
      displayedTotalMi: row.displayedTotalMi, mileageSemantic: row.mileageSemantic,
      observedAtISO: row.observedAtISO, rawEvidenceRef: row.provenance.rawEvidenceRef,
      sourceType: row.provenance.sourceType, fingerprint: row.fingerprint,
      linkState: row.linkState,
    } : { found: false };
  });
  ok(r.found, 'the real production intake path must PERSIST evidence, not return it transiently');
  eq(r.priceSemantic, 'BOARD_TARGET_RATE', 'the governing price semantic is preserved, not collapsed to unknown');
  eq(r.amount, 620, 'the amount is retained as evidence');
  eq(r.canonicalRevenue, null, 'a board target rate is not carrier revenue');
  eq(r.displayedTotalMi, 244, 'a displayed total is stored as a displayed total');
  eq(r.loadedMi, null, 'and never as canonical loaded miles');
  eq(r.observedAtISO, '2026-08-02T14:31:07Z', 'the source observation instant survives with full precision');
  eq(r.rawEvidenceRef, 'msg-id-99@mail', 'the underlying message reference is preserved');
  ok(String(r.fingerprint).startsWith('fp:'), 'a deterministic bounded identity is recorded');
  ok(r.fingerprint.length <= 120, 'and it fits the persisted provenance bound');
});

test('[A-14] historical operator-confirmed evidence with no known confirmation clock stays null', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({
      orderNo:'HIST-CONF', broker:'Acme', amount: 900, priceSemantic:'CARRIER_PAYOUT',
      operatorConfirmedRevenue: true, confirmationState:'OPERATOR_CONFIRMED',
    }, { sourceType:'HISTORY', authority:'OPERATOR_CONFIRMED_HISTORY' });
    return {
      confirmedAt: res.evidence.provenance.operatorConfirmedAt,
      state: res.evidence.provenance.confirmationState,
      revenue: res.evidence.canonicalRevenue,
    };
  });
  eq(r.confirmedAt, null, 'the import clock must never be recorded as the confirmation clock');
  eq(r.state, 'OPERATOR_CONFIRMED', 'while the confirmation itself is still recorded');
  eq(r.revenue, 900, 'and a proven carrier payout is still revenue');
});

test('[A-15] evidence is preserved even when the lifecycle link is unresolved', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    // Two incompatible shipments already carry this external ID.
    await T.upsertLifecycle({ orderNo:'AMB-5', broker:'Acme', origin:'Chicago, IL', destination:'Toledo, OH' });
    await T.upsertLifecycle({ orderNo:'AMB-5', broker:'Acme', origin:'Chicago, IL', destination:'Nashville, TN' });
    const res = await T.intakeOpportunity({
      orderNo:'AMB-5', broker:'Acme', origin:'Chicago, IL', destination:'Memphis, TN',
      amount: 700, priceSemantic:'CARRIER_PAYOUT',
    }, { sourceType:'EMAIL' });
    const stored = await T.getEvidence(res.evidence.evidenceId);
    return { linkOk: res.link.ok, unresolved: res.link.unresolved === true, stored: !!stored, linkState: stored?.linkState, amount: stored?.amount };
  });
  eq(r.linkOk, false, 'an ambiguous reused ID must not link');
  eq(r.unresolved, true, 'the ambiguity is surfaced');
  ok(r.stored, 'the evidence is still durably persisted — a duplicate is safer than a false merge');
  eq(r.linkState, 'UNRESOLVED', 'and its unresolved state is recorded, not hidden');
  eq(r.amount, 700, 'with its material facts intact');
});

test('[A-16] a re-imported identical observation is idempotent; a same-length collision pair is not', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const raw = { orderNo:'IDEM-9', broker:'Acme', origin:'Gary, IN', destination:'Erie, PA', amount: 800, priceSemantic:'CARRIER_PAYOUT' };
    const a = await T.intakeOpportunity(raw, { sourceType:'HISTORY' });
    const b = await T.intakeOpportunity(raw, { sourceType:'HISTORY' });
    const rows = (await T.listEvidence()).filter(x => x.orderNo === 'IDEM-9');

    // A concrete, previously demonstrated same-length 32-bit DJB2 collision
    // pair. The superseded fingerprint was `fp:<8 hex>:<raw.length>`, so for
    // these two inputs it produced ONE identical token — and therefore one
    // deduplicated row where there were two distinct source observations.
    const X = 'SMK0QLMN4JJTSD9HEKAL1JM6';
    const Y = 'J6L9X3FBXUE0CV6VYFERGDRP';
    const djb2 = (s) => { let h = 5381; for (let i=0;i<s.length;i++) h = (((h<<5)+h)+s.charCodeAt(i))>>>0; return h; };
    const legacyToken = (s) => 'fp:' + djb2(s).toString(16).padStart(8,'0') + ':' + String(s.length);
    const fx = await T.evidenceFingerprint(X);
    const fy = await T.evidenceFingerprint(Y);

    // And the real consequence: two observations differing only by these
    // colliding references must remain two durable evidence rows.
    const base = { orderNo:'COLL-1', broker:'Acme', origin:'Gary, IN', destination:'Erie, PA', amount: 500, priceSemantic:'CARRIER_PAYOUT' };
    await T.intakeOpportunity({ ...base, rawEvidenceRef: X }, { sourceType:'HISTORY' });
    await T.intakeOpportunity({ ...base, rawEvidenceRef: Y }, { sourceType:'HISTORY' });
    const collRows = (await T.listEvidence()).filter(e => e.orderNo === 'COLL-1');

    return {
      same: a.evidence.evidenceId === b.evidence.evidenceId, reimported: b.reimported, count: rows.length,
      collision: {
        legacyIdentical: legacyToken(X) === legacyToken(Y),
        distinct: fx !== fy,
        len: Math.max(fx.length, fy.length),
        rowCount: collRows.length,
        refs: collRows.map(e => e.provenance.rawEvidenceRef).sort(),
      },
    };
  });
  eq(r.same, true, 'the same source observation resolves to the same evidence record');
  eq(r.reimported, true, 'and is recognised as a re-import, not a new observation');
  eq(r.count, 1, 'so no phantom duplicate row is created');
  eq(r.collision.legacyIdentical, true, 'the fixture really does produce one identical token under the superseded 32-bit fingerprint');
  eq(r.collision.distinct, true, 'the replacement digest keeps the colliding inputs distinct');
  ok(r.collision.len <= 120, 'and its token still fits the persisted 120-char provenance bound');
  eq(r.collision.rowCount, 2, 'two distinct source observations must remain two evidence rows');
  eq(r.collision.refs.join('|'), ['SMK0QLMN4JJTSD9HEKAL1JM6','J6L9X3FBXUE0CV6VYFERGDRP'].sort().join('|'),
     'and each row still carries its own source reference');
});

test('[A-17] the expanded price vocabulary is preserved and still gated out of revenue', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const out = {};
    for (const sem of ['BOARD_TARGET_RATE','POSTED_RATE','MARKET_BENCHMARK','SHIPPER_BOOKABLE_PRICE','OPERATOR_BID','CONTRACT_RATE']){
      const n = T.normalizeOpportunity({ amount: 500, priceSemantic: sem }, { sourceType:'PROVIDER_API' });
      out[sem] = { semantic: n.priceSemantic, revenue: n.canonicalRevenue };
    }
    return { out, vocabulary: T.PRICE_SEMANTIC };
  });
  for (const sem of ['BOARD_TARGET_RATE','POSTED_RATE','MARKET_BENCHMARK']){
    ok(r.vocabulary.includes(sem), `${sem} must exist in the vocabulary, not collapse to unknown`);
    eq(r.out[sem].semantic, sem, `${sem} is preserved verbatim`);
  }
  for (const [sem, v] of Object.entries(r.out)){
    eq(v.revenue, null, `${sem} must never become canonical revenue`);
  }
});

/* ═══════════════ A6 — protected export integrity ═══════════════ */

test('[A-18] lifecycle and evidence are inside the protected export checksum', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const trips = [], expenses = [], fuel = [], settings = [];
    const lifecycle = [{ lifecycleId:'lc_sum', orderNo:'SUM-1', opportunity:'WON' }];
    const evidence = [{ evidenceId:'ev_sum', orderNo:'SUM-1', amount: 900, priceSemantic:'CARRIER_PAYOUT' }];
    const base = await T.computeExportChecksumProtected(trips, expenses, fuel, settings, lifecycle, evidence);
    const lcMutated = await T.computeExportChecksumProtected(
      trips, expenses, fuel, settings, [{ ...lifecycle[0], opportunity:'LOST' }], evidence);
    const evMutated = await T.computeExportChecksumProtected(
      trips, expenses, fuel, settings, lifecycle, [{ ...evidence[0], amount: 9000 }]);
    const legacyBlind = await T.computeExportChecksumFull(trips, expenses, fuel, settings);
    return { base, lcMutated, evMutated, legacyBlind,
             legacySame: legacyBlind === await T.computeExportChecksumFull(trips, expenses, fuel, settings) };
  });
  ok(r.base !== r.lcMutated, 'mutating a lifecycle row must change the protected checksum');
  ok(r.base !== r.evMutated, 'mutating an evidence amount must change the protected checksum');
  ok(r.legacySame, 'and the legacy checksum is unchanged in behaviour (it simply never saw these stores)');
});

test('[A-19] durable evidence survives a local JSON export -> import round trip', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({
      orderNo:'RT-1', broker:'Roundtrip Co', origin:'Fort Wayne, IN', destination:'Columbus, OH',
      amount: 1150, priceSemantic:'SETTLED_AMOUNT',
      miles: 480, mileageSemantic:'DISPLAYED_TOTAL_MILES',
      observedAt: '2026-07-19T09:03:41Z', rawEvidenceRef:'settlement-pdf-4',
    }, { sourceType:'EMAIL' });

    // Capture what exportJSON would write, without touching the filesystem.
    const captured = { payload: null };
    const origCreate = URL.createObjectURL;
    URL.createObjectURL = (blob) => { captured.blob = blob; return origCreate.call(URL, blob); };
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function(){};
    try { await T.exportJSON(); } finally {
      URL.createObjectURL = origCreate; HTMLAnchorElement.prototype.click = origClick;
    }
    const text = await captured.blob.text();
    const parsed = JSON.parse(text);

    // Wipe the store, then import the file back through the real import path.
    await new Promise((resolve, reject) => {
      const q = indexedDB.open('FreightLogic_v18');
      q.onsuccess = () => { const d = q.result; const t = d.transaction('normalizedEvidence','readwrite');
        t.objectStore('normalizedEvidence').clear(); t.oncomplete = () => { d.close(); resolve(); }; t.onerror = () => reject(t.error); };
      q.onerror = () => reject(q.error);
    });
    const emptied = (await T.listEvidence()).length;
    const file = new File([text], 'export.json', { type:'application/json' });
    await T.importJSON(file, { mode:'merge' });
    const back = (await T.listEvidence()).find(x => x.evidenceId === res.evidence.evidenceId);
    return {
      exported: Array.isArray(parsed.normalizedEvidence) && parsed.normalizedEvidence.some(x => x.orderNo === 'RT-1'),
      hasProtected: typeof parsed.meta.checksumProtected === 'string' && parsed.meta.checksumProtected.length > 0,
      emptied,
      restored: !!back,
      amount: back?.amount, semantic: back?.priceSemantic,
      displayedTotalMi: back?.displayedTotalMi, loadedMi: back?.loadedMi,
      observedAtISO: back?.observedAtISO, ref: back?.provenance?.rawEvidenceRef,
    };
  });
  ok(r.exported, 'evidence travels in the export payload');
  ok(r.hasProtected, 'and the export carries the protected checksum that covers it');
  eq(r.emptied, 0, 'the store really was emptied before re-import');
  ok(r.restored, 'evidence that exports but is dropped on import is a release blocker');
  eq(r.amount, 1150, 'the amount survives');
  eq(r.semantic, 'SETTLED_AMOUNT', 'the price semantic survives');
  eq(r.displayedTotalMi, 480, 'the displayed total stays in its own slot');
  eq(r.loadedMi, null, 'and never migrates into loaded miles');
  eq(r.observedAtISO, '2026-07-19T09:03:41Z', 'the source observation instant survives unchanged');
  eq(r.ref, 'settlement-pdf-4', 'the raw evidence reference survives');
});

test('[A-20] a deliberately corrupted evidence payload fails the integrity check', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const trips = [], expenses = [], fuel = [], settings = [];
    const evidence = [{ evidenceId:'ev_tamper', orderNo:'T-1', amount: 900 }];
    const good = await T.computeExportChecksumProtected(trips, expenses, fuel, settings, [], evidence);
    const tamperedPayload = [{ ...evidence[0], amount: 90000 }];
    const recomputed = await T.computeExportChecksumProtected(trips, expenses, fuel, settings, [], tamperedPayload);
    return { detected: good !== recomputed };
  });
  eq(r.detected, true, 'an edited evidence amount must not verify against the original checksum');
});

/* ═══════════════ A5 — authority-aware field reconciliation ═══════════════ */

test('[A-21] a later operator correction supersedes a populated lower-authority value', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const earlyAi = {
      amount: 700, loadedMi: 300,
      provenance: { authority:'AI_SECONDARY', sourceName:'recovered-summary.csv', sourceType:'HISTORY', sourceTimestampMs: 1000 },
    };
    const laterCorrection = {
      amount: 950,
      provenance: { authority:'OPERATOR_CORRECTION', sourceName:'operator', sourceType:'MANUAL', sourceTimestampMs: 2000 },
    };
    return T.reconcileEvidenceFields([earlyAi, laterCorrection], ['amount','loadedMi']);
  });
  eq(r.values.amount, 950, 'the operator correction wins over an already-populated AI value');
  eq(r.fieldProvenance.amount.authority, 'OPERATOR_CORRECTION', 'and the winning authority is recorded');
  eq(r.values.loadedMi, 300, 'a field the correction did not touch keeps the lower-authority value');
  eq(r.fieldProvenance.loadedMi.sourceName, 'recovered-summary.csv',
     'and that field still names the source it actually came from, not the winning row');
});

test('[A-22] an earlier low-authority value cannot overwrite a later high-authority one, and unknown stays unknown', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const doc = { amount: 1200, provenance: { authority:'PRIMARY_DOCUMENT', sourceName:'rateconf.pdf', sourceTimestampMs: 5000 } };
    const ai  = { amount: 400,  provenance: { authority:'AI_SECONDARY', sourceName:'guess.csv', sourceTimestampMs: 9000 } };
    return T.reconcileEvidenceFields([doc, ai], ['amount','deadMi']);
  });
  eq(r.values.amount, 1200, 'a newer low-authority guess never displaces primary documentary evidence');
  eq(r.values.deadMi, null, 'a fact no source established stays null, never 0');
});

export async function runSpec(){
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
