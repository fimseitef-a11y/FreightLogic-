# GPT -> Claude Code: runtime corrective wave 1

Date: 2026-08-27
Target application branch: current `main`
Observed main head when this packet was written: `fdfc726f6d6c3f43c08020bb7be0ed2b4280982f`
Operator instruction: continue completing FreightLogic in the repository without stopping after one blocker and without requiring project re-explanation.

This is a cross-lane implementation request under `AGENTS.md` / `.agents/LANES.md`. GPT is not editing `app.js`, `tests/`, storage, or core runtime directly. Claude owns the implementation/test paths below. Preserve the release HOLD until the exact-current runtime is recertified.

## Read first

Use current `main`, then re-read:

- `AGENTS.md`
- `.agents/LANES.md`
- `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
- `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md`
- `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`
- `docs/BACKUP_CONTRACT.md`

Do not restore stale pre-PR-108/114/115 state. PR #108's local `importJSON()` lifecycle persistence repair is valid and must remain.

## Exact-current source findings verified on `fdfc726...`

### A. v14 lifecycle indexes are not guaranteed

Current upgrade ordering does this before the v14 block:

```js
// Catch-all: ensure stores exist for users upgrading from any version
ensureStore('settings', { keyPath:'key' });
ensureStore('receipts', { keyPath:'tripOrderNo' });
ensureStore('receiptBlobs', { keyPath:'id' });
ensureStore('auditLog', { keyPath:'id' });
ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
```

The later v14 block only creates indexes inside:

```js
if (!d.objectStoreNames.contains('loadLifecycle')) {
  const lc = d.createObjectStore('loadLifecycle', { keyPath: 'lifecycleId' });
  lc.createIndex('updatedAt', 'updatedAt', { unique: false });
  lc.createIndex('orderNo', 'orderNo', { unique: false });
  lc.createIndex('broker', 'broker', { unique: false });
}
```

Because the catch-all already created the store, that conditional can be false and the indexes never get created. Existing M4-01 proves only store/version presence; it does not inspect actual resulting `indexNames`.

### Required repair

In the v14 upgrade transaction, obtain the `loadLifecycle` store whether it was just created or already exists, then idempotently ensure all three indexes:

- `updatedAt` -> `updatedAt`
- `orderNo` -> `orderNo`
- `broker` -> `broker`

The safe shape is conceptually:

```js
const lc = d.objectStoreNames.contains('loadLifecycle')
  ? upgradeTxn.objectStore('loadLifecycle')
  : d.createObjectStore('loadLifecycle', { keyPath:'lifecycleId' });
if (!lc.indexNames.contains('updatedAt')) lc.createIndex(...);
if (!lc.indexNames.contains('orderNo')) lc.createIndex(...);
if (!lc.indexNames.contains('broker')) lc.createIndex(...);
```

Use the real `onupgradeneeded` transaction object already available in that code, not a second connection.

### Required regressions

Add real browser/IndexedDB tests that inspect the resulting object store `indexNames` for BOTH:

1. fresh database creation at v14;
2. explicit v13 -> v14 upgrade from a synthetic v13 database that contains legacy stores/records and no lifecycle indexes.

Assert legacy data survives and all three indexes exist after the upgrade. Do not test only source text or store existence.

---

### B. `cloudPushBackup()` has a real lifecycle TDZ defect and under-counts lifecycle changes

Current `cloudPushBackup()` computes all non-lifecycle changed arrays, computes `isDelta`, selects `trips/.../gl`, then executes an empty-delta guard containing `lc.length` BEFORE `lc` is declared:

```js
if (isDelta && trips.length === 0 && expenses.length === 0 && fuel.length === 0 &&
    lh.length === 0 && wr.length === 0 && ro.length === 0 && bh.length === 0 &&
    docs.length === 0 && gl.length === 0 && lc.length === 0) {
  ...
}

const allLifecycle = await dumpStore('loadLifecycle');
const changedLifecycle = lastSynced > 0
  ? allLifecycle.filter(r => finiteNum(r.updatedAt, 0) > lastSynced)
  : allLifecycle;
const lc = isDelta ? changedLifecycle : allLifecycle;
```

That is a temporal-dead-zone failure on a legitimate empty delta.

Also, lifecycle changes are currently omitted from the `< 50` delta-size decision because `changedLifecycle` is calculated only after `isDelta`.

### Required repair

Move lifecycle collection/filtering before `isDelta` is calculated, include `changedLifecycle.length` in the changed-record count, derive `lc` with the other selected delta/full arrays, and only then execute the empty-delta guard.

Do not fix this by merely deleting `lc` from the guard; a lifecycle-only delta must still upload.

### Required regressions

Using the real client path with the existing mock worker:

1. **true empty delta** after a successful sync: `cloudPushBackup()` must no-op successfully / surface “Up to date” behavior and must not throw or schedule a retry;
2. **lifecycle-only delta**: mutate only a lifecycle row after the base sync, push, wipe/restore, and prove the lifecycle mutation survived;
3. delta/full threshold accounting must include lifecycle changes so 50+ changed lifecycle rows cannot be misclassified as a small delta solely because every older store is unchanged.

Where practical, extend `tests/integration/backup-restore-parity.spec.mjs`; use the existing real-app + mock-worker pattern rather than a helper-only assertion.

---

### C. local export integrity still protects only four arrays

Current source still exposes:

```js
async function computeExportChecksumFull(trips, expenses, fuel, settings){
  return _computeChecksum({ trips, expenses, fuel, settings });
}
```

while the local JSON export includes additional operational history, including `loadLifecycle`, and the completion contract requires any newly durable normalized evidence to survive export/import AND participate in protected integrity.

This means a lifecycle/evidence mutation can currently fall outside `checksumFull` protection.

### Required repair

Do not special-case only one field and leave a second drift-prone checksum vocabulary. Establish one canonical, secret-free protected-export projection used by BOTH:

- checksum creation;
- checksum verification during import.

It must at minimum cover all data classes the current completion contracts declare protected durable history, including `loadLifecycle` and the durable normalized-evidence structure once that structure lands. Keep API keys/session secrets excluded exactly as today.

If normalized evidence is added in a later commit in the same PR, extend the projection atomically in that commit; do not certify checksum coverage before the evidence store/shape is included.

### Required regressions

Prove on the actual local export/import path:

- identical protected payload => same valid checksum;
- lifecycle mutation => checksum changes;
- durable-evidence mutation => checksum changes once that store exists;
- untouched export imports successfully;
- intentional corruption of protected lifecycle/evidence payload fails integrity validation rather than importing silently.

Preserve the existing X-05 contract that the exact filtered settings array included in payload is the same one hashed.

## Integration/test discipline

These changes touch `app.js`, IndexedDB/storage, cloud backup, and tests. Therefore:

1. claim the required `app.js` lock on `agent-coordination` before editing;
2. use a Claude task branch under the allowed namespace;
3. add/adjust tests without weakening existing assertions;
4. run `node tests/run-all.mjs` on the exact candidate SHA;
5. run the repository lane/ownership gates required by current CI;
6. record the run in `.agents/TEST_LEDGER.md` and status per protocol;
7. PR to `main`; do not direct-push application code;
8. after merge, continue immediately to the next certification blocker instead of stopping.

## Next queue after wave 1

After A/B/C are merged and green, continue in the existing order from the certification state:

1. reused-ID lifecycle safety + full timestamp preservation;
2. stale background `linkLifecycle()` optimistic-concurrency repair;
3. Worker canonical-absence compatibility;
4. M3 real-path confidence/evidence wiring;
5. durable normalized opportunity evidence + a real production M5B manual/email-compatible caller;
6. PR #108 M6 reconciliation correction (identity, precedence, field provenance, DRY RUN/status semantics, collision-resistant fingerprint);
7. M6 observation-recency provenance;
8. release-generation parity only after runtime correctness is stable;
9. full exact-SHA release suite/lane checks;
10. then finite live/physical M7 checks. Do not invent operator-only PASS results.

## Important preservation rules

- `app.js` remains sole deterministic owner of canonical verdict/grade/economics/bid.
- Confidence/evidence remains descriptive-only.
- Missing deadhead/revenue remains UNKNOWN, never zero.
- External order/quote IDs are evidence, not universal unique primary keys.
- Warp shipper quote money remains `SHIPPER_BOOKABLE_PRICE`, never carrier payout or carrier load availability.
- Raw personal operator history/financial files remain out of the public repo.
- Release status remains HOLD until all exact-current blockers and required field/live checks are closed.

Controlling rule: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
