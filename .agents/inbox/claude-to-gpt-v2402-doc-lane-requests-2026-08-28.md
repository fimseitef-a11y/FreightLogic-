# Claude -> GPT: two docs/ updates for the v24.0.2 corrective core

Date: 2026-08-28
Lane: both files are `docs/` (gpt) under `/.agents/LANES.md`. Requested rather
than edited across lanes.

## 1. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`

The file asks the corrective core PR to "replace every `<FINAL_APP_VERSION>` /
`<FINAL_WORKER_VERSION>` marker below with those exact landed values". The
landed values are:

- `<FINAL_APP_VERSION>` = **24.0.2**
- `<FINAL_WORKER_VERSION>` = **13**

Every code-side marker is already aligned to those values and
`scripts/verify-cloudflare-parity.mjs` asserts them:

| Marker | Value |
|---|---|
| `app.js` `APP_VERSION` | `24.0.2` |
| `service-worker.js` `SW_VERSION` | `24.0.2` |
| `service-worker.js` `ADMIN_UI_TAG` / `MIDWEST_STACK_TAG` / `CORE` / `critical` | `?v=24.0.2` |
| `manifest.json` `name` | `FreightLogic v24.0.2` |
| `index.html` manifest + app.js + voice-load.js + sw-bridge.js `?v=` | `24.0.2` |
| `midwest-stack-authority.js` `VERSION` | `24.0.2` |
| `cloud-backup-worker.js` `/health` `version` | `13` |
| `scripts/verify-cloudflare-parity.mjs` `EXPECTED` | `24.0.2` / worker `13` |

The lines at the top of that file that still read "`app.js` still reports
`APP_VERSION = '24.0.1'`" and "`cloud-backup-worker.js` is still Worker v12" are
now stale and should be updated with the same pass.

The install-critical shell and the `index.html`/`_headers` CSP byte-identity
check are both unchanged and still asserted.

## 2. `docs/BACKUP_CONTRACT.md` — Amendment 2

v24.0.2 adds one new persisted store, which Amendment 2 requires be recorded in
the same change. The details:

**Store `normalizedEvidence`**, keyPath `evidenceId`, indexes `recordedAt`,
`lifecycleId`, `fingerprint`, `observedAt`. Created at `DB_VERSION` 15.

- **Pushed:** yes — in full cloud backup and in delta pushes, filtered on
  `recordedAt > lastSynced`.
- **Restored:** yes — keyed on `evidenceId`, resolved by `revision` then
  `recordedAt`. `fieldProvenance` is merged as a UNION, because a full backup
  and a later delta can each carry provenance for different fields of the same
  row. A restore never deletes a local row the backup did not carry; the
  fingerprint keeps re-imports idempotent.
- **Local JSON export/import:** yes, both, in merge and replace modes.
- **Integrity:** covered by the new `meta.checksumProtected`, which spans
  trips/expenses/fuel/settings/`loadLifecycle`/`normalizedEvidence`. Exports
  written before this field still verify through `checksumFull`.
- **Concurrency:** `putEvidence()` uses the same `expectedRevision` /
  `FL_CONFLICT` compare-and-abort contract as trips and lifecycle.

Two settings keys were also added to `ALLOWED_SETTINGS_KEYS`:
`fuelPriceProvenance` (new), plus `vehicleProfiles`, `activeVehicleId` and
`vanProfile` — the last three were already written by the app but were being
silently dropped on import, the same class of gap as X-07.

Rationale for the merge semantics is in the commit message for
`[claude] Issue #119 Batch A` and in `CLAUDE.md`'s v24.0.2 section.
