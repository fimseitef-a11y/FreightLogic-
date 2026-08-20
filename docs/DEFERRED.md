# Deferred — v23.9 "Trust & Recovery"

Per the v23.9 scope instructions: this release is the 12 audit findings (X-01…X-12) +
4 Phase 7 additions, nothing else. Anything else surfaced while working the list goes
here instead of expanding scope. Explicitly out of bounds regardless of how tempting:
the Decision Engine refactor, the visual redesign, the Load Lifecycle schema migration,
Simple/Pro modes, confidence percentages, the Next-Move Engine.

## Phase 1 (X-02/X-03)

- **Full multi-vehicle fleet schema.** X-03 requires `vehicleTaxMethod`/
  `firstYearElection` to be stored per-vehicle, not globally. Implemented as
  `settings['vehicleProfiles']` (an array of lightweight profile objects) +
  `settings['activeVehicleId']` inside the existing `settings` store — no new IDB
  object store, no `DB_VERSION` bump, no vehicle-switching UI beyond what X-03 itself
  needed. A real fleet feature (multiple vehicles with independent trip/expense
  attribution, a vehicle picker, per-vehicle maintenance schedules, etc.) is a
  meaningfully larger feature than this release's scope and is not implied by X-03 —
  deferred to whenever/if a genuine multi-vehicle need is scoped.
- **`cloudPushBackup()` does not yet strip `fmcsaApiKey`/`eiaApiKey` before upload.**
  Noted while writing `docs/BACKUP_CONTRACT.md` (Amendment 2): `exportJSON()` already
  strips these two secret keys (`app.js:1374`, part of the X-05 fix in Phase 3), but
  `cloudPushBackup()`'s `settings` dump is a full-store dump with no such filter. This
  is **not** deferred out of the release — it's tracked here only so it isn't lost
  before Phase 4 (X-01/X-07, the cloud restore-path work) picks it up; Phase 4 should
  fix it in the same pass since it's touching the same push/pull code.
