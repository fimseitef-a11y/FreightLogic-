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
- ~~`cloudPushBackup()` does not yet strip `fmcsaApiKey`/`eiaApiKey` before upload.~~
  **Fixed in Phase 4** (same pass, since it touches the same push code X-01/X-07 were
  already changing) — see `docs/BACKUP_CONTRACT.md`'s Credentials exception section.

## Phase 4 (X-01/X-07)

- **`GET /health` on `cloud-backup-worker.js` doesn't report which endpoints it
  supports.** X-01 added `GET /backup/delta` (Worker v11) and `cloudPullBackup()`
  treats a failed/absent fetch to it as "unverifiable" (a visible partial-restore
  warning, not a silent success) — so an old, not-yet-redeployed Worker degrades safely
  rather than lying about restore completeness. A nicer UX (e.g. `/health` reporting
  supported endpoints, so the client can give a more specific message than
  "unverifiable") is a real improvement but not required for correctness — deferred as
  polish, not a correctness gap.
- **Two-tab/two-device TOCTOU on the merge-restore path itself** was not investigated.
  F-6 (pre-v23.9) fixed optimistic concurrency for `upsertTrip()`'s normal save path;
  `mergeRestoreData()` writes directly via `store.put()` in its own transactions and
  doesn't go through `upsertTrip()`'s conflict check. A restore running concurrently
  with a live edit in another tab was out of scope for X-01/X-07 (which are about
  reaching data at all, not about concurrent-restore races) — noted here in case it
  becomes relevant once Phase 7B (recovery verification) adds more automated
  restore-adjacent activity.
