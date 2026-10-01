# Load One ELI Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register Load One as a provenance-first ELI source, preserve public historical evidence, and add a 20-minute authorization-gated live-source schedule without scraping private or undocumented interfaces.

**Architecture:** Keep public historical evidence in Airtable's existing ELI source/raw-observation control plane. Add a small `LICENSED_LIVE_OPTIONAL` Load One adapter seam to `eli-runtime`; Cloudflare may trigger it every 20 minutes, but the adapter skips outside the operator-observed active window and makes no external request unless a documented authorized collection method is configured. Existing Airtable ingestion remains on its independent cadence.

**Tech Stack:** Node.js 22, Cloudflare Workers/Wrangler, Airtable ELI control plane, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-30-eli-source-agnostic-service-design.md`

## Global Constraints

- Preserve committed `ELI_ENABLED=false`; production enablement remains deployment-time only.
- Keep ELI RPC-only; add no HTTP route.
- Do not scrape/headless-call/guess undocumented Load One or Sylectus endpoints.
- Do not put rates/RPM/profitability into ELI topology evidence.
- Preserve raw provenance and same-lane/repost ambiguity; do not infer cross-platform shipment identity.
- Existing Airtable ingestion cadence and Claude's current ingest verification lane remain untouched.
- Load One desired live cadence is 20 minutes; active-market window is 06:00 inclusive to 22:00 exclusive in `America/New_York`, all days, with DST-aware evaluation. The broad 22:00 cutoff is intentionally conservative because the operator only established that overnight is generally quiet.

## Review Focus

- DST transitions must not shift the intended Eastern active window.
- A cron firing outside the active window must make no provider request.
- Missing authorization/configuration must make no provider request and must return an explicit skip reason.
- The temporary `* * * * *` Run-Now cron must continue routing to existing Airtable ingestion.
- Adding Load One must not make ELI service liveness depend on Load One availability.

---

### Task 1: Load One live-source contract and schedule tests

**Files:**
- Create: `eli-runtime/tests/loadone-source.test.mjs`
- Modify: `eli-runtime/tests/worker-handlers.test.mjs`

**Interfaces:**
- Consumes: existing Worker `scheduled()` handler.
- Produces: required exports `LOADONE_CRON`, `LOADONE_LIVE_SOURCE`, `isLoadOneActiveWindow()`, `runLoadOneCollection()` from `eli-runtime/adapters/loadone-live.mjs`.

- [x] Write tests for source classification, 20-minute cadence, DST-aware 06:00–22:00 ET window, unauthorized/no-config fail-closed behavior, Wrangler cron declaration, Load One cron routing, and preservation of Run-Now Airtable routing.
- [x] RED verified in draft PR #450, ELI Runtime run `36820877261`: missing `loadone-live.mjs` failed as intended and W07 proved the old scheduler incorrectly routed the 20-minute cron into ordinary Airtable ingestion. W08 verified Run-Now routing remained intact.

### Task 2: Minimal authorization-gated adapter and worker dispatch

**Files:**
- Create: `eli-runtime/adapters/loadone-live.mjs`
- Modify: `eli-runtime/worker.mjs`
- Modify: `eli-runtime/wrangler.jsonc`

**Interfaces:**
- Consumes: tests from Task 1.
- Produces: `LOADONE_CRON = '*/20 * * * *'`; source metadata; active-window predicate; fail-closed collection result; worker cron dispatch.

- [x] Implement the minimal adapter with no undocumented provider endpoint or payload assumptions.
- [x] Add the 20-minute cron while retaining `23 */6 * * *`.
- [x] Dispatch only the Load One cron to the Load One adapter; all other cron values continue to existing `runIngestion()` so Run-Now remains valid.
- [ ] Verify GREEN on the governed `agent/gpt/loadone-eli-source` PR head.

### Task 3: Public-history provenance ingestion and coordination

**Files / systems:**
- Airtable `Lane Research - Sources`
- Airtable `Lane Research - Raw Observations`
- Airtable `Lane Research - Project Coordination`

**Interfaces:**
- Consumes: completed public research report and operator timing observations.
- Produces: versioned Load One source registry rows, only defensible concrete public observations, timing policy with explicit non-exhaustive/operator-observed caveat, and a resume checkpoint.

- [x] Add 19 source-registry records spanning public evidence from 2005 through current 2025–2026 pages, with access/reuse restrictions and capability-vs-observation limits explicit.
- [x] Add the Jan. 9–10, 2018 Portsmouth, NH → Norfolk, VA example as one non-exhaustive public article observation. Overdrive corroboration is explicitly the same event, not a second shipment.
- [x] Ruling: `Lane Research - Time Profiles` only supports Market/Directional Lane/Corridor entity types, so source-wide operator timing is not written there. Preserve the operator observation (activity usually begins around 06:00 ET; additional freight sometimes appears after 07:45) in the adapter policy and project coordination instead of polluting a market/lane time-profile table.
- [ ] Add final coordination checkpoint after governed-branch CI completes.

### Task 4: PR and verification

**Files:** none beyond Tasks 1–2.

- [x] Draft PR #450 proved RED but used the invalid branch namespace `gpt/*`.
- [x] Move the exact implementation to governed namespace `agent/gpt/loadone-eli-source`; do not redo implementation.
- [ ] Open replacement governed draft PR and close #450 as superseded.
- [ ] Verify ELI Runtime plus repository governance/required checks.
- [ ] Do not merge without the repository's normal governed approval path.
