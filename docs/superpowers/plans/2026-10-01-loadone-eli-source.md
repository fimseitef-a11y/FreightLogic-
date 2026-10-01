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

- [ ] Write tests for source classification, 20-minute cadence, DST-aware 06:00–22:00 ET window, unauthorized/no-config fail-closed behavior, Wrangler cron declaration, Load One cron routing, and preservation of Run-Now Airtable routing.
- [ ] Run `node --test eli-runtime/tests/*.test.mjs`; verify RED because the Load One adapter/schedule do not yet exist.

### Task 2: Minimal authorization-gated adapter and worker dispatch

**Files:**
- Create: `eli-runtime/adapters/loadone-live.mjs`
- Modify: `eli-runtime/worker.mjs`
- Modify: `eli-runtime/wrangler.jsonc`

**Interfaces:**
- Consumes: tests from Task 1.
- Produces: `LOADONE_CRON = '*/20 * * * *'`; source metadata; active-window predicate; fail-closed collection result; worker cron dispatch.

- [ ] Implement the minimal adapter with no undocumented provider endpoint or payload assumptions.
- [ ] Add the 20-minute cron while retaining `23 */6 * * *`.
- [ ] Dispatch only the Load One cron to the Load One adapter; all other cron values continue to existing `runIngestion()` so Run-Now remains valid.
- [ ] Run `node --test eli-runtime/tests/*.test.mjs`; verify GREEN.

### Task 3: Public-history provenance ingestion and coordination

**Files / systems:**
- Airtable `Lane Research - Sources`
- Airtable `Lane Research - Raw Observations`
- Airtable `Lane Research - Time Profiles`
- Airtable `Lane Research - Project Coordination`

**Interfaces:**
- Consumes: completed public research report and operator timing observations.
- Produces: versioned Load One source registry rows, only defensible concrete public observations, timing profile with explicit non-exhaustive/operator-observed caveat, and a resume checkpoint.

- [ ] Add source records for primary public evidence, recording access restrictions and capability-vs-observation limits.
- [ ] Add the Jan. 9–10, 2018 Portsmouth, NH → Norfolk, VA example as a non-exhaustive public article observation; do not add anecdotal fragments as normalized lane frequency.
- [ ] Record operator-observed timing (loads usually begin around 06:00 ET; additional freight sometimes appears after 07:45) as a non-exhaustive time-profile note, not national truth.
- [ ] Add coordination checkpoint with branch/commit/tests and blocker: no documented authorized live Load One feed currently available.

### Task 4: PR and verification

**Files:** none beyond Tasks 1–2.

- [ ] Open a PR from `gpt/loadone-eli-source` to `main`.
- [ ] Verify ELI runtime CI and required repository checks.
- [ ] Do not merge without the repository's normal governed approval path.
