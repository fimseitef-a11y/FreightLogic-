# ELI Source-Agnostic Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the isolated deterministic ELI runtime approved in PR #441 without changing FreightLogic PWA release files or making any provider a liveness dependency.

**Architecture:** `eli-runtime/` is a private Cloudflare Worker seam with D1-backed immutable evidence/read models. Phase 1 builds storage contracts, deterministic normalization/derive/freshness/confidence, read-only Airtable Load History ingestion contract, and private read API; queues/cron and Agent binding are later tasks after the core contract is stable.

**Tech Stack:** JavaScript ES modules, Node built-in test runner/assert, Cloudflare Workers/D1, Wrangler configuration.

**Spec:** `docs/superpowers/specs/2026-09-30-eli-source-agnostic-service-design.md`

## Global Constraints

- Preserve T31 as historical `Not applicable`; never fake-pass or delete it.
- Preserve UNKNOWN; missing evidence is never zero.
- Airtable governs source eligibility/spec/model/stage/promotion; D1 governs runtime evidence/derived state/query serving.
- Operator evidence never contaminates national Structural Strength.
- `recordOutcome` excludes rates/RPM/revenue/payout/settlement/fuel/cost/payment identifiers/secrets.
- Quote/auction and order/award lineage remain separate without explicit proof.
- Do not edit `app.js`, `index.html`, `styles.css`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, or `manifest.json`.
- No public ELI route; no scraping/undocumented provider APIs.

## Review Focus

- Reused posting IDs must not dedupe distinct origin/destination/pickup observations.
- Stale/missing structural sources must degrade to confidence/UNKNOWN, never fabricate equivalence.
- Lifecycle terminal/non-award states must remain distinct and reject inferred promotion.
- Boundary-sensitive FAF6 geography must not silently map to a finer market.
- D1 candidate state must not imply Airtable promotion.

---

### Task 1: Core contracts and identity

**Files:** Create `eli-runtime/contracts.mjs`, `eli-runtime/identity.mjs`, `eli-runtime/tests/contracts.test.mjs`.

**Interfaces:** Produce lifecycle/source-class enums, `buildEvidenceIdentity(observation)`, and privacy allowlist validation.

- [ ] Write failing tests for composite posting identity, quote/order namespace separation, complete lifecycle set, and forbidden economics fields.
- [ ] Run tests and verify RED because modules do not exist.
- [ ] Implement minimal contracts/identity functions.
- [ ] Run task tests and full suite; verify GREEN.
- [ ] Commit.

### Task 2: Immutable D1 schema and failure journal

**Files:** Create `eli-runtime/migrations/0001_init.sql`, `eli-runtime/storage.mjs`, `eli-runtime/tests/storage.test.mjs`.

**Interfaces:** Append-only raw evidence, receipts, failures, derived lane rows, model runs; `journalFailure()` and immutable insert helpers.

- [ ] RED tests for append-only evidence and durable terminal-failure journal.
- [ ] Implement schema/storage.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 3: Deterministic derive, freshness and confidence

**Files:** Create `eli-runtime/normalize.mjs`, `derive.mjs`, `freshness.mjs`, `confidence.mjs`, tests.

**Interfaces:** Pure deterministic functions returning explicit UNKNOWN/conflict/freshness envelopes.

- [ ] RED tests for missing evidence, stale source, structural-source removal and operator-history isolation.
- [ ] Implement minimal pure functions.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 4: Geography and operator adapter contracts

**Files:** Create `eli-runtime/geography.mjs`, `eli-runtime/adapters/airtable-load-history.mjs`, tests.

**Interfaces:** FAF6-zone-to-market resolver with boundary sensitivity; read-only Load History projection that excludes economics/private fields.

- [ ] RED tests for ambiguous boundary mapping, unknown geography, status preservation and field allowlist.
- [ ] Implement resolver/adapter projection.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 5: Private read API and promotion reconciliation

**Files:** Create `eli-runtime/api.mjs`, `worker.mjs`, `wrangler.jsonc`, tests.

**Interfaces:** `getLaneIntelligence`, `getMarketIntelligence`, `health`; no public route; promotion requires matching governance fingerprint.

- [ ] RED API/reconciliation tests.
- [ ] Implement private API seam and dark Worker config.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 6: T36 degradation matrix and six-pilot harness

**Files:** Create `eli-runtime/tests/t36.test.mjs`, `eli-runtime/tests/pilots.test.mjs`, fixtures.

**Interfaces:** Synthetic optional-provider fixtures plus FAF6/CFS-QCEW removal matrix; frozen ATL/BNA/DTW six-direction harness.

- [ ] RED tests proving removal scenarios and expected Pilot Candidate/UNKNOWN behavior.
- [ ] Add deterministic fixtures/harness only; no confidence fabrication.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 7: Queue/DLQ batching after core stability

**Files:** Create `eli-runtime/queue.mjs`, queue tests; extend Worker/config only if core tasks are green.

**Interfaces:** Snapshot/change-set batching, bounded retry, DLQ consumer journals D1 before ack.

- [ ] RED batching/idempotency/DLQ tests.
- [ ] Implement queue seam without requiring a live provider.
- [ ] GREEN task tests + full suite.
- [ ] Commit.

### Task 8: Agent binding and final verification

**Files:** Modify only `agent-runtime` files required for private `ELI` binding and graceful-unavailable behavior; add tests. Do not activate Agent.

**Interfaces:** Agent reads deterministic ELI projection; ELI failure is non-fatal; canonical FreightLogic economics unchanged.

- [ ] RED integration tests.
- [ ] Implement binding seam behind existing disabled Agent gate.
- [ ] GREEN task tests + repository suite/CI.
- [ ] Revalidate six pilots, record exact outcomes and evidence versions in Airtable.
- [ ] Final branch review and completion checkpoint; do not merge/deploy without separate governed approval if required.
