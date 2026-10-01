# ELI Source-Agnostic Service Design

Date: 2026-09-30
Status: revised design for operator review — PR #441 audit amendments incorporated
Task: AIAG-TASK-0038 / ELI-SOURCE-AGNOSTIC-SERVICE-20260930
Base: FreightLogic main `26835914ff0991fd5b89d6f91e73100e1ab75300`

## 1. Intent

Turn Expedite Lane Intelligence (ELI) into a continuously maintainable, source-agnostic intelligence service that stays useful when any single provider is absent, stale, unavailable, or unauthorized. ELI must ingest evidence, preserve provenance, recompute only affected intelligence, expose freshness/confidence/UNKNOWN state explicitly, and feed the existing FreightLogic Agent through a private contract. AI interprets ELI; AI does not keep ELI alive and does not become the scoring authority.

Success means:

1. T31 is no longer an active production dependency. Its historical evidence remains intact and auditable.
2. No single optional external provider can block ELI service availability or production eligibility.
3. All evidence is provenance-bearing, immutable at the raw layer, deduplicated only in derived layers, and subject to existing source-access/temporal rules.
4. ELI reports both intelligence and its evidence quality: freshness, staleness, confidence, observation counts, UNKNOWN conditions, source lineage, and model versions.
5. FreightLogic outcomes feed back into a private operator-specific evidence layer without contaminating national structural truth.
6. The six existing pilot directional lanes are revalidated under the new service and are promoted only when evidence supports promotion. A valid result may be “remain Pilot Candidate with explicit UNKNOWN flags.”

## 2. Current-state findings

The existing Airtable ELI research model already contains substantial governance that should be reused rather than rebuilt:

- `Lane Research - Sources` tracks source family, vintage/release, retrieval date, adapter version, intended use, restrictions, and immutable reference/hash.
- `Lane Research - Raw Observations` already separates raw observations from normalized shipment events and carries source identity, evidence date, status layer, duplicate/repost fields, equipment eligibility, freshness/coverage flags, time quality, geography resolution, dimensions, commodity/industry and raw evidence references.
- `Lane Research - Directional Lanes` already has structural/expedite/confidence version fields, observation density, UNKNOWN states, lineage refs and lane stage.
- `Lane Research - Model Runs` already versions source snapshots, observation-as-of time, matching, structural, expedite, confidence and threshold formulas plus code/config hash.
- T34 temporal adequacy and T35 source-access authorization are active safety contracts and must remain in force.

T31 (`National production expedite readiness`) is already `Not applicable` for ELI-v1. The operator explicitly scrapped the provider-authorization wait on 2026-09-29. T31 must therefore be preserved as historical governance, not deleted and not marked Pass. If a future licensed live-board source is added, its source-specific eligibility can be evaluated without making that provider a global ELI liveness gate.

The six Pilot Candidate lanes are the two-way ATL/BNA/DTW triangle. They currently retain `INSUFFICIENT_OBSERVATIONS`, `EQUIPMENT_RELEVANCE_UNRESOLVED`, and `EXPOSURE_DENOMINATOR_MISSING`; those conditions may not be erased without new qualifying evidence.

## 3. Approaches considered

### A. Put ELI logic inside the FreightLogic AI Agent

Rejected. It couples evidence collection and scoring availability to the AI runtime, obscures deterministic lineage, makes background maintenance depend on model infrastructure, and creates a second source of truth for decisions.

### B. Use Airtable automations as the production ELI runtime

Rejected as the hot path. Airtable remains valuable as the governance/research/control plane and checkpoint ledger, but it is not the desired queue, retry, low-latency query, idempotency and append-only execution layer for continuous processing.

### C. Isolated `eli-runtime/` service in the FreightLogic monorepo

Recommended. Create a separately deployable Cloudflare Worker seam under GPT ownership, with its own tests/config/database/queue. The existing FreightLogic Agent queries it through a private Service Binding. This mirrors the successful isolation pattern already used by `agent-runtime/` while keeping ELI deterministic and independent of the model runtime.

## 4. Runtime architecture

Add an isolated subtree:

```text
eli-runtime/
  README.md
  contracts.mjs
  source-registry.mjs
  adapters/
  ingest.mjs
  normalize.mjs
  derive.mjs
  freshness.mjs
  confidence.mjs
  feedback.mjs
  api.mjs
  worker.mjs
  migrations/
  tests/
  wrangler.jsonc
```

### Cloud components

- **Worker:** private ELI runtime; no public route, `workers_dev=false`, preview URL disabled.
- **D1 (`ELI_DB`):** authoritative runtime journal/read model for normalized source metadata, immutable raw evidence records, derived events, lane aggregates, model runs, freshness state and operator feedback lifecycle.
- **Queue (`ELI_QUEUE`):** asynchronous ingestion/recompute/feedback work. Messages are idempotent and typed. Consumer retries are bounded.
- **Dead-letter queue (`ELI_DLQ`):** preserves failed work for audit/remediation instead of silently dropping it after retry exhaustion.
- **Cron triggers:** only for adapters whose terms and access method permit scheduled collection. Static/slow sources use cadence appropriate to their release schedule rather than pointless frequent polling.
- **Private Service Binding:** `agent-runtime` receives an `ELI` binding and calls typed ELI methods. The ELI Worker remains non-public.

No new general AI agent is introduced.

## 5. Data planes and source classes

Each source is registered with a stable `source_id` and one of three classes:

1. `STRUCTURAL_PUBLIC` — authoritative/public statistical evidence such as BTS FAF6, 2022 CFS/PUMS, QCEW and existing vetted infrastructure datasets.
2. `OPERATOR_PRIVATE` — the operator's own board observations and FreightLogic/load outcomes. These support an operator-specific actionability/experience overlay and direct shipment evidence where warranted, but cannot silently become national structural truth or an exposure denominator.
3. `LICENSED_LIVE_OPTIONAL` — future provider feeds only after their documented access method authorizes the collection/use. Their absence cannot make the ELI service unavailable.

Every adapter declares:

- source id/class/version
- authorization/access status and allowed collection method
- intended model components
- source snapshot/vintage
- declared scope/filter
- retrieved/observed/source-posted timestamps with time-quality classification
- stable source identity semantics
- cadence and freshness policy
- completeness/exhaustiveness capability
- normalization version

If these properties are unknown, the affected derived fields remain UNKNOWN.

## 6. Raw evidence immutability and provenance

The raw layer is append-only. A raw evidence row includes:

- generated immutable evidence id
- source id + adapter version
- source-side id when available
- observed/retrieved/source-posted timestamps
- canonical payload serialization
- SHA-256 payload hash
- source snapshot/ref/vintage
- authorization/access classification
- scope/filter fingerprint
- parent evidence/lineage references
- ingest run id

A later correction does not mutate the original raw row; it appends a superseding row and derived lineage. Deduplication, repost grouping and cross-platform physical-shipment matching happen in derived tables only.

Large public source files do not have to be duplicated into D1. The runtime stores immutable content hashes, release metadata and stable references; a content-addressed blob layer can be added later if local retention of large archives becomes necessary. Row-level evidence used by scoring is retained append-only in D1.

## 7. Queue, retries and changed-only processing

`ELI_QUEUE` accepts typed messages:

- `INGEST_SOURCE_SNAPSHOT`
- `INGEST_OBSERVATION`
- `NORMALIZE_EVIDENCE`
- `RECOMPUTE_LANES`
- `RECORD_OPERATOR_OUTCOME`
- `REFRESH_FRESHNESS`

Every message contains an idempotency key derived from message type + source/run/evidence identity. Processing writes a durable receipt before side effects become visible. Duplicate delivery is safe.

Changes produce an `affected_keys` set (market, directional lane, source component). Only those keys are recomputed. Full national rebuilds remain an explicit versioned operation, not the default response to every new observation.

Failed messages retry with bounded backoff and then enter `ELI_DLQ`; failure changes the relevant source/component health state but does not erase the previous valid snapshot.

## 8. Freshness and degradation model

Freshness is source-aware, not one universal timeout. Each source declares expected release/capture cadence and four states:

- `FRESH`
- `AGING`
- `STALE`
- `UNAVAILABLE`

A lane response includes component-level age, source as-of time and freshness state. Slow structural datasets can be valid for their intended structural role even when they are not “live.” Live/operational evidence uses stricter cadence.

Rules:

- stale evidence is never silently labeled live;
- a stale optional source cannot stop ELI queries;
- stale/unavailable evidence lowers confidence or routes the affected component to UNKNOWN according to its model contract;
- last-known-good evidence may remain visible with an explicit stale marker;
- missing evidence is never converted to zero;
- an unavailable provider cannot be replaced by unauthorized scraping.

## 9. Provider-independence gate

T31 remains historical `Not applicable` for ELI-v1. Add a new hard acceptance gate (proposed T36): **Provider Independence / Source Degradation Resilience**.

T36 passes only when:

1. removing any one `LICENSED_LIVE_OPTIONAL` source leaves the service queryable;
2. remaining eligible evidence continues to produce deterministic derived state;
3. affected components correctly degrade to lower confidence/UNKNOWN rather than fabricating replacement evidence;
4. last-known-good data is labeled with its actual as-of/freshness state;
5. source-specific authorization still governs each adapter;
6. no source adapter is promoted to “required for service liveness” merely because it improves confidence.

Additional acceptance gates should cover raw immutability, idempotent replay, feedback isolation, staleness semantics and shadow-run non-promotion.

## 10. Scoring and confidence

Scoring remains deterministic and versioned. The AI model does not calculate or mutate ELI scores.

Existing structural and expedite contracts remain authoritative until explicitly superseded by a new model spec. In particular:

- missing components remain UNKNOWN and are not renormalized into an artificially high result;
- general tractor dry-van evidence cannot prove Cargo Van/Sprinter equipment fit;
- public snapshot prevalence is not event rate unless the temporal/exhaustiveness contract is satisfied;
- operator-private history cannot determine national Structural Strength;
- rates, bids, settlement, profitability, fuel and cost-per-mile stay outside structural topology/expedite evidence scoring.

Each lane read model returns:

- structural score + model version
- expedite relevance + model version
- structural/expedite confidence + confidence version
- source/evidence counts by component
- latest evidence timestamp and component ages
- freshness states
- UNKNOWN/conflict flags
- lineage/run ids
- stage (`Structural Candidate`, `Pilot Candidate`, future eligible production stage)

### Shadow testing

A new model/config version first runs in `SHADOW` mode against the same frozen evidence snapshot. Shadow results cannot overwrite the active lane read model. Promotion requires acceptance-test success and an explicit versioned model-run promotion record.

## 11. FreightLogic outcome feedback

Feedback is event-sourced and operator-private. Preserve these states separately rather than collapsing them:

- `SHOWN`
- `BID`
- `WON`
- `LOST`
- `IN_PROGRESS`
- `COMPLETED`
- `PAID`

State transitions are validated. A notification/listing is not a bid; a bid is not a win; a win/in-progress load is not completed; completed is not paid. Unknown deadhead is not zero.

The feedback layer may produce an **operator actionability/experience overlay** (for example, observed win density or personal lane experience) but it must remain separately versioned and must not contaminate national Structural Strength. This preserves the existing personal-history holdout invariant.

## 12. Private ELI API

Expose typed private methods over a Cloudflare Service Binding; no public internet route is required.

### `getLaneIntelligence`

Input: canonical origin market, destination market, optional as-of/version.

Output: deterministic lane intelligence object containing scores, confidence, freshness, evidence summary, UNKNOWN/conflict flags, stage and model/run versions. No secret/raw broker contact fields. No rate recommendation.

### `getMarketIntelligence`

Input: canonical market and optional direction/time.

Output: supported structural/expedite summaries with the same provenance/freshness envelope.

### `recordOutcome`

Input: privacy-allowlisted FreightLogic outcome event + stable internal correlation token.

Output: accepted/replayed/conflict status. It never upgrades lifecycle state from inference.

### `health`

Returns service/schema/model versions, queue/DLQ summary, source health counts and newest successful run timestamps without exposing credentials or private raw evidence.

## 13. FreightLogic Agent integration

The existing Agent remains an interpretation layer. Add a private `ELI` Service Binding to `agent-runtime`, then:

1. Agent request is authenticated/authorized by the existing FreightLogic boundary.
2. Agent calls ELI with canonical market identifiers only.
3. ELI returns deterministic provenance-bearing intelligence.
4. Agent may explain/summarize that result.
5. Canonical FreightLogic economics and bid/verdict calculations remain controlled by the existing deterministic FreightLogic authority and output guard.

ELI unavailability must fail gracefully: the Agent reports ELI unavailable/stale and continues deterministic FreightLogic behavior without inventing lane intelligence.

## 14. Replacement evidence strategy

There is no claim that one free feed replaces the former provider concept. The replacement is layered and explicit:

- **FAF6**: current BTS benchmark structural O-D commodity/mode evidence (2022 base year).
- **2022 CFS / PUMS**: authoritative shipment-level statistical sample and published CFS evidence, subject to its disclosure/coarsening and weighting rules already represented in ELI governance.
- **QCEW**: current county/industry employment context for industry-driver structure, with source-release cadence reflected in freshness.
- existing vetted public infrastructure/transit evidence already in ELI;
- operator-private FreightLogic/board/load outcomes as a separate operator evidence layer;
- future licensed live provider adapters when genuinely authorized.

This stack deliberately separates slow structural truth from live operational signals. A live-board feed can improve confidence and timeliness later without becoming a single point of failure.

## 15. Six-pilot revalidation

The current pilots are:

- DTW → ATL
- ATL → DTW
- ATL → BNA
- BNA → ATL
- BNA → DTW
- DTW → BNA

After implementation:

1. freeze a source snapshot set and model/config version;
2. ingest/reconcile eligible structural and authorized operator evidence;
3. run the six pilots through the same deterministic pipeline;
4. compare active vs shadow output;
5. verify lineage, freshness, confidence and UNKNOWN flags;
6. promote only a lane whose evidence satisfies the applicable production criteria.

“Still Pilot Candidate because equipment relevance/exposure evidence remains unresolved” is a correct completed revalidation result and must not be treated as a failed project.

## 16. Security, privacy and source terms

- no scraping/headless/undocumented API path when terms or access conditions do not authorize it;
- source credentials/secrets never enter Airtable, logs, raw evidence or Agent prompts;
- private operator evidence is never exposed via a public ELI endpoint;
- Service Binding methods accept/return a minimal allowlist;
- raw evidence and operator feedback are not passed to the AI model by default; only the derived allowlisted projection is;
- provider failure or license loss changes source health/eligibility, not historical evidence;
- existing T34/T35 and UNKNOWN-routing safeguards remain mandatory.

## 17. Testing and rollout

Implementation is test-driven and staged:

1. contract tests for evidence immutability, adapter validation and source eligibility;
2. queue/idempotency/retry/DLQ tests;
3. deterministic derive/freshness/confidence tests;
4. negative tests proving missing/stale/restricted evidence does not become zero/high confidence;
5. T36 provider-removal matrix;
6. outcome lifecycle and operator-history-isolation tests;
7. private ELI API contract tests;
8. Agent integration tests proving ELI failure is non-fatal and canonical FreightLogic calculations remain unchanged;
9. six-pilot frozen-snapshot revalidation;
10. exact-head CI and governed integration.

Initial rollout remains production-dark until contracts pass. Deployment/activation follows existing repository/Cloudflare governance; this design does not itself authorize bypassing environment reviewers, secrets management or deployment gates.

## 18. Airtable checkpoint discipline

`AIAG-TASK-0038` is the resume anchor. At each material stage, append/update privacy-safe coordination records with exact repository SHA/branch, tests, run/model versions, blockers and next action. Do not store secrets.

Minimum checkpoints:

1. architecture audit + written spec
2. acceptance/model-governance update (T31 historical + T36 and related gates)
3. isolated ELI runtime implementation
4. test/CI completion
5. private Agent integration
6. six-pilot revalidation
7. final completion/handoff

If interrupted, resume from the newest completed checkpoint and exact repository SHA; do not restart completed audits.

## 19. Non-goals

- building a second general AI agent/bot
- scraping restricted load boards
- forcing all 7,250 Structural Candidates into production
- claiming national real-time event rates from operator notifications
- replacing deterministic FreightLogic economics with model output
- deleting historical T31 evidence
- treating stale, suppressed, missing or unknown data as zero
- making the shared/family PC a production dependency

## 20. PR #441 audit amendments

These amendments are controlling over earlier wording in this design and must be resolved before implementation:

1. **Durable DLQ audit:** queue retention is not durable evidence. A DLQ consumer must journal terminal failures into D1 before acknowledgement. Queue messages are batched per snapshot/change set rather than one message per source row.
2. **Identity and dedupe:** evidence identity may not rely on a posting number alone. For operator/DispatchLand-style observations use source/platform plus posting id, origin, destination, and pickup window/date. Quote/auction lineage and awarded/order lineage remain separate unless explicit lineage proves identity.
3. **Lifecycle completeness:** preserve SHOWN, BID, WON, LOST, EXPIRED, REJECTED, DRY_RUN, DEACTIVATED, IN_PROGRESS, COMPLETED, and PAID as distinct states. No state promotion from inference.
4. **First operator-private adapter:** begin with a read-only Airtable Load History adapter because that is the current durable operator evidence source. recordOutcome excludes all pricing/economic fields and is not dependent on the Agent being enabled.
5. **FAF6 crosswalk:** FAF6 zones are not market clusters. Resolve FAF6 Zone ID through Lane Research - Geography into Market Cluster while preserving geography version and Boundary Sensitivity Status; boundary-sensitive or ambiguous mappings remain explicit/UNKNOWN.
6. **Non-vacuous T36:** use synthetic optional-provider fixtures even when no licensed live provider exists. Also remove FAF6, CFS/PUMS, and QCEW one at a time and verify the service stays queryable while unsupported components degrade to lower confidence/UNKNOWN.
7. **Two authorities:** Airtable is authoritative for source registry/eligibility, model specs, acceptance tests, lane stage/promotion, and geography governance. D1 is authoritative for runtime evidence, receipts, derived rows, freshness, failures, and query serving. A D1 candidate cannot promote a lane/model without a matching approved Airtable record/version.
8. **Repository invariants and sequencing:** this work does not edit app.js, index.html, styles.css, service-worker.js, sw-bridge.js, modern-shell.js, or manifest.json, so it does not trigger the PWA release/version bump by itself. Build D1 storage + deterministic derive + private read API first; add queues/cron only after an authorized adapter needs them; integrate the Agent after the ELI contract is stable.

### Expected six-pilot result

Because the replacement public sources are structural/periodic rather than licensed live-board feeds, the expected completed revalidation outcome for ATL/BNA/DTW is that some or all six lanes remain Pilot Candidate with equipment relevance and/or exposure denominator UNKNOWN. That is a valid successful revalidation, not a reason to manufacture confidence.

### Ownership boundary

Current Airtable registry still names AIAG-GROK-INTELLIGENCE as primary ELI research/methodology owner and ChatGPT as the independent audit/adoption lane. PR #441 does not silently change that assignment. This design edit is a bounded ChatGPT documentation action under AIAG-TASK-0038. Product-code implementation requires an explicit operator assignment/handoff for the bounded eli-runtime implementation lane before code begins.
