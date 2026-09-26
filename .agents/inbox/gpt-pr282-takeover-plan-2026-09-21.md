# PR #282 documentation continuation implementation plan

Goal: finish the existing release documentation from exact main d35ba266, preserve Claude's historical work, and remove obsolete current-generation claims without changing deployed bytes.

Authority: operator's 2026-09-21 takeover instruction; AGENTS.md/LANES.md. Claude and GPT NOW rows were idle, no live lock, draft #282 head 421db420 conflicts with main. The existing Claude request already asks to reconcile it after #281.

Architecture: documentation-only successor on agent/gpt/current-release-completion. No change to runtime, economics policy, test expectations, workflow triggers, security settings, or physical certification. Native execution in this session; every implementation step uses existing verification, with review of exact changed files before PR.

- [ ] Publish/merge a bounded ownership grant for CLAUDE.md, FIELD_TEST_CHECKLIST.md, docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md, docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-20.md, docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-21.md, docs/SAFARI27_MCP_QA_WORKFLOW.md. Lock only .agents/LANES.md; no other lane transfer.
- [ ] Reconcile the original five-path draft with fresh main and add the dated 2026-09-21 state. Retain historical v24.0.25 observations as historical, retain all #281 v24.0.26 economics source changes, label #252 live vision smoke UNOBSERVED and #278 later policy/audit scope OPEN, keep A1-A13 physical HOLD and authentic M6 completed.
- [ ] Verify Safari setup against primary Apple/WebKit sources; correct unsupported assertions or label genuinely unobserved prerequisites. Do not claim Safari execution or iPhone certification.
- [ ] Run lane ownership/prefix checks, release-generation no-deployed-byte check, static parity, certification resolver, and exact-head GitHub CI. Confirm one non-superseded state and no unrelated changed files; run existing targeted certification tests locally if useful.
- [ ] Merge only the current exact green reviewed successor, close #282 as superseded without deleting its source branch, retire the temporary lane grant, release the lock, record exact results in STATUS/TEST_LEDGER and update the continuation handoff.

Review focus: current vs historical generation; single supersession authority; full-suite vs skipped local runner; old authenticated text/backup evidence vs never-run new vision probe; headless observations vs physical device; #278 implemented cost slice vs later policy still awaiting independent review; no source or release-generation drift.
