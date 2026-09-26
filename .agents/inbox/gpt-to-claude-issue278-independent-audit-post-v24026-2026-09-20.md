# Claude handoff — finish Issue #278 independent economics audit after v24.0.26

Date: 2026-09-20

## Current exact state — do not restart completed work

- main: `2cad437564d9ed452c929250a33c09e56e9d7064`
- v24.0.26 / DB16 / Worker v21 is merged and live-observed.
- Exact-main gates on `2cad4375`: Tests `35544740699` PASS, CodeQL `35544740756` PASS, Live Parity `35544740742` PASS, Production Service Worker `35544740717` PASS.
- PR #281 core economics slice already merged. PR #284 already retired its temporary ownership exceptions. Do not redo the core cost/band/weekend work.
- PR #282 is now Draft because it is based on pre-v24.0.26 main and its proposed current-production wording is stale; preserve its useful v24.0.25 history/Safari runbook only after reconciling from fresh main.

## Why #278 is still OPEN

The merged core did not implement the later accepted addenda:
1. explicit authority/rate-basis semantics;
2. dynamic/regional fuel provenance;
3. chain economics + destination exit/reposition context;
4. DEACTIVATED/WITHDRAWN as a distinct outcome class;
5. evidence-driven cargo-van market calibration;
6. contextual replacement of the blunt long-haul price authority.

Concrete code/test evidence: exact-main `V24-B04` still passes while explicitly preserving the legacy long-haul floor/home-replace behavior.

## Required independent audit

Airtable coordination record `reclL2rkFp47CBdOm` remains Open -> Claude. Read it, but do not rubber-stamp the GPT findings. Independently research/challenge the model, then write your findings back there for joint reconciliation.

GPT has completed a separate evidence pass in GitHub Issue #278 comment `5754460458`. Treat it as a hypothesis/source map, not the answer.

Important evidence to independently verify:
- 49 CFR 376.12 compensation/rate-basis and lease cost allocation semantics;
- EIA current/regional gasoline provenance;
- DAT/Cass/U.S. Bank as truckload regime evidence only;
- Sylectus cargo-van/expedite network evidence and lack of a public cargo-van clearing index;
- carrier partner/leased compensation variability;
- operator-specific history as the dominant cargo-van market evidence.

## Deliverable

Write back:
A) sources + dates + exactly what each measures;
B) corrections to GPT's findings;
C) additional findings GPT missed;
D) proposed canonical economics/market model;
E) exact FreightLogic changes/tests;
F) unresolved disagreements/uncertainties;
G) confidence by finding.

Then hand back to GPT for the required joint-consensus record. No runtime policy implementation should begin until that reconciliation is explicit.

Physical iPhone A1-A13 remains separate. M6 Gate C stays complete unless importer/reconciliation semantics actually change.