# Vendored Dependency Review — SheetJS

**Review date:** 2026-09-26  
**Reviewed main:** `55b1bdf21b622475fc9b6eabaed31cbabe397692`  
**Scope:** report only; no `vendor/`, runtime, test, or release-marker files changed.

## Inventory

FreightLogic vendors `vendor/xlsx.full.min.js` directly rather than through npm. The current artifact is Git blob `16e013fceefc689cabc5be352099199847a0e67f`.

The bundle itself declares `version="0.18.5"`. This is no longer an inferred filename/version claim. Repository history also records the original bundling decision in commit `1399d9ff7a8865f95851fe587add89a4a2913991` as **SheetJS v0.18.5**, bundled locally for offline XLSX import.

Because this dependency is vendored and there is no npm package manifest governing it, `npm audit` / Dependabot npm alerts are not authoritative inventory controls for this file.

## Advisory status

SheetJS CE 0.18.5 is inside both current GitHub-reviewed affected ranges:

- **CVE-2023-30533 / GHSA-4r6h-8v6p-xvw6 — prototype pollution.** GitHub Advisory Database: `xlsx < 0.19.3`. The advisory specifically identifies reading specially crafted workbook files as the vulnerable operation; export-only workflows are not affected.
  - https://github.com/advisories/GHSA-4r6h-8v6p-xvw6
- **CVE-2024-22363 / GHSA-5pgg-2g8v-p4x9 — regular-expression denial of service.** GitHub Advisory Database: `xlsx < 0.20.2`.
  - https://github.com/advisories/GHSA-5pgg-2g8v-p4x9

The maintained SheetJS CE fixes are not represented by a newer npm `xlsx` release. A blind `npm update` therefore does not remediate this vendored browser bundle.

## FreightLogic reachability

**Parser reachability is CONFIRMED.**

Evidence on current repository history and current tests:

1. Issue #232 captured the shipped XLSX import path calling `file.arrayBuffer()` followed by `XLSX.read(data, { type:'array' })`. The v24.0.17 repair moved the import-size guard before materialization/parsing; it did **not** remove XLSX parsing.
2. Commit `1c9d5364200eec648b927a03d2e63efeb0b48011` (v24.0.43) explicitly states that the trip-import branch is shared by CSV, XLSX and TXT, confirming XLSX remains an application input path in the current generation family.
3. Current `tests/integration/xlsx-bundled-vendor.spec.mjs` loads the exact local vendor bundle with all external network disabled and exercises `XLSX.read`, `XLSX.write`, and `XLSX.utils.sheet_to_json`. The spec is registered in current `tests/run-all.mjs`.
4. Current `tests/integration/trip-import-integrity.spec.mjs` is the v24.0.43 CSV/XLSX trip-import integrity regression and is also registered in `tests/run-all.mjs`.

Threat-boundary qualification: FreightLogic does not automatically parse arbitrary remote workbooks. The relevant surface is a workbook deliberately selected/imported by the operator. That means user interaction is part of the path, but the vulnerable parser is still reachable with workbook-controlled bytes. This review does **not** claim that either CVE has been successfully exploited against FreightLogic.

Current classification:

- exact vendored version: **CONFIRMED — SheetJS CE 0.18.5**;
- advisory applicability by version: **CONFIRMED**;
- vulnerable parse surface reachable in FreightLogic: **CONFIRMED**;
- FreightLogic-specific exploit demonstration: **NOT PERFORMED / NOT REQUIRED TO JUSTIFY REMEDIATION**;
- safe-to-ignore/waive: **NOT ESTABLISHED**.

## Required remediation gate

Do not edit `vendor/` as part of this report. Any dependency replacement belongs to the Claude-owned vendor/release lane and should:

1. preserve offline-first XLSX import; do not replace the local bundle with an unpinned runtime CDN dependency;
2. choose and pin either a maintained SheetJS CE distribution at or above the advisory fix levels, or a deliberately reviewed replacement parser;
3. preserve the current pre-materialization import-size guard from #232;
4. run the real XLSX import path against representative workbooks, including current trip-import UNKNOWN-vs-zero/date/deduplication protections;
5. retain the bundled-vendor/offline regression or replace it with an equivalent test for the new parser;
6. run the repository full suite and security gates;
7. regenerate governed release/cache markers because the deployed vendor asset changes, then verify production parity and installed-PWA delivery.

## Decision

**RESOLVED 2026-09-27 — SheetJS CE 0.20.3 deployed and verified.**

PR #395 merged the reviewed official SheetJS CE **0.20.3** standalone browser bundle and advanced the coherent app/cache generation to **v24.0.47**. DB remains 16 and Worker source remains v30.

Verification:
- authorized-PC candidate full suite: **906 passed / 0 failed across 89 specs**;
- exact PR-head Tests, Lanes, and CodeQL: PASS;
- exact-main Tests and CodeQL on merge commit `db35cf3cc30becaa2c9def05228e58aa9469be7e`: PASS;
- Production Service Worker: PASS (run 36296068967);
- settled Live Parity: PASS on rerun attempt 2 (run 36296068917);
- production-served vendor asset: **951,904 bytes**, SHA-256 `cc015130aa8521e7f088f88898eba949ccdcbfb38df0bd129b44b7273c3a6f41`, and self-reported `XLSX.version === "0.20.3"`.

Compatibility evidence recorded on #392 covers the real FreightLogic XLSX and legacy XLS import paths, realistic Excel date serials, UNKNOWN deadhead preservation, payment-state handling, and duplicate protection. No FreightLogic-specific exploit was required or claimed.
