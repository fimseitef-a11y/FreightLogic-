# Issue #392 — GPT → Claude vendor remediation handoff

## Verified current state

- Main reviewed: `55b1bdf21b622475fc9b6eabaed31cbabe397692`.
- Current vendored artifact: `vendor/xlsx.full.min.js`, blob `16e013fceefc689cabc5be352099199847a0e67f`.
- Bundle self-declares SheetJS `0.18.5`.
- GitHub-reviewed advisory ranges cover this version:
  - CVE-2023-30533 / GHSA-4r6h-8v6p-xvw6: `xlsx < 0.19.3`;
  - CVE-2024-22363 / GHSA-5pgg-2g8v-p4x9: `xlsx < 0.20.2`.
- Workbook parser reachability is confirmed through the operator XLSX import path. Issue #232 documented `file.arrayBuffer()` -> `XLSX.read(...)`; the size-guard repair retained parsing. v24.0.43 commit `1c9d536` confirms XLSX still shares the trip-import branch.
- Current `tests/integration/xlsx-bundled-vendor.spec.mjs` exercises the local bundle's read/write parser offline and remains registered.
- GPT report-only reconciliation is PR #391. No runtime/vendor/test/release byte changed there.

## Owner action

Issue #392 is intentionally Claude-owned because `vendor/`, runtime import code, tests, and release generation are outside GPT's lane.

Preserve:
- offline-first XLSX import;
- #232 pre-materialization size guard;
- UNKNOWN-vs-zero/date/payment/dedupe import semantics;
- current full release/security gates.

Do not solve this by adding an unpinned runtime CDN dependency.

Any vendor-byte replacement needs a coherent next app/SW/cache generation and post-deploy parity. DB16 / Worker30 stay unchanged unless another independent requirement says otherwise.

No exploit claim is made; the security conclusion is version applicability + parser reachability, not demonstrated exploitation.

## PC compatibility evidence

Authorized shared PC session completed a reversible compatibility probe against the official SheetJS CE 0.20.3 standalone bundle.

Candidate:
- URL: https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js
- bytes: 951904
- SHA-256: cc015130aa8521e7f088f88898eba949ccdcbfb38df0bd129b44b7273c3a6f41
- runtime XLSX.version: 0.20.3

Existing regressions with temporary substitution:
- tests/integration/xlsx-bundled-vendor.spec.mjs PASS
- tests/integration/trip-import-integrity.spec.mjs PASS
- tests/unit/service-worker-shell.spec.mjs PASS

Scratch-only real application probe also PASS:
- actual .xlsx importFile() path
- M/D/YYYY dates normalized correctly
- pay / loaded miles preserved
- blank deadhead stayed null / UNKNOWN
- Paid stayed known true
- importing the same workbook twice produced one trip (dedupe preserved)

The original 0.18.5 vendor file was restored byte-for-byte after every probe:
SHA-256 before/after c9506197caf809a075b6dee1da0d36fb19da7158ffe8a88e7b0c96c5d8623c99.

Local release-generation could not run because this PC has no Git executable available. Do not treat that environment failure as a candidate failure; run normal exact-head release gates in the owner lane.

Official SheetJS docs identify 0.20.3 as the current CE release, recommend vendoring it, and retain Apache-2.0 licensing. Use 0.20.3 as the first migration candidate.

Additional compatibility:
- Realistic Excel serial/date-format cells are identical under 0.18.5 and 0.20.3 (46276 -> 9/11/2026 -> FreightLogic 2026-09-11).
- Synthetic JS Date midnight-UTC cells show the same local-date shift under both versions, so that is not a 0.20.3 regression.
- Legacy BIFF8 .xls actual FreightLogic import path PASS under both versions; pickup/pay/loaded/UNKNOWN deadhead semantics matched.
