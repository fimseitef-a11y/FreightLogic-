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
