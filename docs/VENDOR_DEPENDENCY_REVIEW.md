# Vendored Dependency Review — SheetJS

**Review date:** 2026-09-23  
**Scope:** report only; no `vendor/` files changed.

## Inventory

FreightLogic currently vendors `vendor/xlsx.full.min.js` (881,727 bytes on the reviewed `main`). The repository does not manage this copy through npm, so `npm audit` is not an authoritative inventory check for this vendored asset.

The queue identifies the vendored copy as SheetJS CE / `xlsx` 0.18.5. This review does **not** claim a version from filename inspection alone; the version should be re-confirmed from the vendored artifact/provenance before any replacement release.

## Advisory status

If the vendored file is SheetJS CE 0.18.5, it falls within two known advisory ranges:

- **CVE-2023-30533 / GHSA-4r6h-8v6p-xvw6 — prototype pollution.** Affected versions are below 0.19.3. The vulnerable operation is reading a specially crafted workbook; export-only workflows are not affected by this issue.
- **CVE-2024-22363 / GHSA-5pgg-2g8v-p4x9 — regular-expression denial of service.** The affected 0.18.5 line is below the 0.20.2 fix level described by the SheetJS advisory ecosystem.

The maintained SheetJS CE releases after 0.18.5 are not represented by a newer npm `xlsx` release, so blindly running `npm update` is not a remediation for a vendored 0.18.5 browser bundle.

## FreightLogic reachability

Repository code search on the reviewed `main` did not return an indexed `XLSX.read` call. That is useful evidence but **not sufficient to declare the parser unreachable**: the minified vendor bundle itself is large, code search can miss dynamically constructed/global calls, and browser execution paths need runtime confirmation.

Accordingly, the current classification is:

- dependency advisory: **confirmed applicable if provenance confirms 0.18.5**;
- exploit reachability in FreightLogic: **not yet proven**;
- safe-to-ignore/waive: **not established**.

## Required remediation gate

Do not edit `vendor/` as part of this report. Any dependency replacement belongs to the Claude-owned vendor/release lane and should:

1. confirm the exact vendored SheetJS version and source provenance;
2. enumerate every runtime import/use of the global `XLSX` API, distinguishing read/parse from export-only use;
3. if untrusted workbook parsing is reachable, treat replacement as security-relevant rather than waiving the advisory;
4. choose and pin a maintained distribution or replacement deliberately instead of silently substituting an npm package;
5. run import/export regressions appropriate to the actual call paths plus the repository full release gates;
6. regenerate governed release/cache markers if the deployed vendor asset changes, and verify production parity afterward.

## Decision

**OPEN — vendor owner action required.** This report does not modify the dependency and does not claim FreightLogic is exploitable. It records that a confirmed 0.18.5 artifact would be inside known vulnerable ranges and that reachability must be established before either remediation or a documented waiver.
