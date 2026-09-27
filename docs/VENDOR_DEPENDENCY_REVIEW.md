# Vendored Dependency Review — SheetJS

**Status:** RESOLVED  
**Resolution date:** 2026-09-27  
**Verified main:** `db35cf3cc30becaa2c9def05228e58aa9469be7e`  
**Release:** FreightLogic v24.0.47 / DB16 / Worker30

## Resolution

PR #395 replaced the offline vendored parser at `vendor/xlsx.full.min.js` from SheetJS CE **0.18.5** with the reviewed official SheetJS CE **0.20.3** standalone browser bundle.

Resolved artifact:

- SheetJS runtime declaration: **0.20.3**
- repository blob: `21471af69ef0e4cda1613c2702c54101b92f48d2`
- source/live bytes: **951,904**
- SHA-256: `cc015130aa8521e7f088f88898eba949ccdcbfb38df0bd129b44b7273c3a6f41`
- delivery model: vendored locally; no runtime CDN dependency

A direct production fetch from `/vendor/xlsx.full.min.js` after deployment returned the same byte count and SHA-256 and declared `version="0.20.3"`.

## Why remediation was required

The superseded SheetJS CE 0.18.5 artifact was inside both GitHub-reviewed affected ranges:

- **CVE-2023-30533 / GHSA-4r6h-8v6p-xvw6 — prototype pollution:** `xlsx < 0.19.3`
  - https://github.com/advisories/GHSA-4r6h-8v6p-xvw6
- **CVE-2024-22363 / GHSA-5pgg-2g8v-p4x9 — regular-expression denial of service:** `xlsx < 0.20.2`
  - https://github.com/advisories/GHSA-5pgg-2g8v-p4x9

FreightLogic's XLSX parser is operator-triggered rather than automatic, but workbook-controlled bytes do reach `XLSX.read(...)`. The old parser was therefore reachable and was not eligible for a safe-to-ignore waiver.

SheetJS CE 0.20.3 is above both affected ranges.

## Compatibility and data-integrity evidence

Before integration, the authorized PC ran reversible substitutions of the official 0.20.3 bundle and restored the 0.18.5 vendor bytes after each probe.

The candidate passed:

- the existing offline bundled-vendor browser regression;
- the v24.0.43 trip-import integrity regression;
- the service-worker shell regression;
- an actual FreightLogic `.xlsx` import through the application import path;
- an actual legacy BIFF8 `.xls` import;
- duplicate re-import protection;
- M/D/YYYY and realistic Excel serial/date-format normalization;
- payment-status preservation;
- loaded-mile/pay preservation;
- blank deadhead remaining `null` / **UNKNOWN**, including the expected review reason.

A synthetic JavaScript `Date` at midnight UTC showed the same local-calendar shift under 0.18.5 and 0.20.3 in America/Chicago. The realistic Excel serial/date-format path produced identical dates under both versions, so that synthetic behavior was not a migration regression.

## Release and production evidence

Integrated PR #395 head `5f79cc001b031d8bab7ad2fe0322d534d638c1cd`:

- all 13 changed GitHub blob SHAs matched the PC-certified candidate tree;
- local exact-tree release-generation verifier: **PASS**;
- local static Cloudflare parity: **PASS**;
- local full suite: **906 passed / 0 failed across 89 spec files**;
- GitHub exact-head Tests: **906 / 0**;
- GitHub Lanes: **PASS**;
- GitHub CodeQL: **PASS**.

Merged main `db35cf3cc30becaa2c9def05228e58aa9469be7e`:

- exact-main Tests run `36296069001`: **906 / 0 across 89 specs**;
- CodeQL run `36296069048`: **PASS**;
- Production Service Worker run `36296068967`: **PASS**, current cache `freightlogic-24.0.47`, all 21 runtime assets present, exactly one generation cache survives;
- Verify Live Parity run `36296068917` attempt 2: **PASS**, app/SW/manifest v24.0.47, Worker30, all 21 runtime assets load;
- the initial parity attempt observed the prior v24.0.46 generation during deployment propagation and is retained as a deployment-race failure rather than relabelled as a pass.

The production service-worker verifier also confirmed activation, control after reload, offline subresource behavior, cached shell completeness, recovery when the network returns, and no stale generation cache. Physical iPhone offline-navigation certification remains a separate manual gate and is not claimed here.

## Decision

**RESOLVED — SheetJS CE 0.18.5 has been replaced by verified, production-served SheetJS CE 0.20.3.**

The prior advisory exposure and parser reachability remain documented as historical evidence. No FreightLogic-specific exploit was required or performed. Future vendored-parser upgrades should continue to preserve offline operation, pre-materialization size limits, UNKNOWN-vs-zero semantics, date/payment handling, deduplication, full-suite coverage, coherent app/SW cache generation, and production parity.
