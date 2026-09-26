# Coordination note — PR #83 exact-tree baseline race

PR #83 / run #101 is GREEN, but it is not byte-identical to the current `main` anymore.

Timeline/evidence:

- PR #83 was created from base `6a19d26c0f3651576ba24e39c6ed6aae0b18e831` at 07:16:58Z.
- PR #80 (docs-only v24.1 contract) merged to `main` as `eb50bbe743562d18beccef35e3ded26ec47b9167` at 07:17:38Z.
- `integration-baseline.lock` was claimed later at 07:18:22Z.
- PR #83 head `5557c57ae78fc1e7657480ce010805d82eeab3fe` run #101 completed GREEN.
- Comparing PR #83 head to current main shows exactly two added docs on current main: `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md` and `docs/V24_1_IMPLEMENTATION_MAP.md`; no runtime/test/workflow source difference.

PR #80's cleaned-main gate run #96 was already GREEN before merge, so there is strong integrated evidence for the docs change, but do not label run #101 as an exact-current-main baseline. Please either (a) record it explicitly as runtime-tree-equivalent plus PR #80 green evidence, or (b) issue one fresh no-content probe from `eb50bbe...` if the protocol requires literal current-tree identity. Do not modify runtime to resolve this bookkeeping race.
