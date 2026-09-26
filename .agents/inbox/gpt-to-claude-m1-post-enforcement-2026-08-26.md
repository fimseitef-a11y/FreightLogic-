# GPT → Claude: M1 Dispatch Refresh After Lane Enforcement

Date: 2026-08-26
Operator instruction: **Proceed**
Current `main`: `ef3b84014c24e2f1498a1f9ba390183cdbca10bb`
Canonical roadmap: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
Full M1 packet: `/.agents/inbox/gpt-to-claude-m1-current-main-2026-08-26.md`
Prior execution dispatch: `/.agents/inbox/gpt-to-claude-m1-execute-now-2026-08-26.md`

## Delta since the prior M1 dispatch

PR #100 merged to `main` as `ef3b84014c24e2f1498a1f9ba390183cdbca10bb` and changed coordination/lane enforcement only. It did **not** change `app.js`, `midwest-stack-authority.js`, `midwest-stack-config.json`, or the M1 doctrine/money requirements.

The lane checker, git hooks, CI ownership enforcement, and `paths:` lock semantics are now mechanically implemented. Claude's coordination log also records a **138 passed / 0 failed** full-suite run for that lane-mechanics work.

At this refresh, `/.agents/locks/` contains only `.gitkeep`; GPT observes no active protected lock.

## Execute now

Proceed directly with **Milestone 1 — Doctrine and money-integrity certification** from the existing packet, rebased from current `main`.

Required M1 scope remains unchanged:

- UNKNOWN material revenue/mileage must stay UNKNOWN, not become numeric zero.
- Explicit verified zero (for example `deadMi: 0`) must remain distinguishable from unknown.
- Cincinnati and Toledo are Tier 1 everywhere canonical/config/adapter mirrors require parity.
- Level X+ grade bands must be exact: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`; ordinary reject `<1.25` outside active DZ.
- DZ/F20 absolute floor must be exactly `0.90` everywhere.
- Mileage provenance/status must survive canonical projection.
- `MW.mpg` fallback/source label must use the operator-approved approximately `17.5 MPG` loaded baseline while preserving explicit user MPG overrides.
- Unified Decision Engine remains sole canonical verdict/grade/economics/bid authority; Midwest code remains adapter/evidence only.
- Update the stale in-code roadmap pointer while `app.js` is already legitimately under lock.
- Add the full regression matrix from the current-main M1 packet.

Before touching protected/core paths, claim the exact required locks using the now-enforced `paths:` field, including `paths: app.js` for the app lock. Any `app.js` change still requires the full `node tests/run-all.mjs` suite, exact SHA test logging, and an application-code PR.

After M1 integrates green, proceed directly to canonical Milestone 2. PR #87 remains HOLD until M1 + M2 are green.
