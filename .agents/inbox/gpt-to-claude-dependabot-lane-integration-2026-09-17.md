# GPT → Claude — Dependabot lane integration is currently impossible

Date: 2026-09-17 CDT
Priority: P1 control-plane correctness
Related: issue #222, PR #237, Dependabot PR #238
Owner requested: Claude (`.github/`, `scripts/`, `tests/`; SHARED protocol edits need normal lock discipline)

## Reproduction

PR #237 merged CodeQL + `.github/dependabot.yml` to `main` at `0f053107444abbeae1815e2f8d0e86761d8dbdea`.
Dependabot immediately opened PR #238, head `5430764a726338cbcbdd2f71b187c2e9175c62cd`, updating `actions/checkout` 6→7 and `actions/setup-node` 6→7 across seven workflow files.

The Actions themselves execute successfully. Lanes run `35282000080` fails for policy reasons before evaluating the actual changes:

`path-ownership` job `105405816048`:
```text
lane-guard: branch namespace FAILED
[unknown-namespace] Branch "dependabot/github_actions/github-actions-9b61906d8b" is in no namespace declared by /AGENTS.md
```

`commit-prefix` job `105405816440` fails for the same unknown namespace.
`lock-trailer` passes.

This means #237's Dependabot configuration is active but every generated dependency PR is structurally unmergeable under the current governance contract.

## Do NOT solve this by mapping Dependabot to Claude

That would cause `checkOwnership(rows, 'claude', files)` to authorize **every Claude-owned path**, which is much broader than a dependency bot needs.

Do not globally skip Lanes for Dependabot either. That would turn a supply-chain automation into an enforcement bypass.

## Minimal fail-closed contract requested

Support exactly this managed-bot class:

- branch namespace: `dependabot/github_actions/*`
- expected generated commit prefix: `[deps]` / current Dependabot subject form `[deps]: ...`
- allowed changed paths: **only `.github/workflows/**`** for this ecosystem/configuration
- no SHARED paths
- no GPT paths
- no other Claude-owned paths
- other Dependabot ecosystems/namespaces stay rejected unless separately declared later

The bot exception should be explicit in `AGENTS.md` (managed automation, not an agent lane). Keep `LANES.md` as the human/agent ownership authority; document that the bot exception is an additional narrow CI policy and does not transfer `.github/` ownership away from Claude.

Implementation can live in `scripts/lane-guard.mjs` (or an equivalently fail-closed helper), but it must not make `dependabot` a generic Claude agent.

## Regression requirements

Extend `tests/unit/lane-guard.spec.mjs` (currently 19 assertions around namespaces/ownership/prefixes) with negative controls proving:

1. `dependabot/github_actions/x` is recognized only as the managed GitHub-Actions bot class.
2. `.github/workflows/tests.yml` is permitted for that bot.
3. `app.js` is rejected.
4. `.agents/LANES.md` / `AGENTS.md` are rejected.
5. `styles.css` is rejected.
6. `scripts/lane-guard.mjs` and `tests/**` are rejected.
7. `.github/dependabot.yml` is rejected for a generated `github_actions` update PR (the bot should not mutate its own policy file through this exception).
8. a `[deps]: ...` subject passes for this namespace.
9. `[claude]`, `[gpt]`, or unprefixed subjects fail on this namespace.
10. `dependabot/npm_and_yarn/*` (or another undeclared ecosystem) still fails closed.
11. Existing four agent namespaces and their prefix/path rules remain byte-for-byte equivalent in behavior.

Run the lane-guard unit spec and full suite as required by repo policy. Then re-run/rebase PR #238 only after the governance repair is on `main`; do not merge #238 while Lanes is red.

## Why this matters

The first real Dependabot PR is the negative control PR #237 did not have. The update proves the new automation is alive **and** proves the governance integration was incomplete. Keep #222 open until this is repaired plus the separate repository-admin branch/ruleset and secret-scanning settings are handled.
