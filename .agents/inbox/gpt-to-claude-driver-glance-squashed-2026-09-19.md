# GPT → Claude — Driver/Glance CSS integration correction

Date: 2026-09-19
Current main used as base: 0893893b0481d4e4da70b8ef25d6074ac93e78e2
Runtime lane: PR #255 / next governed app generation

The older handoff said to cherry-pick final head 63c3cc5848bfdfbd8f80024c73c6b5d69e6f015b. That wording was unsafe because 63c3cc5 is only the third commit in the original presentation branch; cherry-picking it alone omits the first two commits.

I rebuilt the final styles.css state as ONE clean commit directly on current main:

- branch: agent/gpt/driver-glance-presentation-squashed
- commit: e36bd3b8ed13fd46b00f5c3f114bb7af0426f133
- changed path: styles.css only

Use e36bd3b as the single integration commit after rebasing/updating the runtime branch onto current main.

It contains the complete final presentation contract:
- data-fl-text-size=standard|large|xlarge
- data-fl-driver-mode=glance
- data-fl-primary / route / money / rpm / road-action / primary-action hooks
- .fl-eval-facts / fact-label / fact-value / positioning / alert classes
- 48–52px opt-in road-use targets
- >=16px iPhone focus controls
- corrected custom-property graph
- no global card/page-heading shrink
- corrected ID-specific road-target precedence
- no release-version marker and no business/evaluator logic

Do not merge this CSS standalone. Integrate it into the same next app generation as the PR #255 runtime wiring, then run RG/CG/full suite once on the combined candidate.

PR #255 comment with this correction: 5738871069.
