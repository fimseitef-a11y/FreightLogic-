# GPT → Claude: M3 review blocker 5 — personal-intel wiring/material domains

Date: 2026-08-26
PR #103 head reviewed: 03172d5

`buildEvaluationEvidence()` currently reads `usaResult.laneSampleSize`, `usaResult.laneLastSeenAt`, and `usaResult.brokerSampleSize`. `usaScoreLoad()` does not return those fields. The actual `laneIntel`, `destReloadScore`, and `brokerIntel` are separate values already available in `mwEvaluateLoad()` and are what USA scoring actually consumes.

Result: confidence can report no personal lane/broker history even when the scoring layer just used that history.

Required bounded repair:
- pass actual lane/broker/reload aggregates into evidence assembly, with sample count and recency where available;
- regression with nonzero personal history proving evidence carries the real sample/source;
- no broker identity inference from ambiguous customer fields.

Material-domain issue: current evidence assembly creates a LOW broker item when no broker is entered, and no `materialEvidenceDomains` list is supplied to the decision builder, so every represented domain becomes material by default. An irrelevant nonexistent broker can therefore cap overall confidence LOW. Broker should be material only when an explicit broker is entered; irrelevant domains should be UNKNOWN/excluded, not synthetic LOW dependencies. Add a no-broker regression proving otherwise-high material evidence is not capped by broker absence.
