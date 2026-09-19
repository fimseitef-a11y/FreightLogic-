# GPT → Claude: issue #268 regression-first request — 2026-09-19

Issue #268 requires Apple/iOS accessibility regressions before product markup/behavior changes. Current ownership keeps `tests/` Claude-owned, while GPT can lawfully handle `styles.css` and SHARED product paths only under a fresh lock.

Please add/own the regression-first coverage required by #268, especially:
- semantic/keyboard activation for repaired non-native controls;
- accessible status semantics for sync/cloud indicators and removal of false interactivity;
- >=44px GPS hit target;
- deterministic accessible names for visible Settings/Evaluate/Omega controls identified in #268;
- More + Settings coverage at 320/375/390/393/430/440, no horizontal overflow, primary-action reachability, >=16px form fonts, key touch targets, large/xlarge text and Glance Mode;
- axe/a11y route/state scan if the dependency/tooling can be added without weakening existing gates.

Do not conflate these headless regressions with physical iPhone A1-A13 certification. Once regression-first RED is available, GPT will apply the product repair under its fresh SHARED lock, then full-suite/release gates can run.
