# GPT v24.0.22 SHARED runtime patch plan — exact continuation checkpoint

Date: 2026-09-19
Current integration PR: #260
Current head at plan write: d25902ac2793c3b269fd2ca76d7c9f3fe3de4741
Current main: 74f068345e9db1c7675a71f9b5aa58353aaa1b10

DO NOT RESTART. Non-SHARED integration is already staged on PR #260:
- final Driver/Glance styles.css contract;
- screenshot decision-first regressions SSI-14..18;
- strengthened provenance negative control (bans strong reload market language too);
- DD-01..04 Driver/Glance preference regression registered in run-all;
- midwest-stack-config / authority / parity expectations at 24.0.22;
- CLAUDE.md candidate record.

The only remaining implementation is in the still-live Claude lock:
app.js, index.html, service-worker.js, sw-bridge.js, manifest.json, modern-shell.js.

Required SHARED changes, once the lock is released/expired+reaped:

1. app.js
- APP_VERSION -> 24.0.22; DB_VERSION stays 16.
- Preserve all current 24.0.21 screenshot/OCR and onboarding-exposure behavior.
- Add device-local display preference normalization:
  - localStorage key fl_text_size: only standard|large|xlarge, default standard.
  - localStorage key fl_driver_mode: only glance enables mode; anything else is off.
  - always apply data-fl-text-size on <html>; apply/remove data-fl-driver-mode="glance".
  - controls must apply immediately and survive reload.
- Bind Settings controls #driverTextSize and #driverGlanceMode without creating a second settings/evaluator pipeline.
- Integrate PR #255 decision-first facts into _mwRenderDecision, but use semantic CSS hooks:
  .fl-eval-facts, .fl-eval-fact-label, .fl-eval-fact-value, .fl-eval-positioning, .fl-eval-alert, [data-fl-rpm].
- Positioning copy must identify static doctrine context, e.g. "Tier 1 — static market class", never imply measured live reload strength.
- _genVerdictSentence must also stop saying "strong reload market ahead" from static tier membership. Use economics/static-density wording instead (e.g. premium economics / Tier 1 density ahead), so SSI-17 cannot be bypassed by the hero sentence.
- Explicit zero deadhead must remain 0; unknown deadhead remains blocked/blank per existing authority.

2. index.html
- Add the display controls in the ALWAYS-VISIBLE Settings area, after the three essential settings and BEFORE #advSettingsToggle. Do NOT place them inside the existing "App" subsection, because that subsection lives inside collapsed #advSettingsBody and DD-01 intentionally requires these road-use preferences to be immediately visible.
  - #driverTextSize select with exactly standard, large, xlarge (labels Standard, Large, Extra Large).
  - #driverGlanceMode checkbox.
  - A compact "Driver display" label/helper is fine; preserve one-handed layout and >=16px focused control text on iPhone.
- Advance governed app/sw asset query markers from 24.0.21 to 24.0.22 wherever release-generation discipline requires.
- Preserve current CSP and all existing IDs/routes.

3. service-worker.js
- Header + SW_VERSION -> 24.0.22.
- Advance all governed ?v=24.0.21 asset strings to 24.0.22.
- Cache generation becomes freightlogic-24.0.22; no DB or Worker generation change.

4. sw-bridge.js
- Header -> 24.0.22.
- modern-shell import query -> 24.0.22.

5. modern-shell.js
- Header generation -> 24.0.22 only; preserve current five-surface navigation behavior.

6. manifest.json
- name -> FreightLogic v24.0.22; preserve all capabilities/shortcuts.

Verification after SHARED patch:
- run exact-head full suite; do not weaken DD/SSI/RG/CG assertions.
- RG/CG must be green.
- mark PR #260 ready only when Lanes + CodeQL + Tests all pass.
- merge exact head, then re-dispatch live parity + production SW after Cloudflare propagation; push-triggered early failures are not evidence.
- physical A1–A13 and M6 remain separate final evidence gates.

Current coordination constraint:
claude-p0-screenshot-ocr.lock token b0bbdd8f-cba3-4523-b2a5-4ef0440610e1 remains time-valid through 2026-09-19T06:22:43Z. GPT requested release in gpt-to-claude-release-runtime-lock-2026-09-19.md and will not cross it while valid.
