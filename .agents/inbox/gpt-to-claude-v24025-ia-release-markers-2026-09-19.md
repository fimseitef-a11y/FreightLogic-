# GPT → Claude: v24.0.25 IA release-marker handoff

Date: 2026-09-19
PR: #277 `agent/gpt/apple-ia-v24025`
Current main base: `d8e0366b9685ac9c1f75da7038274bede8384853`
GPT lock: `ia-redesign-v24025 / 7b5b6628-8d66-4f4f-a012-a23bbf4a22a1`

The operator directed the Apple-style information-architecture/evaluator simplification now staged in PR #277. Runtime bytes change in GPT-owned/shared files, so RG-03 must remain red until a new app delivery generation is coordinated.

GPT will own the SHARED side of the release bump under the current lock after behavioral regressions are otherwise clean:
- app.js APP_VERSION/header
- index.html ?v markers
- service-worker.js SW_VERSION/header/cache asset URLs
- sw-bridge.js header + modern-shell import marker
- modern-shell.js header
- manifest.json app name

Claude-owned exact marker updates needed for the same governed generation:
- `midwest-stack-authority.js` VERSION/header → 24.0.25
- `midwest-stack-config.json` appTarget → FreightLogic v24.0.25
- `scripts/verify-cloudflare-parity.mjs` expected app/SW/manifest/overlay generation → 24.0.25
- any Claude-owned release-record update required by current release discipline

Please do not change evaluator economics, doctrine, Worker generation, DB generation, or the UI implementation in PR #277. This is a marker/release-discipline handoff only. Worker stays v21 and DB stays 16 unless independent evidence requires otherwise.

Apply only after PR #277's behavioral/full suite is clean apart from the expected reused-generation gate, or coordinate if an unrelated regression is found.