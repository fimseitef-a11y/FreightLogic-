# P0 handoff — screenshot OCR -> canonical Load Evaluator

**Operator priority:** immediate / P0.
**GitHub authority:** Issue #252.
**Source state when raised:** main 54e36f25491928e23453f5e2244d9e1ca596eada, v24.0.20.
**Concurrency:** do not interrupt the current claude-onboarding-exposure lock. Start #252 in the next safe Claude runtime lane after that repair releases its protected paths.

## Operator intent

FreightLogic should feel like the ChatGPT interaction the operator just used: paste/share a DispatchLand screenshot, wait briefly, then have the load evaluator already populated and ready with the canonical FreightLogic decision.

The phone should not perform heavyweight OCR. The image should go through the existing FreightLogic Worker; server-side vision/OCR returns structured observational fields; the operator reviews uncertainty; the existing canonical evaluator runs unchanged.

## Existing architecture verified

- Unified Load Intake and Evaluate/OMEGA already exist.
- app.js is sole canonical authority for True RPM, economics, grade/verdict, bid range, UNKNOWN deadhead, feasibility, and persistence.
- cloud-backup-worker.js /extract is text-only and currently uses OpenAI.
- browser Tesseract remote fallback was removed for security (#220); vendor/ has no Tesseract.
- keep provider keys server-side. Do not add a browser-visible key or reopen third-party script CSP.

## Required implementation shape

image -> same-origin Worker /extract-image -> provider adapter -> strict normalized extraction result with confidence/provenance -> compact review -> existing Load Intake object -> existing canonical evaluator.

No second evaluator. No AI-owned math. Missing deadhead must remain UNKNOWN.

Support iPhone-reliable image file/Photos/share path plus clipboard-image paste where platform support permits. Do not depend on clipboard image APIs as the only path.

## Provider facts checked 2026-09-18

1. Cloudflare Workers AI has a 10,000-neuron/day free allocation and supports vision models. It fits the current Worker architecture with the least provider plumbing.
2. Gemini 2.5 Flash / Flash-Lite free tier accepts images and supports structured JSON outputs; free-tier submissions are eligible for product improvement, so expose that privacy tradeoff before selecting it for real freight screenshots.
3. DeepSeek's official hosted API is **not free**; it is token-priced. The DeepSeek consumer app may be free, but that does not provide a free production API for FreightLogic.
4. DeepSeek-OCR/OCR2 are open-source and free software, but official examples require GPU/CUDA-style self-hosting; not suitable for running inside the iPhone/PWA or a normal Cloudflare Worker.

Recommendation: provider abstraction, benchmark sanitized screenshot fixtures. Prefer Cloudflare Workers AI as zero-cost operational default if accuracy clears the corpus; Gemini free tier is the quality benchmark/fallback. Keep DeepSeek pluggable if operator later supplies an API/grant or self-hosted endpoint.

## Acceptance

Use Issue #252 verbatim for field contract, test corpus, UX, privacy, authority, and done criteria. Full suite required for app.js changes; exact-head/live gates after integration; physical iPhone flow must cover screenshot -> extraction -> review -> evaluation.

GPT will stay out of Claude-owned/locked runtime paths and can independently review the implementation once a PR exists.
