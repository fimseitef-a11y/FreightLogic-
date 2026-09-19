# GPT → Claude — privacy-safe live /extract-image smoke

Issue #252 still has one production-evidence gap: current authenticated smoke proves driver auth/backup/invite/claim, but it never exercises the new Worker v21 `POST /extract-image` path.

Do **not** solve this by putting operator screenshots into GitHub Actions.

## Add one synthetic provider-path check to the existing Claude-owned workflow

Target:
`.github/workflows/verify-authenticated-worker.yml`

Reuse the workflow's existing short-lived synthetic `TOKEN`, `USER_ID`, cleanup trap and `WORKER_ORIGIN`.

After the synthetic identity is visible, POST a harmless valid PNG to `/extract-image`:

- `Content-Type: application/json`
- `X-Backup-Token: $TOKEN`
- `X-Device-Id: fl-cert-vision`
- body:
  - `mime: "image/png"`
  - `image: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl2WQAAAABJRU5ErkJggg=="`

This is a 1×1 synthetic PNG with no operator data. It is deliberately **not** an OCR-quality benchmark.

## Expected contract

The purpose is to prove the configured live provider path is reachable:

- **200** is acceptable if the provider returns a normalized observation.
- **422** is also acceptable for a blank image because the normalizer correctly fails closed when no useful load fields are present.
- **501 is a failure** — provider/binding is not configured.
- **502 is a failure** — provider execution failed.
- 401/403 is a failure of synthetic driver auth.
- any unexpected 5xx is a failure.

For both 200 and 422, require the JSON body to name a non-empty `provider` and `model`; with the current default it should identify the configured Workers AI path. Do not assert invented field values from a blank image.

Write a concise result to `GITHUB_STEP_SUMMARY` without printing the synthetic driver token.

## What this proves — and what it does not

It proves:
- Worker v21 image endpoint is live under driver auth;
- Workers AI/provider binding is present;
- provider invocation succeeds far enough to reach normalization;
- blank/non-useful imagery fails closed rather than creating a fake load.

It does **not** prove real DispatchLand screenshot OCR accuracy. Keep the real/sanitized screenshot quality benchmark separate and operator-controlled; do not put private freight screenshots in CI.

This can run alongside the Admin Console and v24.0.22 integration work; it uses only the existing privileged smoke workflow and no operator credential.
