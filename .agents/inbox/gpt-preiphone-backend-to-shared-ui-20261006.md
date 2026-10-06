# Pre-iPhone shared UI handoff — 2026-10-06

Owner target: current `.agents/locks/preiphone-final.lock` holder.

A non-overlapping backend/test lane is published as draft PR #468 on branch
`chatgpt/preiphone-document-worker-20261006`.

Current backend head observed during this handoff: `bf8f387b7277fa01bfaf8d52025b3460f4061515`.
Do not copy this SHA blindly; refresh PR #468 before integration.

## Document Review Import contract

- Authenticated endpoint: `POST /document/extract`.
- Request: JSON/base64 with `name`, `mime`, `file`.
- Allowed: PDF, JPEG, PNG, WebP, text/plain.
- 4 MiB source limit; MIME/magic mismatch fails closed.
- PDF returns `embedded-pdf-text` via Workers AI Markdown Conversion, output format text, PDF metadata excluded.
- Images return `image-ocr` using an explicit OCR-only prompt.
- Text/plain is decoded locally.
- Worker stores nothing and performs no Business/Personal/category decision.
- Text-empty scanned PDF returns 422 + `needsOcrFallback:true`; do not report an empty successful import.

Review Import must:
1. hash/source-track the selected document locally;
2. parse transaction candidates deterministically;
3. preserve source line/provenance and confidence;
4. compare against existing typed records and flag possible duplicates;
5. default ambiguous or duplicate rows to review/ignore;
6. present Business / Personal / Ignore plus category/date/amount/description corrections;
7. call existing typed writers only for rows explicitly approved as Business;
8. require a second confirmation for possible duplicates;
9. never convert an unknown amount/date into zero/a guessed date.

`agent-runtime/document-roles.mjs` defines Extraction, Reconciliation,
Classification, QA/Audit as advisory-only. None can write canonical data.

## Google Drive contract

Use only `https://www.googleapis.com/auth/drive.appdata` and the hidden
`appDataFolder`. No Gmail, no broad `drive` scope.

- Google access token stays session-memory only; never IndexedDB/settings/export/Airtable.
- OAuth/token request must be user-gesture initiated.
- Upload ONLY the already-encrypted FreightLogic backup envelope.
- Restore downloads the blob with Drive files.get `alt=media`, decrypts locally,
  and requires explicit restore confirmation before existing merge logic runs.
- OAuth client registration/consent remains an external/manual gate if no
  configured client exists; never fake a Connected state.

## Coordination

Do not overwrite PR #468 Worker/agent-role/test files without reconciling its
latest head. Shared UI/release marker files remain exclusively under your
preiphone-final lock.
