Offline vendor notes
====================

Current hardened Excel/XLSX import behavior:

- FreightLogic ships its required SheetJS runtime in `vendor/xlsx.full.min.js`.
- The bundled file is part of the install-critical offline shell.
- Excel/XLSX import does NOT fall back to a CDN when the bundled file is missing.
- The repository currently includes the bundled SheetJS file and its license.

Historical OCR dependency notes:

Older FreightLogic documentation referenced these Tesseract assets for optional OCR experiments:

- tesseract.min.js — tesseract.js@5.1.1/dist/tesseract.min.js
- worker.min.js — tesseract.js@5.1.1/dist/worker.min.js
- tesseract-core-simd-lstm.wasm.js — tesseract.js-core@5.1.0/tesseract-core-simd-lstm.wasm.js

Those files are not present in the current `vendor/` directory.

As of Issue #220 there is NO CDN fallback for OCR, and `cdn.jsdelivr.net` is no
longer permitted by the Content-Security-Policy at all. `loadTesseract()` loads
the three files above from `vendor/` or returns null, and the two OCR entry
points (receipt camera scan, load-screenshot Quick Evaluate) say OCR is not
installed rather than failing obscurely. Paste and typed intake are unaffected (voice
intake was removed in v24.0.17 by operator decision, Issue #230).

Removing the fallback took away nothing that worked. The shipped CSP could never
have completed the CDN path: `connect-src` does not allow
`tessdata.projectnaptha.com`, where tesseract.js must fetch its English model,
and `worker-src 'self' blob:` forbids a cross-origin worker. Both are proved
from real CSP violation events in `tests/integration/ocr-self-hosted.spec.mjs`
(OCR-01/02). What the fallback COULD do was execute unpinned third-party
JavaScript in the FreightLogic origin, with the same access to IndexedDB as the
operator's trips, expenses, receipts and stored cloud credential.

To enable OCR, drop all three files into `vendor/` — no code change is needed.
They are deliberately not committed: together they are roughly 15 MB (engine
~66 KB, worker ~124 KB, SIMD LSTM core ~3.9 MB, and the English model
`eng.traineddata.gz` ~10.9 MB, which must also be self-hosted via `langPath`
since the CSP allows no third-party origin). Committing that much third-party
binary to a flat-file repository whose service worker precaches its assets is an
operator decision, not a side effect of a security fix. Anything added must be
version-reviewed, licensed in `vendor/`, and added to the deploy-asset inventory
(`scripts/lib/deploy-assets.mjs`) so the parity gate sweeps it.

Core FreightLogic functionality remains offline-first.
