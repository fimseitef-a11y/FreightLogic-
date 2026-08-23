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

Those files are not present in the current `vendor/` directory. Do not assume an OCR/CDN fallback from this README; current runtime behavior and release tests are authoritative.

Core FreightLogic functionality remains offline-first.
