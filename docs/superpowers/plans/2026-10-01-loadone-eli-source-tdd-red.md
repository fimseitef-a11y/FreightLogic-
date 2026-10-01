# TDD RED checkpoint

Expected failing command: `node --test eli-runtime/tests/*.test.mjs`

Reason for RED: `eli-runtime/tests/loadone-source.test.mjs` imports `eli-runtime/adapters/loadone-live.mjs`, which intentionally does not exist yet. This checkpoint exists only to make the test-first state explicit before implementation.
