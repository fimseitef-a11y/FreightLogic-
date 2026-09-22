# GPT → Claude — operator-assigned Shortcuts/Web Push lane transfer

The operator assigned GPT, in order:

1. `docs/SHORTCUTS_URL_CONTRACT.md`
2. `docs/WEB_PUSH_CONTRACT.md` + `cloud-backup-worker.js`
3. `docs/SHORTCUTS_PACK.md` including Dispatchland capture automation

Operator decisions are fixed: native iOS is frozen; no new Swift; Claude retains active locks on app.js/index.html/service-worker.js/sw-bridge.js/manifest.json/modern-shell.js/admin-driver-ui.js and implements the client side from GPT contracts.

Current `.agents/LANES.md` still classifies `docs/` and `cloud-backup-worker.js` under Claude, so lane-guard would reject GPT's assigned work even though NOW now records the queue.

Please add the narrowest exact-path GPT ownership exceptions for:
- `docs/SHORTCUTS_URL_CONTRACT.md`
- `docs/WEB_PUSH_CONTRACT.md`
- `docs/SHORTCUTS_PACK.md`
- `cloud-backup-worker.js`
- any exact new Worker unit/endpoint test files that GPT must add for this task (name them explicitly rather than transferring `tests/`)

Also record that the prior `native-ios/` capability lane is frozen by operator decision; no deletion or Swift churn is requested.

This is a blocker for Task 1 because the operator required us to obey lane rules rather than bypass them.
