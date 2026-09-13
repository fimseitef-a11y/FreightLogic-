#!/usr/bin/env bash
# FreightLogic — guarded deploy for the BACKUP/API Worker (completion gate 2).
#
# Closes the gate that has held the completion release at HOLD since
# 2026-09-02: "deploy and observe Worker v14". Nothing here is automatic — the
# deploy requires an explicit --confirm, and every check below runs first.
#
# USAGE
#   scripts/deploy-backup-worker.sh             # preflight only, no deploy
#   scripts/deploy-backup-worker.sh --confirm   # preflight, then deploy
#   scripts/deploy-backup-worker.sh --verify    # post-deploy live checks only
#
# WHAT IS ACTUALLY DEPLOYED IN PRODUCTION RIGHT NOW: v7.
# Read from the Cloudflare control plane on 2026-09-12, not inferred from HTTP.
# The certification records describe the live Worker as "stale or otherwise not
# the current repository source" — it is SEVEN generations behind, and the gap
# is not cosmetic. Deployed v7 versus repository v14:
#
#   * v7 stores each driver bearer token in KV IN PLAINTEXT, both as the key
#     `token:<flk_...>` and inside the `user:<id>` record value.
#     v14 stores only a SHA-256 hash under `tokh:<hash>` and deletes the
#     plaintext copy on first use of each token.
#   * v7 `GET /admin/users` returns `JSON.parse(val)` for each user record —
#     the whole record, INCLUDING `token`. The admin listing hands back every
#     driver's live bearer token. v14 projects only
#     {userId, name, createdAt, active, backupCount}.
#   * v7 compares the admin token with `!==` (timing-variable) and has NO
#     per-IP rate limit on /admin/. v14 uses an HMAC timing-safe compare and
#     limits to 20/IP.
#   * v7 has no `flk_` token FORMAT validation before the KV lookup.
#   * v7 has NO `/health` route at all — it falls through to the driver-token
#     gate, which is the exact 401 the live probe recorded.
#   * v7 computes `env.ALLOWED_ORIGIN || '*'`; the probe observed `*`, proving
#     ALLOWED_ORIGIN is unset in production today.
#   * v7 has NO `GET /backup/delta`. Audit finding X-01 is LIVE: deltas are
#     written and can never be read back, so any delta pruned by the 20-key cap
#     or the 7-day TTL is already permanently lost.
#   * v7 `/evaluate` lets the MODEL own verdict and grade
#     (`validateVerdict(parsed.verdict)`, defaulting to PASS/C) and ignores the
#     client's `canonicalDecision` entirely. That is a live violation of the
#     v24.0 authority rule: the deployed Worker is a second decision authority.
#
# WHY THE UPGRADE IS SAFE (verified against the deployed v7 bytes, not assumed):
#   * Existing backups stay visible. v14 reads a pointer key, and `getPtr()`
#     lazily seeds that pointer from `env.BACKUPS.list({prefix})` on first call
#     (cloud-backup-worker.js:564-573), so v7's list-derived
#     `...:backup:<ts>` keys are found and adopted rather than orphaned.
#   * Existing tokens keep working. v14 reads `tokh:<hash>`, falls back to the
#     legacy `token:<plaintext>` key, migrates it to the hashed key, and deletes
#     the plaintext (cloud-backup-worker.js:165-181). v7 minted tokens as
#     `flk_` + 32 hex, which satisfies v14's `/^flk_[a-f0-9]{32}$/` gate.
#   * Existing user IDs keep working. v7 minted `u_` + 12 UUID chars (dashes
#     included); v14's admin validator is `/^u_[a-f0-9-]{8,36}$/i`, which
#     accepts them, and its delete path cleans up BOTH `tokh:` and legacy
#     `token:` keys.
#   * Secrets survive. ADMIN_TOKEN and OPENAI_API_KEY are service state, not
#     config state, and a `wrangler deploy` does not clear them.
#
# AFTER A SUCCESSFUL DEPLOY, the plaintext `token:` keys still in KV are
# residue: each is deleted only when that driver's token is next used, or when
# that user is revoked. Treat every driver token as exposed-at-rest until then
# and rotate on the operator's own schedule — see the note printed at the end.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/scripts/wrangler.backup-worker.jsonc"
WORKER_SRC="$REPO_ROOT/cloud-backup-worker.js"
APP_SERVICE="freightlogic-v2"
API_SERVICE="freightlogic-backup"
APP_ORIGIN="https://freightlogic-v2.fimseitef.workers.dev"
API_ORIGIN="https://freightlogic-backup.fimseitef.workers.dev"

MODE="preflight"
case "${1:-}" in
  --confirm) MODE="deploy" ;;
  --verify)  MODE="verify" ;;
  "")        MODE="preflight" ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

fail() { echo "  FAIL  $*" >&2; FAILED=1; }
pass() { echo "  ok    $*"; }
FAILED=0

if [ "$MODE" != "verify" ]; then
  echo "== Preflight: backup/API Worker deploy =="

  # 1. The config must exist and must name the API service, never the app one.
  [ -f "$CONFIG" ] || { echo "missing config: $CONFIG" >&2; exit 1; }
  if grep -q "\"name\"[[:space:]]*:[[:space:]]*\"$API_SERVICE\"" "$CONFIG"; then
    pass "config targets $API_SERVICE"
  else
    fail "config does not name $API_SERVICE — refusing to deploy"
  fi
  # Guard the `name` field specifically, NOT any mention of the string: the
  # ALLOWED_ORIGIN var legitimately contains the app ORIGIN
  # (https://freightlogic-v2.fimseitef.workers.dev), which is a different thing
  # from the app SERVICE name. A bare `grep -q freightlogic-v2` here would
  # false-positive on a correct config and fail every preflight.
  if grep -qE "\"name\"[[:space:]]*:[[:space:]]*\"$APP_SERVICE\"" "$CONFIG"; then
    fail "config's name field is the app service $APP_SERVICE — refusing to deploy"
  else
    pass "config's name field is not the app service"
  fi

  # 2. An `assets` block here would publish the repo from the API origin.
  if grep -q '"assets"' "$CONFIG"; then
    fail "config carries an \"assets\" block — that is the root config's job, not this one"
  else
    pass "no assets block (JSON-only service)"
  fi

  # 3. The KV binding must be present and must be a real id, not a placeholder.
  if grep -q '"binding"[[:space:]]*:[[:space:]]*"BACKUPS"' "$CONFIG"; then
    pass "BACKUPS KV binding declared"
  else
    fail "BACKUPS KV binding missing — the Worker has 27 env.BACKUPS call sites"
  fi
  if grep -qiE '"id"[[:space:]]*:[[:space:]]*"(|TODO|REPLACE|<[^"]*>|x+)"' "$CONFIG"; then
    fail "KV namespace id looks like a placeholder"
  else
    pass "KV namespace id is populated"
  fi

  # 4. No secret may be committed in the config.
  if grep -qE '"(ADMIN_TOKEN|OPENAI_API_KEY)"[[:space:]]*:' "$CONFIG"; then
    fail "config appears to declare a SECRET as a var — remove it"
  else
    pass "no secrets in config"
  fi

  # 5. Source must be the version we intend to ship, and must still be the
  #    v14 contract the certification gate names.
  # Derive the expectation instead of hardcoding it. Two literals that must
  # agree, updated by hand, is exactly the drift this repo keeps rediscovering
  # (checklist items 11 and 13 exist because of it). The parity verifier's
  # EXPECTED block is the single source of truth for the Worker generation, so
  # read it and assert the source agrees — then a future bump touches one place.
  SRC_VER="$(grep -m1 -oE "version: '[0-9]+'" "$WORKER_SRC" | grep -oE "[0-9]+" || true)"
  WANT_VER="$(grep -m1 -oE 'workerVersion: "[0-9]+"' "$REPO_ROOT/scripts/verify-cloudflare-parity.mjs" | grep -oE '[0-9]+' || true)"
  if [ -z "$WANT_VER" ]; then
    fail "could not read workerVersion from verify-cloudflare-parity.mjs"
  elif [ "$SRC_VER" = "$WANT_VER" ]; then
    pass "source /health reports version $SRC_VER, matching the parity verifier"
  else
    fail "source /health version is '${SRC_VER:-none}' but the parity verifier expects '$WANT_VER' — bump them together"
  fi
  grep -q "GET /health — unauthenticated liveness check" "$WORKER_SRC" \
    && pass "source keeps /health unauthenticated" \
    || fail "source no longer documents /health as unauthenticated"
  grep -q "path === '/backup/delta'" "$WORKER_SRC" \
    && pass "source exposes GET /backup/delta (X-01)" \
    || fail "source is missing /backup/delta — X-01 would stay live"
  grep -q "CLIENT_UNIFIED_DECISION_ENGINE" "$WORKER_SRC" \
    && pass "source projects the canonical decision (v24.0 authority rule)" \
    || fail "source does not project canonical authority"

  # 6. The parity script must already expect what we are about to deploy.
  if grep -q 'workerVersion: "14"' "$REPO_ROOT/scripts/verify-cloudflare-parity.mjs"; then
    pass "parity verifier expects Worker 14"
  else
    fail "parity verifier does not expect Worker 14 — bump it with the deploy"
  fi

  if [ "$FAILED" -ne 0 ]; then
    echo
    echo "PREFLIGHT FAILED — nothing was deployed." >&2
    exit 1
  fi
  echo
  echo "PREFLIGHT PASS."
fi

if [ "$MODE" = "preflight" ]; then
  cat <<BANNER

Nothing has been deployed. This was a preflight only.

To deploy, from an authenticated Cloudflare session:

  npx wrangler deploy -c scripts/wrangler.backup-worker.jsonc --dry-run   # inspect
  scripts/deploy-backup-worker.sh --confirm                               # deploy

Then prove the gate:

  scripts/deploy-backup-worker.sh --verify
  node scripts/verify-cloudflare-parity.mjs

BANNER
  exit 0
fi

if [ "$MODE" = "deploy" ]; then
  echo
  echo "== Deploying $API_SERVICE from cloud-backup-worker.js =="
  echo "   config: scripts/wrangler.backup-worker.jsonc"
  echo "   NOTE: this does not touch the $APP_SERVICE app/assets service."
  echo
  npx wrangler deploy -c "$CONFIG"
  echo
  echo "Deployed. Verifying..."
fi

echo
echo "== Live verification =="

HEALTH="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' \
  -H "Origin: $APP_ORIGIN" "$API_ORIGIN/health" || echo "000")"
HEALTH_BODY="$(curl -sS --max-time 20 -H "Origin: $APP_ORIGIN" "$API_ORIGIN/health" || echo "")"
HEALTH_CORS="$(curl -sS --max-time 20 -D - -o /dev/null \
  -H "Origin: $APP_ORIGIN" "$API_ORIGIN/health" 2>/dev/null \
  | grep -i '^access-control-allow-origin:' | tr -d '\r' || echo "")"

[ "$HEALTH" = "200" ] && pass "/health HTTP 200" || fail "/health HTTP $HEALTH (v7 answers 401 — it has no /health route)"
echo "$HEALTH_BODY" | grep -q '"version":"14"' \
  && pass "/health reports version 14" \
  || fail "/health body did not report version 14: $HEALTH_BODY"
case "$HEALTH_CORS" in
  *"$APP_ORIGIN"*) pass "CORS echoes the production app origin" ;;
  *"*"*)           fail "CORS is still wildcard '*' — ALLOWED_ORIGIN is unset (v7 behaviour)" ;;
  *)               fail "CORS header unexpected: ${HEALTH_CORS:-none}" ;;
esac

ADMIN="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$API_ORIGIN/admin/users" || echo "000")"
[ "$ADMIN" = "401" ] && pass "unauthenticated /admin/users denied (401)" || fail "unauthenticated /admin/users returned $ADMIN, expected 401"

EVAL="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' -X POST "$API_ORIGIN/evaluate" || echo "000")"
[ "$EVAL" = "401" ] && pass "unauthenticated /evaluate denied (401)" || fail "unauthenticated /evaluate returned $EVAL, expected 401"

echo
if [ "$FAILED" -ne 0 ]; then
  echo "LIVE VERIFICATION FAILED — gate 2 is NOT closed." >&2
  exit 1
fi

cat <<'DONE'
LIVE VERIFICATION PASS — Worker v14 is deployed and answering the v14 contract.

Gate 2 is closed for the unauthenticated surface. Still owed before the
release can be frozen:

  1. Authenticated smokes with a real (never published) driver token. Both
     halves are scripted — run them, do not hand-test:

       FL_BACKUP_TOKEN=flk_... node scripts/verify-live-authority.mjs
         /evaluate + /extract authority boundary. Add --paid to include the
         checks that spend OpenAI quota.

       FL_BACKUP_TOKEN=flk_... node scripts/verify-live-backup.mjs
         backup / delta / restore round trip. Writes only under a synthetic
         device id, so operator data is never touched. Its GET /backup/delta
         check is the one that catches X-01 still being live.

     Both use exit 2 for UNOBSERVED (unreachable origin / no token) and exit 1
     only for a real contract failure. Never record an exit 2 as a failure.

  2. node scripts/verify-cloudflare-parity.mjs  — the full live gate.
  3. A certification-state record superseding the HOLD, naming release and
     rollback SHAs.

CREDENTIAL ACTION, not optional: the superseded v7 stored every driver bearer
token in KV in plaintext AND returned it from GET /admin/users. Those plaintext
`token:` keys are deleted lazily — only when each token is next used, or when
that user is revoked. Until then every driver token must be treated as exposed
at rest. Rotate them through POST /admin/users + DELETE /admin/users/:id on the
operator's own schedule.
DONE
