#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$DIR/wrangler.jsonc"
EXPECTED_NAME="freightlogic-admin-console"

if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "::error::CLOUDFLARE_API_TOKEN is unavailable; Admin Console was not deployed."
  exit 2
fi

if [ ! -f "$CONFIG" ]; then
  echo "::error::Admin Console Wrangler config is missing: $CONFIG"
  exit 1
fi

NAME="$(node -e '
  const fs = require("fs");
  const p = process.argv[1];
  const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
  process.stdout.write(String(cfg.name || ""));
' "$CONFIG")"

if [ "$NAME" != "$EXPECTED_NAME" ]; then
  echo "::error::Refusing to deploy unexpected Worker name: ${NAME:-missing}"
  exit 1
fi

echo "Dry-running dedicated Admin Console Worker: $EXPECTED_NAME"
npx --yes wrangler@4 deploy -c "$CONFIG" --dry-run

echo "Deploying dedicated Admin Console Worker: $EXPECTED_NAME"
npx --yes wrangler@4 deploy -c "$CONFIG"

echo "Waiting briefly for Workers.dev propagation..."
sleep 8

node "$DIR/verify-live.mjs"
