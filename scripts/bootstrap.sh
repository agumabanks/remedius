#!/usr/bin/env bash
set -euo pipefail

# Paths
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="$ROOT/remedius-admin"
GATEWAY_DIR="$ROOT/realtime-gateway"
FLUTTER_DIR="$ROOT/remedius-mobile"

echo "==> Bootstrapping RemediusLive MVP Starter"

# 1) Laravel app
if [ ! -d "$API_DIR" ] || [ ! -f "$API_DIR/artisan" ]; then
  echo "==> Creating Laravel 11 app in remedius-admin/"
  composer create-project laravel/laravel "$API_DIR"
fi

pushd "$API_DIR" >/dev/null
composer require laravel/sanctum spatie/laravel-permission
composer require --dev pestphp/pest laravel/pint
php artisan vendor:publish --provider="Spatie\\Permission\\PermissionServiceProvider" --force
php artisan vendor:publish --provider="Laravel\\Sanctum\\SanctumServiceProvider" --force
php artisan migrate || true
popd >/dev/null

# 2) Copy drop-in files
echo "==> Copying drop-in files into Laravel app"
rsync -a --exclude=".gitkeep" "$ROOT/remedius-admin/" "$API_DIR/"

# 3) Realtime gateway
echo "==> Setting up realtime-gateway"
pushd "$GATEWAY_DIR" >/dev/null
npm install
popd >/dev/null

echo "==> Done. Next steps:"
echo "  - Start Redis & Laravel: php artisan serve; php artisan queue:work"
echo "  - Start gateway: (cd realtime-gateway && node server.js)"
echo "  - Start TURN: (cd coturn && docker compose up -d)"
echo "  - Apply Firebase rules: firebase deploy --only firestore:rules,storage"
chmod +x "$ROOT/scripts/bootstrap.sh"
