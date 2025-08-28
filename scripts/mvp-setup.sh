#!/usr/bin/env bash
set -Eeuo pipefail

# RemediusLive MVP Setup Orchestrator (non-destructive)
# - Validates dependencies
# - Boots Laravel API (remedius-admin)
# - Boots Realtime Gateway (realtime-gateway)
# - Runs Flutter deps (remedius-mobile)
# - Prepares Firebase rules (firebase)
#
# This script is idempotent and respects the existing repo layout.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
headr() { echo -e "\n${BLUE}=== $* ===${NC}"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="$ROOT_DIR/remedius-admin"
GATEWAY_DIR="$ROOT_DIR/realtime-gateway"
FLUTTER_DIR="$ROOT_DIR/remedius-mobile"
FIREBASE_DIR="$ROOT_DIR/firebase"
LOG_DIR="$ROOT_DIR/logs"

# Cross-platform in-place sed
sedi() {
  if sed --version >/dev/null 2>&1; then
    sed -i "$@"
  else
    # macOS/BSD sed
    sed -i '' "$@"
  fi
}

require_cmd() {
  local cmd=$1; local hint=${2:-}
  if ! command -v "$cmd" >/dev/null 2>&1; then
    error "Missing dependency: $cmd ${hint:+($hint)}"
    return 1
  fi
}

version_ge() {
  # returns 0 if $1 >= $2 (semver-ish, using sort -V)
  local a=$1 b=$2
  [ "$(printf '%s\n' "$b" "$a" | sort -V | head -n1)" = "$b" ]
}

check_dependencies() {
  headr "Checking Dependencies"
  require_cmd php ">= 8.2" || exit 1
  require_cmd composer || exit 1
  require_cmd node ">= 18" || exit 1
  require_cmd npm || exit 1
  require_cmd git || exit 1
  require_cmd mysql || warn "MySQL client not found (DB setup script will skip)"
  if command -v flutter >/dev/null 2>&1; then :; else warn "Flutter not found (mobile step will skip)"; fi
  if command -v firebase >/dev/null 2>&1; then :; else warn "Firebase CLI not found (rules deploy step will skip)"; fi

  local PHP_V
  PHP_V=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
  if ! version_ge "$PHP_V" "8.2"; then
    error "PHP 8.2+ required, found $PHP_V"
    exit 1
  fi
  local NODE_V
  NODE_V=$(node -v 2>/dev/null | sed 's/^v//') || true
  if [ -n "${NODE_V:-}" ] && ! version_ge "$NODE_V" "18.0.0"; then
    error "Node.js 18+ required, found $NODE_V"
    exit 1
  fi
  info "Dependencies look good (PHP $PHP_V, Node ${NODE_V:-n/a})"
}

ensure_logs() {
  mkdir -p "$LOG_DIR"
}

setup_laravel() {
  headr "Laravel API setup (remedius-admin)"
  if [ ! -d "$API_DIR" ]; then
    error "Directory $API_DIR not found. This repo already contains drop-in files."
    error "If you want to create a fresh Laravel app, run: composer create-project laravel/laravel remedius-admin"
    return 1
  fi

  pushd "$API_DIR" >/dev/null
  if [ ! -f composer.json ]; then
    warn "composer.json missing in remedius-admin; is this a fresh Laravel app?"
  fi
  info "Installing PHP dependencies"
  composer install --no-interaction --prefer-dist

  if [ ! -f .env ]; then
    info "Creating .env from .env.example"
    cp .env.example .env || touch .env
    # Best-effort DB defaults for local dev
    grep -q '^DB_DATABASE=' .env && sedi 's/^DB_DATABASE=.*/DB_DATABASE=remedius_live/' .env || echo 'DB_DATABASE=remedius_live' >> .env
    grep -q '^DB_USERNAME=' .env && sedi 's/^DB_USERNAME=.*/DB_USERNAME=remedius_user/' .env || echo 'DB_USERNAME=remedius_user' >> .env
    grep -q '^DB_PASSWORD=' .env && sedi 's/^DB_PASSWORD=.*/DB_PASSWORD=remedius_secure_pass/' .env || echo 'DB_PASSWORD=remedius_secure_pass' >> .env
  fi

  php artisan key:generate || true
  info "Running migrations (will skip if DB not reachable)"
  php artisan migrate || warn "Migrations failed (likely DB not ready). You can re-run later."
  popd >/dev/null
}

setup_gateway() {
  headr "Realtime Gateway setup (realtime-gateway)"
  if [ ! -d "$GATEWAY_DIR" ]; then
    warn "No realtime-gateway directory found. Skipping."
    return 0
  fi
  pushd "$GATEWAY_DIR" >/dev/null
  npm install --silent
  if [ ! -f .env ]; then
    info "Creating realtime-gateway .env"
    cat > .env <<EOF
PORT=8081
LARAVEL_URL=http://127.0.0.1:8000
CORS_ORIGIN=http://localhost:8000,http://localhost:3000
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
EOF
  fi
  popd >/dev/null
}

setup_flutter() {
  headr "Flutter Mobile setup (remedius-mobile)"
  if command -v flutter >/dev/null 2>&1 && [ -d "$FLUTTER_DIR" ]; then
    pushd "$FLUTTER_DIR" >/dev/null
    flutter pub get || warn "flutter pub get failed"
    popd >/dev/null
  else
    warn "Flutter not installed or remedius-mobile missing. Skipping."
  fi
}

setup_firebase_rules() {
  headr "Firebase rules"
  if [ -d "$FIREBASE_DIR" ]; then
    info "Rules present in firebase/. Deploy with: firebase deploy --only firestore:rules,storage"
  else
    warn "firebase/ directory not found. Skipping."
  fi
}

write_dev_scripts() {
  headr "Writing helper scripts"
  mkdir -p "$ROOT_DIR/scripts"
  cat > "$ROOT_DIR/scripts/dev-setup.sh" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="$ROOT/remedius-admin"
GATEWAY_DIR="$ROOT/realtime-gateway"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

echo "Starting Laravel API and Realtime Gateway..."

pushd "$API_DIR" >/dev/null
php artisan serve --host=127.0.0.1 --port=8000 > "$LOG_DIR/laravel.http.log" 2>&1 &
LARAVEL_PID=$!
popd >/dev/null

pushd "$GATEWAY_DIR" >/dev/null
node server.js > "$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
popd >/dev/null

echo "$LARAVEL_PID" > "$LOG_DIR/laravel.pid"
echo "$GATEWAY_PID" > "$LOG_DIR/gateway.pid"

sleep 2
echo "Laravel PID: $LARAVEL_PID"
echo "Gateway PID: $GATEWAY_PID"
echo "Health checks:"
curl -fsS http://127.0.0.1:8000/api/health && echo || true
curl -fsS http://127.0.0.1:8081/health && echo || true
echo "Done. Logs in $LOG_DIR"
EOS
  chmod +x "$ROOT_DIR/scripts/dev-setup.sh"

  cat > "$ROOT_DIR/scripts/dev-stop.sh" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT/logs"

stop_pid() { local f=$1; if [ -f "$f" ]; then PID=$(cat "$f"); if kill -0 "$PID" 2>/dev/null; then kill "$PID"; echo "Stopped $PID"; fi; rm -f "$f"; fi }

stop_pid "$LOG_DIR/laravel.pid"
stop_pid "$LOG_DIR/gateway.pid"
echo "Services stopped."
EOS
  chmod +x "$ROOT_DIR/scripts/dev-stop.sh"
}

write_summary() {
  headr "Writing SETUP_COMPLETE.md"
  cat > "$ROOT_DIR/SETUP_COMPLETE.md" <<'EOS'
# RemediusLive MVP Setup Complete

Components prepared:
- Laravel API: remedius-admin (composer install, migrations attempted)
- Realtime Gateway: realtime-gateway (npm install, .env created if missing)
- Flutter app: remedius-mobile (pub get)
- Firebase: firebase/ (rules present; deploy with Firebase CLI)

Next steps:
1) Create/verify database credentials in remedius-admin/.env
2) Run scripts/dev-setup.sh to start API and gateway
3) Optionally run scripts/dev-stop.sh to stop them
4) Deploy Firebase rules: firebase deploy --only firestore:rules,storage

Logs directory: logs/
EOS
}

main() {
  headr "RemediusLive MVP Setup"
  check_dependencies
  ensure_logs
  setup_laravel
  setup_gateway
  setup_flutter
  setup_firebase_rules
  write_dev_scripts
  write_summary
  headr "All done"
  info "Start dev: scripts/dev-setup.sh"
}

main "$@"

