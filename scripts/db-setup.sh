#!/usr/bin/env bash
set -Eeuo pipefail

# Creates database and app user from remedius-admin/.env
# Requires MYSQL_ROOT_USER and MYSQL_ROOT_PASSWORD to be set in the environment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/remedius-admin/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE. Create it first (cp .env.example .env in remedius-admin)." >&2
  exit 1
fi

DB_DATABASE=$(grep -E '^DB_DATABASE=' "$ENV_FILE" | cut -d= -f2-)
DB_USERNAME=$(grep -E '^DB_USERNAME=' "$ENV_FILE" | cut -d= -f2-)
DB_PASSWORD=$(grep -E '^DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
DB_HOST=${DB_HOST:-$(grep -E '^DB_HOST=' "$ENV_FILE" | cut -d= -f2-)}
DB_PORT=${DB_PORT:-$(grep -E '^DB_PORT=' "$ENV_FILE" | cut -d= -f2-)}

DB_HOST=${DB_HOST:-127.0.0.1}
DB_PORT=${DB_PORT:-3306}

if [ -z "${MYSQL_ROOT_USER:-}" ] || [ -z "${MYSQL_ROOT_PASSWORD:-}" ]; then
  echo "Set MYSQL_ROOT_USER and MYSQL_ROOT_PASSWORD env vars to run this non-interactively." >&2
  echo "Example: MYSQL_ROOT_USER=root MYSQL_ROOT_PASSWORD=secret scripts/db-setup.sh" >&2
  exit 1
fi

mysql -h "$DB_HOST" -P "$DB_PORT" -u "$MYSQL_ROOT_USER" -p"$MYSQL_ROOT_PASSWORD" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_DATABASE\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USERNAME'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_DATABASE\`.* TO '$DB_USERNAME'@'%';
FLUSH PRIVILEGES;
SQL

echo "Database '$DB_DATABASE' and user '$DB_USERNAME' ensured."

