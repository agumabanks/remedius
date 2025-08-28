# RemediusLive — 0→Hero Autopilot Report

## What Shipped
- Laravel app scaffolded inside `remedius-admin/` (kept starter drop-ins):
  - Sanctum + Spatie Permission installed and migrations published
  - API routing enabled (bootstrap/app.php) and `/api/health` route added
  - Appointment model and controller with overlap validation
  - Messaging endpoint: `POST /api/threads/{thread}/messages` broadcasting `MessageSent`
- Pest test runner configured (`tests/Pest.php`) and dependencies pinned for compatibility
- CI workflow updated to use SQLite and create `database/database.sqlite` before migrations
- coturn compose fixed for macOS/Windows (ports mapping instead of host networking)
- Realtime gateway `.env` template and install/start guidance
- docs/architecture.md added

## Endpoints (MVP)
- `GET /api/health` — health probe
- `POST /api/appointments` — creates appointment; rejects time overlap (same doctor)
- `POST /api/threads/{thread}/messages` — persists + broadcasts (auth:sanctum)

## Environment
- Laravel `.env` defaults to SQLite for dev/test
- Realtime Gateway `.env` example:
  - `PORT=8081`
  - `LARAVEL_URL=http://127.0.0.1:8000`
  - `CORS_ORIGIN=http://localhost:8000,http://localhost:3000`
  - `REDIS_HOST=127.0.0.1`
  - `REDIS_PORT=6379`
- coturn config: `coturn/turnserver.conf` (user/realm, ports 3478/5349, UDP 49152–65535)

## How to Run (Local)
- Backend
  - `cd remedius-admin && composer install`
  - `cp .env.example .env && php artisan key:generate`
  - `php artisan migrate`
  - `php artisan serve`
- Redis (optional for gateway)
  - `docker run -d --name remedius-redis -p 6379:6379 redis:7`
- Realtime Gateway
  - `cd realtime-gateway && npm i && node server.js`
- coturn
  - `cd coturn && docker compose up -d`
- Firebase Rules
  - `cd firebase && firebase deploy --only firestore:rules,storage`

## Tests & CI
- Local: `cd remedius-admin && ./vendor/bin/pest`
- CI: `remedius-admin/.github/workflows/ci.yml` runs Pint + Pest on SQLite
- Current status: All feature tests pass locally (5 passed / 8 assertions)

## Known Gaps / Next Steps
- Expand REST API: auth/register/login/logout, doctor search, reschedule/cancel appointments, EHR (encounters, prescriptions PDF), payments webhook
- Private broadcast channels and `/broadcasting/auth`
- Seed roles/permissions and factories
- Flutter app wiring to API and gateway; WebRTC signaling in Firestore and coturn ICE verified end-to-end
- GitHub Actions for Flutter tests/build

