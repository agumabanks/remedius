# RemediusLive MVP Architecture

## Overview
- Backend: Laravel 12 API with Sanctum and Spatie Permissions. SQLite dev/test, MySQL/Cloud SQL prod.
- Realtime: Node.js Socket.IO gateway bridging Laravel broadcast events via Redis pub/sub to clients.
- Mobile: Flutter app (chat + WebRTC signaling). Uses coturn for ICE relays.
- Firebase: Firestore for signaling/threads, Storage for attachments, FCM for push.
- TURN: coturn via Docker (instrumentisto/coturn) with UDP port range 49152–65535.

## Data Flow
- Chat send: Client → Gateway (message:send) → Laravel API (persist) → broadcast(MessageSent) → Redis → Gateway → io.to(thread.{id}).emit('message.sent').
- Appointments: Conflict-checked creation in Laravel; events emit for notifications.
- WebRTC: Offer/answer exchanged via Firestore `/signals/{callId}`, ICE via coturn.

## Security
- API: auth:sanctum for protected endpoints; roles via Spatie.
- Firestore Rules: require thread membership; presence restricted per user; signals gated by participants.
- Storage Rules: scope to thread/prescription paths.

## Local Dev
- API: `php artisan serve` (SQLite). Migrations auto-run in CI and tests.
- Redis: docker `redis:7` (optional for local tests).
- Gateway: `cd realtime-gateway && npm i && node server.js` (env in `.env`).
- coturn: `cd coturn && docker compose up -d`.

## CI
- GitHub Actions in `remedius-admin/.github/workflows/ci.yml` runs Pint and Pest with SQLite database.

