# Agent Tasks (Paste into Agent Mode)

## Task 1 — Bootstrap & Repo Hygiene
- Ensure Laravel 11 project exists at `remedius-admin/`. If not, run:
  ```bash
  composer create-project laravel/laravel remedius-admin
  ```
- Install: Sanctum, Spatie Permission, Pest, Pint.
- Copy all files from `remedius-admin/` in this starter into the Laravel app.
- Run migrations and ensure seeds/factories compile.

## Task 2 — Realtime Gateway
- In `realtime-gateway/`, install deps and start the Socket.IO server.
- Bridge Redis broadcast messages to Socket.IO rooms.

## Task 3 — Firebase
- Apply the rules in `firebase/` using Firebase CLI.
- Create collections: `threads`, `signals`, `presence` during runtime.

## Task 4 — coturn
- Start `coturn/` compose and verify connectivity from Flutter with `flutter_webrtc`.
- Replace TURN auth with secure credentials and TLS certs in production.

## Task 5 — Endpoints & Tests
- Implement auth endpoints, appointment endpoints, policies, and factories
  so `tests/Feature/*.php` pass.
- Extend messaging, encounters, prescriptions, and payments APIs.
