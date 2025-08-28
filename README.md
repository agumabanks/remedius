# RemediusLive MVP Starter

This starter gives you a **Pest-ready** Laravel API scaffold (drop-in files),
a **Socket.IO realtime gateway**, **Firebase security rules**, a **coturn** TURN server
compose, and basic **Flutter** app snippets for chat + WebRTC signaling.

**How to use (Agent or Manual):**
1. Run `scripts/bootstrap.sh` (adjust domains, ports, credentials).  
2. The script will create a Laravel app in `remedius-admin/` (if missing),
   copy the provided migrations/models/controllers/tests, and set up the realtime
   gateway, Firebase rules, and coturn.
3. Open the repository in VS Code and let your agent continue:
   - Implement missing controllers/endpoints and factories
   - Wire auth (Sanctum), roles (Spatie), and remaining models
   - Flesh out Flutter UI using your Remedius UI mockups

Alternatively, use the non-destructive orchestrator:
- `scripts/mvp-setup.sh` — checks dependencies, installs deps, prepares envs, and writes helper scripts (`scripts/dev-setup.sh`, `scripts/dev-stop.sh`).
# remedius
