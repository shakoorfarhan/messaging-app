# Go Messaging App (minimal)

Tiny Go API + embedded widget UI with Postgres persistence. Users register with location and university metadata, log in, and exchange direct messages.

## Run locally
1) Ensure Postgres is running and reachable. The app will default to `postgres://localhost:5432/messaging_app?sslmode=disable`.
2) Set a custom DSN via `DATABASE_URL` if needed:
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/messaging_app?sslmode=disable"
GOCACHE=$PWD/.gocache go run .
```
3) Open http://localhost:8080 to use the single-page React widget (bundled via CDN, no build step).

Tables are auto-created on startup (`users`, `sessions`, `messages`).
Users can be public or private. Private accounts require an invitation/acceptance flow before messaging; public accounts are open. Message writes use a goroutine-per-request channel pattern to showcase Go's concurrency while keeping the API surface unchanged. Database connection pool sizing is left at Go defaults (no hard cap).

## API quick reference
- `POST /api/register` — `{username,password,location,university}` → 201
- `POST /api/login` — `{username,password}`; sets `session_token` cookie
- `POST /api/logout` — clears session
- `GET /api/profile` — current user profile (requires login)
- `GET /api/messages` — list of messages to/from current user (requires login)
- `POST /api/messages` — `{to,body}` send a message (requires login)
- `GET /api/users?search=abc` — search users for autocomplete
- `GET /api/invitations` — pending invitations for current user
- `POST /api/invitations` — `{id}` accept an invitation
