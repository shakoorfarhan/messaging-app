# Go Messaging App

Go API + React (CDN) single-page UI with Postgres persistence. Users register with location/university metadata, choose public/private visibility, and exchange direct messages. Private users require an invitation/acceptance first; accepting an invite seeds a first message and lifts the chat to the top.

## Run locally
1) Ensure Postgres is running and reachable. Defaults to `postgres://localhost:5432/messaging_app?sslmode=disable`.
2) Optional DSN override:
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/messaging_app?sslmode=disable"
GOCACHE=$PWD/.gocache go run .
```
3) Open http://localhost:8080 for the SPA (no build step).

Tables auto-create on startup (`users`, `sessions`, `messages`, `invitations`, `connections`). Message writes are concurrent (goroutine per request). Visibility toggle is available in the UI; search prioritizes same university/location; polling every second keeps chats/invitations fresh.

## API quick reference
- `POST /api/register` — `{username,password,location,university,public}` → 201
- `POST /api/login` — `{username,password}`; sets `session_token` cookie
- `POST /api/logout` — clears session
- `GET /api/profile` — current user profile (requires login)
- `POST /api/profile/update` — `{public}` toggle visibility (requires login)
- `GET /api/messages` — list of messages to/from current user (requires login)
- `POST /api/messages` — `{to,body}` send a message (requires login; sends invite if recipient is private and not connected)
- `GET /api/users?search=abc` — search users for autocomplete (prioritized same university/location)
- `GET /api/invitations` — pending invitations for current user
- `POST /api/invitations` — `{id}` accept an invitation (creates connection and seeds first message)

## Run with Docker
Build the image locally:
```bash
docker build -t messaging-app .
```

Run the container (requires a Postgres connection string):
```bash
docker run --rm -p 8080:8080 \
  -e DATABASE_URL="postgres://postgres:postgres@host.docker.internal:5432/messaging_app?sslmode=disable" \
  messaging-app
```

Quick docker-compose to run app + Postgres:
```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: messaging_app
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      retries: 5
  app:
    build: .
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://postgres:postgres@db:5432/messaging_app?sslmode=disable
    ports: ["8080:8080"]
```

## Free deploy suggestions
- **Render free tier**: Web service (Go) + free Postgres. Simple `render.yaml`; sleeps on inactivity.
- **Railway free tier**: Quick Go deploy + managed Postgres; watch free hours/egress caps.
- **Fly.io**: Deploy Go + a Fly Postgres free starter; may need volume for DB.
- **Supabase/Neon + Fly/Render**: Use a free Postgres host (Neon/Supabase) with the Go app on Fly/Render free tier.

App is single binary; no build step beyond `go build`. Ensure `DATABASE_URL` is set and allow HTTP-only cookies.***
