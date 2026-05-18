# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

### Local Development
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt

export CIPHER_SECRET=$(openssl rand -hex 32)
export CIPHER_DB=$(pwd)/data/cipher.db
export CIPHER_STATIC=$(pwd)/static

uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### Run Tests
```bash
cd backend
pip install -r requirements.txt
pytest                              # Run all tests
pytest -v                           # Verbose output
pytest test_main.py::TestAuthEndpoints::test_login_success  # Specific test
pytest --cov=. --cov-report=html    # Coverage report
```

### Docker
```bash
cp .env.example .env
echo "CIPHER_SECRET=$(openssl rand -hex 32)" >> .env
docker compose up -d --build
```

## Architecture Overview

**XorCrypt** is a self-hostable encrypted vault with messaging (DM + group chat). The architecture is **zero-knowledge**: the server never sees plaintext passwords or vault contents.

```
Client (Browser)                    Server (FastAPI)              Storage
├─ PBKDF2(password)           ├─ Argon2id(authHash)        ├─ SQLite
├─ AES-256-GCM(vault items)   ├─ Session mgmt              │  ├─ users
├─ Crypto.js                  ├─ CSRF double-submit        │  ├─ sessions
└─ App.js (SPA)               └─ Rate limiting              │  ├─ vault_items
                                                             │  ├─ messages
                                                             │  ├─ groups
                                                             │  └─ ...
```

### Encryption Flow

**Registration/Login:**
1. Client: `salt` = 16 random bytes (reg) or fetched from `/api/auth/preflight` (login)
2. Client: `material` = PBKDF2-HMAC-SHA256(password, salt, 200k iterations, 64 bytes)
3. Client splits material:
   - `authHash` = material[0:32] → sent to server
   - `vaultKey` = material[32:64] → stays in browser (never sent)
4. Server: re-hashes authHash with Argon2id before storage

**Vault Items:**
- Encrypted in browser with AES-256-GCM under `vaultKey`
- Server stores only ciphertext
- No plaintext recovery if password is forgotten

### Key Security Decisions

- **No password reset flow** — forgotten passwords = unrecoverable vault (by design)
- **Sessions**: 32-byte tokens, HttpOnly cookies, 30-day TTL, server-side revocable
- **CSRF**: Double-submit pattern — `csrf` cookie (not HttpOnly) + `X-CSRF-Token` header match
- **Rate limiting**: In-process (no Redis). Strict per IP: 30 preflights/min, 10 logins/min, 10 registrations/hour
- **CSP**: Strict headers, no inline scripts, no remote origins
- **Groups**: Create with group key (also used as join code); members get wrapped key sealed under their vault key

## Code Structure

### Backend (`backend/main.py`)
Single FastAPI application (~1500 lines) with:
- **Auth**: preflight, register, login, verify, logout, change-password, delete-account, logout-all
- **Vault**: CRUD operations on encrypted items
- **History**: Encrypt/decrypt operation log
- **Sessions**: List, revoke individual sessions
- **Messaging**: Direct messages between users, group creation/join/leave, group messaging
- **Groups**: Invite system, wrapped key distribution
- **Media**: File uploads with per-user access control
- **Blocks & Reports**: User blocking, content reporting
- **Health**: Status probe

### Database Schema (SQLite + WAL mode, foreign keys enabled)
- `users` — email, auth_salt, auth_hash
- `sessions` — id, user_id, csrf, expires_at, user_agent, ip
- `vault_items` — user_id, label_ct, payload_ct, pinned, timestamps
- `history` — user_id, op (encrypt/decrypt), preview_ct
- `messages` — sender_id, recipient_id, ciphertext, hint, reply_to_id
- `groups` — name, creator_id, salt, auth_hash, wrapped_key
- `group_messages` — group_id, sender_id, ciphertext, hint, reply_to_id
- `group_members` — group_id, user_id (with unread tracking)
- `group_invites` — token, group_id, inviter_id, invitee_id, wrapped_key, expires (7 days)
- `blocks`, `reports`, `media`, `media_access`, `login_history`, `push_subscriptions`

### Frontend (`static/`)
SPA (Single Page Application) with:
- `index.html` — Shell
- `js/crypto.js` — PBKDF2, Argon2id, AES-256-GCM, HMAC-SHA256 (original cipher algorithm)
- `js/api.js` — CSRF-aware fetch wrapper
- `js/app.js` — Controller + all view logic

### Standalone Mode
`cipher.html` — Pure client-side cipher (no server calls, no localStorage). Fallback if backend is down.

## Important Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `CIPHER_SECRET` | *(required)* | HMAC secret for deterministic salts. Must be 64-char hex. |
| `CIPHER_DB` | `/data/cipher.db` | SQLite path. Mount a volume in Docker. |
| `CIPHER_STATIC` | `/app/static` | Directory served at `/static/`. |
| `CIPHER_REGISTRATION_TOKEN` | *(empty = open)* | If set, all registrations require this token. |
| `CIPHER_TRUST_PROXY` | `1` | Trust `X-Forwarded-*` headers (set to `0` if no proxy). |

## Testing

### Setup
Test fixtures in `conftest.py` handle database isolation and user auth:
- `temp_db` — Temporary database per test
- `app` — FastAPI app with temp DB
- `client` — TestClient for making requests
- `registered_user` — Pre-created user (email + authHash)
- `logged_in_user` — User logged in with valid session

### Test Organization (`test_main.py`)
- `TestAuthEndpoints` — Registration, login, password change, account deletion
- `TestVaultEndpoints` — Create, read, update, delete vault items
- `TestHistoryEndpoints` — Operation history management
- `TestSessionEndpoints` — Session listing, logout-all, login history
- `TestHealthEndpoint` — Health probe
- `TestUnauthenticatedAccess` — Verify auth is required for protected routes

### Field Names
API uses **camelCase** in JSON requests/responses (Pydantic `Field` aliases):
- `authHash`, `authSalt` (not `auth_hash`, `auth_salt`)
- `labelCt`, `payloadCt` (not `label_ct`, `payload_ct`)
- `previewCt`, `replyToId`, `mediaIds`, etc.

## Deployment

### Docker Compose (Recommended)
- Binds to `127.0.0.1:8765`
- Requires reverse proxy (Nginx Proxy Manager or plain Nginx) for TLS
- Example Nginx config in README

### Volume Mounts
- `/data` — SQLite database + WAL files (must persist across restarts)
- `/app/static` — Frontend assets (can be overridden if customizing)

## Common Tasks

**Add new API endpoint:**
1. Define Pydantic model in `main.py` (use camelCase field names)
2. Add route handler with `@app.get/post/put/delete`
3. Use `Depends(auth_dep)` for endpoints requiring validated password or `Depends(require_user)` for simple auth check
4. Add corresponding tests in `test_main.py`

**Change master password:**
- User sends `currentAuthHash`, `newAuthSalt`, `newAuthHash`, `rewrappedItems` (client re-wraps vault under new key)
- Server atomically updates user + vault items in transaction

**Add a test:**
```python
def test_new_feature(self, client, logged_in_user):
    """Test description."""
    response = client.post("/api/endpoint", json={"field": "camelCase"})
    assert response.status_code == 200
    assert response.json()["key"] == "value"
```

## Known Limitations / Design Decisions

- **Single FastAPI file** — All routes in `backend/main.py` for simplicity. Consider splitting if it grows.
- **In-process rate limiting** — No Redis dependency. Resets on app restart (acceptable for small deployments).
- **No password recovery** — Forgotten passwords = lost vault (intentional security model).
- **SQLite** — Fine for small to medium deployments. Migrate to PostgreSQL if scaling to thousands of users.
- **No end-to-end encryption for direct messages** — Messages encrypted at rest (server side), but recipient doesn't decrypt without server. Group messages work similarly. Only vault is true E2E.
