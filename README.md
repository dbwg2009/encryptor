# ASCII Cipher Vault

A self-hostable web app around the original ASCII Cipher tool: account system,
encrypted key vault, history, multi-session management, and a zero-knowledge
architecture so the server never sees your master password or saved keys.

```
┌────────────────────┐   HTTPS   ┌──────────────────┐   :8000   ┌──────────┐
│ Browser            │ ────────▶ │ Nginx Proxy Mgr  │ ────────▶ │ FastAPI  │
│ (PBKDF2 + AES-GCM) │           │ (TLS, headers)   │           │ + SQLite │
└────────────────────┘           └──────────────────┘           └──────────┘
   master password                X-Forwarded-Proto              auth_hash + ciphertext
   never leaves                   X-Forwarded-For                 only
```

## What's in the box

- **Cipher tool** — the original PBKDF2 / HMAC-SHA256 encryptor, byte-for-byte
  compatible with the Python build. Output from one is decryptable by the other.
- **Account system** — email + master password. Sessions are HttpOnly cookies
  with CSRF double-submit, 30-day TTL, server-side revocable.
- **Key vault** — labels, tags, notes, pinning, search, sort. Every entry is
  AES-256-GCM-encrypted in the browser before it touches the server.
- **History** — the last 200 encrypt/decrypt previews per user, encrypted.
- **Settings** — change master password (re-wraps the whole vault in one
  transaction), revoke sessions individually, export / import an encrypted
  vault backup, delete account.
- **Standalone mode** — `/standalone` serves the original single-file
  `cipher.html` for emergency / no-account use.
- **Hardened defaults** — Argon2id over the client-derived auth hash, CSP,
  X-Frame-Options DENY, rate-limited login & registration, optional
  registration-token gate.

### Zero-knowledge specifics

On registration / login the browser does:

```
salt        = 16 random bytes (registration) or fetched from server (login)
material    = PBKDF2-HMAC-SHA256(password, salt, 200_000 iter, 64 bytes)
authHash    = material[0:32]   ── sent to server, re-hashed with Argon2id
vaultKey    = material[32:64]  ── kept in memory, never sent
```

Vault items are sealed with AES-256-GCM under `vaultKey` before upload, so the
database contains only ciphertext. **If you forget your master password the
vault is unrecoverable** — there is no reset flow, by design.

---

## Quick start (Docker Compose)

```bash
# 1. Generate a server secret and put it in .env
cp .env.example .env
echo "CIPHER_SECRET=$(openssl rand -hex 32)" >> .env

# 2. Build and start
sudo docker compose up -d --build

# 3. Open http://127.0.0.1:8765 and create your first account
```

The app binds to `127.0.0.1:8765` on the host, so it is **not** publicly
reachable until you put a reverse proxy in front of it.

### Locking down registration

After you have created your own account, set a registration token so randos
can't sign up:

```bash
echo "CIPHER_REGISTRATION_TOKEN=$(openssl rand -hex 16)" >> .env
sudo docker compose up -d
```

New sign-ups must paste the token into the registration form.

---

## Putting it behind Nginx Proxy Manager

### Option A — same Docker network (recommended)

If NPM and this app are on the same machine, add the app to NPM's network.
Find the network name with:

```bash
docker network ls | grep npm
```

It is usually `npm_default`. Set it in `.env`:

```
NPM_NETWORK=npm_default
```

then `docker compose up -d --build`.

In Nginx Proxy Manager, **Add Proxy Host**:

| Field                 | Value                              |
| --------------------- | ---------------------------------- |
| Domain Names          | `cipher.example.com`               |
| Scheme                | `http`                             |
| Forward Hostname / IP | `cipher` (the compose service name) |
| Forward Port          | `8000`                             |
| Block Common Exploits | ✓                                  |
| Websockets Support    | not required                       |
| **SSL** tab           | request a Let's Encrypt cert       |
| Force SSL             | ✓                                  |
| HTTP/2 Support        | ✓                                  |

In the **Advanced** tab, paste:

```nginx
client_max_body_size 8m;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP         $remote_addr;
```

That's it — the app already trusts `X-Forwarded-Proto` (`CIPHER_TRUST_PROXY=1`)
so secure cookies and HTTPS detection work correctly.

### Option B — host port (NPM and app on different machines)

Leave `127.0.0.1:8765` as-is on the app host, then in NPM set:

| Forward Hostname / IP | the host's LAN IP |
| Forward Port          | `8765`            |

…and bind the app to the LAN IP instead of localhost in
`docker-compose.yml`:

```yaml
ports:
  - "10.0.0.5:8765:8000"
```

Make sure only NPM can reach that port (firewall, Tailscale, etc.).

---

## Plain Nginx (no NPM)

```nginx
server {
    listen 443 ssl http2;
    server_name cipher.example.com;

    ssl_certificate     /etc/letsencrypt/live/cipher.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cipher.example.com/privkey.pem;

    client_max_body_size 8m;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}

server {
    listen 80;
    server_name cipher.example.com;
    return 301 https://$host$request_uri;
}
```

---

## Local development (no Docker)

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

export CIPHER_SECRET=$(openssl rand -hex 32)
export CIPHER_DB=$(pwd)/data/cipher.db
export CIPHER_STATIC=$(pwd)/static

uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

---

## Configuration

| env var                        | default                  | description                                                              |
| ------------------------------ | ------------------------ | ------------------------------------------------------------------------ |
| `CIPHER_SECRET`                | *(required)*             | HMAC secret for deterministic preflight salts. `openssl rand -hex 32`.  |
| `CIPHER_DB`                    | `/data/cipher.db`        | SQLite path. Mount a volume here.                                       |
| `CIPHER_STATIC`                | `/app/static`            | Directory served at `/static/`.                                         |
| `CIPHER_REGISTRATION_TOKEN`    | *(empty = open)*         | If set, registration requires this exact token.                         |
| `CIPHER_TRUST_PROXY`           | `1`                      | Trust `X-Forwarded-*` headers from a reverse proxy.                     |

---

## Backups

The SQLite database is the single source of truth. Two ways to back up:

1. **Server-side**: copy `data/cipher.db` (with WAL files) while the app is
   stopped, or `sqlite3 data/cipher.db ".backup '/path/to/backup.db'"` while
   it's running.
2. **Per-user**: each user can export an encrypted JSON vault from
   *Settings → Backup → Export vault*. The export is safe to store anywhere —
   it contains no plaintext.

---

## API surface

All routes are JSON. State-changing requests require an `X-CSRF-Token` header
matching the `csrf` cookie issued at login.

| method | path                          | purpose                                 |
| ------ | ----------------------------- | --------------------------------------- |
| POST   | `/api/auth/preflight`         | get `authSalt` for a given email        |
| POST   | `/api/auth/register`          | create account                          |
| POST   | `/api/auth/login`             | sign in, set cookies                    |
| POST   | `/api/auth/verify`            | verify password without rotating session|
| POST   | `/api/auth/logout`            | revoke current session                  |
| GET    | `/api/auth/me`                | current user info                       |
| POST   | `/api/auth/change-password`   | re-wrap vault + replace auth            |
| POST   | `/api/auth/delete-account`    | nuke the account                        |
| GET    | `/api/vault`                  | list ciphertext entries                 |
| POST   | `/api/vault`                  | add entry                               |
| PUT    | `/api/vault/{id}`             | update entry                            |
| DELETE | `/api/vault/{id}`             | delete entry                            |
| GET    | `/api/history`                | recent operations                       |
| POST   | `/api/history`                | add an entry                            |
| DELETE | `/api/history`                | clear all                               |
| DELETE | `/api/history/{id}`           | remove one                              |
| GET    | `/api/sessions`               | list your sessions                      |
| DELETE | `/api/sessions/{id}`          | revoke one                              |
| GET    | `/api/health`                 | health probe                            |

---

## Security notes

- Sessions are 32-byte URL-safe tokens stored server-side. Cookie is
  `HttpOnly; Secure; SameSite=Lax` whenever the proxy reports HTTPS.
- CSRF uses the **double-submit cookie** pattern — the `csrf` cookie is not
  HttpOnly so JS can read it, but the same value must arrive in
  `X-CSRF-Token` and match the session's stored token.
- Passwords are never sent to the server. The browser sends a
  PBKDF2-derived 32-byte hash; the server then re-hashes with Argon2id
  (`m=64MiB, t=3, p=2`) before storage.
- Rate limits are in-process (no Redis dep): 30 preflights / IP / minute,
  10 logins / IP / minute, 10 registrations / IP / hour.
- Content-Security-Policy is strict: no inline scripts, no remote origins.
- The standalone cipher (`/standalone`) is purely client-side — no calls to
  the server, no localStorage, useful as a fallback if the backend is down.

## Files

```
.
├── backend/
│   ├── main.py             # FastAPI app, all routes
│   └── requirements.txt
├── static/
│   ├── index.html          # SPA shell
│   ├── app.css
│   ├── cipher.html         # standalone offline version
│   └── js/
│       ├── crypto.js       # cipher + KDF + AES-GCM
│       ├── api.js          # CSRF-aware fetch
│       └── app.js          # controller + all view logic
├── encryption python.py    # original tk app, untouched
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```
