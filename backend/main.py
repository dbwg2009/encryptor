"""ASCII Cipher Vault — FastAPI backend.

Zero-knowledge architecture: server stores only a per-user salt, an Argon2id hash
of the client-derived auth_hash, and AES-GCM ciphertext for vault items. The
master password and the vault key never leave the browser.
"""
import os
import re
import time
import secrets
import hmac
import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("CIPHER_DB", str(ROOT / "data" / "cipher.db")))
STATIC_DIR = Path(os.environ.get("CIPHER_STATIC", str(ROOT / "static")))
SECRET_KEY = os.environ.get("CIPHER_SECRET")
if not SECRET_KEY or SECRET_KEY == "changeme":
    raise RuntimeError("CIPHER_SECRET env var required (run: openssl rand -hex 32)")

REGISTRATION_TOKEN = os.environ.get("CIPHER_REGISTRATION_TOKEN", "")
TRUST_PROXY = os.environ.get("CIPHER_TRUST_PROXY", "1") == "1"

SESSION_TTL = 30 * 24 * 60 * 60
SESSION_COOKIE = "sid"
CSRF_COOKIE = "csrf"
CSRF_HEADER = "X-CSRF-Token"
PBKDF2_ITERATIONS = 200_000
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  auth_salt BLOB NOT NULL,
  auth_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  user_agent TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS vault_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label_ct TEXT NOT NULL,
  payload_ct TEXT NOT NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vault_user ON vault_items(user_id);

CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  op TEXT NOT NULL,
  preview_ct TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_user_time ON history(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  hint TEXT,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  deleted_by_sender INTEGER NOT NULL DEFAULT 0,
  deleted_by_recipient INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender    ON messages(sender_id,    created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_pair      ON messages(sender_id, recipient_id, created_at DESC);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  salt BLOB NOT NULL,
  verifier_hash TEXT NOT NULL,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_key TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  last_read_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

CREATE TABLE IF NOT EXISTS group_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  ciphertext TEXT NOT NULL,
  hint TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, created_at DESC);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subscription_json TEXT NOT NULL,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);
"""


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


_rl_store: dict[str, list[float]] = {}

def rate_limit(key: str, limit: int, window: float):
    now = time.time()
    bucket = _rl_store.setdefault(key, [])
    cutoff = now - window
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= limit:
        raise HTTPException(429, "Too many requests")
    bucket.append(now)


def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_https(request: Request) -> bool:
    if TRUST_PROXY:
        proto = request.headers.get("x-forwarded-proto")
        if proto:
            return proto == "https"
    return request.url.scheme == "https"


def deterministic_salt(email: str) -> str:
    h = hmac.new(SECRET_KEY.encode(), b"preflight:" + email.encode(), hashlib.sha256)
    return h.digest()[:16].hex()


def set_cookie(response: Response, name: str, value: str, request: Request, http_only: bool):
    response.set_cookie(
        key=name, value=value, max_age=SESSION_TTL,
        httponly=http_only, secure=is_https(request),
        samesite="lax", path="/",
    )


def make_session(user_id: int, request: Request, response: Response):
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, csrf, created_at, expires_at, user_agent, ip) VALUES (?,?,?,?,?,?,?)",
            (sid, user_id, csrf, now, now + SESSION_TTL,
             (request.headers.get("user-agent") or "")[:300], client_ip(request)),
        )
    set_cookie(response, SESSION_COOKIE, sid, request, http_only=True)
    set_cookie(response, CSRF_COOKIE, csrf, request, http_only=False)


def current_user(request: Request) -> Optional[sqlite3.Row]:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    with db() as conn:
        row = conn.execute(
            """SELECT u.id, u.email, u.auth_salt, u.auth_hash, u.created_at, u.last_login_at,
                      s.id AS sess_id, s.csrf AS sess_csrf, s.expires_at AS sess_exp
                 FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.id = ?""",
            (sid,)
        ).fetchone()
    if not row or row["sess_exp"] < int(time.time()):
        return None
    return row


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


def require_csrf(request: Request, user):
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(CSRF_COOKIE)
    if not header or not cookie:
        raise HTTPException(403, "CSRF token missing")
    if not secrets.compare_digest(header, cookie):
        raise HTTPException(403, "CSRF token mismatch")
    if not secrets.compare_digest(header, user["sess_csrf"]):
        raise HTTPException(403, "CSRF token invalid")


def auth_dep(request: Request):
    user = require_user(request)
    require_csrf(request, user)
    return user


class PreflightIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    authSalt: str = Field(pattern="^[0-9a-fA-F]{32}$")
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    registrationToken: Optional[str] = None


class LoginIn(BaseModel):
    email: str
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")


class VaultItemIn(BaseModel):
    labelCt: str = Field(min_length=1, max_length=4096)
    payloadCt: str = Field(min_length=1, max_length=131072)
    pinned: bool = False


class HistoryIn(BaseModel):
    op: str = Field(pattern="^(encrypt|decrypt)$")
    previewCt: str = Field(max_length=8192)


class ChangePwIn(BaseModel):
    currentAuthHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    newAuthSalt: str = Field(pattern="^[0-9a-fA-F]{32}$")
    newAuthHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    rewrappedItems: list[dict]


class DeleteAccountIn(BaseModel):
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")


class MessageIn(BaseModel):
    recipientId: int
    ciphertext: str = Field(min_length=1, max_length=131072)
    hint: Optional[str] = Field(default=None, max_length=120)


class LookupIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class GroupCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    salt: str = Field(pattern="^[0-9a-fA-F]{32}$")
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    wrappedKey: str = Field(min_length=1, max_length=4096)


class GroupJoinIn(BaseModel):
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    wrappedKey: str = Field(min_length=1, max_length=4096)


class GroupMessageIn(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=131072)
    hint: Optional[str] = Field(default=None, max_length=120)


class PushSubscriptionIn(BaseModel):
    subscription: dict


app = FastAPI(title="ASCII Cipher Vault", openapi_url=None, docs_url=None, redoc_url=None)


@app.on_event("startup")
def _startup():
    init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "interest-cohort=(), browsing-topics=()"
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@app.post("/api/auth/preflight")
def preflight(body: PreflightIn, request: Request):
    rate_limit(f"preflight:{client_ip(request)}", 30, 60)
    email = body.email.lower().strip()
    if not EMAIL_RE.match(email):
        return {"authSalt": deterministic_salt(email), "iterations": PBKDF2_ITERATIONS}
    with db() as conn:
        row = conn.execute("SELECT auth_salt FROM users WHERE email = ?", (email,)).fetchone()
    salt_hex = row["auth_salt"].hex() if row else deterministic_salt(email)
    return {"authSalt": salt_hex, "iterations": PBKDF2_ITERATIONS}


@app.post("/api/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response):
    rate_limit(f"register:{client_ip(request)}", 10, 3600)
    if REGISTRATION_TOKEN:
        if not body.registrationToken or not secrets.compare_digest(body.registrationToken, REGISTRATION_TOKEN):
            raise HTTPException(403, "Invalid registration token")
    email = body.email.lower().strip()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email")
    salt_bytes = bytes.fromhex(body.authSalt)
    auth_hash_stored = hasher.hash(body.authHash.lower())
    now = int(time.time())
    with db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (email, auth_salt, auth_hash, created_at, last_login_at) VALUES (?,?,?,?,?)",
                (email, salt_bytes, auth_hash_stored, now, now)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Email already registered")
        user_id = cur.lastrowid
    make_session(user_id, request, response)
    return {"id": user_id, "email": email, "createdAt": now}


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response):
    rate_limit(f"login:{client_ip(request)}", 10, 60)
    email = body.email.lower().strip()
    with db() as conn:
        row = conn.execute("SELECT id, auth_hash FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    try:
        hasher.verify(row["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash):
        raise HTTPException(401, "Invalid credentials")
    make_session(row["id"], request, response)
    with db() as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (int(time.time()), row["id"]))
    return {"id": row["id"], "email": email}


@app.post("/api/auth/verify")
def verify_password(body: LoginIn, user = Depends(auth_dep)):
    if user["email"] != body.email.lower().strip():
        raise HTTPException(403, "Email mismatch")
    try:
        hasher.verify(user["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash):
        raise HTTPException(401, "Wrong password")
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    sid = request.cookies.get(SESSION_COOKIE)
    if sid:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return Response(status_code=204)


@app.get("/api/auth/me")
def me(user = Depends(require_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "authSalt": user["auth_salt"].hex(),
        "createdAt": user["created_at"],
        "lastLoginAt": user["last_login_at"],
        "iterations": PBKDF2_ITERATIONS,
    }


@app.post("/api/auth/change-password")
def change_password(body: ChangePwIn, user = Depends(auth_dep)):
    try:
        hasher.verify(user["auth_hash"], body.currentAuthHash.lower())
    except (VerifyMismatchError, InvalidHash):
        raise HTTPException(403, "Current password incorrect")
    new_salt = bytes.fromhex(body.newAuthSalt)
    new_hash = hasher.hash(body.newAuthHash.lower())
    now = int(time.time())
    with db() as conn:
        conn.execute("BEGIN")
        try:
            conn.execute("UPDATE users SET auth_salt = ?, auth_hash = ? WHERE id = ?",
                         (new_salt, new_hash, user["id"]))
            for item in body.rewrappedItems:
                if not isinstance(item, dict):
                    continue
                iid = item.get("id"); l = item.get("labelCt"); p = item.get("payloadCt")
                if not isinstance(iid, int) or not isinstance(l, str) or not isinstance(p, str):
                    continue
                conn.execute(
                    "UPDATE vault_items SET label_ct=?, payload_ct=?, updated_at=? WHERE id=? AND user_id=?",
                    (l, p, now, iid, user["id"])
                )
            conn.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (user["id"], user["sess_id"]))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise HTTPException(500, "Update failed")
    return {"ok": True}


@app.post("/api/auth/delete-account")
def delete_account(body: DeleteAccountIn, response: Response, user = Depends(auth_dep)):
    try:
        hasher.verify(user["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash):
        raise HTTPException(403, "Password incorrect")
    with db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return Response(status_code=204)


@app.get("/api/vault")
def vault_list(user = Depends(require_user)):
    with db() as conn:
        rows = conn.execute(
            """SELECT id, label_ct, payload_ct, pinned, created_at, updated_at
                 FROM vault_items WHERE user_id = ?
              ORDER BY pinned DESC, updated_at DESC""",
            (user["id"],)
        ).fetchall()
    return [{"id": r["id"], "labelCt": r["label_ct"], "payloadCt": r["payload_ct"],
             "pinned": bool(r["pinned"]), "createdAt": r["created_at"], "updatedAt": r["updated_at"]} for r in rows]


@app.post("/api/vault", status_code=201)
def vault_create(body: VaultItemIn, user = Depends(auth_dep)):
    now = int(time.time())
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO vault_items (user_id, label_ct, payload_ct, pinned, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (user["id"], body.labelCt, body.payloadCt, int(body.pinned), now, now)
        )
    return {"id": cur.lastrowid, "labelCt": body.labelCt, "payloadCt": body.payloadCt,
            "pinned": body.pinned, "createdAt": now, "updatedAt": now}


@app.put("/api/vault/{item_id}")
def vault_update(item_id: int, body: VaultItemIn, user = Depends(auth_dep)):
    now = int(time.time())
    with db() as conn:
        cur = conn.execute(
            "UPDATE vault_items SET label_ct=?, payload_ct=?, pinned=?, updated_at=? WHERE id=? AND user_id=?",
            (body.labelCt, body.payloadCt, int(body.pinned), now, item_id, user["id"])
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Not found")
    return {"id": item_id, "labelCt": body.labelCt, "payloadCt": body.payloadCt,
            "pinned": body.pinned, "updatedAt": now}


@app.delete("/api/vault/{item_id}")
def vault_delete(item_id: int, user = Depends(auth_dep)):
    with db() as conn:
        cur = conn.execute("DELETE FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Not found")
    return Response(status_code=204)


@app.get("/api/history")
def history_list(user = Depends(require_user), limit: int = 100):
    limit = max(1, min(limit, 500))
    with db() as conn:
        rows = conn.execute(
            "SELECT id, op, preview_ct, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user["id"], limit)
        ).fetchall()
    return [{"id": r["id"], "op": r["op"], "previewCt": r["preview_ct"], "createdAt": r["created_at"]} for r in rows]


@app.post("/api/history", status_code=201)
def history_add(body: HistoryIn, user = Depends(auth_dep)):
    now = int(time.time())
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO history (user_id, op, preview_ct, created_at) VALUES (?,?,?,?)",
            (user["id"], body.op, body.previewCt, now)
        )
        conn.execute(
            """DELETE FROM history WHERE user_id = ? AND id NOT IN (
                 SELECT id FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 200
               )""",
            (user["id"], user["id"])
        )
    return {"id": cur.lastrowid, "op": body.op, "previewCt": body.previewCt, "createdAt": now}


@app.delete("/api/history/{item_id}")
def history_delete(item_id: int, user = Depends(auth_dep)):
    with db() as conn:
        conn.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (item_id, user["id"]))
    return Response(status_code=204)


@app.delete("/api/history")
def history_clear(user = Depends(auth_dep)):
    with db() as conn:
        conn.execute("DELETE FROM history WHERE user_id = ?", (user["id"],))
    return Response(status_code=204)


@app.get("/api/sessions")
def sessions_list(user = Depends(require_user)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, created_at, expires_at, user_agent, ip FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
    return [{"id": r["id"], "current": r["id"] == user["sess_id"],
             "createdAt": r["created_at"], "expiresAt": r["expires_at"],
             "userAgent": r["user_agent"], "ip": r["ip"]} for r in rows]


@app.delete("/api/sessions/{sess_id}")
def sessions_revoke(sess_id: str, user = Depends(auth_dep)):
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ? AND user_id = ?", (sess_id, user["id"]))
    return Response(status_code=204)


@app.post("/api/messages/lookup")
def message_lookup(body: LookupIn, request: Request, user = Depends(auth_dep)):
    rate_limit(f"lookup:{client_ip(request)}", 30, 60)
    email = body.email.lower().strip()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email")
    if email == user["email"]:
        raise HTTPException(400, "Cannot message yourself")
    with db() as conn:
        row = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        raise HTTPException(404, "No account with that email")
    return {"id": row["id"], "email": row["email"]}


@app.get("/api/messages/threads")
def message_threads(user = Depends(require_user)):
    uid = user["id"]
    with db() as conn:
        rows = conn.execute("""
            WITH peers AS (
              SELECT recipient_id AS peer_id FROM messages
                WHERE sender_id = ? AND deleted_by_sender = 0
              UNION
              SELECT sender_id AS peer_id FROM messages
                WHERE recipient_id = ? AND deleted_by_recipient = 0
            )
            SELECT p.peer_id, u.email,
              (SELECT COUNT(*) FROM messages
                 WHERE recipient_id = ? AND sender_id = p.peer_id
                   AND read_at IS NULL AND deleted_by_recipient = 0) AS unread,
              (SELECT MAX(created_at) FROM messages
                 WHERE ((sender_id = ? AND recipient_id = p.peer_id AND deleted_by_sender = 0)
                     OR (sender_id = p.peer_id AND recipient_id = ? AND deleted_by_recipient = 0))) AS last_at
              FROM peers p JOIN users u ON u.id = p.peer_id
             ORDER BY last_at DESC
        """, (uid, uid, uid, uid, uid)).fetchall()
    return [{"peerId": r["peer_id"], "peerEmail": r["email"],
             "unread": r["unread"], "lastAt": r["last_at"]} for r in rows]


@app.get("/api/messages")
def messages_list(peer: int, limit: int = 200, user = Depends(require_user)):
    limit = max(1, min(limit, 500))
    uid = user["id"]
    with db() as conn:
        rows = conn.execute("""
            SELECT id, sender_id, recipient_id, ciphertext, hint, created_at, read_at
              FROM messages
             WHERE ((sender_id = ? AND recipient_id = ? AND deleted_by_sender = 0)
                 OR (sender_id = ? AND recipient_id = ? AND deleted_by_recipient = 0))
             ORDER BY created_at DESC
             LIMIT ?
        """, (uid, peer, peer, uid, limit)).fetchall()
    return [{
        "id": r["id"],
        "fromMe": r["sender_id"] == uid,
        "senderId": r["sender_id"],
        "recipientId": r["recipient_id"],
        "ciphertext": r["ciphertext"],
        "hint": r["hint"],
        "createdAt": r["created_at"],
        "readAt": r["read_at"],
    } for r in rows]


@app.post("/api/messages", status_code=201)
def message_send(body: MessageIn, user = Depends(auth_dep)):
    if body.recipientId == user["id"]:
        raise HTTPException(400, "Cannot message yourself")
    with db() as conn:
        peer = conn.execute("SELECT id FROM users WHERE id = ?", (body.recipientId,)).fetchone()
        if not peer:
            raise HTTPException(404, "Recipient not found")
        now = int(time.time())
        cur = conn.execute(
            "INSERT INTO messages (sender_id, recipient_id, ciphertext, hint, created_at) VALUES (?,?,?,?,?)",
            (user["id"], body.recipientId, body.ciphertext, body.hint, now)
        )
    return {"id": cur.lastrowid, "createdAt": now}


@app.post("/api/messages/{msg_id}/read")
def message_mark_read(msg_id: int, user = Depends(auth_dep)):
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "UPDATE messages SET read_at = ? WHERE id = ? AND recipient_id = ? AND read_at IS NULL",
            (now, msg_id, user["id"])
        )
    return {"ok": True}


@app.delete("/api/messages/{msg_id}")
def message_delete(msg_id: int, user = Depends(auth_dep)):
    with db() as conn:
        row = conn.execute(
            "SELECT sender_id, recipient_id FROM messages WHERE id = ?", (msg_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        if row["sender_id"] == user["id"]:
            conn.execute("UPDATE messages SET deleted_by_sender = 1 WHERE id = ?", (msg_id,))
        elif row["recipient_id"] == user["id"]:
            conn.execute("UPDATE messages SET deleted_by_recipient = 1 WHERE id = ?", (msg_id,))
        else:
            raise HTTPException(403, "Not your message")
        conn.execute(
            "DELETE FROM messages WHERE id = ? AND deleted_by_sender = 1 AND deleted_by_recipient = 1",
            (msg_id,)
        )
    return Response(status_code=204)


@app.get("/api/messages/unread-count")
def unread_count(user = Depends(require_user)):
    uid = user["id"]
    with db() as conn:
        dm = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NULL AND deleted_by_recipient = 0",
            (uid,)
        ).fetchone()[0]
        grp = conn.execute("""
            SELECT COALESCE(SUM(c), 0) FROM (
              SELECT (SELECT COUNT(*) FROM group_messages
                        WHERE group_id = gm.group_id
                          AND created_at > gm.last_read_at
                          AND sender_id != ?) AS c
                FROM group_members gm
               WHERE gm.user_id = ?
            )
        """, (uid, uid)).fetchone()[0]
    return {"unread": dm + (grp or 0)}


@app.post("/api/push-subscription", status_code=201)
def register_push_subscription(body: PushSubscriptionIn, request: Request, user = Depends(require_user)):
    import json
    user_agent = request.headers.get("user-agent", "unknown")
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "INSERT INTO push_subscriptions (user_id, subscription_json, user_agent, created_at) VALUES (?,?,?,?)",
            (user["id"], json.dumps(body.subscription), user_agent, now)
        )
    return {"ok": True}


def _require_group_member(conn, group_id: int, user_id: int):
    row = conn.execute(
        "SELECT wrapped_key, last_read_at FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    if not row:
        raise HTTPException(403, "Not a member of this group")
    return row


@app.post("/api/groups", status_code=201)
def group_create(body: GroupCreateIn, user = Depends(auth_dep)):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Name required")
    salt_bytes = bytes.fromhex(body.salt)
    verifier = hasher.hash(body.authHash.lower())
    now = int(time.time())
    with db() as conn:
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                "INSERT INTO groups (name, salt, verifier_hash, created_by, created_at) VALUES (?,?,?,?,?)",
                (name, salt_bytes, verifier, user["id"], now)
            )
            gid = cur.lastrowid
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, wrapped_key, joined_at, last_read_at) VALUES (?,?,?,?,?)",
                (gid, user["id"], body.wrappedKey, now, now)
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise HTTPException(500, "Could not create group")
    return {"id": gid, "name": name, "salt": body.salt, "createdAt": now}


@app.get("/api/groups")
def groups_list(user = Depends(require_user)):
    uid = user["id"]
    with db() as conn:
        rows = conn.execute("""
            SELECT g.id, g.name, g.salt, gm.wrapped_key, gm.last_read_at,
                   (SELECT MAX(created_at) FROM group_messages WHERE group_id = g.id) AS last_at,
                   (SELECT COUNT(*) FROM group_messages
                      WHERE group_id = g.id AND created_at > gm.last_read_at AND sender_id != ?) AS unread
              FROM group_members gm
              JOIN groups g ON g.id = gm.group_id
             WHERE gm.user_id = ?
             ORDER BY COALESCE(last_at, gm.joined_at) DESC
        """, (uid, uid)).fetchall()
    return [{
        "id": r["id"],
        "name": r["name"],
        "salt": r["salt"].hex(),
        "wrappedKey": r["wrapped_key"],
        "lastAt": r["last_at"],
        "unread": r["unread"],
    } for r in rows]


@app.get("/api/groups/{group_id}/preflight")
def group_preflight(group_id: int, user = Depends(require_user)):
    with db() as conn:
        row = conn.execute("SELECT id, name, salt FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    return {"id": row["id"], "name": row["name"], "salt": row["salt"].hex()}


@app.post("/api/groups/{group_id}/join", status_code=201)
def group_join(group_id: int, body: GroupJoinIn, request: Request, user = Depends(auth_dep)):
    rate_limit(f"groupjoin:{client_ip(request)}", 20, 60)
    with db() as conn:
        g = conn.execute("SELECT verifier_hash FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not g:
            raise HTTPException(404, "Group not found")
        try:
            hasher.verify(g["verifier_hash"], body.authHash.lower())
        except (VerifyMismatchError, InvalidHash):
            raise HTTPException(403, "Wrong join code")
        now = int(time.time())
        existing = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user["id"])
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE group_members SET wrapped_key = ? WHERE group_id = ? AND user_id = ?",
                (body.wrappedKey, group_id, user["id"])
            )
        else:
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, wrapped_key, joined_at, last_read_at) VALUES (?,?,?,?,?)",
                (group_id, user["id"], body.wrappedKey, now, now)
            )
    return {"ok": True}


@app.post("/api/groups/{group_id}/leave")
def group_leave(group_id: int, user = Depends(auth_dep)):
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user["id"]))
        remaining = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id = ?", (group_id,)).fetchone()[0]
        if remaining == 0:
            conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    return Response(status_code=204)


@app.get("/api/groups/{group_id}/messages")
def group_messages_list(group_id: int, limit: int = 200, user = Depends(require_user)):
    limit = max(1, min(limit, 500))
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        rows = conn.execute("""
            SELECT id, sender_id, ciphertext, hint, created_at
              FROM group_messages
             WHERE group_id = ?
             ORDER BY created_at DESC
             LIMIT ?
        """, (group_id, limit)).fetchall()
        senders = {r["sender_id"] for r in rows if r["sender_id"] is not None}
        emails = {}
        if senders:
            qmarks = ",".join("?" * len(senders))
            for u in conn.execute(f"SELECT id, email FROM users WHERE id IN ({qmarks})", tuple(senders)).fetchall():
                emails[u["id"]] = u["email"]
    return [{
        "id": r["id"],
        "fromMe": r["sender_id"] == user["id"],
        "senderId": r["sender_id"],
        "senderEmail": emails.get(r["sender_id"]),
        "ciphertext": r["ciphertext"],
        "hint": r["hint"],
        "createdAt": r["created_at"],
    } for r in rows]


@app.post("/api/groups/{group_id}/messages", status_code=201)
def group_message_send(group_id: int, body: GroupMessageIn, user = Depends(auth_dep)):
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        now = int(time.time())
        cur = conn.execute(
            "INSERT INTO group_messages (group_id, sender_id, ciphertext, hint, created_at) VALUES (?,?,?,?,?)",
            (group_id, user["id"], body.ciphertext, body.hint, now)
        )
    return {"id": cur.lastrowid, "createdAt": now}


@app.post("/api/groups/{group_id}/read")
def group_mark_read(group_id: int, user = Depends(auth_dep)):
    now = int(time.time())
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        conn.execute(
            "UPDATE group_members SET last_read_at = ? WHERE group_id = ? AND user_id = ?",
            (now, group_id, user["id"])
        )
    return {"ok": True}


@app.delete("/api/groups/{group_id}/messages/{msg_id}")
def group_message_delete(group_id: int, msg_id: int, user = Depends(auth_dep)):
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        row = conn.execute(
            "SELECT sender_id FROM group_messages WHERE id = ? AND group_id = ?", (msg_id, group_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        if row["sender_id"] != user["id"]:
            raise HTTPException(403, "Not your message")
        conn.execute("DELETE FROM group_messages WHERE id = ?", (msg_id,))
    return Response(status_code=204)

@app.get("/api/health")
def health():
    return {"ok": True, "time": int(time.time())}


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index_root():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/standalone")
    def standalone():
        f = STATIC_DIR / "cipher.html"
        if not f.is_file():
            raise HTTPException(404)
        return FileResponse(f)
