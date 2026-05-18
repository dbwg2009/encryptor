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
import logging
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

# List of email addresses that should be registered as moderators.
# Set via CIPHER_MODERATOR_EMAILS environment variable (comma-separated emails).
# Example: export CIPHER_MODERATOR_EMAILS="mod1@example.com,mod2@example.com"
# If not set, all registered users will be regular users (role='user')
MODERATOR_EMAILS = {
    email.strip().lower()
    for email in os.environ.get("CIPHER_MODERATOR_EMAILS", "").split(",")
    if email.strip()
}

START_TIME = int(time.time())

# Group invite tokens expire after 7 days
GROUP_INVITE_TTL = 7 * 24 * 60 * 60

logger = logging.getLogger(__name__)

hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  auth_salt BLOB NOT NULL,
  auth_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  suspended_until INTEGER,
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
  reply_to_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
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
  reply_to_id INTEGER REFERENCES group_messages(id) ON DELETE SET NULL,
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

CREATE TABLE IF NOT EXISTS blocked_users (
  blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (blocker_id, blocked_id)
);
CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked ON blocked_users(blocked_id);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  reported_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
  group_message_id INTEGER REFERENCES group_messages(id) ON DELETE SET NULL,
  reason TEXT NOT NULL,
  details TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_reported_user ON reports(reported_user_id);

CREATE TABLE IF NOT EXISTS archived_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_msg_id INTEGER NOT NULL,
  sender_id INTEGER,
  recipient_id INTEGER,
  ciphertext TEXT NOT NULL,
  hint TEXT,
  created_at INTEGER NOT NULL,
  archived_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_archived_messages_sender ON archived_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_archived_messages_recipient ON archived_messages(recipient_id);

CREATE TABLE IF NOT EXISTS login_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_user ON media(user_id);

-- Tracks which users are authorised to download a given media file.
-- The uploader is inserted automatically on upload; additional recipients
-- are added when the uploader sends a message that references the media.
CREATE TABLE IF NOT EXISTS media_access (
  media_id TEXT NOT NULL REFERENCES media(id) ON DELETE CASCADE,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (media_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_media_access_user ON media_access(user_id);

-- Pending group invitations.  The inviter pre-wraps the group key for the
-- invitee and stores it here; the invitee redeems the token to join without
-- needing the group passphrase.
CREATE TABLE IF NOT EXISTS group_invites (
  token       TEXT PRIMARY KEY,
  group_id    INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  inviter_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invitee_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_key TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  accepted_at INTEGER,
  UNIQUE (group_id, invitee_id)   -- one pending invite per (group, invitee) pair
);
CREATE INDEX IF NOT EXISTS idx_group_invites_invitee ON group_invites(invitee_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_group_invites_group   ON group_invites(group_id);
CREATE TABLE IF NOT EXISTS mod_actions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  mod_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action      TEXT NOT NULL,
  reason      TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_actions_mod ON mod_actions(mod_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mod_actions_target ON mod_actions(target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mod_actions_time ON mod_actions(created_at DESC);
CREATE TABLE IF NOT EXISTS appeals (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status      TEXT NOT NULL DEFAULT 'pending',
  reason      TEXT NOT NULL,
  response    TEXT,
  created_at  INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_appeals_user ON appeals(user_id);
CREATE INDEX IF NOT EXISTS idx_appeals_status ON appeals(status, created_at DESC);
"""


def _migrate(conn):
    """Apply additive column migrations safely."""
    migrations = [
        ("users",          "role", "TEXT NOT NULL DEFAULT 'user'"),
        ("users",          "status", "TEXT NOT NULL DEFAULT 'active'"),
        ("users",          "suspended_until", "INTEGER"),
        ("messages",       "reply_to_id", "INTEGER REFERENCES messages(id) ON DELETE SET NULL"),
        ("group_messages", "reply_to_id", "INTEGER REFERENCES group_messages(id) ON DELETE SET NULL"),
        ("push_subscriptions", None, None),  # table-level check only
    ]
    existing_tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for table, col, coldef in migrations:
        if col is None:
            continue
        if table not in existing_tables:
            continue
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coldef}")


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


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


def is_super_moderator(user: sqlite3.Row) -> bool:
    return user["role"] == "super_moderator"


def is_moderator_row(user: sqlite3.Row) -> bool:
    return user["role"] in ("moderator", "super_moderator")


def current_user(request: Request) -> Optional[sqlite3.Row]:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    with db() as conn:
        row = conn.execute(
            """SELECT u.id, u.email, u.auth_salt, u.auth_hash, u.role, u.status,
                      u.created_at, u.last_login_at,
                      s.id AS sess_id, s.csrf AS sess_csrf, s.expires_at AS sess_exp
                 FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.id = ?""",
            (sid,)
        ).fetchone()
    if not row or row["sess_exp"] < int(time.time()) or row["status"] == "banned":
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


def require_active_user(request: Request, user = Depends(require_user)):
    require_csrf(request, user)
    if user["status"] != "active":
        raise HTTPException(403, "Account suspended")
    return user


def require_moderator(user = Depends(require_active_user)):
    if not is_moderator_row(user):
        raise HTTPException(403, "Moderator access required")
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


class BaseMessageIn(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=131072)
    hint: Optional[str] = Field(default=None, max_length=120)
    replyToId: Optional[int] = None
    mediaIds: Optional[list[str]] = Field(default=None, max_items=20)


class MessageIn(BaseMessageIn):
    recipientId: int


class GroupMessageIn(BaseMessageIn):
    pass


class GroupCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    salt: str = Field(pattern="^[0-9a-fA-F]{32}$")
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    wrappedKey: str = Field(min_length=1, max_length=4096)


class GroupJoinIn(BaseModel):
    authHash: str = Field(pattern="^[0-9a-fA-F]{64}$")
    wrappedKey: str = Field(min_length=1, max_length=4096)


class PushSubscriptionIn(BaseModel):
    subscription: dict


class BlockIn(BaseModel):
    userId: int


class ReportIn(BaseModel):
    reportedUserId: Optional[int] = None
    messageId: Optional[int] = None
    groupMessageId: Optional[int] = None
    reason: str = Field(min_length=1, max_length=500)
    details: Optional[str] = Field(default=None, max_length=2000)


class ModUserActionIn(BaseModel):
    action: str = Field(..., pattern="^(suspend|ban|restore|approve|reject)$")
    duration_days: Optional[int] = Field(default=7, ge=1, le=365)  # For suspend action only
    reason: Optional[str] = Field(default=None, max_length=500)


class ModChangeRoleIn(BaseModel):
    new_role: str = Field(..., pattern="^(user|moderator|super_moderator)$")


class InviteToGroupIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    # The inviter must pre-wrap the group key for the invitee's public key
    # (or derive it via the group passphrase on the client) before sending.
    wrappedKeyForInvitee: str = Field(min_length=1, max_length=4096)


class AcceptInviteIn(BaseModel):
    # The invitee may optionally re-wrap the key (e.g. to a different local
    # key format); if omitted the server uses the key the inviter stored.
    wrappedKey: Optional[str] = Field(default=None, min_length=1, max_length=4096)


class LookupIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)


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
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
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
    role = "moderator" if email in MODERATOR_EMAILS else "user"
    with db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (email, auth_salt, auth_hash, role, status, created_at, last_login_at) VALUES (?,?,?,?,?,?,?)",
                (email, salt_bytes, auth_hash_stored, role, "active", now, now)
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
    now = int(time.time())
    with db() as conn:
        row = conn.execute("SELECT id, auth_hash, status, suspended_until FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    if row["status"] == "banned":
        raise HTTPException(403, "Account banned")
    # Auto-restore if suspension expired
    if row["status"] == "suspended" and row["suspended_until"] and row["suspended_until"] <= now:
        with db() as conn:
            conn.execute("UPDATE users SET status = 'active', suspended_until = NULL WHERE id = ?", (row["id"],))
    elif row["status"] == "suspended":
        raise HTTPException(403, "Account suspended")
    try:
        hasher.verify(row["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash) as err:
        raise HTTPException(401, "Invalid credentials") from err
    make_session(row["id"], request, response)
    _log_login(row["id"], request)
    with db() as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, row["id"]))
    return {"id": row["id"], "email": email}


@app.post("/api/auth/verify")
def verify_password(body: LoginIn, user = Depends(auth_dep)):
    if user["email"] != body.email.lower().strip():
        raise HTTPException(403, "Email mismatch")
    try:
        hasher.verify(user["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash) as err:
        raise HTTPException(401, "Wrong password") from err
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
        "role": user["role"],
        "status": user["status"],
        "isModerator": is_moderator_row(user),
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
    now = int(time.time())
    with db() as conn:
        # Archive sent and received DMs before delete
        try:
            conn.execute("""
                INSERT INTO archived_messages (original_msg_id, sender_id, recipient_id, ciphertext, hint, created_at, archived_at)
                SELECT id, sender_id, recipient_id, ciphertext, hint, created_at, ?
                FROM messages WHERE sender_id = ? OR recipient_id = ?
            """, (now, user["id"], user["id"]))
        except Exception:
            pass  # Archive may fail if table doesn't exist yet
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


def _fire_push(recipient_ids: list, title: str, body_text: str):
    """Fire-and-forget push notification to a list of user IDs (runs in background thread)."""
    import json, threading
    def _send():
        for uid in recipient_ids:
            try:
                with db() as conn:
                    subs = conn.execute(
                        "SELECT id, subscription_json FROM push_subscriptions WHERE user_id = ?",
                        (uid,)
                    ).fetchall()
                for sub in subs:
                    try:
                        sub_data = json.loads(sub["subscription_json"])
                        endpoint = sub_data.get("endpoint", "")
                        # Real Web Push would POST to endpoint with encrypted payload.
                        # Requires VAPID keys + pywebpush library. Logged for now.
                        print(f"[push] → {endpoint[:60]}… | {title}: {body_text[:40]}")
                    except Exception as e:
                        print(f"[push] error: {e}")
            except Exception as e:
                print(f"[push] db error: {e}")
    threading.Thread(target=_send, daemon=True).start()


def _grant_media_access(conn, media_ids: list[str], uploader_id: int, recipient_ids: list[int]):
    """Grant recipients access to uploaded media owned by uploader_id."""

    if not media_ids or not recipient_ids:
        return

    now = int(time.time())

    deduped_media_ids = list(dict.fromkeys(media_ids))
    deduped_recipient_ids = list(dict.fromkeys(recipient_ids))

    for mid in deduped_media_ids:
        if not re.match(r"^[A-Za-z0-9_\-]{1,64}$", mid):
            logger.warning("Rejected invalid media_id during grant: %s", mid)
            continue

        row = conn.execute(
            "SELECT user_id FROM media WHERE id = ?",
            (mid,),
        ).fetchone()

        if not row or row["user_id"] != uploader_id:
            logger.warning(
                "Unauthorized media access grant attempt (media_id=%s uploader_id=%s)",
                mid,
                uploader_id,
            )
            continue

        values = [(mid, uid, now) for uid in deduped_recipient_ids]

        try:
            conn.executemany(
                "INSERT OR IGNORE INTO media_access "
                "(media_id, user_id, granted_at) VALUES (?,?,?)",
                values,
            )
        except sqlite3.DatabaseError:
            logger.exception(
                "Failed granting media access during INSERT OR IGNORE into media_access "
                "(media_id=%s recipient_count=%s granted_at=%s)",
                mid,
                len(deduped_recipient_ids),
                now,
            )
            raise


@app.post("/api/messages", status_code=201)
def message_send(body: MessageIn, user = Depends(require_active_user)):
    if body.recipientId == user["id"]:
        raise HTTPException(400, "Cannot message yourself")
    with db() as conn:
        peer = conn.execute("SELECT id FROM users WHERE id = ?", (body.recipientId,)).fetchone()
        if not peer:
            raise HTTPException(404, "Recipient not found")
        now = int(time.time())
        cur = conn.execute(
            "INSERT INTO messages (sender_id, recipient_id, ciphertext, hint, reply_to_id, created_at) VALUES (?,?,?,?,?,?)",
            (user["id"], body.recipientId, body.ciphertext, body.hint, body.replyToId, now)
        )
        # Grant recipient access to any attached media files.
        if body.mediaIds:
            _grant_media_access(conn, body.mediaIds, user["id"], [body.recipientId])
    _fire_push([body.recipientId], f"New message from {user['email']}", body.hint or "encrypted message")
    return {"id": cur.lastrowid, "createdAt": now}


@app.post("/api/messages/{msg_id}/read")
def message_mark_read(msg_id: int, user = Depends(require_active_user)):
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "UPDATE messages SET read_at = ? WHERE id = ? AND recipient_id = ? AND read_at IS NULL",
            (now, msg_id, user["id"])
        )
    return {"ok": True}


@app.delete("/api/messages/{msg_id}")
def message_delete(msg_id: int, user = Depends(require_active_user)):
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
def group_join(group_id: int, body: GroupJoinIn, request: Request, user = Depends(require_active_user)):
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
def group_leave(group_id: int, user = Depends(require_active_user)):
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user["id"]))
        remaining = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id = ?", (group_id,)).fetchone()[0]
        if remaining == 0:
            conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    return Response(status_code=204)


@app.get("/api/groups/{group_id}/messages")
def group_messages_list(group_id: int, limit: int = 200, user = Depends(require_active_user)):
    limit = max(1, min(limit, 500))
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        rows = conn.execute("""
            SELECT id, sender_id, ciphertext, hint, reply_to_id, created_at
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
        "replyToId": r["reply_to_id"],
        "createdAt": r["created_at"],
    } for r in rows]


@app.post("/api/groups/{group_id}/messages", status_code=201)
def group_message_send(group_id: int, body: GroupMessageIn, user = Depends(require_active_user)):
    with db() as conn:
        _require_group_member(conn, group_id, user["id"])
        now = int(time.time())
        cur = conn.execute(
            "INSERT INTO group_messages (group_id, sender_id, ciphertext, hint, reply_to_id, created_at) VALUES (?,?,?,?,?,?)",
            (group_id, user["id"], body.ciphertext, body.hint, body.replyToId, now)
        )
        members = conn.execute(
            "SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?",
            (group_id, user["id"])
        ).fetchall()
        member_ids = [m["user_id"] for m in members]
        # Grant all current group members access to any attached media.
        if body.mediaIds:
            _grant_media_access(conn, body.mediaIds, user["id"], member_ids)

    _fire_push(member_ids, "New group message", body.hint or "encrypted message")
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
def group_message_delete(group_id: int, msg_id: int, user = Depends(require_active_user)):
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


# ── Group invites ──────────────────────────────────────────────────────────────

def _get_valid_invite(conn, token: str, now: int):
    row = conn.execute(
        """
        SELECT gi.group_id,
               gi.invitee_id,
               gi.inviter_id,
               gi.wrapped_key,
               gi.expires_at,
               gi.accepted_at,
               g.name AS group_name,
               u.email AS inviter_email
          FROM group_invites gi
          JOIN groups g ON g.id = gi.group_id
          JOIN users u ON u.id = gi.inviter_id
         WHERE gi.token = ?
        """,
        (token,),
    ).fetchone()

    if not row:
        raise HTTPException(404, "Invite not found")

    if row["expires_at"] < now:
        raise HTTPException(410, "Invite has expired")

    if row["accepted_at"] is not None:
        raise HTTPException(410, "Invite has already been accepted")

    return row



@app.post("/api/groups/{group_id}/invite", status_code=201)
def invite_to_group(group_id: int, body: InviteToGroupIn, request: Request, user = Depends(auth_dep)):
    """
    Create a time-limited invite for another registered user.

    The inviter must already be a group member and must supply
    `wrappedKeyForInvitee`: the group key wrapped for the invitee (e.g.
    encrypted to their public key or re-derived from the group passphrase
    on the client).  The invitee redeems the invite via POST /api/invites/{token}/accept
    — they never need to know the group passphrase.
    """
    rate_limit(f"invite:{client_ip(request)}", 20, 60)
    email = body.email.lower().strip()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email")
    now = int(time.time())
    with db() as conn:
        # Caller must be a member.
        _require_group_member(conn, group_id, user["id"])

        target = conn.execute(
            "SELECT id, email FROM users WHERE email = ?", (email,)
        ).fetchone()
        if not target:
            raise HTTPException(404, "No account with that email")
        if target["id"] == user["id"]:
            raise HTTPException(400, "Cannot invite yourself")

        # Check the invitee is not already a member.
        already = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, target["id"])
        ).fetchone()
        if already:
            raise HTTPException(409, "User is already a member of this group")

        token = secrets.token_urlsafe(32)
        expires_at = now + GROUP_INVITE_TTL
        try:
            conn.execute(
                """INSERT INTO group_invites
                     (token, group_id, inviter_id, invitee_id, wrapped_key, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(group_id, invitee_id) DO UPDATE SET
                     token       = excluded.token,
                     inviter_id  = excluded.inviter_id,
                     wrapped_key = excluded.wrapped_key,
                     created_at  = excluded.created_at,
                     expires_at  = excluded.expires_at,
                     accepted_at = NULL
                """,
                (token, group_id, user["id"], target["id"],
                 body.wrappedKeyForInvitee, now, expires_at)
            )
        except sqlite3.IntegrityError as err:
            raise HTTPException(500, "Could not create invite") from err

    # In a real deployment you would email the token to target["email"] here.
    return {
        "token": token,
        "inviteeEmail": target["email"],
        "expiresAt": expires_at,
    }


@app.get("/api/invites/{token}")
def invite_info(token: str, user = Depends(require_user)):
    """
    Return public metadata about a pending invite so the client can show a
    confirmation screen before the invitee accepts.
    """
    now = int(time.time())

    with db() as conn:
        row = _get_valid_invite(conn, token, now)

    if user["id"] not in (row["invitee_id"], row["inviter_id"]):
        raise HTTPException(403, "Not your invite")

    return {
        "groupId": row["group_id"],
        "groupName": row["group_name"],
        "inviterEmail": row["inviter_email"],
        "expiresAt": row["expires_at"],
    }


@app.post("/api/invites/{token}/accept", status_code=201)
def accept_invite(token: str, body: AcceptInviteIn, user = Depends(auth_dep)):
    """
    Redeem a pending group invite.
    """
    now = int(time.time())

    with db() as conn:
        row = _get_valid_invite(conn, token, now)

        if row["invitee_id"] != user["id"]:
            raise HTTPException(403, "This invite is not for you")

        group_id = row["group_id"]
        wrapped_key = body.wrappedKey or row["wrapped_key"]

        conn.execute("BEGIN")

        try:
            existing = conn.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group_id, user["id"]),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE group_members "
                    "SET wrapped_key = ? "
                    "WHERE group_id = ? AND user_id = ?",
                    (wrapped_key, group_id, user["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO group_members "
                    "(group_id, user_id, wrapped_key, joined_at, last_read_at) "
                    "VALUES (?,?,?,?,?)",
                    (group_id, user["id"], wrapped_key, now, now),
                )

            conn.execute(
                "UPDATE group_invites SET accepted_at = ? WHERE token = ?",
                (now, token),
            )

            conn.execute("COMMIT")

        except Exception:
            conn.execute("ROLLBACK")
            logger.exception(
              "Failed accepting group invite for user_id=%s group_id=%s",
               user["id"],
               group_id,
           )
            raise

        group = conn.execute(
            "SELECT name FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()

    return {
        "groupId": group_id,
        "groupName": group["name"] if group else None,
    }


@app.get("/api/invites")
def list_pending_invites(user = Depends(require_user)):
    """Return all pending (unaccepted, unexpired) invites addressed to the current user."""
    now = int(time.time())
    with db() as conn:
        rows = conn.execute(
            """SELECT gi.token, gi.group_id, g.name AS group_name,
                      u.email AS inviter_email, gi.expires_at
                 FROM group_invites gi
                 JOIN groups g ON g.id = gi.group_id
                 JOIN users  u ON u.id = gi.inviter_id
                WHERE gi.invitee_id = ?
                  AND gi.accepted_at IS NULL
                  AND gi.expires_at > ?
                ORDER BY gi.created_at DESC""",
            (user["id"], now)
        ).fetchall()
    return [{
        "token": r["token"],
        "groupId": r["group_id"],
        "groupName": r["group_name"],
        "inviterEmail": r["inviter_email"],
        "expiresAt": r["expires_at"],
    } for r in rows]


# ── Blocking ──────────────────────────────────────────────────────────────────

@app.post("/api/block", status_code=201)
def block_user(body: BlockIn, user = Depends(auth_dep)):
    if body.userId == user["id"]:
        raise HTTPException(400, "Cannot block yourself")
    now = int(time.time())
    with db() as conn:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (body.userId,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        try:
            conn.execute(
                "INSERT INTO blocked_users (blocker_id, blocked_id, created_at) VALUES (?,?,?)",
                (user["id"], body.userId, now)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Already blocked")
    return {"ok": True}


@app.delete("/api/block/{user_id}")
def unblock_user(user_id: int, user = Depends(auth_dep)):
    with db() as conn:
        conn.execute(
            "DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
            (user["id"], user_id)
        )
    return Response(status_code=204)


@app.get("/api/blocks")
def list_blocked(user = Depends(auth_dep)):
    with db() as conn:
        rows = conn.execute(
            "SELECT u.id, u.email, b.created_at FROM blocked_users b "
            "JOIN users u ON b.blocked_id = u.id WHERE b.blocker_id = ? "
            "ORDER BY b.created_at DESC",
            (user["id"],)
        ).fetchall()
    return [{"id": r["id"], "email": r["email"], "blockedAt": r["created_at"]} for r in rows]


# ── Reports ───────────────────────────────────────────────────────────────────

@app.post("/api/report", status_code=201)
def report(body: ReportIn, user = Depends(require_active_user)):
    if not body.reportedUserId and not body.messageId and not body.groupMessageId:
        raise HTTPException(400, "Must report a user or message")
    now = int(time.time())
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO reports (reporter_id, reported_user_id, message_id, group_message_id, reason, details, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (user["id"], body.reportedUserId, body.messageId, body.groupMessageId, body.reason, body.details, now)
        )
    return {"id": cur.lastrowid}


@app.get("/api/mod/stats")
def mod_stats(user = Depends(require_moderator)):
    with db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_active = conn.execute("SELECT COUNT(*) FROM users WHERE status = 'active'").fetchone()[0]
        total_suspended = conn.execute("SELECT COUNT(*) FROM users WHERE status = 'suspended'").fetchone()[0]
        total_banned = conn.execute("SELECT COUNT(*) FROM users WHERE status = 'banned'").fetchone()[0]
        total_messages = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        recent_reports = conn.execute("SELECT COUNT(*) FROM reports WHERE created_at > ?", (int(time.time()) - 86400,)).fetchone()[0]
    return {
        "totalUsers": total_users,
        "activeUsers": total_active,
        "suspendedUsers": total_suspended,
        "bannedUsers": total_banned,
        "totalMessages": total_messages,
        "totalReports": total_reports,
        "recentReports": recent_reports,
        "serverUptime": int(time.time()) - START_TIME,
        "now": int(time.time()),
    }


@app.get("/api/mod/reports")
def mod_reports(limit: int = 100, offset: int = 0, user = Depends(require_moderator)):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id, r.reason, r.details, r.created_at,
                        r.message_id, r.group_message_id,
                        r.reporter_id, rep.email AS reporter_email,
                        r.reported_user_id, tgt.email AS reported_email
                   FROM reports r
                   LEFT JOIN users rep ON rep.id = r.reporter_id
                   LEFT JOIN users tgt ON tgt.id = r.reported_user_id
                  ORDER BY r.created_at DESC LIMIT ? OFFSET ?""",
            (limit, offset)
        ).fetchall()
    return [{
        "id": r["id"],
        "reason": r["reason"],
        "details": r["details"],
        "createdAt": r["created_at"],
        "messageId": r["message_id"],
        "groupMessageId": r["group_message_id"],
        "reporterId": r["reporter_id"],
        "reporterEmail": r["reporter_email"],
        "reportedUserId": r["reported_user_id"],
        "reportedUserEmail": r["reported_email"],
    } for r in rows]


@app.get("/api/mod/users")
def mod_users(limit: int = 200, offset: int = 0, user = Depends(require_moderator)):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, email, role, status, created_at, last_login_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    return [{
        "id": r["id"],
        "email": r["email"],
        "role": r["role"],
        "status": r["status"],
        "createdAt": r["created_at"],
        "lastLoginAt": r["last_login_at"],
    } for r in rows]


@app.post("/api/mod/users/{user_id}/status")
def mod_user_status(user_id: int, body: ModUserActionIn, user = Depends(require_moderator)):
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot modify your own account")

    now = int(time.time())
    with db() as conn:
        target = conn.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")

        # Determine new status and suspended_until
        if body.action == "suspend":
            new_status = "suspended"
            suspended_until = now + (body.duration_days * 86400) if body.duration_days else now + (7 * 86400)
        elif body.action == "ban":
            new_status = "banned"
            suspended_until = None
        else:  # restore
            new_status = "active"
            suspended_until = None

        # Permission checks: only super_moderators can modify moderators
        target_is_mod = target["role"] in ("moderator", "super_moderator")
        if target_is_mod and not is_super_moderator(user):
            raise HTTPException(403, "Only super moderators can modify moderators")

        # Update user status
        conn.execute(
            "UPDATE users SET status = ?, suspended_until = ? WHERE id = ?",
            (new_status, suspended_until, user_id)
        )

        # Log action to audit log
        action_str = body.action
        if body.action == "suspend" and body.duration_days:
            action_str = f"suspend_{body.duration_days}d"

        conn.execute(
            "INSERT INTO mod_actions (mod_id, target_id, action, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], user_id, action_str, body.reason, now)
        )

        # Revoke sessions if suspending or banning
        if new_status in ("banned", "suspended"):
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    return {"ok": True}


@app.post("/api/mod/users/{user_id}/role")
def mod_change_role(user_id: int, body: ModChangeRoleIn, user = Depends(require_moderator)):
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot change your own role")
    if not is_super_moderator(user):
        raise HTTPException(403, "Only super moderators can change roles")

    now = int(time.time())
    with db() as conn:
        target = conn.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.new_role, user_id))

        # Log action to audit log
        conn.execute(
            "INSERT INTO mod_actions (mod_id, target_id, action, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], user_id, f"role_change_{body.new_role}", f"Changed from {target['role']}", now)
        )

    return {"ok": True, "newRole": body.new_role}


@app.get("/api/mod/audit-log")
def get_audit_log(user = Depends(require_moderator), limit: int = 100, offset: int = 0):
    """Get audit log of moderator actions. Limited to 100 entries by default."""
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    with db() as conn:
        # Get total count
        total = conn.execute("SELECT COUNT(*) as cnt FROM mod_actions").fetchone()["cnt"]

        # Get audit log entries ordered by most recent first
        rows = conn.execute(
            """SELECT ma.id, ma.mod_id, ma.target_id, ma.action, ma.reason, ma.created_at,
                      mod_user.username as mod_username,
                      target_user.username as target_username
               FROM mod_actions ma
               LEFT JOIN users mod_user ON ma.mod_id = mod_user.id
               LEFT JOIN users target_user ON ma.target_id = target_user.id
               ORDER BY ma.created_at DESC
               LIMIT ? OFFSET ?""",
            (limit, offset)
        ).fetchall()

    entries = [
        {
            "id": r["id"],
            "modId": r["mod_id"],
            "modUsername": r["mod_username"],
            "targetId": r["target_id"],
            "targetUsername": r["target_username"],
            "action": r["action"],
            "reason": r["reason"],
            "createdAt": r["created_at"]
        }
        for r in rows
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": entries
    }


@app.post("/api/appeals")
def create_appeal(body: ModUserActionIn, user = Depends(auth_dep)):
    """Allow suspended/banned users to appeal their status."""
    now = int(time.time())
    with db() as conn:
        user_row = conn.execute("SELECT id, status FROM users WHERE id = ?", (user["id"],)).fetchone()
        if user_row["status"] == "active":
            raise HTTPException(400, "Only suspended or banned users can appeal")

        # Check if user already has a pending appeal
        existing = conn.execute(
            "SELECT id FROM appeals WHERE user_id = ? AND status = 'pending'",
            (user["id"],)
        ).fetchone()
        if existing:
            raise HTTPException(400, "You already have a pending appeal")

        # Create appeal
        conn.execute(
            "INSERT INTO appeals (user_id, status, reason, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], "pending", body.reason, now)
        )

    return {"ok": True, "message": "Appeal submitted successfully"}


@app.get("/api/mod/appeals")
def get_appeals(user = Depends(require_moderator), status: str = "pending", limit: int = 50, offset: int = 0):
    """Get appeals for moderator review."""
    # Validate status parameter to prevent SQL injection
    valid_statuses = {"pending", "approved", "rejected"}
    if status and status not in valid_statuses:
        raise HTTPException(400, "Invalid status value")

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    with db() as conn:
        # Get total count
        if status:
            total = conn.execute("SELECT COUNT(*) as cnt FROM appeals WHERE status = ?", (status,)).fetchone()["cnt"]
        else:
            total = conn.execute("SELECT COUNT(*) as cnt FROM appeals").fetchone()["cnt"]

        # Get appeals
        if status:
            rows = conn.execute(
                """SELECT a.id, a.user_id, a.status, a.reason, a.response, a.created_at, a.reviewed_at,
                          a.reviewed_by, u.email
                   FROM appeals a
                   LEFT JOIN users u ON a.user_id = u.id
                   WHERE a.status = ?
                   ORDER BY a.created_at DESC LIMIT ? OFFSET ?""",
                (status, limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT a.id, a.user_id, a.status, a.reason, a.response, a.created_at, a.reviewed_at,
                          a.reviewed_by, u.email
                   FROM appeals a
                   LEFT JOIN users u ON a.user_id = u.id
                   ORDER BY a.created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            ).fetchall()

    entries = [
        {
            "id": r["id"],
            "userId": r["user_id"],
            "userEmail": r["email"],
            "status": r["status"],
            "reason": r["reason"],
            "response": r["response"],
            "createdAt": r["created_at"],
            "reviewedAt": r["reviewed_at"]
        }
        for r in rows
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": entries
    }


@app.post("/api/mod/appeals/{appeal_id}")
def review_appeal(appeal_id: int, body: ModUserActionIn, user = Depends(require_moderator)):
    """Review and approve/reject an appeal."""
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "Action must be 'approve' or 'reject'")

    now = int(time.time())
    with db() as conn:
        appeal = conn.execute("SELECT user_id, status FROM appeals WHERE id = ?", (appeal_id,)).fetchone()
        if not appeal:
            raise HTTPException(404, "Appeal not found")
        if appeal["status"] != "pending":
            raise HTTPException(400, "Appeal already reviewed")

        if body.action == "approve":
            # Restore user
            conn.execute(
                "UPDATE users SET status = 'active', suspended_until = NULL WHERE id = ?",
                (appeal["user_id"],)
            )
            new_status = "approved"
        else:
            new_status = "rejected"

        # Update appeal
        conn.execute(
            "UPDATE appeals SET status = ?, response = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?",
            (new_status, body.reason, now, user["id"], appeal_id)
        )

        # Log action
        conn.execute(
            "INSERT INTO mod_actions (mod_id, target_id, action, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], appeal["user_id"], f"appeal_{new_status}", body.reason, now)
        )

    return {"ok": True, "status": new_status}


# ── Session management ────────────────────────────────────────────────────────────

@app.post("/api/auth/logout-all")
def logout_all(body: DeleteAccountIn, user = Depends(auth_dep)):
    """Logout all other sessions, require password (auth_hash) verification"""
    try:
        hasher.verify(user["auth_hash"], body.authHash.lower())
    except (VerifyMismatchError, InvalidHash) as err:
        raise HTTPException(401, "Wrong password") from err
    with db() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND id != ?",
            (user["id"], user["sess_id"])
        )
    return {"ok": True}


# ── Login tracking ────────────────────────────────────────────────────────────

def _log_login(user_id: int, request: Request):
    """Track login history for sign-in notifications"""
    try:
        ip = client_ip(request)
        ua = request.headers.get("user-agent", "unknown")[:500]
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT INTO login_history (user_id, ip, user_agent, created_at) VALUES (?,?,?,?)",
                (user_id, ip, ua, now)
            )
    except Exception as e:
        print(f"[login_history] error: {e}")


@app.get("/api/auth/logins")
def get_logins(user = Depends(require_user)):
    """List recent logins"""
    with db() as conn:
        rows = conn.execute(
            "SELECT ip, user_agent, created_at FROM login_history WHERE user_id = ? "
            "ORDER BY created_at DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
    return [{
        "ip": r["ip"],
        "userAgent": r["user_agent"],
        "createdAt": r["created_at"]
    } for r in rows]


# ── Media uploads (zero-knowledge: ciphertext only) ───────────────────────────

@app.post("/api/media", status_code=201)
async def media_upload(request: Request, user = Depends(auth_dep)):
    """Accept encrypted media blob and store it. Returns media_id for the recipient."""
    content_length = int(request.headers.get("content-length", 0))
    if content_length > 50 * 1024 * 1024:  # 50MB max
        raise HTTPException(413, "File too large (max 50MB)")
    body = await request.body()
    if len(body) == 0:
        raise HTTPException(400, "Empty body")
    media_dir = DB_PATH.parent / "media"
    media_dir.mkdir(parents=True, exist_ok=True)
    media_id = secrets.token_urlsafe(24)
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "INSERT INTO media (id, user_id, size_bytes, created_at) VALUES (?,?,?,?)",
            (media_id, user["id"], len(body), now)
        )
        # The uploader always has access to their own file.
        conn.execute(
            "INSERT OR IGNORE INTO media_access (media_id, user_id, granted_at) VALUES (?,?,?)",
            (media_id, user["id"], now)
        )
    (media_dir / media_id).write_bytes(body)
    return {"mediaId": media_id, "size": len(body)}


@app.get("/api/media/{media_id}")
def media_get(media_id: str, user = Depends(require_user)):
    """
    Return the raw encrypted blob.

    Access is restricted to:
      - the original uploader, and
      - any user explicitly granted access (i.e. a message recipient or group
        member whose message included this media_id).
    """
    if not re.match(r"^[A-Za-z0-9_\-]{1,64}$", media_id):
        raise HTTPException(400, "Invalid media id")
    with db() as conn:
        access = conn.execute(
            "SELECT 1 FROM media_access WHERE media_id = ? AND user_id = ?",
            (media_id, user["id"])
        ).fetchone()
    if not access:
        raise HTTPException(403, "Access denied")
    media_dir = DB_PATH.parent / "media"
    path = media_dir / media_id
    if not path.is_file():
        raise HTTPException(404, "Not found")
    return FileResponse(path, media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store"})


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
