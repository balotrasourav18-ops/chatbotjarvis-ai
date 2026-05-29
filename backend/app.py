import os, sqlite3, hashlib, secrets, time, smtplib
import logging, json, re, threading
import hmac as _hmac
import urllib.parse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from functools import wraps
import ssl
import requests
from flask import (
    Flask, request, jsonify, session as flask_session,
    redirect, g, Response, send_from_directory, url_for,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from typing import Optional, Dict, List, Any, Tuple, Callable

# ── Resolve project root (one level up from backend/) ────────────────────────
_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

load_dotenv(os.path.join(_BASE_DIR, ".env"))

# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  App bootstrap
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder = os.path.join(_BASE_DIR, "templates"),
    static_folder   = os.path.join(_BASE_DIR, "static"),
    static_url_path = "",
)

# ── Secret key ────────────────────────────────────────────────────────────────
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    if os.environ.get("PRODUCTION", "").lower() == "true":
        raise RuntimeError(
            "SECRET_KEY must be set in production. "
            "Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    _secret_key = secrets.token_hex(32)
    log.warning("SECRET_KEY not set — temporary key in use. Sessions lost on restart.")

app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    SESSION_COOKIE_SECURE      = os.environ.get("PRODUCTION", "").lower() == "true",
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24),
    WTF_CSRF_TIME_LIMIT        = None,
    WTF_CSRF_CHECK_DEFAULT     = False,
    GOOGLE_CLIENT_ID           = os.environ.get("GOOGLE_CLIENT_ID",     ""),
    GOOGLE_CLIENT_SECRET       = os.environ.get("GOOGLE_CLIENT_SECRET", ""),
)

csrf    = CSRFProtect(app)
limiter = Limiter(
    key_func       = get_remote_address,
    app            = app,
    default_limits = [],
    storage_uri    = "memory://",
)

# ─────────────────────────────────────────────────────────────────────────────
#  Admin credentials
# ─────────────────────────────────────────────────────────────────────────────

_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
_ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "")
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not _ADMIN_PASSWORD:
    if os.environ.get("PRODUCTION", "").lower() == "true":
        raise RuntimeError(
            "ADMIN_PASSWORD must be set in .env before running in production."
        )
    _ADMIN_PASSWORD = "changeme_set_ADMIN_PASSWORD_in_env"
    log.warning("ADMIN_PASSWORD not set in .env — using insecure fallback.")

log.info(
    "Admin identity loaded: username='%s'  email='%s'",
    _ADMIN_USERNAME, _ADMIN_EMAIL,
)

# Pre-generate dummy hash for timing attack prevention
_DUMMY_HASH = generate_password_hash("dummy_prevent_timing_8chars!")

# ─────────────────────────────────────────────────────────────────────────────
#  Google OAuth
# ─────────────────────────────────────────────────────────────────────────────

oauth  = OAuth(app)
google = oauth.register(
    name                = "google",
    client_id           = app.config["GOOGLE_CLIENT_ID"],
    client_secret       = app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs       = {"scope": "openid email profile"},
)

# ─────────────────────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────────────────────

DATABASE_PATH = os.environ.get(
    "DATABASE_PATH",
    os.path.join(_BASE_DIR, "jarvis.db"),
)

log.info("SQLite database: %s", DATABASE_PATH)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(
            DATABASE_PATH,
            detect_types      = sqlite3.PARSE_DECLTYPES,
            check_same_thread = False,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def _q(sql: str, params: Tuple = ()):
    cur = get_db().cursor()
    cur.execute(sql, params)
    return cur


def _commit():
    get_db().commit()


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        if exc:
            db.rollback()
        db.close()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password      TEXT,
    google_id     TEXT UNIQUE,
    avatar_url    TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'local'
                  CHECK(auth_provider IN ('local','google')),
    role          TEXT NOT NULL DEFAULT 'user'
                  CHECK(role IN ('user','admin')),
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','inactive')),
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    title         TEXT DEFAULT 'New Chat',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('user','assistant')),
    content     TEXT NOT NULL,
    tokens_used INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS donations (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT,
    razorpay_order_id   TEXT UNIQUE NOT NULL,
    razorpay_payment_id TEXT,
    amount              INTEGER NOT NULL,
    currency            TEXT NOT NULL DEFAULT 'INR',
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','completed','failed')),
    donor_name          TEXT,
    donor_email         TEXT,
    created_at          TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS otp_tokens (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    token       TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
);

CREATE TABLE IF NOT EXISTS app_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    level        TEXT NOT NULL,
    message      TEXT NOT NULL,
    endpoint     TEXT,
    user_id      TEXT,
    ip_address   TEXT,
    response_ms  INTEGER,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id     TEXT PRIMARY KEY,
    theme       TEXT NOT NULL DEFAULT 'dark',
    language    TEXT NOT NULL DEFAULT 'en',
    preferences TEXT,
    updated_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feedback (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT,
    message     TEXT NOT NULL,
    is_read     INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
    ip_address  TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_feedback_read    ON feedback(is_read);

CREATE INDEX IF NOT EXISTS idx_users_google     ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_username   ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at);
CREATE INDEX IF NOT EXISTS idx_messages_sess    ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_otp_email        ON otp_tokens(email, used);
CREATE INDEX IF NOT EXISTS idx_logs_level       ON app_logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_created     ON app_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_donations_status ON donations(status);
CREATE INDEX IF NOT EXISTS idx_donations_user   ON donations(user_id);
"""


def init_db():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    
    pw_hash  = generate_password_hash(_ADMIN_PASSWORD)
    existing = conn.execute(
        "SELECT id FROM users WHERE role='admin' LIMIT 1"
    ).fetchone()
    
    if not existing:
        conn.execute(
            "INSERT INTO users "
            "(id,username,email,password,auth_provider,role,status,created_at) "
            "VALUES (?,?,?,?,'local','admin','active',?)",
            (_uid(), _ADMIN_USERNAME, _ADMIN_EMAIL, pw_hash, _now()),
        )
        conn.commit()
        log.warning(
            "Admin account created — username='%s'  email='%s'",
            _ADMIN_USERNAME, _ADMIN_EMAIL,
        )
    else:
        conn.execute(
            "UPDATE users SET username=?,email=?,password=? WHERE role='admin'",
            (_ADMIN_USERNAME, _ADMIN_EMAIL, pw_hash),
        )
        conn.commit()
        log.info(
            "Admin synced from env — username='%s'  email='%s'",
            _ADMIN_USERNAME, _ADMIN_EMAIL,
        )
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _uid()  -> str: return secrets.token_hex(12)
def _now()  -> str: return datetime.utcnow().isoformat(timespec="seconds")


def _row(cur) -> Optional[Dict]:
    row = cur.fetchone()
    return dict(row) if row else None


def _rows(cur) -> List[Dict]:
    return [dict(r) for r in cur.fetchall()]


def _db_log(
    level:    str,
    msg:      str,
    endpoint: Optional[str] = None,
    user_id:  Optional[str] = None,
    ms:       Optional[int] = None,
    ip:       Optional[str] = None,
):
    def _write():
        try:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            conn.execute(
                "INSERT INTO app_logs "
                "(level,message,endpoint,user_id,ip_address,response_ms,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (level, msg, endpoint, user_id, ip, ms, _now()),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
    threading.Thread(target=_write, daemon=True).start()


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "unknown")


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _set_user_session(user: Dict):
    oauth_next = flask_session.pop("oauth_next", None)
    flask_session.clear()
    flask_session["user_id"]    = user["id"]
    flask_session["role"]       = user["role"]
    flask_session["email"]      = user["email"]
    flask_session["login_time"] = _now()
    if oauth_next:
        flask_session["oauth_next"] = oauth_next


VALID_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$", re.IGNORECASE)
_RZPID_RE      = re.compile(r"^[A-Za-z0-9_]{6,64}$")

_pub_cache_lock = threading.Lock()
_pub_cache: Dict[str, float] = {}
_PUB_CACHE_TTL  = 60
_PUB_CACHE_MAX  = 10_000


def _cleanup_pub_cache():
    cutoff = time.time() - _PUB_CACHE_TTL
    with _pub_cache_lock:
        expired = [k for k, v in _pub_cache.items() if v < cutoff]
        for k in expired:
            del _pub_cache[k]
        if len(_pub_cache) > _PUB_CACHE_MAX:
            for k in sorted(
                _pub_cache, key=_pub_cache.get
            )[:len(_pub_cache) - _PUB_CACHE_MAX]:
                del _pub_cache[k]


_USER_PATCH_FIELDS: Dict[str, Tuple[str, Callable[[str], bool]]] = {
    "username": ("username", lambda v: 2 <= len(v) <= 50),
    "email":    ("email",    lambda v: bool(VALID_EMAIL_RE.match(v))),
    "role":     ("role",     lambda v: v in ("user", "admin")),
    "status":   ("status",   lambda v: v in ("active", "inactive")),
}

# ─────────────────────────────────────────────────────────────────────────────
#  Auth decorators
# ─────────────────────────────────────────────────────────────────────────────

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask_session:
            if request.accept_mimetypes.accept_json:
                return jsonify(error="Authentication required"), 401
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        uid = flask_session.get("user_id")
        if not uid:
            return jsonify(error="Authentication required"), 401
        row = _row(_q("SELECT role,status FROM users WHERE id=?", (uid,)))
        if not row or row["role"] != "admin" or row["status"] != "active":
            return jsonify(error="Admin access required"), 403
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
#  CSRF cookie injection
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def inject_csrf_cookie(resp):
    if resp.content_type and "text/html" in resp.content_type:
        resp.set_cookie(
            "csrf_token", generate_csrf(),
            samesite = "Lax",
            httponly = False,
            secure   = os.environ.get("PRODUCTION", "").lower() == "true",
        )
    return resp

# ─────────────────────────────────────────────────────────────────────────────
#  Email Logic
# ─────────────────────────────────────────────────────────────────────────────

def _send_email_raw(to_email: str, subject: str, body: str) -> bool:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "").strip()
    pw   = os.environ.get("SMTP_PASS", "").strip()
    frm  = os.environ.get("SMTP_FROM", "").strip() or user

    if not host or not user or not pw:
        log.warning(
            "[DEV MODE] Email to %s: %s\n%s\n"
            "(Set SMTP_HOST, SMTP_USER, SMTP_PASS in .env to send real emails)",
            to_email, subject, body,
        )
        return True

    if not frm:
        log.error("SMTP_FROM / SMTP_USER is empty — cannot send email")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to_email
    pw_clean = pw.replace(" ", "")

    try:
        context = ssl.create_default_context()

        if port == 465:
            log.info("Sending email via SMTP_SSL to %s on port 465", to_email)
            with smtplib.SMTP_SSL(host, 465, context=context, timeout=15) as srv:
                srv.login(user, pw_clean)
                srv.sendmail(frm, [to_email], msg.as_string())

        elif port == 587:
            log.info("Sending email via STARTTLS to %s on port 587", to_email)
            with smtplib.SMTP(host, 587, timeout=15) as srv:
                srv.ehlo()
                srv.starttls(context=context)
                srv.ehlo()
                srv.login(user, pw_clean)
                srv.sendmail(frm, [to_email], msg.as_string())

        else:
            log.error("Unsupported SMTP_PORT=%d — use 465 or 587", port)
            return False

        log.info("Email sent successfully to %s", to_email)
        return True

    except Exception as exc:
        log.exception("Unexpected error sending email to %s: %s", to_email, exc)
        return False


def _send_notification_bg(email: str, subject: str, body: str):
    def _worker():
        if not email or not VALID_EMAIL_RE.match(email):
            return
        _send_email_raw(email, subject, body)
    
    threading.Thread(target=_worker, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
#  Welcome Email  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

def _send_welcome_email(email: str, username: str):
    """Send a welcome email to a newly registered user (local or Google)."""
    subject = "Welcome to Jarvis AI! "
    body = f"""Hi {username},

Welcome to Jarvis AI! We're really excited to have you here.

Your account is all set and ready to go. Here's what you can do right now:

  • Chat with Jarvis  — ask anything: coding, writing, research, and more
  • Save conversations — your full chat history is always stored for you
  • Explore features   — new tools and improvements are on the way!

Just head over to the chat and say hello — Jarvis is ready whenever you are.

If you ever run into any issues, feel free to reach out.

See you inside,
— The Jarvis AI Team

────────────────────────────────────
This is an automated message. Please do not reply to this email.
"""
    _send_notification_bg(email, subject, body)


# ─────────────────────────────────────────────────────────────────────────────
#  Password reset (OTP)
# ─────────────────────────────────────────────────────────────────────────────

def _send_otp_email(to_email: str, otp: str) -> bool:
    body = (
        f"Your Jarvis AI password-reset OTP:\n\n"
        f"  {otp}\n\n"
        f"This code expires in 10 minutes.\n\n"
        f"— Jarvis AI"
    )
    return _send_email_raw(to_email, "Jarvis AI — Password Reset OTP", body)


def _send_otp_background(email: str, otp: str, endpoint: str = "/api/forgot-password"):
    def _worker():
        success = _send_otp_email(email, otp)
        if not success:
            _db_log(
                "ERROR",
                f"OTP email delivery failed for {email} — check SMTP settings in .env",
                endpoint,
                ip=None,
            )
            log.error(
                "OTP email delivery FAILED for %s. "
                "Verify SMTP_HOST / SMTP_USER / SMTP_PASS / SMTP_PORT in your .env",
                email,
            )

    threading.Thread(target=_worker, daemon=True).start()


@app.route("/api/forgot-password", methods=["POST"])
@csrf.exempt
@limiter.limit("3 per minute; 10 per hour")
def api_forgot_password():
    data  = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email:
        return jsonify(error="Email is required"), 400
    if not VALID_EMAIL_RE.match(email):
        return jsonify(error="Invalid email address"), 400

    user = _row(_q(
        "SELECT id,auth_provider,password FROM users WHERE LOWER(email)=?",
        (email,),
    ))

    if user:
        if not user["password"]:
            _db_log(
                "INFO",
                f"Forgot-password ignored for Google-only account: {email}",
                "/api/forgot-password",
                ip=_client_ip(),
            )
            return jsonify(success=True)

        otp     = "".join(str(secrets.randbelow(10)) for _ in range(6))
        expires = (
            datetime.utcnow() + timedelta(minutes=10)
        ).isoformat(timespec="seconds")

        _q("UPDATE otp_tokens SET used=1 WHERE LOWER(email)=? AND used=0", (email,))
        _q(
            "INSERT INTO otp_tokens (id,email,token,expires_at,used) "
            "VALUES (?,?,?,?,0)",
            (_uid(), email, otp, expires),
        )
        _commit()

        _send_otp_background(email, otp)
        _db_log("INFO", f"OTP queued for: {email}",
                "/api/forgot-password", ip=_client_ip())

    return jsonify(success=True)


@app.route("/api/verify-otp", methods=["POST"])
@csrf.exempt
@limiter.limit("3 per minute; 10 per hour")
def api_verify_otp():
    data  = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    otp   = str(data.get("otp",   "")).strip()

    if not email or not VALID_EMAIL_RE.match(email):
        return jsonify(error="Valid email required"), 400
    if len(otp) != 6 or not otp.isdigit():
        return jsonify(error="OTP must be exactly 6 digits"), 400

    rec = _row(_q(
        "SELECT id,token,expires_at FROM otp_tokens "
        "WHERE LOWER(email)=? AND used=0 "
        "ORDER BY expires_at DESC LIMIT 1",
        (email,),
    ))

    stored_token = rec["token"] if rec else "000000"
    token_match  = _hmac.compare_digest(
        stored_token.encode("utf-8"),
        otp.encode("utf-8"),
    )
    not_expired = (
        rec is not None and
        datetime.fromisoformat(rec["expires_at"]) > datetime.utcnow()
    )

    if not token_match or not not_expired:
        _db_log("WARN", f"OTP verify failed for {email}",
                "/api/verify-otp", ip=_client_ip())
        return jsonify(error="Invalid or expired OTP — please try again"), 400

    _q("UPDATE otp_tokens SET used=1 WHERE id=?", (rec["id"],))
    _commit()

    flask_session["otp_verified_email"] = email
    _db_log("INFO", f"OTP verified for {email}",
            "/api/verify-otp", ip=_client_ip())
    return jsonify(success=True)


@app.route("/api/reset-password", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute")
def api_reset_password():
    data     = request.get_json(force=True, silent=True) or {}
    email    = str(data.get("email",    "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify(error="Email and new password required"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    if flask_session.get("otp_verified_email") != email:
        return jsonify(error="OTP verification required first"), 403

    _q(
        "UPDATE users SET password=? WHERE LOWER(email)=?",
        (generate_password_hash(password), email),
    )
    _q("UPDATE otp_tokens SET used=1 WHERE LOWER(email)=?", (email,))
    _commit()
    flask_session.pop("otp_verified_email", None)
    _db_log("INFO", f"Password reset: {email}",
            "/api/reset-password", ip=_client_ip())
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  AI / OpenRouter
# ─────────────────────────────────────────────────────────────────────────────

OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
CHAT_MODEL     = "nvidia/nemotron-3-super-120b-a12b:free"
EMBED_MODEL    = "nvidia/llama-nemotron-embed-vl-1b-v2:free"

SYSTEM_PROMPT = (
    "You are Jarvis, a highly capable AI assistant created to help people "
    "with coding, writing, research, learning, and problem-solving. "
    "Be concise, accurate, and friendly. "
    "Format code with proper markdown code blocks using the correct language tag. "
    "When explaining complex topics use clear analogies and structure your response. "
    "Never refuse reasonable requests."
)

OPENROUTER_HEADERS = {
    "Authorization": f"Bearer {OPENROUTER_KEY}",
    "Content-Type":  "application/json",
    "HTTP-Referer":  os.environ.get("SITE_URL", "http://localhost:5000"),
    "X-Title":       "Jarvis AI",
}


def _get_history(session_id: str, limit: int = 20) -> List[Dict]:
    rows = _rows(_q(
        "SELECT role,content FROM messages "
        "WHERE session_id=? ORDER BY created_at ASC LIMIT ?",
        (session_id, limit),
    ))
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def _ensure_chat_session(session_id, user_id: str, title: str) -> str:
    if session_id:
        row = _row(_q(
            "SELECT id FROM sessions WHERE id=? AND user_id=?",
            (session_id, user_id),
        ))
        if row:
            return session_id
    new_id = _uid()
    _q(
        "INSERT INTO sessions (id,user_id,title,created_at,updated_at) "
        "VALUES (?,?,?,?,?)",
        (new_id, user_id, title[:80] or "New Chat", _now(), _now()),
    )
    _commit()
    return new_id


def _call_openrouter(payload: Dict, timeout: int = 45) -> Dict:
    if not OPENROUTER_KEY:
        raise ValueError("OPENROUTER_API_KEY is not configured")
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers = OPENROUTER_HEADERS,
        json    = payload,
        timeout = timeout,
    )
    if resp.status_code != 200:
        body = resp.json() if resp.content else {}
        raise RuntimeError(
            (body.get("error") or {}).get("message") or f"HTTP {resp.status_code}"
        )
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
#  Chat endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
@csrf.exempt
@login_required
def api_chat():
    t0      = time.monotonic()
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]
    user_email = flask_session.get("email")

    if not message:
        return jsonify(error="Message is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long (max 8000 chars)"), 400

    sess_id = _ensure_chat_session(sess_id, user_id, message)
    _q(
        "INSERT INTO messages (id,session_id,role,content,tokens_used,created_at) "
        "VALUES (?,?,?,?,?,?)",
        (_uid(), sess_id, "user", message, _estimate_tokens(message), _now()),
    )
    _commit()

    history = _get_history(sess_id)
    payload = {
        "model":       CHAT_MODEL,
        "messages":    [{"role": "system", "content": SYSTEM_PROMPT}] + history,
        "max_tokens":  2048,
        "temperature": 0.7,
    }

    try:
        result = _call_openrouter(payload)

        if not result.get("choices") or len(result["choices"]) == 0:
            log.error("OpenRouter returned empty choices")
            return jsonify(error="AI returned an empty response"), 502

        reply = result["choices"][0]["message"]["content"]

        if not reply:
            return jsonify(error="AI generated an empty response"), 502

        _q(
            "INSERT INTO messages (id,session_id,role,content,tokens_used,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (_uid(), sess_id, "assistant", reply, _estimate_tokens(reply), _now()),
        )
        _q("UPDATE sessions SET updated_at=? WHERE id=?", (_now(), sess_id))
        _commit()

        ms = int((time.monotonic() - t0) * 1000)
        _db_log("INFO", f"Chat {ms}ms", "/api/chat", user_id, ms, ip=_client_ip())
        
        # ── Send Chat Notification Email ──────────────────────────────────────
        _send_notification_bg(
            user_email, 
            "Jarvis AI - New Message Received", 
            f"You asked: {message}\n\nJarvis replied: {reply}"
        )

        return jsonify(reply=reply, session_id=sess_id)

    except requests.Timeout:
        return jsonify(error="AI timed out — try again"), 504
    except ValueError as exc:
        return jsonify(error=str(exc)), 503
    except RuntimeError as exc:
        _db_log("ERROR", f"OpenRouter: {exc}", "/api/chat", user_id)
        return jsonify(error=str(exc)), 502
    except Exception as exc:
        _db_log("ERROR", f"Chat error: {exc}", "/api/chat", user_id)
        return jsonify(error="Failed to get AI response"), 500


@app.route("/api/chat/public", methods=["POST"])
@csrf.exempt
def api_chat_public():
    ip        = _client_ip()
    cache_key = f"pub_{ip}"
    now_      = time.time()

    _cleanup_pub_cache()

    with _pub_cache_lock:
        if now_ - _pub_cache.get(cache_key, 0) < 10:
            return jsonify(error="Too many requests — wait a moment."), 429
        _pub_cache[cache_key] = now_

    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify(error="Message is required"), 400
    if len(message) > 500:
        return jsonify(error="Max 500 chars in demo"), 400
    if not OPENROUTER_KEY:
        return jsonify(
            reply="Demo mode — set OPENROUTER_API_KEY for live responses."
        ), 200

    try:
        result = _call_openrouter({
            "model":       CHAT_MODEL,
            "messages":    [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": message},
            ],
            "max_tokens":  512,
            "temperature": 0.7,
        }, timeout=30)

        if not result.get("choices") or len(result["choices"]) == 0:
            return jsonify(error="AI returned an empty response"), 502

        return jsonify(reply=result["choices"][0]["message"]["content"])
    except requests.Timeout:
        return jsonify(error="AI timed out — try again"), 504
    except (ValueError, RuntimeError) as exc:
        return jsonify(error=str(exc)), 502
    except Exception:
        return jsonify(error="Failed to get AI response"), 500


@app.route("/api/chat/stream", methods=["POST"])
@csrf.exempt
@login_required
def api_chat_stream():
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    if not message:
        return jsonify(error="Message is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long"), 400

    sess_id = _ensure_chat_session(sess_id, user_id, message)
    _q(
        "INSERT INTO messages (id,session_id,role,content,tokens_used,created_at) "
        "VALUES (?,?,?,?,?,?)",
        (_uid(), sess_id, "user", message, _estimate_tokens(message), _now()),
    )
    _commit()
    history = _get_history(sess_id)

    def _stream():
        full_reply = ""
        try:
            payload = {
                "model":       CHAT_MODEL,
                "messages":    [
                    {"role": "system", "content": SYSTEM_PROMPT}
                ] + history,
                "max_tokens":  2048,
                "temperature": 0.7,
                "stream":      True,
            }
            yield f"data: {json.dumps({'session_id': sess_id})}\n\n"

            with requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers = OPENROUTER_HEADERS,
                json    = payload,
                stream  = True,
                timeout = 60,
            ) as r:
                for line in r.iter_lines():
                    if not line:
                        continue
                    line = line.decode("utf-8")
                    if not line.startswith("data: "):
                        continue
                    chunk = line[6:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        data = json.loads(chunk)
                        if "choices" in data and len(data["choices"]) > 0:
                            delta   = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                full_reply += content
                                yield f"data: {json.dumps({'delta': content})}\n\n"
                    except Exception:
                        pass

            yield "data: [DONE]\n\n"
            
            # ── Send Stream Chat Notification Email ───────────────────────────
            user_email = flask_session.get("email")
            if user_email:
                _send_notification_bg(
                    user_email,
                    "Jarvis AI - New Message Received",
                    f"You asked: {message}\n\nJarvis replied: {full_reply}"
                )

        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

        finally:
            if full_reply.strip():
                try:
                    conn = sqlite3.connect(
                        DATABASE_PATH, check_same_thread=False
                    )
                    conn.execute(
                        "INSERT INTO messages "
                        "(id,session_id,role,content,tokens_used,created_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (_uid(), sess_id, "assistant",
                         full_reply, _estimate_tokens(full_reply), _now()),
                    )
                    conn.execute(
                        "UPDATE sessions SET updated_at=? WHERE id=?",
                        (_now(), sess_id),
                    )
                    conn.commit()
                    conn.close()
                except Exception as exc:
                    log.error("Stream persist: %s", exc)

    return Response(
        _stream(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/embed", methods=["POST"])
@csrf.exempt
@login_required
def api_embed():
    data  = request.get_json(force=True, silent=True) or {}
    texts = data.get("texts") or []
    if isinstance(texts, str):
        texts = [texts]
    if not texts or not all(isinstance(t, str) for t in texts):
        return jsonify(error="'texts' must be a non-empty list of strings"), 400
    if len(texts) > 50:
        return jsonify(error="Max 50 texts per request"), 400
    if not OPENROUTER_KEY:
        return jsonify(error="OPENROUTER_API_KEY not configured"), 503

    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/embeddings",
            headers = OPENROUTER_HEADERS,
            json    = {"model": EMBED_MODEL, "input": texts},
            timeout = 30,
        )
        if resp.status_code != 200:
            err = (resp.json().get("error") or {}).get("message", "Embed error")
            return jsonify(error=err), 502
        result = resp.json()
        return jsonify(
            embeddings = [i["embedding"] for i in result.get("data", [])],
            model      = EMBED_MODEL,
        )
    except requests.Timeout:
        return jsonify(error="Embedding timed out"), 504
    except Exception as exc:
        _db_log("ERROR", f"Embed: {exc}",
                "/api/embed", flask_session.get("user_id"))
        return jsonify(error="Failed to generate embeddings"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Page routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")

@app.route("/feedback")
def feedback_page():
    return send_from_directory(app.template_folder, "feedback.html")

@app.route("/login")
def login_page():
    return send_from_directory(app.template_folder, "auth.html")

@app.route("/register")
@app.route("/auth/register")
def register_page():
    return send_from_directory(app.template_folder, "auth.html")

@app.route("/auth/login")
def auth_login_alias():
    return send_from_directory(app.template_folder, "auth.html")

@app.route("/chat")
@login_required
def chat_page():
    return send_from_directory(app.template_folder, "chat.html")

@app.route("/admin")
@login_required
def admin_page():
    user = _row(_q("SELECT role FROM users WHERE id=?", (flask_session["user_id"],)))
    if not user or user["role"] != "admin":
        return redirect("/chat")
    return send_from_directory(app.template_folder, "admin.html")


# ─────────────────────────────────────────────────────────────────────────────
#  Admin login
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/admin/login", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute; 15 per hour")
def api_admin_login():
    t0   = time.monotonic()
    data = request.get_json(force=True, silent=True) or {}

    identifier = (
        str(data.get("username") or data.get("email") or "")
        .strip().lower()
    )
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify(error="Username/email and password are required"), 400

    user = _row(_q(
        "SELECT * FROM users "
        "WHERE (LOWER(username)=? OR LOWER(email)=?) AND role='admin'",
        (identifier, identifier),
    ))

    stored = user["password"] if (user and user["password"]) else _DUMMY_HASH
    valid  = check_password_hash(stored, password)
    ms     = int((time.monotonic() - t0) * 1000)

    if not valid or not user:
        _db_log("WARN", f"Failed admin login — identifier='{identifier}'",
                "/api/admin/login", ms=ms, ip=_client_ip())
        return jsonify(error="Invalid admin credentials"), 401

    if user["status"] != "active":
        return jsonify(error="Admin account is disabled"), 403

    _q("UPDATE users SET last_login=? WHERE id=?", (_now(), user["id"]))
    _commit()
    _set_user_session(user)

    _db_log("INFO", f"Admin login OK — username='{user['username']}'",
            "/api/admin/login", user["id"], ms, ip=_client_ip())
    
    # ── Send Admin Login Notification Email ───────────────────────────────────
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Admin Login",
        f"Admin account '{user['username']}' logged in successfully from IP: {_client_ip()} at {_now()}."
    )
    
    return jsonify(success=True, redirect="/admin")


# ─────────────────────────────────────────────────────────────────────────────
#  Google OAuth routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/auth/google")
def google_login():
    if not app.config["GOOGLE_CLIENT_ID"]:
        return jsonify(error="Google OAuth is not configured"), 503
    flask_session["oauth_next"] = request.args.get("next", "/chat")
    return google.authorize_redirect(url_for("google_callback", _external=True))


@app.route("/auth/google/callback")
def google_callback():
    try:
        token    = google.authorize_access_token()
        userinfo = token.get("userinfo") or google.userinfo()
    except Exception as exc:
        log.warning("Google OAuth callback error: %s", exc)
        _db_log("WARN", f"Google OAuth failed: {exc}",
                "/auth/google/callback", ip=_client_ip())
        return redirect("/login?error=google_auth_failed")

    google_id = userinfo.get("sub")
    email     = (userinfo.get("email") or "").lower().strip()
    name      = userinfo.get("name") or email.split("@")[0]
    avatar    = userinfo.get("picture", "")
    verified  = userinfo.get("email_verified", False)

    if not google_id or not email:
        return redirect("/login?error=missing_google_info")
    if not verified:
        return redirect("/login?error=email_not_verified")

    user = _row(_q("SELECT * FROM users WHERE google_id=?", (google_id,)))

    if not user:
        user = _row(_q(
            "SELECT * FROM users WHERE LOWER(email)=?", (email,)
        ))
        if user:
            # Existing local account — link Google to it
            _q(
                "UPDATE users "
                "SET google_id=?,avatar_url=?,auth_provider='google',last_login=? "
                "WHERE id=?",
                (google_id, avatar, _now(), user["id"]),
            )
            _commit()
            user = _row(_q("SELECT * FROM users WHERE id=?", (user["id"],)))
        else:
            # Brand new Google user — create account and send welcome email
            user_id = _uid()
            _q(
                "INSERT INTO users "
                "(id,username,email,password,google_id,avatar_url,"
                " auth_provider,role,status,created_at,last_login) "
                "VALUES (?,?,?,NULL,?,?,'google','user','active',?,?)",
                (user_id, name, email, google_id, avatar, _now(), _now()),
            )
            _commit()
            user = _row(_q("SELECT * FROM users WHERE id=?", (user_id,)))
            _db_log("INFO", f"New Google user: {email}",
                    "/auth/google/callback", user_id, ip=_client_ip())
            # ── Welcome email for new Google signup ───────────────────────────
            _send_welcome_email(email, name)
    else:
        _q(
            "UPDATE users SET avatar_url=?,last_login=? WHERE id=?",
            (avatar, _now(), user["id"]),
        )
        _commit()

    if user["status"] != "active":
        return redirect("/login?error=account_disabled")

    _set_user_session(user)
    _db_log("INFO", f"Google login: {email}",
            "/auth/google/callback", user["id"], ip=_client_ip())
        
    # ── Send Login Notification Email ─────────────────────────────────────────
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Login Successful",
        f"Your account '{user['username']}' logged in successfully via Google from IP: {_client_ip()} at {_now()}."
    )

    next_url = flask_session.pop("oauth_next", None) or (
        "/admin" if user["role"] == "admin" else "/chat"
    )
    return redirect(next_url)


@app.route("/auth/google/unlink", methods=["POST"])
@csrf.exempt
@login_required
def google_unlink():
    user_id = flask_session["user_id"]
    user    = _row(_q(
        "SELECT password,google_id FROM users WHERE id=?", (user_id,)
    ))

    if not user:
        return jsonify(error="User not found"), 404
    if not user["google_id"]:
        return jsonify(error="Google is not linked to this account"), 400
    if not user["password"]:
        return jsonify(error="Set a local password before unlinking Google"), 400

    _q("UPDATE users SET google_id=NULL,auth_provider='local' WHERE id=?", (user_id,))
    _commit()
    _db_log("INFO", "Google unlinked", "/auth/google/unlink", user_id, ip=_client_ip())
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Regular user auth API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute; 20 per hour")
def api_register():
    data     = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    email    = str(data.get("email",    "")).strip().lower()
    password = str(data.get("password", ""))

    if not username or not email or not password:
        return jsonify(error="All fields are required"), 400
    if not VALID_EMAIL_RE.match(email):
        return jsonify(error="Invalid email address"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    if len(username) < 2 or len(username) > 50:
        return jsonify(error="Username must be 2–50 characters"), 400
    if username.lower() == _ADMIN_USERNAME.lower():
        return jsonify(error="That username is reserved"), 409

    if _row(_q("SELECT id FROM users WHERE LOWER(email)=?", (email,))):
        return jsonify(error="Email already registered"), 409

    user_id = _uid()
    _q(
        "INSERT INTO users "
        "(id,username,email,password,auth_provider,role,status,created_at) "
        "VALUES (?,?,?,?,'local','user','active',?)",
        (user_id, username, email, generate_password_hash(password), _now()),
    )
    _commit()
    flask_session["user_id"] = user_id
    flask_session["role"]    = "user"
    flask_session["email"]   = email

    _db_log("INFO", f"New user: {email}", "/api/register", user_id, ip=_client_ip())
    # ── Welcome email for manual signup ──────────────────────────────────────
    _send_welcome_email(email, username)

    return jsonify(success=True, redirect="/chat"), 201


@app.route("/api/login", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute; 50 per hour")
def api_login():
    t0   = time.monotonic()
    data = request.get_json(force=True, silent=True) or {}
    email    = str(data.get("email",    "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify(error="Email and password are required"), 400

    user = _row(_q("SELECT * FROM users WHERE LOWER(email)=?", (email,)))

    stored = user["password"] if (user and user["password"]) else _DUMMY_HASH
    valid  = check_password_hash(stored, password)
    ms     = int((time.monotonic() - t0) * 1000)

    if not valid or not user:
        _db_log("WARN", f"Failed login: {email}",
                "/api/login", ms=ms, ip=_client_ip())
        return jsonify(error="Invalid email or password"), 401

    if user["status"] != "active":
        return jsonify(error="Account disabled — contact support"), 403

    if not user["password"]:
        return jsonify(
            error="This account uses Google sign-in. Please log in with Google."
        ), 400

    _q("UPDATE users SET last_login=? WHERE id=?", (_now(), user["id"]))
    _commit()
    _set_user_session(user)

    _db_log("INFO", f"Login: {email}", "/api/login", user["id"], ms, ip=_client_ip())
    
    # ── Send Login Notification Email ─────────────────────────────────────────
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Login Successful",
        f"Your account '{user['username']}' logged in successfully from IP: {_client_ip()} at {_now()}."
    )

    dest = "/admin" if user["role"] == "admin" else "/chat"
    return jsonify(success=True, redirect=dest)


@app.route("/api/logout", methods=["POST"])
@csrf.exempt
def api_logout():
    uid = flask_session.get("user_id")
    flask_session.clear()
    _db_log("INFO", "Logout", "/api/logout", uid, ip=_client_ip())
    return jsonify(success=True)


@app.route("/api/me")
@csrf.exempt
@login_required
def api_me():
    user = _row(_q(
        "SELECT id,username,email,role,status,"
        "auth_provider,avatar_url,created_at,last_login "
        "FROM users WHERE id=?",
        (flask_session["user_id"],),
    ))
    if not user:
        flask_session.clear()
        return jsonify(error="User not found"), 401
    user["google_linked"] = bool(user.get("avatar_url"))
    return jsonify(user)


@app.route("/api/me/set-password", methods=["POST"])
@csrf.exempt
@login_required
def api_set_password():
    data   = request.get_json(force=True, silent=True) or {}
    new_pw = str(data.get("password",         ""))
    old_pw = str(data.get("current_password", ""))

    if len(new_pw) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    user_id = flask_session["user_id"]
    user    = _row(_q("SELECT password FROM users WHERE id=?", (user_id,)))
    if not user:
        return jsonify(error="User not found"), 404

    if user["password"]:
        if not old_pw:
            return jsonify(error="Current password required to set a new one"), 400
        if not check_password_hash(user["password"], old_pw):
            return jsonify(error="Current password is incorrect"), 401

    _q(
        "UPDATE users SET password=? WHERE id=?",
        (generate_password_hash(new_pw), user_id),
    )
    _commit()
    _db_log("INFO", "Password updated",
            "/api/me/set-password", user_id, ip=_client_ip())
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Sessions API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/sessions")
@csrf.exempt
@login_required
def api_list_sessions():
    rows = _rows(_q(
        "SELECT id,title,created_at,updated_at FROM sessions "
        "WHERE user_id=? ORDER BY updated_at DESC LIMIT 50",
        (flask_session["user_id"],),
    ))
    return jsonify(sessions=rows)


@app.route("/api/sessions/<sid>", methods=["GET", "PATCH", "DELETE"])
@csrf.exempt
@login_required
def api_session(sid):
    sess = _row(_q(
        "SELECT * FROM sessions WHERE id=? AND user_id=?",
        (sid, flask_session["user_id"]),
    ))
    if not sess:
        return jsonify(error="Session not found"), 404

    if request.method == "GET":
        msgs = _rows(_q(
            "SELECT role,content,created_at FROM messages "
            "WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ))
        return jsonify(session=sess, messages=msgs)

    if request.method == "PATCH":
        data  = request.get_json(force=True, silent=True) or {}
        title = str(data.get("title", "")).strip()[:100]
        if title:
            _q("UPDATE sessions SET title=?,updated_at=? WHERE id=?",
               (title, _now(), sid))
            _commit()
        return jsonify(success=True)

    _q("DELETE FROM sessions WHERE id=?", (sid,))
    _commit()
    return jsonify(success=True)


@app.route("/api/sessions/<sid>/title", methods=["PATCH"])
@csrf.exempt
@login_required
def api_patch_session_title(sid):
    sess = _row(_q(
        "SELECT id FROM sessions WHERE id=? AND user_id=?",
        (sid, flask_session["user_id"]),
    ))
    if not sess:
        return jsonify(error="Session not found"), 404

    data  = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "")).strip()[:100]
    if not title:
        return jsonify(error="Title cannot be empty"), 400

    _q("UPDATE sessions SET title=?,updated_at=? WHERE id=?",
       (title, _now(), sid))
    _commit()
    return jsonify(success=True, title=title)


@app.route("/api/sessions/<sid>/auto-title", methods=["PATCH"])
@csrf.exempt
@login_required
def api_auto_title(sid):
    sess = _row(_q(
        "SELECT id FROM sessions WHERE id=? AND user_id=?",
        (sid, flask_session["user_id"]),
    ))
    if not sess:
        return jsonify(error="Session not found"), 404

    first = _row(_q(
        "SELECT content FROM messages "
        "WHERE session_id=? AND role='user' "
        "ORDER BY created_at ASC LIMIT 1",
        (sid,),
    ))
    if first:
        raw   = first["content"]
        title = (raw[:57] + "…") if len(raw) > 60 else raw
        _q("UPDATE sessions SET title=?,updated_at=? WHERE id=?",
           (title, _now(), sid))
        _commit()
    return jsonify(success=True)



# ─────────────────────────────────────────────────────────────────────────────
#  Donations (Razorpay)
# ─────────────────────────────────────────────────────────────────────────────

RZP_KEY_ID     = os.environ.get("RAZORPAY_KEY_ID",     "")
RZP_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")

_rzp_client = None
if RZP_KEY_ID and RZP_KEY_SECRET:
    try:
        import razorpay as _rzp_mod
        _rzp_client = _rzp_mod.Client(auth=(RZP_KEY_ID, RZP_KEY_SECRET))
        log.info("Razorpay ready (key: %s…)", RZP_KEY_ID[:8])
    except ImportError:
        log.warning("razorpay not installed — run: pip install razorpay")
else:
    log.warning("RAZORPAY_KEY_ID/SECRET not set — donations disabled")


@app.route("/api/donations/create-order", methods=["POST"])
@csrf.exempt
def api_donation_create():
    data = request.get_json(force=True, silent=True) or {}
    try:
        amount = int(data.get("amount", 0))
    except (ValueError, TypeError):
        return jsonify(error="Invalid amount"), 400

    if amount < 100:
        return jsonify(error="Minimum donation ₹1 (100 paise)"), 400
    if amount > 50_000_000:
        return jsonify(error="Amount exceeds maximum"), 400
    if not _rzp_client:
        return jsonify(error="Payment gateway not configured"), 503

    try:
        order   = _rzp_client.order.create(
            {"amount": amount, "currency": "INR", "payment_capture": 1}
        )
        user_id = flask_session.get("user_id")
        _q(
            "INSERT INTO donations "
            "(id,user_id,razorpay_order_id,amount,currency,status,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (_uid(), user_id, order["id"], amount, "INR", "pending", _now()),
        )
        _commit()
        _db_log("INFO", f"Donation order {order['id']} ₹{amount//100}",
                "/api/donations/create-order", user_id, ip=_client_ip())
        return jsonify(
            order_id = order["id"],
            amount   = order["amount"],
            currency = order["currency"],
            key_id   = RZP_KEY_ID,
        )
    except Exception as exc:
        _db_log("ERROR", f"Razorpay: {exc}",
                "/api/donations/create-order", ip=_client_ip())
        return jsonify(error="Could not create payment order"), 500


@app.route("/api/donations/verify", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute")
def api_donation_verify():
    data       = request.get_json(force=True, silent=True) or {}
    payment_id = str(data.get("payment_id", "")).strip()
    order_id   = str(data.get("order_id",   "")).strip()
    signature  = str(data.get("signature",  "")).strip()

    if not payment_id or not order_id or not signature:
        return jsonify(error="payment_id, order_id and signature are required"), 400

    if not _RZPID_RE.match(payment_id) or not _RZPID_RE.match(order_id):
        return jsonify(error="Invalid payment or order ID format"), 400

    if not RZP_KEY_SECRET:
        return jsonify(error="Payment gateway not configured"), 503

    try:
        expected = _hmac.new(
            key       = RZP_KEY_SECRET.encode("utf-8"),
            msg       = f"{order_id}|{payment_id}".encode("utf-8"),
            digestmod = hashlib.sha256,
        ).hexdigest()
    except Exception as exc:
        _db_log("ERROR", f"HMAC error: {exc}",
                "/api/donations/verify", ip=_client_ip())
        return jsonify(error="Internal verification error"), 500

    if not _hmac.compare_digest(expected, signature):
        _db_log("WARN", f"Razorpay sig mismatch order={order_id}",
                "/api/donations/verify", ip=_client_ip())
        return jsonify(error="Payment signature verification failed"), 400

    donation = _row(_q(
        "SELECT id,status FROM donations WHERE razorpay_order_id=?",
        (order_id,),
    ))

    if not donation:
        return jsonify(error="Order not found"), 404
    if donation["status"] == "completed":
        return jsonify(success=True, already_verified=True)
    if donation["status"] == "failed":
        return jsonify(error="This order was marked failed"), 400

    _q(
        "UPDATE donations SET razorpay_payment_id=?,status='completed' "
        "WHERE razorpay_order_id=?",
        (payment_id, order_id),
    )
    _commit()
    _db_log("INFO", f"Donation verified order={order_id}",
            "/api/donations/verify", ip=_client_ip())
    return jsonify(success=True)


@app.route("/api/donations/history")
@csrf.exempt
@login_required
def api_donation_history():
    rows = _rows(_q(
        "SELECT razorpay_order_id,razorpay_payment_id,"
        "amount,currency,status,created_at "
        "FROM donations WHERE user_id=? "
        "ORDER BY created_at DESC LIMIT 50",
        (flask_session["user_id"],),
    ))
    for r in rows:
        r["amount_inr"] = r["amount"] // 100
    return jsonify(donations=rows)


# ─────────────────────────────────────────────────────────────────────────────
#  Admin API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/api/me")
@csrf.exempt
@admin_required
def admin_me():
    user = _row(_q(
        "SELECT id,username,email,role,avatar_url,created_at "
        "FROM users WHERE id=?",
        (flask_session["user_id"],),
    ))
    return jsonify(user)


@app.route("/admin/api/stats")
@csrf.exempt
@admin_required
def admin_stats():
    users_total  = _row(_q("SELECT COUNT(*) AS cnt FROM users"))["cnt"]
    new_week     = _row(_q(
        "SELECT COUNT(*) AS cnt FROM users WHERE created_at >= ?",
        ((datetime.utcnow() - timedelta(days=7)).isoformat(timespec="seconds"),),
    ))["cnt"]
    active_today = _row(_q(
        "SELECT COUNT(*) AS cnt FROM users WHERE last_login >= ?",
        ((datetime.utcnow() - timedelta(days=1)).isoformat(timespec="seconds"),),
    ))["cnt"]
    google_users = _row(_q(
        "SELECT COUNT(*) AS cnt FROM users WHERE auth_provider='google'"
    ))["cnt"]
    local_users  = _row(_q(
        "SELECT COUNT(*) AS cnt FROM users WHERE auth_provider='local'"
    ))["cnt"]
    sess_total   = _row(_q("SELECT COUNT(*) AS cnt FROM sessions"))["cnt"]
    msg_total    = _row(_q("SELECT COUNT(*) AS cnt FROM messages"))["cnt"]
    revenue_p    = _row(_q(
        "SELECT COALESCE(SUM(amount),0) AS total FROM donations WHERE status='completed'"
    ))["total"]
    donation_cnt = _row(_q(
        "SELECT COUNT(*) AS cnt FROM donations WHERE status='completed'"
    ))["cnt"]

    recent_users = _rows(_q(
        """SELECT u.id,u.username,u.email,u.role,u.status,
                  u.auth_provider,u.avatar_url,u.created_at,u.last_login,
                  COUNT(s.id) AS chats
           FROM   users u
           LEFT JOIN sessions s ON s.user_id=u.id
           GROUP BY u.id,u.username,u.email,u.role,u.status,
                    u.auth_provider,u.avatar_url,u.created_at,u.last_login
           ORDER BY u.created_at DESC LIMIT 10"""
    ))

    week_ago = (
        datetime.utcnow() - timedelta(days=7)
    ).isoformat(timespec="seconds")
    chart = _rows(_q(
        """SELECT DATE(created_at) AS day, COUNT(*) AS cnt
           FROM   messages
           WHERE  created_at >= ?
           GROUP BY day ORDER BY day""",
        (week_ago,),
    ))

    activity = _rows(_q(
        "SELECT level,message,endpoint,created_at "
        "FROM app_logs ORDER BY created_at DESC LIMIT 15"
    ))

    top_donors = _rows(_q(
        """SELECT COALESCE(u.username,'Anonymous') AS user,
                  SUM(d.amount) AS total_paise, COUNT(*) AS donations
           FROM   donations d
           LEFT JOIN users u ON u.id=d.user_id
           WHERE  d.status='completed'
           GROUP BY d.user_id, u.username
           ORDER BY total_paise DESC LIMIT 5"""
    ))

    return jsonify(
        stats = dict(
            users          = users_total,
            active_today   = active_today,
            sessions       = sess_total,
            messages       = msg_total,
            revenue        = revenue_p // 100,
            donation_count = donation_cnt,
            new_users_week = new_week,
            google_users   = google_users,
            local_users    = local_users,
        ),
        recent_users = recent_users,
        activity = [
            {"type": a["level"].lower(), "text": a["message"],
             "endpoint": a["endpoint"], "time": a["created_at"]}
            for a in activity
        ],
        chart = {
            "labels": [str(r["day"]) for r in chart],
            "data":   [r["cnt"]     for r in chart],
        },
        top_donors = [
            {"user": d["user"], "amount": d["total_paise"] // 100,
             "donations": d["donations"]}
            for d in top_donors
        ],
    )


@app.route("/admin/api/users", methods=["GET", "POST"])
@csrf.exempt
@admin_required
def admin_users():
    if request.method == "GET":
        search = request.args.get("q", "").strip()
        q      = f"%{search}%"
        users = _rows(_q(
            """SELECT u.id,u.username,u.email,u.role,u.status,
                      u.auth_provider,u.avatar_url,u.created_at,
                      u.last_login,COUNT(s.id) AS chats
               FROM   users u
               LEFT JOIN sessions s ON s.user_id=u.id
               WHERE  u.username LIKE ? OR u.email LIKE ?
               GROUP BY u.id,u.username,u.email,u.role,u.status,
                        u.auth_provider,u.avatar_url,u.created_at,u.last_login
               ORDER BY u.created_at DESC""",
            (q, q),
        ))
        return jsonify(users=users)

    data     = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    email    = str(data.get("email",    "")).strip().lower()
    role     = str(data.get("role",    "user"))
    status   = str(data.get("status",  "active"))

    if not username or not email:
        return jsonify(error="Username and email required"), 400
    if not VALID_EMAIL_RE.match(email):
        return jsonify(error="Invalid email"), 400
    if role   not in ("user", "admin"):
        return jsonify(error="Invalid role"), 400
    if status not in ("active", "inactive"):
        return jsonify(error="Invalid status"), 400
    if _row(_q("SELECT id FROM users WHERE LOWER(email)=?", (email,))):
        return jsonify(error="Email already exists"), 409

    user_id = _uid()
    _q(
        "INSERT INTO users "
        "(id,username,email,password,auth_provider,role,status,created_at) "
        "VALUES (?,?,?,?,'local',?,?,?)",
        (user_id, username, email,
         generate_password_hash(secrets.token_hex(16)),
         role, status, _now()),
    )
    _commit()
    _db_log("INFO", f"Admin created user {email} role={role}",
            "/admin/api/users", flask_session["user_id"])
    return jsonify(success=True, id=user_id), 201


@app.route("/admin/api/users/<uid_>", methods=["GET", "PATCH", "DELETE"])
@csrf.exempt
@admin_required
def admin_user(uid_):
    if not _row(_q("SELECT id FROM users WHERE id=?", (uid_,))):
        return jsonify(error="User not found"), 404

    if request.method == "GET":
        user      = _row(_q(
            "SELECT id,username,email,role,status,"
            "auth_provider,avatar_url,created_at,last_login "
            "FROM users WHERE id=?", (uid_,)
        ))
        sessions  = _rows(_q(
            "SELECT id,title,created_at,updated_at FROM sessions "
            "WHERE user_id=? ORDER BY updated_at DESC LIMIT 20", (uid_,)
        ))
        donations = _rows(_q(
            "SELECT razorpay_order_id,amount,status,created_at "
            "FROM donations WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
            (uid_,),
        ))
        for d in donations:
            d["amount_inr"] = d["amount"] // 100
        return jsonify(user=user, sessions=sessions, donations=donations)

    if request.method == "DELETE":
        if uid_ == flask_session["user_id"]:
            return jsonify(error="Cannot delete your own account"), 400
        _q("DELETE FROM users WHERE id=?", (uid_,))
        _commit()
        _db_log("WARN", f"Admin deleted user {uid_}",
                "/admin/api/users", flask_session["user_id"])
        return jsonify(success=True)

    data = request.get_json(force=True, silent=True) or {}
    set_clauses: List[str] = []
    set_values:  List[Any] = []

    for field, (col, validate) in _USER_PATCH_FIELDS.items():
        if field not in data:
            continue
        value = str(data[field]).strip()
        if not validate(value):
            return jsonify(error=f"Invalid value for '{field}'"), 400
        if field == "email":
            conflict = _row(_q(
                "SELECT id FROM users WHERE LOWER(email)=? AND id != ?",
                (value.lower(), uid_),
            ))
            if conflict:
                return jsonify(error="Email already in use"), 409
            value = value.lower()
        if field == "role" and value == "user":
            cnt = _row(_q(
                "SELECT COUNT(*) AS cnt FROM users WHERE role='admin'"
            ))["cnt"]
            if cnt <= 1 and uid_ == flask_session["user_id"]:
                return jsonify(error="Cannot remove the last admin role"), 400
        set_clauses.append(f"{col} = ?")
        set_values.append(value)

    if not set_clauses:
        return jsonify(error="No valid fields provided"), 400

    set_values.append(uid_)
    _q(
        f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?",
        tuple(set_values),
    )
    _commit()
    _db_log("INFO", f"Admin updated user {uid_}",
            "/admin/api/users", flask_session["user_id"])
    return jsonify(success=True)


@app.route("/admin/api/users/<uid_>/reset-password", methods=["POST"])
@csrf.exempt
@admin_required
def admin_reset_user_password(uid_):
    user = _row(_q("SELECT email FROM users WHERE id=?", (uid_,)))
    if not user:
        return jsonify(error="User not found"), 404
    new_pw = secrets.token_urlsafe(12)
    _q(
        "UPDATE users SET password=? WHERE id=?",
        (generate_password_hash(new_pw), uid_),
    )
    _commit()
    _db_log("WARN", f"Admin force-reset password for {user['email']}",
            "/admin/api/users/reset-password", flask_session["user_id"])
    return jsonify(success=True, temp_password=new_pw)


@app.route("/admin/api/sessions")
@csrf.exempt
@admin_required
def admin_sessions():
    rows = _rows(_q(
        """SELECT s.id,u.username AS user,u.email,s.title,
                  COUNT(m.id) AS messages,s.created_at,s.updated_at
           FROM   sessions s
           JOIN   users u ON u.id=s.user_id
           LEFT JOIN messages m ON m.session_id=s.id
           GROUP BY s.id,u.username,u.email,s.title,s.created_at,s.updated_at
           ORDER BY s.updated_at DESC LIMIT 200"""
    ))
    return jsonify(sessions=rows)


@app.route("/admin/api/sessions/<sid>", methods=["GET", "DELETE"])
@csrf.exempt
@admin_required
def admin_session_detail(sid):
    if request.method == "GET":
        sess = _row(_q(
            "SELECT s.*,u.username,u.email FROM sessions s "
            "JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,)
        ))
        if not sess:
            return jsonify(error="Session not found"), 404
        msgs = _rows(_q(
            "SELECT role,content,created_at FROM messages "
            "WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ))
        return jsonify(session=sess, messages=msgs)

    _q("DELETE FROM sessions WHERE id=?", (sid,))
    _commit()
    _db_log("WARN", f"Admin deleted session {sid}",
            "/admin/api/sessions", flask_session["user_id"])
    return jsonify(success=True)


@app.route("/admin/api/donations")
@csrf.exempt
@admin_required
def admin_donations():
    status = request.args.get("status", "all")
    ALLOWED = {"all", "pending", "completed", "failed"}
    if status not in ALLOWED:
        return jsonify(error="Invalid status filter"), 400

    if status == "all":
        rows = _rows(_q(
            """SELECT d.id,d.razorpay_order_id,d.razorpay_payment_id,
                       COALESCE(u.username,'Anonymous') AS user,
                       u.email AS user_email,
                       d.amount,d.currency,d.status,d.created_at,
                       'Razorpay' AS method
                FROM   donations d
                LEFT JOIN users u ON u.id=d.user_id
                ORDER BY d.created_at DESC LIMIT 500"""
        ))
    else:
        rows = _rows(_q(
            """SELECT d.id,d.razorpay_order_id,d.razorpay_payment_id,
                       COALESCE(u.username,'Anonymous') AS user,
                       u.email AS user_email,
                       d.amount,d.currency,d.status,d.created_at,
                       'Razorpay' AS method
                FROM   donations d
                LEFT JOIN users u ON u.id=d.user_id
                WHERE  d.status=?
                ORDER BY d.created_at DESC LIMIT 500""",
            (status,),
        ))

    for r in rows:
        r["amount_inr"] = r["amount"] // 100
        r["date"]       = str(r["created_at"])[:10]

    total = sum(r["amount_inr"] for r in rows if r["status"] == "completed")
    return jsonify(donations=rows, total_inr=total)


@app.route("/admin/api/logs")
@csrf.exempt
@admin_required
def admin_logs():
    log_type = request.args.get("type", "all").strip().lower()
    limit    = request.args.get("limit", 200)

    try:
        limit = int(limit)
        if limit < 1 or limit > 1000:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify(error="limit must be between 1 and 1000"), 400

    FILTER_CLAUSES: Dict[str, Tuple[str, Tuple]] = {
        "all":   ("", ()),
        "error": ("WHERE level = ?",   ("ERROR",)),
        "warn":  ("WHERE level = ?",   ("WARN",)),
        "info":  ("WHERE level = ?",   ("INFO",)),
        "auth":  (
            "WHERE endpoint IN ("
            "'/api/login','/api/register','/api/logout',"
            "'/api/admin/login','/auth/google/callback')",
            (),
        ),
        "chat":  ("WHERE endpoint LIKE ?",  ("/api/chat%",)),
        "admin": ("WHERE endpoint LIKE ?",  ("/admin/api%",)),
    }

    if log_type not in FILTER_CLAUSES:
        return jsonify(error=f"Unknown log type '{log_type}'"), 400

    where_clause, where_params = FILTER_CLAUSES[log_type]

    rows = _rows(_q(
        f"""
        SELECT id,level,message,endpoint,
               user_id,ip_address,response_ms,created_at
        FROM   app_logs
        {where_clause}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (*where_params, limit),
    ))

    lines = []
    for r in rows:
        ms_  = f" | {r['response_ms']}ms" if r["response_ms"] else ""
        uid_ = f" | user:{r['user_id']}"  if r["user_id"]     else ""
        ip_  = f" | ip:{r['ip_address']}" if r["ip_address"]  else ""
        lines.append(
            f"[{r['level']}]  {r['created_at']}  "
            f"{r['endpoint'] or '—'}{ms_}{uid_}{ip_}  |  {r['message']}"
        )

    return jsonify(logs=lines, count=len(lines))


@app.route("/admin/api/settings", methods=["GET", "POST"])
@csrf.exempt
@admin_required
def admin_settings():
    if request.method == "GET":
        return jsonify(settings=dict(
            site_name               = os.environ.get("SITE_NAME", "Jarvis AI"),
            admin_username          = _ADMIN_USERNAME,
            admin_email             = _ADMIN_EMAIL,
            chat_model              = CHAT_MODEL,
            embed_model             = EMBED_MODEL,
            razorpay_configured     = bool(_rzp_client),
            smtp_configured         = bool(os.environ.get("SMTP_HOST")),
            openrouter_configured   = bool(OPENROUTER_KEY),
            google_oauth_configured = bool(app.config["GOOGLE_CLIENT_ID"]),
            database                = "SQLite",
            database_path           = DATABASE_PATH,
        ))
    _db_log("INFO", "Admin settings updated",
            "/admin/api/settings", flask_session["user_id"])
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Health check
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  Feedback  (public submission + admin management)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/feedback", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute; 20 per hour")
def api_submit_feedback():
    data    = request.get_json(force=True, silent=True) or {}
    name    = str(data.get("name",    "")).strip()[:120]
    email   = str(data.get("email",   "")).strip()[:254]
    message = str(data.get("message", "")).strip()[:5000]

    if not name:
        return jsonify(error="Name is required"), 400
    if len(name) < 2:
        return jsonify(error="Name must be at least 2 characters"), 400
    if not message:
        return jsonify(error="Feedback message is required"), 400
    if len(message) < 5:
        return jsonify(error="Message too short"), 400
    if email and not VALID_EMAIL_RE.match(email):
        return jsonify(error="Invalid email address"), 400

    fid = _uid()
    _q(
        "INSERT INTO feedback (id, name, email, message, is_read, ip_address, created_at) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (fid, name, email or None, message, _client_ip(), _now()),
    )
    _commit()
    _db_log("INFO", f"Feedback submitted by '{name}'", "/api/feedback",
            ip=_client_ip())

    # Notify admin by email (non-blocking, best-effort)
    if _ADMIN_EMAIL:
        subject = f"[Jarvis] New feedback from {name}"
        body = (
            f"New feedback received on Jarvis AI.\n\n"
            f"Name:    {name}\n"
            f"Email:   {email or '(not provided)'}\n"
            f"IP:      {_client_ip()}\n\n"
            f"Message:\n{message}\n\n"
            f"--- Jarvis Admin System"
        )
        _send_notification_bg(_ADMIN_EMAIL, subject, body)

    return jsonify(success=True)


@app.route("/admin/api/feedback")
@csrf.exempt
@admin_required
def admin_feedback_list():
    read_filter = request.args.get("read", "all").strip().lower()
    limit = request.args.get("limit", 200)
    try:
        limit = max(1, min(int(limit), 1000))
    except (ValueError, TypeError):
        limit = 200

    if read_filter == "unread":
        rows = _rows(_q(
            "SELECT id, name, email, message, is_read, ip_address, created_at "
            "FROM feedback WHERE is_read=0 ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ))
    elif read_filter == "read":
        rows = _rows(_q(
            "SELECT id, name, email, message, is_read, ip_address, created_at "
            "FROM feedback WHERE is_read=1 ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ))
    else:
        rows = _rows(_q(
            "SELECT id, name, email, message, is_read, ip_address, created_at "
            "FROM feedback ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ))

    total  = _row(_q("SELECT COUNT(*) AS c FROM feedback"))["c"]
    unread = _row(_q("SELECT COUNT(*) AS c FROM feedback WHERE is_read=0"))["c"]
    return jsonify(feedback=rows, total=total, unread=unread)


@app.route("/admin/api/feedback/<fid>", methods=["DELETE"])
@csrf.exempt
@admin_required
def admin_feedback_delete(fid):
    row = _row(_q("SELECT id FROM feedback WHERE id=?", (fid,)))
    if not row:
        return jsonify(error="Feedback not found"), 404
    _q("DELETE FROM feedback WHERE id=?", (fid,))
    _commit()
    _db_log("INFO", f"Admin deleted feedback {fid}",
            "/admin/api/feedback", flask_session["user_id"])
    return jsonify(success=True)


@app.route("/admin/api/feedback/<fid>/read", methods=["PATCH"])
@csrf.exempt
@admin_required
def admin_feedback_mark_read(fid):
    data    = request.get_json(force=True, silent=True) or {}
    is_read = 1 if data.get("is_read", True) else 0
    row = _row(_q("SELECT id FROM feedback WHERE id=?", (fid,)))
    if not row:
        return jsonify(error="Feedback not found"), 404
    _q("UPDATE feedback SET is_read=? WHERE id=?", (is_read, fid))
    _commit()
    return jsonify(success=True)


@app.route("/api/health")
@csrf.exempt
def api_health():
    db_ok = False
    try:
        _row(_q("SELECT 1 AS ok"))
        db_ok = True
    except Exception:
        pass
    return jsonify(
        status       = "ok" if db_ok else "degraded",
        db           = db_ok,
        db_type      = "sqlite",
        model        = CHAT_MODEL,
        embed        = EMBED_MODEL,
        razorpay     = bool(_rzp_client),
        openrouter   = bool(OPENROUTER_KEY),
        google_oauth = bool(app.config["GOOGLE_CLIENT_ID"]),
        ts           = _now(),
    ), 200 if db_ok else 503


# ─────────────────────────────────────────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):          return jsonify(error="Not found"), 404

@app.errorhandler(405)
def method_not_allowed(_): return jsonify(error="Method not allowed"), 405

@app.errorhandler(429)
def rate_limited(_):       return jsonify(error="Too many requests — slow down"), 429

@app.errorhandler(500)
def server_error(_):       return jsonify(error="Internal server error"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port  = int(os.environ.get("PORT", 5000))
    log.info(
        "Jarvis AI  |  debug=%s  port=%d  admin='%s'  model=%s  db=%s",
        debug, port, _ADMIN_USERNAME, CHAT_MODEL, DATABASE_PATH,
    )
    app.run(host="0.0.0.0", port=port, debug=debug)