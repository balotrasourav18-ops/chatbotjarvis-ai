import os
import sqlite3
import hashlib
import secrets
import time
import smtplib
import logging
import json
import re
import threading
import base64
import mimetypes
import hmac as _hmac
import queue as _queue
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from functools import wraps
import ssl
import requests
from flask import (
    Flask, request, jsonify, session as flask_session,
    redirect, g, Response, send_from_directory, url_for,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from typing import Optional, Dict, List, Any, Tuple, Callable

# ── Resolve project root ──────────────────────────────────────────────────────
_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(_BASE_DIR, ".env"))

# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Reasoning model — strip <think> blocks
# ─────────────────────────────────────────────────────────────────────────────

_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)


def _strip_reasoning(text: str) -> str:
    """Remove <think>…</think> chain-of-thought emitted by reasoning models."""
    return _THINK_RE.sub("", text).strip()


# ─────────────────────────────────────────────────────────────────────────────
#  App bootstrap
# ─────────────────────────────────────────────────────────────────────────────

_IS_PROD = os.environ.get("PRODUCTION", "").lower() == "true"

app = Flask(
    __name__,
    template_folder = os.path.join(_BASE_DIR, "templates"),
    static_folder   = os.path.join(_BASE_DIR, "static"),
    static_url_path = "",
)

# Trust one layer of reverse-proxy headers (Render's load balancer)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Allow 60 MB total (5 files × 10 MB + multipart overhead + base64 expansion)
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024

# ── Secret key ────────────────────────────────────────────────────────────────
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    if _IS_PROD:
        raise RuntimeError(
            "SECRET_KEY must be set in production. "
            "Add it to your Render environment variables."
        )
    _secret_key = secrets.token_hex(32)
    log.warning("SECRET_KEY not set — using a temporary key. Sessions will be lost on restart.")

app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    SESSION_COOKIE_SECURE      = _IS_PROD,
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24),
    WTF_CSRF_TIME_LIMIT        = 7200,
    WTF_CSRF_CHECK_DEFAULT     = False,
    PREFERRED_URL_SCHEME       = "https" if _IS_PROD else "http",
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

_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
_ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "")
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not _ADMIN_PASSWORD:
    if _IS_PROD:
        raise RuntimeError("ADMIN_PASSWORD must be set in your Render environment variables.")
    _ADMIN_PASSWORD = "changeme_dev_only"
    log.warning("ADMIN_PASSWORD not set — using insecure dev fallback.")

if not _ADMIN_EMAIL and _IS_PROD:
    raise RuntimeError("ADMIN_EMAIL must be set in your Render environment variables.")

log.info("Admin: username='%s'  email='%s'", _ADMIN_USERNAME, _ADMIN_EMAIL)

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

# Ensure DB directory exists (only if path has a directory component)
_db_dir = os.path.dirname(os.path.abspath(DATABASE_PATH))
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)


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
        g.db.execute("PRAGMA busy_timeout=5000")
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
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    title      TEXT DEFAULT 'New Chat',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('user','assistant')),
    content     TEXT NOT NULL,
    tokens_used INTEGER DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0 CHECK(has_attachments IN (0,1)),
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
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    token      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
);

CREATE TABLE IF NOT EXISTS app_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    level       TEXT NOT NULL,
    message     TEXT NOT NULL,
    endpoint    TEXT,
    user_id     TEXT,
    ip_address  TEXT,
    response_ms INTEGER,
    created_at  TEXT NOT NULL
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
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT,
    message    TEXT NOT NULL,
    is_read    INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
    ip_address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uploads (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    filename   TEXT NOT NULL,
    mime_type  TEXT NOT NULL,
    size       INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
CREATE INDEX IF NOT EXISTS idx_uploads_user     ON uploads(user_id);
"""


def init_db():
    """Initialise schema and upsert admin account only when credentials change."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    # ── Schema migrations (idempotent) ────────────────────────────────────────
    def _migrate(table: str, column: str, ddl: str):
        """Add a column if it doesn't already exist."""
        try:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            if column not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
                conn.commit()
                log.info("Migration: added %s.%s", table, column)
        except Exception as exc:
            log.warning("Migration failed for %s.%s: %s", table, column, exc)

    _migrate("messages", "has_attachments",
             "has_attachments INTEGER NOT NULL DEFAULT 0")

    existing = conn.execute(
        "SELECT id, password FROM users WHERE role='admin' LIMIT 1"
    ).fetchone()

    if not existing:
        pw_hash = generate_password_hash(_ADMIN_PASSWORD)
        conn.execute(
            "INSERT INTO users "
            "(id,username,email,password,auth_provider,role,status,created_at) "
            "VALUES (?,?,?,?,'local','admin','active',?)",
            (_uid(), _ADMIN_USERNAME, _ADMIN_EMAIL, pw_hash, _now()),
        )
        conn.commit()
        log.warning("Admin created — username='%s'", _ADMIN_USERNAME)
    else:
        current_hash     = existing["password"] or ""
        password_changed = not check_password_hash(current_hash, _ADMIN_PASSWORD)
        if password_changed:
            pw_hash = generate_password_hash(_ADMIN_PASSWORD)
            conn.execute(
                "UPDATE users SET username=?, email=?, password=? WHERE role='admin'",
                (_ADMIN_USERNAME, _ADMIN_EMAIL, pw_hash),
            )
            log.info("Admin password updated from env.")
        else:
            conn.execute(
                "UPDATE users SET username=?, email=? WHERE role='admin'",
                (_ADMIN_USERNAME, _ADMIN_EMAIL),
            )
            log.info("Admin username/email synced from env.")
        conn.commit()

    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _uid() -> str:
    return secrets.token_hex(12)


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "")
    )


def _utc_ago(**kwargs) -> str:
    return (
        (datetime.now(timezone.utc) - timedelta(**kwargs))
        .isoformat(timespec="seconds")
        .replace("+00:00", "")
    )


def _row(cur) -> Optional[Dict]:
    row = cur.fetchone()
    return dict(row) if row else None


def _rows(cur) -> List[Dict]:
    return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
#  DB log writer  (single thread + bounded queue)
# ─────────────────────────────────────────────────────────────────────────────

_log_queue: _queue.Queue = _queue.Queue(maxsize=5000)


def _db_log(
    level:    str,
    msg:      str,
    endpoint: Optional[str] = None,
    user_id:  Optional[str] = None,
    ms:       Optional[int] = None,
    ip:       Optional[str] = None,
):
    try:
        _log_queue.put_nowait((level, msg, endpoint, user_id, ip, ms, _now()))
    except _queue.Full:
        pass


def _log_writer_loop():
    def _open():
        c = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
        return c

    conn = _open()
    while True:
        try:
            item = _log_queue.get(timeout=2)
            conn.execute(
                "INSERT INTO app_logs "
                "(level,message,endpoint,user_id,ip_address,response_ms,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                item,
            )
            conn.commit()
        except _queue.Empty:
            continue
        except Exception as exc:
            log.error("Log writer error: %s", exc)
            try:
                conn.close()
            except Exception:
                pass
            conn = _open()


# ─────────────────────────────────────────────────────────────────────────────
#  Public chat rate-limit cache
# ─────────────────────────────────────────────────────────────────────────────

_pub_cache_lock = threading.Lock()
_pub_cache: Dict[str, float] = {}
_PUB_CACHE_TTL = 60
_PUB_CACHE_MAX = 10_000


def _cache_cleanup_loop():
    while True:
        time.sleep(30)
        cutoff = time.time() - _PUB_CACHE_TTL
        with _pub_cache_lock:
            dead = [k for k, v in _pub_cache.items() if v < cutoff]
            for k in dead:
                del _pub_cache[k]
            if len(_pub_cache) > _PUB_CACHE_MAX:
                oldest = sorted(_pub_cache, key=_pub_cache.__getitem__)
                for k in oldest[: len(_pub_cache) - _PUB_CACHE_MAX]:
                    del _pub_cache[k]


def _start_workers():
    threading.Thread(target=_log_writer_loop, daemon=True, name="db-log-writer").start()
    threading.Thread(target=_cache_cleanup_loop, daemon=True, name="cache-cleaner").start()
    log.info("Background workers started.")


# ─────────────────────────────────────────────────────────────────────────────
#  Startup — runs once per process, idempotent and worker-safe
# ─────────────────────────────────────────────────────────────────────────────

_startup_lock = threading.Lock()
_startup_done = False


def _do_startup():
    """Run init exactly once per process. Safe under Gunicorn forking."""
    global _startup_done
    with _startup_lock:
        if _startup_done:
            return
        try:
            init_db()
            _start_workers()
            _startup_done = True
            log.info("Startup complete (pid=%d)", os.getpid())
        except Exception as exc:
            log.exception("Startup failed: %s", exc)
            raise


# Run at import time so Gunicorn workers all initialise correctly
_do_startup()


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _set_user_session(user: Dict):
    """Clear the session and re-populate with a fresh nonce (anti-fixation)."""
    oauth_next = flask_session.pop("oauth_next", None)
    flask_session.clear()
    flask_session.permanent   = True
    flask_session.modified    = True
    flask_session["user_id"]    = user["id"]
    flask_session["role"]       = user["role"]
    flask_session["email"]      = user["email"]
    flask_session["login_time"] = _now()
    flask_session["_sid_nonce"] = secrets.token_hex(16)
    if oauth_next:
        flask_session["oauth_next"] = oauth_next


VALID_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$", re.IGNORECASE)
_RZPID_RE      = re.compile(r"^[A-Za-z0-9_]{6,64}$")
_TITLE_RE      = re.compile(r"^[\w\s\-.,!?()'\"]{1,100}$", re.UNICODE)

_USER_PATCH_FIELDS: Dict[str, Tuple[str, Callable[[str], bool]]] = {
    "username": ("username", lambda v: 2 <= len(v) <= 50),
    "email":    ("email",    lambda v: bool(VALID_EMAIL_RE.match(v))),
    "role":     ("role",     lambda v: v in ("user", "admin")),
    "status":   ("status",   lambda v: v in ("active", "inactive")),
}
_SAFE_UPDATE_COLUMNS: frozenset = frozenset({"username", "email", "role", "status"})

# ─────────────────────────────────────────────────────────────────────────────
#  CSRF helper
# ─────────────────────────────────────────────────────────────────────────────

def _check_csrf() -> Optional[Tuple[Response, int]]:
    token = request.headers.get("X-CSRFToken", "")
    try:
        validate_csrf(token)
    except Exception:
        return jsonify(error="CSRF validation failed"), 403
    return None


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
#  CSRF cookie
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def inject_csrf_cookie(resp):
    if resp.content_type and "text/html" in resp.content_type:
        resp.set_cookie(
            "csrf_token", generate_csrf(),
            samesite = "Lax",
            httponly = False,
            secure   = _IS_PROD,
        )
    return resp


# ─────────────────────────────────────────────────────────────────────────────
#  Email
# ─────────────────────────────────────────────────────────────────────────────

def _send_email_raw(to_email: str, subject: str, body: str) -> bool:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "").strip()
    pw   = os.environ.get("SMTP_PASS", "").strip()
    frm  = os.environ.get("SMTP_FROM", "").strip() or user

    if not host or not user or not pw:
        log.info("[DEV] Email to %s — %s (SMTP not configured)", to_email, subject)
        return True
    if not frm:
        log.error("SMTP_FROM / SMTP_USER empty — cannot send email")
        return False

    msg            = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to_email

    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, 465, context=ctx, timeout=15) as s:
                s.login(user, pw.replace(" ", ""))
                s.sendmail(frm, [to_email], msg.as_string())
        elif port == 587:
            with smtplib.SMTP(host, 587, timeout=15) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(user, pw.replace(" ", ""))
                s.sendmail(frm, [to_email], msg.as_string())
        else:
            log.error("Unsupported SMTP_PORT=%d (use 465 or 587)", port)
            return False
        log.info("Email sent to %s", to_email)
        return True
    except Exception as exc:
        log.exception("Email error → %s: %s", to_email, exc)
        return False


def _send_notification_bg(email: str, subject: str, body: str):
    def _w():
        if not email or not VALID_EMAIL_RE.match(email):
            return
        _send_email_raw(email, subject, body)
    threading.Thread(target=_w, daemon=True).start()


def _send_welcome_email(email: str, username: str):
    _send_notification_bg(
        email,
        "Welcome to Jarvis AI!",
        (
            f"Hi {username},\n\n"
            "Your Jarvis AI account is ready.\n\n"
            "  • Chat with Jarvis — coding, writing, research and more\n"
            "  • Upload images, PDFs, code files for analysis\n"
            "  • Your history is always saved\n\n"
            "— The Jarvis AI Team"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  AI model registry
# ─────────────────────────────────────────────────────────────────────────────

CHAT_MODEL     = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"
CODING_MODEL_1 = "moonshotai/kimi-k2.6:free"
CODING_MODEL_2 = "minimax/minimax-m2.5:free"
RESEARCH_MODEL = "minimax/minimax-m2.5:free"
RERANK_MODEL   = "cohere/rerank-v3.5"
IMAGE_MODEL    = "sourceful/riverflow-v2-fast"
OWL_MODEL      = "openrouter/owl-alpha"
EMBED_MODEL    = "nvidia/llama-nemotron-embed-vl-1b-v2:free"

ALL_MODELS: Dict[str, str] = {
    "chat":     CHAT_MODEL,
    "coding_1": CODING_MODEL_1,
    "coding_2": CODING_MODEL_2,
    "research": RESEARCH_MODEL,
    "rerank":   RERANK_MODEL,
    "image":    IMAGE_MODEL,
    "owl":      OWL_MODEL,
    "embed":    EMBED_MODEL,
}

SYSTEM_PROMPT_CHAT = (
    "You are Jarvis, a highly capable AI assistant. "
    "Be concise, accurate, and friendly. "
    "Format code with proper markdown code blocks. "
    "When the user attaches files or images, analyse them carefully and reference their contents. "
    "Never refuse reasonable requests."
)
SYSTEM_PROMPT_CODING = (
    "You are Jarvis Code, an expert software engineer and pair programmer. "
    "Write clean, idiomatic, well-commented code with the correct markdown code-fence. "
    "Explain your approach before the code and summarise decisions after. "
    "When the user attaches code files, review them carefully and reference specific lines. "
    "Highlight edge-cases or bugs. Never refuse reasonable coding requests."
)
SYSTEM_PROMPT_RESEARCH = (
    "You are Jarvis Research, a rigorous academic assistant. "
    "Provide thorough answers with clear section headings. "
    "When the user attaches documents (PDFs, papers, articles), analyse them deeply and cite specific sections. "
    "Cite sources as [Source: <name>]. Prefer depth over brevity."
)
SYSTEM_PROMPT_OWL = (
    "You are Jarvis Owl, an intelligent meta-assistant and task orchestrator. "
    "Help plan complex tasks, break down problems, decide which specialist to use. "
    "When the user attaches files, use them as context for planning. "
    "Be structured. Output numbered action plans when helpful."
)


def _or_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY', '')}",
        "Content-Type":  "application/json",
        "HTTP-Referer":  os.environ.get("SITE_URL", "https://chatbotjarvis-ai.onrender.com"),
        "X-Title":       "Jarvis AI",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  OpenRouter helpers
# ─────────────────────────────────────────────────────────────────────────────

def _call_openrouter(payload: Dict, timeout: int = 45) -> Dict:
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise ValueError("OPENROUTER_API_KEY is not configured")
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers = _or_headers(),
        json    = payload,
        timeout = timeout,
    )
    if resp.status_code != 200:
        body = resp.json() if resp.content else {}
        raise RuntimeError(
            (body.get("error") or {}).get("message") or f"HTTP {resp.status_code}"
        )
    return resp.json()


def _extract_reply(result: Dict) -> str:
    choices = result.get("choices") or []
    if not choices:
        raise RuntimeError("AI returned an empty choices array")
    content = choices[0].get("message", {}).get("content", "")
    if not content:
        raise RuntimeError("AI generated an empty response")
    return content


def _get_history(session_id: str, limit: int = 20) -> List[Dict]:
    rows = _rows(_q(
        "SELECT role,content FROM messages "
        "WHERE session_id=? ORDER BY created_at ASC LIMIT ?",
        (session_id, limit),
    ))
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def _ensure_chat_session(session_id: Any, user_id: str, title: str) -> str:
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


def _save_assistant_reply(sess_id: str, reply: str):
    _q(
        "INSERT INTO messages (id,session_id,role,content,tokens_used,has_attachments,created_at) "
        "VALUES (?,?,?,?,?,0,?)",
        (_uid(), sess_id, "assistant", reply, _estimate_tokens(reply), _now()),
    )
    _q("UPDATE sessions SET updated_at=? WHERE id=?", (_now(), sess_id))
    _commit()


def _save_assistant_reply_conn(conn: sqlite3.Connection, sess_id: str, reply: str):
    conn.execute(
        "INSERT INTO messages (id,session_id,role,content,tokens_used,has_attachments,created_at) "
        "VALUES (?,?,?,?,?,0,?)",
        (_uid(), sess_id, "assistant", reply, _estimate_tokens(reply), _now()),
    )
    conn.execute(
        "UPDATE sessions SET updated_at=? WHERE id=?", (_now(), sess_id)
    )
    conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
#  FILE UPLOAD MODULE
# ═════════════════════════════════════════════════════════════════════════════

ALLOWED_MIME = {
    # Images (sent to vision-capable models as base64)
    "image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp",
    # Documents (text extracted)
    "text/plain", "text/markdown", "text/csv",
    "application/pdf",
    "application/json",
    # Code files
    "text/x-python", "text/javascript", "application/javascript",
    "text/html", "text/css",
    "text/x-c", "text/x-c++", "text/x-java", "text/x-go", "text/x-rust",
    "text/x-typescript",
}

MAX_FILE_SIZE  = 10 * 1024 * 1024  # 10 MB per file
MAX_FILES      = 5                  # per upload request
MAX_PDF_PAGES  = 50
MAX_TEXT_CHARS = 50_000


def _extract_text_from_pdf(data: bytes) -> str:
    """Extract text from PDF bytes. Returns empty string on failure."""
    try:
        import PyPDF2
        from io import BytesIO
        reader = PyPDF2.PdfReader(BytesIO(data))
        text = ""
        for page in reader.pages[:MAX_PDF_PAGES]:
            try:
                text += (page.extract_text() or "") + "\n\n"
            except Exception:
                pass
        return text.strip()[:MAX_TEXT_CHARS]
    except ImportError:
        log.warning("PyPDF2 not installed — PDF text extraction disabled")
        return "[PDF text extraction unavailable — install PyPDF2: pip install PyPDF2]"
    except Exception as exc:
        log.warning("PDF parse failed: %s", exc)
        return f"[Could not extract PDF text: {exc}]"


def _safe_decode_text(data: bytes) -> Optional[str]:
    """Try to decode bytes as text using common encodings."""
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


@app.route("/api/upload", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("20 per minute; 100 per hour")
def api_upload():
    """
    Accept file uploads. Returns extracted text for documents,
    or base64 data URL for images.
    """
    err = _check_csrf()
    if err:
        return err

    if "files" not in request.files:
        return jsonify(error="No files provided"), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify(error="No files provided"), 400
    if len(files) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} files per upload"), 400

    user_id = flask_session["user_id"]
    results = []

    for f in files:
        if not f or not f.filename:
            continue

        safe_name = os.path.basename(f.filename)[:200]
        if not safe_name:
            continue

        data = f.read()
        if len(data) == 0:
            return jsonify(error=f"File '{safe_name}' is empty"), 400
        if len(data) > MAX_FILE_SIZE:
            return jsonify(
                error=f"File '{safe_name}' exceeds {MAX_FILE_SIZE // 1024 // 1024} MB"
            ), 413

        mime = (
            f.mimetype
            or mimetypes.guess_type(safe_name)[0]
            or "application/octet-stream"
        )
        mime = mime.lower()
        is_image = mime.startswith("image/")

        accepted = mime in ALLOWED_MIME or is_image or mime.startswith("text/")
        if not accepted:
            text_attempt = _safe_decode_text(data[:4096])
            if text_attempt is not None:
                mime = "text/plain"
                accepted = True

        if not accepted:
            return jsonify(
                error=f"File type '{mime}' not allowed for '{safe_name}'"
            ), 415

        result: Dict[str, Any] = {
            "name":     safe_name,
            "type":     mime,
            "size":     len(data),
            "is_image": is_image,
        }

        try:
            if is_image:
                b64 = base64.b64encode(data).decode("ascii")
                result["data_url"] = f"data:{mime};base64,{b64}"
                result["content"]  = f"[Image: {safe_name} ({len(data)//1024} KB)]"
            elif mime == "application/pdf":
                result["content"] = _extract_text_from_pdf(data)
            else:
                text = _safe_decode_text(data)
                if text is None:
                    return jsonify(
                        error=f"Cannot read '{safe_name}' as text"
                    ), 400
                result["content"] = text[:MAX_TEXT_CHARS]
                if len(text) > MAX_TEXT_CHARS:
                    result["content"] += "\n\n[... truncated ...]"

            _q(
                "INSERT INTO uploads (id,user_id,filename,mime_type,size,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (_uid(), user_id, safe_name, mime, len(data), _now()),
            )

            results.append(result)
        except Exception as exc:
            log.exception("Upload processing failed for %s: %s", safe_name, exc)
            return jsonify(error=f"Failed to process '{safe_name}': {exc}"), 500

    _commit()
    _db_log("INFO", f"Uploaded {len(results)} file(s)",
            "/api/upload", user_id, ip=_client_ip())
    return jsonify(files=results)


def _build_multimodal_message(
    message: str,
    attachments: List[Dict],
) -> Tuple[Any, str]:
    """
    Build the user message content for AI consumption and the display text
    saved to the database.

    Returns:
        (ai_content, display_text)
    """
    if not attachments:
        return message, message

    image_atts = [a for a in attachments if a.get("is_image") and a.get("data_url")]
    doc_atts   = [a for a in attachments if not a.get("is_image")]

    display = message or ""
    if attachments:
        names = ", ".join(a.get("name", "file") for a in attachments)
        suffix = f"\n\n📎 Attached: {names}"
        display = (display + suffix).strip() if display else suffix.strip()

    # If no images, inline document text as a single string
    if not image_atts:
        ai_text = message or ""
        for att in doc_atts:
            ai_text += (
                f"\n\n--- File: {att.get('name','file')} "
                f"({att.get('type','unknown')}) ---\n"
                f"{att.get('content','')}\n"
            )
        return ai_text.strip(), display

    # Otherwise, build multimodal parts list
    parts: List[Dict[str, Any]] = []

    combined_text = message or ""
    for att in doc_atts:
        combined_text += (
            f"\n\n--- File: {att.get('name','file')} "
            f"({att.get('type','unknown')}) ---\n"
            f"{att.get('content','')}\n"
        )
    if combined_text.strip():
        parts.append({"type": "text", "text": combined_text.strip()})

    # Add each image as image_url part — validate format
    for img in image_atts:
        url = img.get("data_url", "")
        if not url.startswith("data:image/"):
            log.warning("Skipping invalid image data_url for %s", img.get("name"))
            continue
        parts.append({
            "type": "image_url",
            "image_url": {"url": url},
        })

    if not parts:
        # All images were invalid — fall back to text-only
        return (message or "").strip() or "[Attachments failed to load]", display

    return parts, display


def _persist_user_message(
    sess_id: str,
    display_text: str,
    has_attachments: bool,
):
    """Insert the user message row into the DB."""
    _q(
        "INSERT INTO messages "
        "(id,session_id,role,content,tokens_used,has_attachments,created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            _uid(), sess_id, "user", display_text,
            _estimate_tokens(display_text),
            1 if has_attachments else 0,
            _now(),
        ),
    )
    _commit()


def _safe_stream_persist(sess_id: str, reply: str):
    """Persist an assistant reply from a streaming generator with safe cleanup."""
    if not reply or not reply.strip():
        return
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=5000")
        _save_assistant_reply_conn(conn, sess_id, reply)
    except Exception as exc:
        log.error("Stream persist: %s", exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  OTP / password reset
# ─────────────────────────────────────────────────────────────────────────────

def _send_otp_background(email: str, otp: str):
    def _w():
        body = (
            f"Your Jarvis AI password-reset OTP:\n\n"
            f"  {otp}\n\n"
            f"This code expires in 10 minutes.\n\n— Jarvis AI"
        )
        ok = _send_email_raw(email, "Jarvis AI — Password Reset OTP", body)
        if not ok:
            _db_log("ERROR", f"OTP email failed for {email}", "/api/forgot-password")
    threading.Thread(target=_w, daemon=True).start()


@app.route("/api/forgot-password", methods=["POST"])
@csrf.exempt
@limiter.limit("3 per minute; 10 per hour")
def api_forgot_password():
    err = _check_csrf()
    if err:
        return err

    data  = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email or not VALID_EMAIL_RE.match(email):
        return jsonify(error="Valid email is required"), 400

    user = _row(_q("SELECT id,password FROM users WHERE LOWER(email)=?", (email,)))
    if user and user["password"]:
        otp     = "".join(str(secrets.randbelow(10)) for _ in range(6))
        expires = (
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat(timespec="seconds").replace("+00:00", "")
        _q("UPDATE otp_tokens SET used=1 WHERE LOWER(email)=? AND used=0", (email,))
        _q(
            "INSERT INTO otp_tokens (id,email,token,expires_at,used) VALUES (?,?,?,?,0)",
            (_uid(), email, otp, expires),
        )
        _commit()
        _send_otp_background(email, otp)

    return jsonify(success=True)


@app.route("/api/verify-otp", methods=["POST"])
@csrf.exempt
@limiter.limit("3 per minute; 10 per hour")
def api_verify_otp():
    err = _check_csrf()
    if err:
        return err

    data  = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    otp   = str(data.get("otp",   "")).strip()

    if not email or not VALID_EMAIL_RE.match(email):
        return jsonify(error="Valid email required"), 400
    if len(otp) != 6 or not otp.isdigit():
        return jsonify(error="OTP must be exactly 6 digits"), 400

    rec = _row(_q(
        "SELECT id,token,expires_at FROM otp_tokens "
        "WHERE LOWER(email)=? AND used=0 ORDER BY expires_at DESC LIMIT 1",
        (email,),
    ))

    stored      = rec["token"] if rec else secrets.token_hex(3)
    token_match = _hmac.compare_digest(stored.encode(), otp.encode())
    not_expired = (
        datetime.fromisoformat(rec["expires_at"]) > datetime.now(timezone.utc)
        if rec else False
    )

    if not (token_match and not_expired):
        _db_log("WARN", f"OTP fail: {email}", "/api/verify-otp", ip=_client_ip())
        return jsonify(error="Invalid or expired OTP"), 400

    _q("UPDATE otp_tokens SET used=1 WHERE id=?", (rec["id"],))
    _commit()
    flask_session["otp_verified_email"] = email
    return jsonify(success=True)


@app.route("/api/reset-password", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute")
def api_reset_password():
    err = _check_csrf()
    if err:
        return err

    data     = request.get_json(force=True, silent=True) or {}
    email    = str(data.get("email",    "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify(error="Email and new password required"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    if flask_session.get("otp_verified_email") != email:
        return jsonify(error="OTP verification required first"), 403

    _q("UPDATE users SET password=? WHERE LOWER(email)=?",
       (generate_password_hash(password), email))
    _q("UPDATE otp_tokens SET used=1 WHERE LOWER(email)=?", (email,))
    _commit()
    flask_session.pop("otp_verified_email", None)
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  General chat  (nvidia reasoning) — WITH ATTACHMENT SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
@csrf.exempt
@login_required
def api_chat():
    err = _check_csrf()
    if err:
        return err

    t0      = time.monotonic()
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments per message"), 400

    if not message and not attachments:
        return jsonify(error="Message or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long (max 8000 chars)"), 400

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(
        sess_id, user_id, display_text or "Attachment"
    )
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    try:
        result = _call_openrouter({
            "model":       CHAT_MODEL,
            "messages":    [{"role": "system", "content": SYSTEM_PROMPT_CHAT}] + history,
            "max_tokens":  2048,
            "temperature": 0.7,
        }, timeout=60 if attachments else 45)
        reply = _strip_reasoning(_extract_reply(result))
        _save_assistant_reply(sess_id, reply)

        ms = int((time.monotonic() - t0) * 1000)
        _db_log(
            "INFO",
            f"Chat {ms}ms attach={len(attachments)}",
            "/api/chat", user_id, ms, ip=_client_ip(),
        )
        return jsonify(reply=reply, session_id=sess_id, model=CHAT_MODEL)

    except requests.Timeout:
        return jsonify(error="AI timed out — try again"), 504
    except ValueError as exc:
        return jsonify(error=str(exc)), 503
    except RuntimeError as exc:
        _db_log("ERROR", str(exc), "/api/chat", user_id)
        return jsonify(error=str(exc)), 502
    except Exception as exc:
        _db_log("ERROR", f"Chat error: {exc}", "/api/chat", user_id)
        return jsonify(error="Failed to get AI response"), 500


@app.route("/api/chat/stream", methods=["POST"])
@csrf.exempt
@login_required
def api_chat_stream():
    err = _check_csrf()
    if err:
        return err

    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Message or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long"), 400

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(
        sess_id, user_id, display_text or "Attachment"
    )
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    cap_sess = sess_id
    cap_hist = history

    def _stream():
        full_reply = ""
        in_think   = False
        think_done = False

        try:
            yield f"data: {json.dumps({'session_id': cap_sess})}\n\n"

            with requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers = _or_headers(),
                json    = {
                    "model":       CHAT_MODEL,
                    "messages":    [{"role": "system", "content": SYSTEM_PROMPT_CHAT}] + cap_hist,
                    "max_tokens":  2048,
                    "temperature": 0.7,
                    "stream":      True,
                },
                stream  = True,
                timeout = 90,
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
                        parsed  = json.loads(chunk)
                        content = (parsed.get("choices") or [{}])[0].get("delta", {}).get("content", "")
                        if not content:
                            continue
                        full_reply += content
                        if not think_done:
                            if "<think>" in full_reply:
                                in_think = True
                            if in_think and "</think>" in full_reply:
                                in_think = False; think_done = True
                                after = _strip_reasoning(full_reply)
                                if after:
                                    yield f"data: {json.dumps({'delta': after})}\n\n"
                            elif in_think:
                                yield f"data: {json.dumps({'thinking': True})}\n\n"
                            else:
                                yield f"data: {json.dumps({'delta': content})}\n\n"
                        else:
                            yield f"data: {json.dumps({'delta': content})}\n\n"
                    except Exception:
                        pass

            yield "data: [DONE]\n\n"

        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            _safe_stream_persist(cap_sess, _strip_reasoning(full_reply))

    return Response(
        _stream(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/chat/public", methods=["POST"])
@csrf.exempt
def api_chat_public():
    ip        = _client_ip()
    cache_key = f"pub_{ip}"
    now_      = time.time()

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
    if not os.environ.get("OPENROUTER_API_KEY"):
        return jsonify(reply="Demo mode — set OPENROUTER_API_KEY."), 200

    try:
        result = _call_openrouter({
            "model":       CHAT_MODEL,
            "messages":    [
                {"role": "system", "content": SYSTEM_PROMPT_CHAT},
                {"role": "user",   "content": message},
            ],
            "max_tokens":  512,
            "temperature": 0.7,
        }, timeout=30)
        return jsonify(
            reply = _strip_reasoning(_extract_reply(result)),
            model = CHAT_MODEL,
        )
    except requests.Timeout:
        return jsonify(error="AI timed out — try again"), 504
    except (ValueError, RuntimeError) as exc:
        return jsonify(error=str(exc)), 502
    except Exception:
        return jsonify(error="Failed to get AI response"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Coding  (kimi-k2.6 primary  /  minimax-m2.5 fallback) — WITH ATTACHMENTS
# ─────────────────────────────────────────────────────────────────────────────

def _coding_payload(model: str, history: List[Dict]) -> Dict:
    return {
        "model":       model,
        "messages":    [{"role": "system", "content": SYSTEM_PROMPT_CODING}] + history,
        "max_tokens":  4096,
        "temperature": 0.2,
    }


@app.route("/api/code", methods=["POST"])
@csrf.exempt
@login_required
def api_code():
    err = _check_csrf()
    if err:
        return err

    t0      = time.monotonic()
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    model   = str(data.get("model", "kimi")).strip().lower()
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Message or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long (max 8000 chars)"), 400

    primary   = CODING_MODEL_1 if model != "minimax" else CODING_MODEL_2
    secondary = CODING_MODEL_2 if primary == CODING_MODEL_1 else CODING_MODEL_1

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(sess_id, user_id, display_text or "Code Attachment")
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    used_model = primary

    try:
        result = _call_openrouter(_coding_payload(primary, history), timeout=90)
    except Exception as exc:
        log.warning("Coding primary (%s) failed: %s — trying fallback", primary, exc)
        try:
            result     = _call_openrouter(_coding_payload(secondary, history), timeout=90)
            used_model = secondary
        except Exception as exc2:
            _db_log("ERROR", f"Coding fallback failed: {exc2}", "/api/code", user_id)
            return jsonify(error="Both coding models failed — try again later"), 502

    try:
        reply = _extract_reply(result)
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 502

    _save_assistant_reply(sess_id, reply)
    ms = int((time.monotonic() - t0) * 1000)
    _db_log(
        "INFO",
        f"Code {ms}ms model={used_model} attach={len(attachments)}",
        "/api/code", user_id, ms, ip=_client_ip(),
    )
    return jsonify(reply=reply, session_id=sess_id, model=used_model)


@app.route("/api/code/stream", methods=["POST"])
@csrf.exempt
@login_required
def api_code_stream():
    err = _check_csrf()
    if err:
        return err

    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    model   = str(data.get("model", "kimi")).strip().lower()
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Message or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long"), 400

    primary   = CODING_MODEL_1 if model != "minimax" else CODING_MODEL_2
    secondary = CODING_MODEL_2 if primary == CODING_MODEL_1 else CODING_MODEL_1

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(sess_id, user_id, display_text or "Code Attachment")
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    cap_sess      = sess_id
    cap_primary   = primary
    cap_secondary = secondary
    cap_history   = history

    def _stream():
        full_reply   = ""
        active_model = cap_primary

        def _do_stream(mdl: str):
            nonlocal full_reply, active_model
            active_model = mdl
            with requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers = _or_headers(),
                json    = {
                    "model":       mdl,
                    "messages":    [{"role": "system", "content": SYSTEM_PROMPT_CODING}] + cap_history,
                    "max_tokens":  4096,
                    "temperature": 0.2,
                    "stream":      True,
                },
                stream  = True,
                timeout = 120,
            ) as r:
                for line in r.iter_lines():
                    if not line:
                        continue
                    line = line.decode("utf-8")
                    if not line.startswith("data: "):
                        continue
                    chunk = line[6:].strip()
                    if chunk == "[DONE]":
                        return
                    try:
                        parsed  = json.loads(chunk)
                        content = (parsed.get("choices") or [{}])[0].get("delta", {}).get("content", "")
                        if content:
                            full_reply += content
                            yield f"data: {json.dumps({'delta': content, 'model': mdl})}\n\n"
                    except Exception:
                        pass

        try:
            yield f"data: {json.dumps({'session_id': cap_sess, 'model': cap_primary})}\n\n"
            try:
                yield from _do_stream(cap_primary)
            except Exception as exc:
                log.warning("Code stream primary failed: %s", exc)
                yield f"data: {json.dumps({'info': 'Switching to fallback model…'})}\n\n"
                yield from _do_stream(cap_secondary)
            yield "data: [DONE]\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            _safe_stream_persist(cap_sess, full_reply)

    return Response(
        _stream(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Deep research — WITH ATTACHMENT SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/research", methods=["POST"])
@csrf.exempt
@login_required
def api_research():
    err = _check_csrf()
    if err:
        return err

    t0      = time.monotonic()
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Query or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Query too long (max 8000 chars)"), 400

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(sess_id, user_id, display_text or "Research")
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    try:
        result = _call_openrouter({
            "model":       RESEARCH_MODEL,
            "messages":    [{"role": "system", "content": SYSTEM_PROMPT_RESEARCH}] + history,
            "max_tokens":  8192,
            "temperature": 0.3,
        }, timeout=120)
        reply = _extract_reply(result)
        _save_assistant_reply(sess_id, reply)

        ms = int((time.monotonic() - t0) * 1000)
        _db_log(
            "INFO",
            f"Research {ms}ms attach={len(attachments)}",
            "/api/research", user_id, ms, ip=_client_ip(),
        )
        return jsonify(reply=reply, session_id=sess_id, model=RESEARCH_MODEL)

    except requests.Timeout:
        return jsonify(error="Research model timed out — try a shorter query"), 504
    except (ValueError, RuntimeError) as exc:
        return jsonify(error=str(exc)), 502
    except Exception as exc:
        _db_log("ERROR", f"Research: {exc}", "/api/research", user_id)
        return jsonify(error="Research failed"), 500


@app.route("/api/research/stream", methods=["POST"])
@csrf.exempt
@login_required
def api_research_stream():
    err = _check_csrf()
    if err:
        return err

    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Query or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Query too long"), 400

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(sess_id, user_id, display_text or "Research")
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    cap_sess = sess_id
    cap_hist = history

    def _stream():
        full_reply = ""
        try:
            yield f"data: {json.dumps({'session_id': cap_sess, 'model': RESEARCH_MODEL})}\n\n"

            with requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers = _or_headers(),
                json    = {
                    "model":       RESEARCH_MODEL,
                    "messages":    [{"role": "system", "content": SYSTEM_PROMPT_RESEARCH}] + cap_hist,
                    "max_tokens":  8192,
                    "temperature": 0.3,
                    "stream":      True,
                },
                stream  = True,
                timeout = 150,
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
                        parsed  = json.loads(chunk)
                        content = (parsed.get("choices") or [{}])[0].get("delta", {}).get("content", "")
                        if content:
                            full_reply += content
                            yield f"data: {json.dumps({'delta': content})}\n\n"
                    except Exception:
                        pass

            yield "data: [DONE]\n\n"

        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            _safe_stream_persist(cap_sess, full_reply)

    return Response(
        _stream(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Reranking
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/rerank", methods=["POST"])
@csrf.exempt
@login_required
def api_rerank():
    err = _check_csrf()
    if err:
        return err

    data  = request.get_json(force=True, silent=True) or {}
    query = str(data.get("query", "")).strip()
    docs  = data.get("documents") or []
    top_n = data.get("top_n")

    if not query:
        return jsonify(error="'query' is required"), 400
    if not docs or not isinstance(docs, list):
        return jsonify(error="'documents' must be a non-empty list"), 400
    if len(docs) > 100:
        return jsonify(error="Max 100 documents per request"), 400
    if not all(isinstance(d, str) for d in docs):
        return jsonify(error="All documents must be strings"), 400
    if not os.environ.get("OPENROUTER_API_KEY"):
        return jsonify(error="OPENROUTER_API_KEY not configured"), 503

    payload: Dict[str, Any] = {
        "model":     RERANK_MODEL,
        "query":     query,
        "documents": docs,
    }
    if top_n is not None:
        try:
            payload["top_n"] = max(1, int(top_n))
        except (ValueError, TypeError):
            return jsonify(error="'top_n' must be an integer"), 400

    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/rerank",
            headers = _or_headers(),
            json    = payload,
            timeout = 30,
        )
        if resp.status_code != 200:
            msg = (resp.json().get("error") or {}).get("message", "Rerank error")
            return jsonify(error=msg), 502

        results = resp.json().get("results") or []
        n_docs  = len(docs)
        formatted = []
        for r in results:
            idx = r.get("index")
            if idx is None or not isinstance(idx, int) or not (0 <= idx < n_docs):
                log.warning("Rerank out-of-range index %s — skipping", idx)
                continue
            formatted.append({
                "index":           idx,
                "text":            docs[idx],
                "relevance_score": r.get("relevance_score"),
            })

        _db_log("INFO", f"Rerank {len(docs)} docs",
                "/api/rerank", flask_session.get("user_id"), ip=_client_ip())
        return jsonify(results=formatted, model=RERANK_MODEL)

    except requests.Timeout:
        return jsonify(error="Rerank timed out"), 504
    except Exception as exc:
        _db_log("ERROR", f"Rerank: {exc}", "/api/rerank", flask_session.get("user_id"))
        return jsonify(error="Rerank failed"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Image generation
# ─────────────────────────────────────────────────────────────────────────────

_IMAGE_SIZES: Dict[str, Tuple[int, int]] = {
    "square":    (1024, 1024),
    "landscape": (1792, 1024),
    "portrait":  (1024, 1792),
}


@app.route("/api/image/generate", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute; 50 per hour")
def api_image_generate():
    err = _check_csrf()
    if err:
        return err

    data    = request.get_json(force=True, silent=True) or {}
    prompt  = str(data.get("prompt", "")).strip()
    size    = str(data.get("size",   "square")).strip().lower()
    quality = str(data.get("quality", "standard")).strip().lower()
    user_id = flask_session["user_id"]

    try:
        n = int(data.get("n", 1))
        if not 1 <= n <= 4:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify(error="'n' must be 1–4"), 400

    if not prompt:
        return jsonify(error="'prompt' is required"), 400
    if len(prompt) > 1000:
        return jsonify(error="Prompt too long (max 1000 chars)"), 400
    if size not in _IMAGE_SIZES:
        return jsonify(error=f"'size' must be one of: {', '.join(_IMAGE_SIZES)}"), 400
    if quality not in ("standard", "hd"):
        return jsonify(error="'quality' must be 'standard' or 'hd'"), 400
    if not os.environ.get("OPENROUTER_API_KEY"):
        return jsonify(error="OPENROUTER_API_KEY not configured"), 503

    w, h     = _IMAGE_SIZES[size]
    payload: Dict[str, Any] = {
        "model":  IMAGE_MODEL,
        "prompt": prompt,
        "n":      n,
        "size":   f"{w}x{h}",
    }
    if quality == "hd":
        payload["quality"] = "hd"

    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/images/generations",
            headers = _or_headers(),
            json    = payload,
            timeout = 60,
        )
        if resp.status_code != 200:
            msg = (resp.json().get("error") or {}).get("message", "Image generation error")
            _db_log("ERROR", f"Image error: {msg}", "/api/image/generate", user_id)
            return jsonify(error=msg), 502

        data_list = resp.json().get("data") or []
        if not data_list:
            return jsonify(error="Image generation returned no images"), 502

        images = [
            {"url": item.get("url", ""), "revised_prompt": item.get("revised_prompt", prompt)}
            for item in data_list if item.get("url")
        ]
        if not images:
            return jsonify(error="No valid image URLs in response"), 502

        _db_log("INFO", f"Image n={n} size={size}",
                "/api/image/generate", user_id, ip=_client_ip())
        return jsonify(images=images, model=IMAGE_MODEL, size=f"{w}x{h}")

    except requests.Timeout:
        return jsonify(error="Image generation timed out"), 504
    except Exception as exc:
        _db_log("ERROR", f"Image: {exc}", "/api/image/generate", user_id)
        return jsonify(error="Image generation failed"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Owl Alpha — WITH ATTACHMENT SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/owl", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("20 per minute; 100 per hour")
def api_owl():
    err = _check_csrf()
    if err:
        return err

    t0      = time.monotonic()
    data    = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    sess_id = data.get("session_id")
    user_id = flask_session["user_id"]

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if len(attachments) > MAX_FILES:
        return jsonify(error=f"Max {MAX_FILES} attachments"), 400

    if not message and not attachments:
        return jsonify(error="Message or attachment is required"), 400
    if len(message) > 8000:
        return jsonify(error="Message too long (max 8000 chars)"), 400
    if not os.environ.get("OPENROUTER_API_KEY"):
        return jsonify(error="OPENROUTER_API_KEY not configured"), 503

    ai_content, display_text = _build_multimodal_message(message, attachments)

    sess_id = _ensure_chat_session(sess_id, user_id, display_text or "Owl Task")
    _persist_user_message(sess_id, display_text, bool(attachments))

    history = _get_history(sess_id)
    if history and attachments:
        history[-1] = {"role": "user", "content": ai_content}

    try:
        result = _call_openrouter({
            "model":       OWL_MODEL,
            "messages":    [{"role": "system", "content": SYSTEM_PROMPT_OWL}] + history,
            "max_tokens":  2048,
            "temperature": 0.5,
        }, timeout=90)
        reply = _extract_reply(result)
        _save_assistant_reply(sess_id, reply)

        ms = int((time.monotonic() - t0) * 1000)
        _db_log(
            "INFO",
            f"Owl {ms}ms attach={len(attachments)}",
            "/api/owl", user_id, ms, ip=_client_ip(),
        )
        return jsonify(reply=reply, session_id=sess_id, model=OWL_MODEL)

    except requests.Timeout:
        return jsonify(error="Owl timed out — try again"), 504
    except (ValueError, RuntimeError) as exc:
        return jsonify(error=str(exc)), 502
    except Exception as exc:
        _db_log("ERROR", f"Owl: {exc}", "/api/owl", user_id)
        return jsonify(error="Owl request failed"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Embeddings
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/embed", methods=["POST"])
@csrf.exempt
@login_required
def api_embed():
    err = _check_csrf()
    if err:
        return err

    data  = request.get_json(force=True, silent=True) or {}
    texts = data.get("texts") or []
    if isinstance(texts, str):
        texts = [texts]
    if not texts or not all(isinstance(t, str) for t in texts):
        return jsonify(error="'texts' must be a non-empty list of strings"), 400
    if len(texts) > 50:
        return jsonify(error="Max 50 texts per request"), 400
    if not os.environ.get("OPENROUTER_API_KEY"):
        return jsonify(error="OPENROUTER_API_KEY not configured"), 503

    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/embeddings",
            headers = _or_headers(),
            json    = {"model": EMBED_MODEL, "input": texts},
            timeout = 30,
        )
        if resp.status_code != 200:
            msg = (resp.json().get("error") or {}).get("message", "Embed error")
            return jsonify(error=msg), 502
        return jsonify(
            embeddings = [i["embedding"] for i in resp.json().get("data", [])],
            model      = EMBED_MODEL,
        )
    except requests.Timeout:
        return jsonify(error="Embedding timed out"), 504
    except Exception as exc:
        _db_log("ERROR", f"Embed: {exc}", "/api/embed", flask_session.get("user_id"))
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
    err = _check_csrf()
    if err:
        return err

    t0         = time.monotonic()
    data       = request.get_json(force=True, silent=True) or {}
    identifier = str(data.get("username") or data.get("email") or "").strip().lower()
    password   = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify(error="Username/email and password are required"), 400

    user   = _row(_q(
        "SELECT * FROM users "
        "WHERE (LOWER(username)=? OR LOWER(email)=?) AND role='admin'",
        (identifier, identifier),
    ))
    stored = user["password"] if (user and user["password"]) else _DUMMY_HASH
    valid  = check_password_hash(stored, password)
    ms     = int((time.monotonic() - t0) * 1000)

    if not valid or not user:
        _db_log("WARN", f"Failed admin login: '{identifier}'",
                "/api/admin/login", ms=ms, ip=_client_ip())
        return jsonify(error="Invalid admin credentials"), 401

    if user["status"] != "active":
        return jsonify(error="Admin account is disabled"), 403

    _q("UPDATE users SET last_login=? WHERE id=?", (_now(), user["id"]))
    _commit()
    _set_user_session(user)
    _db_log("INFO", f"Admin login OK: '{user['username']}'",
            "/api/admin/login", user["id"], ms, ip=_client_ip())
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Admin Login",
        f"Admin '{user['username']}' logged in from {_client_ip()} at {_now()}.",
    )
    return jsonify(success=True, redirect="/admin")


# ─────────────────────────────────────────────────────────────────────────────
#  Google OAuth
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
        log.warning("Google OAuth error: %s", exc)
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
        user = _row(_q("SELECT * FROM users WHERE LOWER(email)=?", (email,)))
        if user:
            _q(
                "UPDATE users SET google_id=?,avatar_url=?,auth_provider='google',last_login=? "
                "WHERE id=?",
                (google_id, avatar, _now(), user["id"]),
            )
            _commit()
            user = _row(_q("SELECT * FROM users WHERE id=?", (user["id"],)))
        else:
            uid = _uid()
            _q(
                "INSERT INTO users "
                "(id,username,email,password,google_id,avatar_url,"
                " auth_provider,role,status,created_at,last_login) "
                "VALUES (?,?,?,NULL,?,?,'google','user','active',?,?)",
                (uid, name, email, google_id, avatar, _now(), _now()),
            )
            _commit()
            user = _row(_q("SELECT * FROM users WHERE id=?", (uid,)))
            _send_welcome_email(email, name)
    else:
        _q("UPDATE users SET avatar_url=?,last_login=? WHERE id=?",
           (avatar, _now(), user["id"]))
        _commit()

    if user["status"] != "active":
        return redirect("/login?error=account_disabled")

    _set_user_session(user)
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Login Successful",
        f"Account '{user['username']}' logged in via Google from {_client_ip()} at {_now()}.",
    )
    next_url = flask_session.pop("oauth_next", None) or (
        "/admin" if user["role"] == "admin" else "/chat"
    )
    return redirect(next_url)


@app.route("/auth/google/unlink", methods=["POST"])
@csrf.exempt
@login_required
def google_unlink():
    err = _check_csrf()
    if err:
        return err

    user_id = flask_session["user_id"]
    user    = _row(_q("SELECT password,google_id FROM users WHERE id=?", (user_id,)))

    if not user:
        return jsonify(error="User not found"), 404
    if not user["google_id"]:
        return jsonify(error="Google not linked"), 400
    if not user["password"]:
        return jsonify(error="Set a local password before unlinking Google"), 400

    _q("UPDATE users SET google_id=NULL,auth_provider='local' WHERE id=?", (user_id,))
    _commit()
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  User auth
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute; 20 per hour")
def api_register():
    err = _check_csrf()
    if err:
        return err

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
    _send_welcome_email(email, username)
    _db_log("INFO", f"New user: {email}", "/api/register", user_id, ip=_client_ip())
    return jsonify(success=True, redirect="/chat"), 201


@app.route("/api/login", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute; 50 per hour")
def api_login():
    err = _check_csrf()
    if err:
        return err

    t0       = time.monotonic()
    data     = request.get_json(force=True, silent=True) or {}
    email    = str(data.get("email",    "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify(error="Email and password are required"), 400

    user   = _row(_q("SELECT * FROM users WHERE LOWER(email)=?", (email,)))
    stored = user["password"] if (user and user["password"]) else _DUMMY_HASH
    valid  = check_password_hash(stored, password)
    ms     = int((time.monotonic() - t0) * 1000)

    if not valid or not user:
        _db_log("WARN", f"Failed login: {email}", "/api/login", ms=ms, ip=_client_ip())
        return jsonify(error="Invalid email or password"), 401
    if user["status"] != "active":
        return jsonify(error="Account disabled — contact support"), 403
    if not user["password"]:
        return jsonify(error="This account uses Google sign-in."), 400

    _q("UPDATE users SET last_login=? WHERE id=?", (_now(), user["id"]))
    _commit()
    _set_user_session(user)
    _db_log("INFO", f"Login: {email}", "/api/login", user["id"], ms, ip=_client_ip())
    _send_notification_bg(
        user["email"],
        "Jarvis AI - Login Successful",
        f"Account '{user['username']}' logged in from {_client_ip()} at {_now()}.",
    )
    return jsonify(success=True, redirect="/admin" if user["role"] == "admin" else "/chat")


@app.route("/api/logout", methods=["POST"])
@csrf.exempt
def api_logout():
    err = _check_csrf()
    if err:
        return err
    uid = flask_session.get("user_id")
    flask_session.clear()
    _db_log("INFO", "Logout", "/api/logout", uid, ip=_client_ip())
    return jsonify(success=True)


@app.route("/api/me")
@csrf.exempt
@login_required
def api_me():
    user = _row(_q(
        "SELECT id,username,email,role,status,auth_provider,avatar_url,created_at,last_login,google_id "
        "FROM users WHERE id=?",
        (flask_session["user_id"],),
    ))
    if not user:
        flask_session.clear()
        return jsonify(error="User not found"), 401
    user["google_linked"] = bool(user.get("google_id"))
    return jsonify(user)


@app.route("/api/me/set-password", methods=["POST"])
@csrf.exempt
@login_required
def api_set_password():
    err = _check_csrf()
    if err:
        return err

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
            return jsonify(error="Current password required"), 400
        if not check_password_hash(user["password"], old_pw):
            return jsonify(error="Current password is incorrect"), 401

    _q("UPDATE users SET password=? WHERE id=?",
       (generate_password_hash(new_pw), user_id))
    _commit()
    return jsonify(success=True)


@app.route("/api/me/update", methods=["POST"])
@csrf.exempt
@login_required
def api_me_update():
    """Allow a user to update their own username."""
    err = _check_csrf()
    if err:
        return err

    data     = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()

    if len(username) < 2 or len(username) > 50:
        return jsonify(error="Username must be 2–50 characters"), 400
    if username.lower() == _ADMIN_USERNAME.lower():
        return jsonify(error="That username is reserved"), 409

    user_id = flask_session["user_id"]
    _q("UPDATE users SET username=? WHERE id=?", (username, user_id))
    _commit()
    return jsonify(success=True, username=username)


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
            "SELECT role,content,created_at,has_attachments FROM messages "
            "WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ))
        return jsonify(session=sess, messages=msgs)

    if request.method == "PATCH":
        err = _check_csrf()
        if err:
            return err
        data  = request.get_json(force=True, silent=True) or {}
        title = str(data.get("title", "")).strip()[:100]
        if title:
            _q("UPDATE sessions SET title=?,updated_at=? WHERE id=?",
               (title, _now(), sid))
            _commit()
        return jsonify(success=True)

    err = _check_csrf()
    if err:
        return err
    _q("DELETE FROM sessions WHERE id=?", (sid,))
    _commit()
    return jsonify(success=True)


@app.route("/api/sessions/<sid>/title", methods=["PATCH"])
@csrf.exempt
@login_required
def api_patch_session_title(sid):
    err = _check_csrf()
    if err:
        return err

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
    if not _TITLE_RE.match(title):
        return jsonify(error="Title contains invalid characters"), 400

    _q("UPDATE sessions SET title=?,updated_at=? WHERE id=?", (title, _now(), sid))
    _commit()
    return jsonify(success=True, title=title)


@app.route("/api/sessions/<sid>/auto-title", methods=["PATCH"])
@csrf.exempt
@login_required
def api_auto_title(sid):
    err = _check_csrf()
    if err:
        return err

    sess = _row(_q(
        "SELECT id FROM sessions WHERE id=? AND user_id=?",
        (sid, flask_session["user_id"]),
    ))
    if not sess:
        return jsonify(error="Session not found"), 404

    first = _row(_q(
        "SELECT content FROM messages WHERE session_id=? AND role='user' "
        "ORDER BY created_at ASC LIMIT 1", (sid,),
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
    err = _check_csrf()
    if err:
        return err

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
        return jsonify(
            order_id=order["id"], amount=order["amount"],
            currency=order["currency"], key_id=RZP_KEY_ID,
        )
    except Exception as exc:
        _db_log("ERROR", f"Razorpay: {exc}", "/api/donations/create-order")
        return jsonify(error="Could not create payment order"), 500


@app.route("/api/donations/verify", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute")
def api_donation_verify():
    err = _check_csrf()
    if err:
        return err

    data       = request.get_json(force=True, silent=True) or {}
    payment_id = str(data.get("payment_id", "")).strip()
    order_id   = str(data.get("order_id",   "")).strip()
    signature  = str(data.get("signature",  "")).strip()

    if not payment_id or not order_id or not signature:
        return jsonify(error="payment_id, order_id and signature required"), 400
    if not _RZPID_RE.match(payment_id) or not _RZPID_RE.match(order_id):
        return jsonify(error="Invalid ID format"), 400
    if not RZP_KEY_SECRET:
        return jsonify(error="Payment gateway not configured"), 503

    try:
        expected = _hmac.new(
            key       = RZP_KEY_SECRET.encode(),
            msg       = f"{order_id}|{payment_id}".encode(),
            digestmod = hashlib.sha256,
        ).hexdigest()
    except Exception:
        return jsonify(error="Internal verification error"), 500

    if not _hmac.compare_digest(expected, signature):
        return jsonify(error="Signature verification failed"), 400

    donation = _row(_q(
        "SELECT id,status FROM donations WHERE razorpay_order_id=?", (order_id,)
    ))
    if not donation:
        return jsonify(error="Order not found"), 404
    if donation["status"] == "completed":
        return jsonify(success=True, already_verified=True)
    if donation["status"] == "failed":
        return jsonify(error="Order was marked failed"), 400

    _q(
        "UPDATE donations SET razorpay_payment_id=?,status='completed' "
        "WHERE razorpay_order_id=?",
        (payment_id, order_id),
    )
    _commit()
    return jsonify(success=True)


@app.route("/api/donations/history")
@csrf.exempt
@login_required
def api_donation_history():
    rows = _rows(_q(
        "SELECT razorpay_order_id,razorpay_payment_id,amount,currency,status,created_at "
        "FROM donations WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
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
        "SELECT id,username,email,role,avatar_url,created_at FROM users WHERE id=?",
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
        (_utc_ago(days=7),),
    ))["cnt"]
    active_today = _row(_q(
        "SELECT COUNT(*) AS cnt FROM users WHERE last_login >= ?",
        (_utc_ago(days=1),),
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

    uploads_total = _row(_q("SELECT COUNT(*) AS cnt FROM uploads"))["cnt"]
    uploads_size  = _row(_q("SELECT COALESCE(SUM(size),0) AS total FROM uploads"))["total"]

    recent_users = _rows(_q(
        """SELECT u.id,u.username,u.email,u.role,u.status,
                  u.auth_provider,u.avatar_url,u.created_at,u.last_login,
                  COUNT(s.id) AS chats
           FROM   users u
           LEFT JOIN sessions s ON s.user_id=u.id
           GROUP BY u.id ORDER BY u.created_at DESC LIMIT 10"""
    ))

    chart = _rows(_q(
        "SELECT DATE(created_at) AS day, COUNT(*) AS cnt FROM messages "
        "WHERE created_at >= ? GROUP BY day ORDER BY day",
        (_utc_ago(days=7),),
    ))

    activity = _rows(_q(
        "SELECT level,message,endpoint,created_at FROM app_logs "
        "ORDER BY created_at DESC LIMIT 15"
    ))

    top_donors = _rows(_q(
        """SELECT COALESCE(u.username,'Anonymous') AS user,
                  SUM(d.amount) AS total_paise, COUNT(*) AS donations
           FROM   donations d
           LEFT JOIN users u ON u.id=d.user_id
           WHERE  d.status='completed'
           GROUP BY d.user_id ORDER BY total_paise DESC LIMIT 5"""
    ))

    return jsonify(
        stats = dict(
            users=users_total, active_today=active_today,
            sessions=sess_total, messages=msg_total,
            revenue=revenue_p // 100, donation_count=donation_cnt,
            new_users_week=new_week, google_users=google_users,
            local_users=local_users,
            uploads=uploads_total,
            uploads_size_mb=round(uploads_size / 1024 / 1024, 2),
        ),
        recent_users = recent_users,
        activity = [
            {"type": a["level"].lower(), "text": a["message"],
             "endpoint": a["endpoint"], "time": a["created_at"]}
            for a in activity
        ],
        chart = {
            "labels": [str(r["day"]) for r in chart],
            "data":   [r["cnt"]      for r in chart],
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
        users  = _rows(_q(
            """SELECT u.id,u.username,u.email,u.role,u.status,
                      u.auth_provider,u.avatar_url,u.created_at,
                      u.last_login,COUNT(s.id) AS chats
               FROM   users u
               LEFT JOIN sessions s ON s.user_id=u.id
               WHERE  u.username LIKE ? OR u.email LIKE ?
               GROUP BY u.id ORDER BY u.created_at DESC""",
            (q, q),
        ))
        return jsonify(users=users)

    err = _check_csrf()
    if err:
        return err

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
    return jsonify(success=True, id=user_id), 201


@app.route("/admin/api/users/<uid_>", methods=["GET", "PATCH", "DELETE"])
@csrf.exempt
@admin_required
def admin_user(uid_):
    if not _row(_q("SELECT id FROM users WHERE id=?", (uid_,))):
        return jsonify(error="User not found"), 404

    if request.method == "GET":
        user      = _row(_q(
            "SELECT id,username,email,role,status,auth_provider,"
            "avatar_url,created_at,last_login FROM users WHERE id=?", (uid_,)
        ))
        sessions  = _rows(_q(
            "SELECT id,title,created_at,updated_at FROM sessions "
            "WHERE user_id=? ORDER BY updated_at DESC LIMIT 20", (uid_,)
        ))
        donations = _rows(_q(
            "SELECT razorpay_order_id,amount,status,created_at "
            "FROM donations WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (uid_,)
        ))
        for d in donations:
            d["amount_inr"] = d["amount"] // 100
        return jsonify(user=user, sessions=sessions, donations=donations)

    if request.method == "DELETE":
        err = _check_csrf()
        if err:
            return err
        if uid_ == flask_session["user_id"]:
            return jsonify(error="Cannot delete your own account"), 400
        _q("DELETE FROM users WHERE id=?", (uid_,))
        _commit()
        return jsonify(success=True)

    err = _check_csrf()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    set_clauses: List[str] = []
    set_values:  List[Any] = []

    for field, (col, validate) in _USER_PATCH_FIELDS.items():
        if field not in data:
            continue
        if col not in _SAFE_UPDATE_COLUMNS:
            log.error("Blocked unsafe column: %s", col)
            return jsonify(error="Internal configuration error"), 500
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
            cnt = _row(_q("SELECT COUNT(*) AS cnt FROM users WHERE role='admin'"))["cnt"]
            if cnt <= 1 and uid_ == flask_session["user_id"]:
                return jsonify(error="Cannot remove the last admin role"), 400
        set_clauses.append(f"{col} = ?")
        set_values.append(value)

    if not set_clauses:
        return jsonify(error="No valid fields provided"), 400

    set_values.append(uid_)
    _q(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", tuple(set_values))
    _commit()
    return jsonify(success=True)


@app.route("/admin/api/users/<uid_>/reset-password", methods=["POST"])
@csrf.exempt
@admin_required
def admin_reset_user_password(uid_):
    err = _check_csrf()
    if err:
        return err
    user = _row(_q("SELECT email FROM users WHERE id=?", (uid_,)))
    if not user:
        return jsonify(error="User not found"), 404
    new_pw = secrets.token_urlsafe(12)
    _q("UPDATE users SET password=? WHERE id=?",
       (generate_password_hash(new_pw), uid_))
    _commit()
    return jsonify(success=True, temp_password=new_pw)


@app.route("/admin/api/sessions")
@csrf.exempt
@admin_required
def admin_sessions():
    return jsonify(sessions=_rows(_q(
        """SELECT s.id,u.username AS user,u.email,s.title,
                  COUNT(m.id) AS messages,s.created_at,s.updated_at
           FROM   sessions s
           JOIN   users u ON u.id=s.user_id
           LEFT JOIN messages m ON m.session_id=s.id
           GROUP BY s.id ORDER BY s.updated_at DESC LIMIT 200"""
    )))


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
            "SELECT role,content,created_at,has_attachments FROM messages "
            "WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ))
        return jsonify(session=sess, messages=msgs)

    err = _check_csrf()
    if err:
        return err
    _q("DELETE FROM sessions WHERE id=?", (sid,))
    _commit()
    return jsonify(success=True)


@app.route("/admin/api/donations")
@csrf.exempt
@admin_required
def admin_donations():
    status  = request.args.get("status", "all")
    ALLOWED = {"all", "pending", "completed", "failed"}
    if status not in ALLOWED:
        return jsonify(error="Invalid status filter"), 400

    base = """
        SELECT d.id,d.razorpay_order_id,d.razorpay_payment_id,
               COALESCE(u.username,'Anonymous') AS user,
               u.email AS user_email,
               d.amount,d.currency,d.status,d.created_at,
               'Razorpay' AS method
        FROM   donations d
        LEFT JOIN users u ON u.id=d.user_id
    """
    if status == "all":
        rows = _rows(_q(base + " ORDER BY d.created_at DESC LIMIT 500"))
    else:
        rows = _rows(_q(
            base + " WHERE d.status=? ORDER BY d.created_at DESC LIMIT 500",
            (status,),
        ))

    for r in rows:
        r["amount_inr"] = r["amount"] // 100
        r["date"]       = str(r["created_at"])[:10]

    total = sum(r["amount_inr"] for r in rows if r["status"] == "completed")
    return jsonify(donations=rows, total_inr=total)


@app.route("/admin/api/uploads")
@csrf.exempt
@admin_required
def admin_uploads():
    """List recent file uploads across all users."""
    rows = _rows(_q(
        """SELECT u.id, u.filename, u.mime_type, u.size, u.created_at,
                  users.username, users.email
           FROM uploads u
           JOIN users ON users.id = u.user_id
           ORDER BY u.created_at DESC LIMIT 500"""
    ))
    for r in rows:
        r["size_kb"] = round(r["size"] / 1024, 1)
    return jsonify(uploads=rows)


@app.route("/admin/api/logs")
@csrf.exempt
@admin_required
def admin_logs():
    log_type = request.args.get("type", "all").strip().lower()
    try:
        limit = int(request.args.get("limit", 200))
        if not 1 <= limit <= 1000:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify(error="limit must be 1–1000"), 400

    FILTER_CLAUSES: Dict[str, Tuple[str, Tuple]] = {
        "all":   ("", ()),
        "error": ("WHERE level = ?",  ("ERROR",)),
        "warn":  ("WHERE level = ?",  ("WARN",)),
        "info":  ("WHERE level = ?",  ("INFO",)),
        "auth":  (
            "WHERE endpoint IN ("
            "'/api/login','/api/register','/api/logout',"
            "'/api/admin/login','/auth/google/callback')", (),
        ),
        "chat":   ("WHERE endpoint LIKE ?", ("/api/chat%",)),
        "upload": ("WHERE endpoint LIKE ?", ("/api/upload%",)),
        "admin":  ("WHERE endpoint LIKE ?", ("/admin/api%",)),
    }

    if log_type not in FILTER_CLAUSES:
        return jsonify(error=f"Unknown log type '{log_type}'"), 400

    where_clause, where_params = FILTER_CLAUSES[log_type]
    rows = _rows(_q(
        f"SELECT id,level,message,endpoint,user_id,ip_address,response_ms,created_at "
        f"FROM app_logs {where_clause} ORDER BY created_at DESC LIMIT ?",
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
        pdf_ok = False
        try:
            import PyPDF2  # noqa
            pdf_ok = True
        except ImportError:
            pass

        return jsonify(settings=dict(
            site_name               = os.environ.get("SITE_NAME", "Jarvis AI"),
            admin_username          = _ADMIN_USERNAME,
            admin_email             = _ADMIN_EMAIL,
            models                  = ALL_MODELS,
            razorpay_configured     = bool(_rzp_client),
            smtp_configured         = bool(os.environ.get("SMTP_HOST")),
            openrouter_configured   = bool(os.environ.get("OPENROUTER_API_KEY")),
            google_oauth_configured = bool(app.config["GOOGLE_CLIENT_ID"]),
            pdf_extraction          = pdf_ok,
            max_file_size_mb        = MAX_FILE_SIZE // 1024 // 1024,
            max_files_per_upload    = MAX_FILES,
            database                = "SQLite",
            database_path           = DATABASE_PATH,
            production              = _IS_PROD,
        ))

    err = _check_csrf()
    if err:
        return err
    _db_log("INFO", "Admin visited settings (POST)",
            "/admin/api/settings", flask_session["user_id"])
    return jsonify(
        success = True,
        note    = "Runtime settings are read-only. Edit your env vars and redeploy.",
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Feedback
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/feedback", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute; 20 per hour")
def api_submit_feedback():
    err = _check_csrf()
    if err:
        return err

    data    = request.get_json(force=True, silent=True) or {}
    name    = str(data.get("name",    "")).strip()[:120]
    email   = str(data.get("email",   "")).strip()[:254]
    message = str(data.get("message", "")).strip()[:5000]

    if not name or len(name) < 2:
        return jsonify(error="Name must be at least 2 characters"), 400
    if not message or len(message) < 5:
        return jsonify(error="Message too short"), 400
    if email and not VALID_EMAIL_RE.match(email):
        return jsonify(error="Invalid email address"), 400

    _q(
        "INSERT INTO feedback (id,name,email,message,is_read,ip_address,created_at) "
        "VALUES (?,?,?,?,0,?,?)",
        (_uid(), name, email or None, message, _client_ip(), _now()),
    )
    _commit()

    if _ADMIN_EMAIL:
        _send_notification_bg(
            _ADMIN_EMAIL,
            f"[Jarvis] New feedback from {name}",
            f"Name:  {name}\nEmail: {email or '(none)'}\nIP: {_client_ip()}\n\n{message}",
        )
    return jsonify(success=True)


@app.route("/admin/api/feedback")
@csrf.exempt
@admin_required
def admin_feedback_list():
    read_filter = request.args.get("read", "all").strip().lower()
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except (ValueError, TypeError):
        limit = 200

    base = (
        "SELECT id,name,email,message,is_read,ip_address,created_at "
        "FROM feedback"
    )
    if read_filter == "unread":
        rows = _rows(_q(base + " WHERE is_read=0 ORDER BY created_at DESC LIMIT ?", (limit,)))
    elif read_filter == "read":
        rows = _rows(_q(base + " WHERE is_read=1 ORDER BY created_at DESC LIMIT ?", (limit,)))
    else:
        rows = _rows(_q(base + " ORDER BY created_at DESC LIMIT ?", (limit,)))

    total  = _row(_q("SELECT COUNT(*) AS c FROM feedback"))["c"]
    unread = _row(_q("SELECT COUNT(*) AS c FROM feedback WHERE is_read=0"))["c"]
    return jsonify(feedback=rows, total=total, unread=unread)


@app.route("/admin/api/feedback/<fid>", methods=["DELETE"])
@csrf.exempt
@admin_required
def admin_feedback_delete(fid):
    err = _check_csrf()
    if err:
        return err
    if not _row(_q("SELECT id FROM feedback WHERE id=?", (fid,))):
        return jsonify(error="Feedback not found"), 404
    _q("DELETE FROM feedback WHERE id=?", (fid,))
    _commit()
    return jsonify(success=True)


@app.route("/admin/api/feedback/<fid>/read", methods=["PATCH"])
@csrf.exempt
@admin_required
def admin_feedback_mark_read(fid):
    err = _check_csrf()
    if err:
        return err
    if not _row(_q("SELECT id FROM feedback WHERE id=?", (fid,))):
        return jsonify(error="Feedback not found"), 404
    data    = request.get_json(force=True, silent=True) or {}
    is_read = 1 if data.get("is_read", True) else 0
    _q("UPDATE feedback SET is_read=? WHERE id=?", (is_read, fid))
    _commit()
    return jsonify(success=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Health check
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health")
@csrf.exempt
def api_health():
    db_ok = False
    try:
        _row(_q("SELECT 1 AS ok"))
        db_ok = True
    except Exception:
        pass

    pdf_ok = False
    try:
        import PyPDF2  # noqa
        pdf_ok = True
    except ImportError:
        pass

    return jsonify(
        status        = "ok" if db_ok else "degraded",
        db            = db_ok,
        db_type       = "sqlite",
        models        = ALL_MODELS,
        razorpay      = bool(_rzp_client),
        openrouter    = bool(os.environ.get("OPENROUTER_API_KEY")),
        google_oauth  = bool(app.config["GOOGLE_CLIENT_ID"]),
        pdf_extract   = pdf_ok,
        uploads       = dict(
            max_file_mb = MAX_FILE_SIZE // 1024 // 1024,
            max_files   = MAX_FILES,
        ),
        production    = _IS_PROD,
        ts            = _now(),
    ), 200 if db_ok else 503


# ─────────────────────────────────────────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):          return jsonify(error="Not found"), 404

@app.errorhandler(405)
def method_not_allowed(_): return jsonify(error="Method not allowed"), 405

@app.errorhandler(413)
def too_large(_):          return jsonify(error="File too large — max 10 MB per file"), 413

@app.errorhandler(415)
def unsupported_media(_):  return jsonify(error="Unsupported file type"), 415

@app.errorhandler(429)
def rate_limited(_):       return jsonify(error="Too many requests — slow down"), 429

@app.errorhandler(500)
def server_error(_):       return jsonify(error="Internal server error"), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point  (python app.py only — Gunicorn imports the module directly)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port  = int(os.environ.get("PORT", 5000))
    log.info(
        "Jarvis AI starting — debug=%s  port=%d  admin='%s'  db=%s",
        debug, port, _ADMIN_USERNAME, DATABASE_PATH,
    )
    log.info("Models: %s", json.dumps(ALL_MODELS, indent=2))
    log.info("Upload limits: %d files × %d MB", MAX_FILES, MAX_FILE_SIZE // 1024 // 1024)
    app.run(host="0.0.0.0", port=port, debug=debug)