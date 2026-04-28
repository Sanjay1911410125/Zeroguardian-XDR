# config/security.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Security Configuration
# Loads secrets from .env, adds session timeout, CSRF token generation.
#
# In app.py, replace the hardcoded secret_key block with:
#
#   from config.security import init_security
#   init_security(app)
# ─────────────────────────────────────────────────────────────────────────────

import os
import secrets
import hashlib
from datetime import timedelta
from functools import wraps
from flask import session, request, abort

ENV_FILE = os.path.join(os.path.dirname(__file__), "..", ".env")


def _load_env(path):
    """Load key=value pairs from .env file into os.environ (if not already set)."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


def _get_secret_key():
    """
    Load secret key from environment.
    If not set, generate one and warn the developer.
    """
    key = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if key:
        return key

    # Auto-generate a strong key and print it once
    generated = secrets.token_hex(32)
    print("\n" + "="*60)
    print("[Security] WARNING: FLASK_SECRET_KEY not set in .env!")
    print(f"[Security] Generated temporary key (sessions won't persist restarts):")
    print(f"[Security] Add this to your .env file:")
    print(f"  FLASK_SECRET_KEY={generated}")
    print("="*60 + "\n")
    return generated


def init_security(app):
    """
    Call this in app.py after creating the Flask app.
    Sets secret key, session lifetime, and security headers.
    """
    _load_env(ENV_FILE)

    # Secret key from .env (never hardcoded)
    app.secret_key = _get_secret_key()

    # Session expires after 30 minutes of inactivity
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
    app.config["SESSION_COOKIE_HTTPONLY"]    = True
    app.config["SESSION_COOKIE_SAMESITE"]   = "Lax"

    # Make all sessions permanent (so the timeout applies)
    @app.before_request
    def _make_session_permanent():
        session.permanent = True

    # Security headers on every response
    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        return response

    print("[Security] Security config applied ✅")
    return app


# ── CSRF Protection ───────────────────────────────────────────────────────────
def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]


def validate_csrf_token():
    """Check that the submitted CSRF token matches the session token."""
    token_form    = request.form.get("csrf_token", "")
    token_header  = request.headers.get("X-CSRF-Token", "")
    token_session = session.get("csrf_token", "")

    if not token_session:
        return False

    submitted = token_form or token_header
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(
        hashlib.sha256(submitted.encode()).hexdigest(),
        hashlib.sha256(token_session.encode()).hexdigest()
    )


def csrf_protect(fn):
    """Decorator — apply to any POST route that modifies state."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            if not validate_csrf_token():
                abort(403)
        return fn(*args, **kwargs)
    return wrapper
