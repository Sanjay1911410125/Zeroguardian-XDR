# dashboard/settings_routes.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Alert Settings Routes
# Add these routes to your app.py using:
#   from dashboard.settings_routes import register_settings_routes
#   register_settings_routes(app)
# ─────────────────────────────────────────────────────────────────────────────

import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import render_template, request, jsonify, session, redirect, url_for

ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")

# ── .env reader/writer ────────────────────────────────────────────────────────
def _read_env():
    """Read .env file into a dict."""
    result = {}
    if not os.path.exists(ENV_PATH):
        return result
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _write_env(updates: dict):
    """
    Update specific keys in .env file.
    Preserves all comments and existing keys.
    Creates file if it doesn't exist.
    """
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            lines = f.readlines()

    updated_keys = set()

    # Update existing lines
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        k, _, _ = stripped.partition("=")
        k = k.strip()
        if k in updates:
            new_lines.append(f"{k}={updates[k]}\n")
            updated_keys.add(k)
        else:
            new_lines.append(line)

    # Append new keys that weren't in the file
    for k, v in updates.items():
        if k not in updated_keys:
            new_lines.append(f"{k}={v}\n")

    with open(ENV_PATH, "w") as f:
        f.writelines(new_lines)

    # Also update os.environ so changes take effect immediately
    for k, v in updates.items():
        os.environ[k] = v


def _mask(value: str) -> str:
    """Mask sensitive values for display — show first 4 and last 4 chars."""
    if not value or len(value) < 8:
        return value
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _require_admin(f):
    """Simple decorator — only logged-in users can access settings."""
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ── Register all routes ───────────────────────────────────────────────────────
def register_settings_routes(app):

    # ── Settings page (GET) ───────────────────────────────────────────────────
    @app.route("/settings")
    @_require_admin
    def settings():
        env = _read_env()
        return render_template("settings.html",
            page="settings",
            title="Alert Settings — ZeroGuardian XDR",

            # Telegram
            telegram_configured = bool(env.get("TELEGRAM_BOT_TOKEN")),
            telegram_token_masked = _mask(env.get("TELEGRAM_BOT_TOKEN", "")),
            telegram_chat_id    = env.get("TELEGRAM_CHAT_ID", ""),
            tg_threshold        = env.get("TG_ALERT_THRESHOLD", "MEDIUM"),

            # Email
            email_configured    = bool(env.get("ALERT_EMAIL_FROM") and
                                       env.get("ALERT_EMAIL_PASSWORD")),
            email_from          = env.get("ALERT_EMAIL_FROM", ""),
            email_pass_masked   = _mask(env.get("ALERT_EMAIL_PASSWORD", "")),
            email_to            = env.get("ALERT_EMAIL_TO", ""),
            smtp_host           = env.get("SMTP_HOST", "smtp.gmail.com"),
            smtp_port           = env.get("SMTP_PORT", "587"),
            email_threshold     = env.get("EMAIL_ALERT_THRESHOLD", "HIGH"),
        )

    # ── Save Telegram credentials ─────────────────────────────────────────────
    @app.route("/api/settings/telegram/save", methods=["POST"])
    @_require_admin
    def api_settings_telegram_save():
        data    = request.get_json() or {}
        token   = (data.get("token") or "").strip()
        chat_id = (data.get("chat_id") or "").strip()

        if not token or not chat_id:
            return jsonify({"success": False, "error": "Both token and chat ID are required"})

        # Basic format validation
        if ":" not in token:
            return jsonify({"success": False,
                            "error": "Invalid token format — should contain ':'"})

        _write_env({
            "TELEGRAM_BOT_TOKEN": token,
            "TELEGRAM_CHAT_ID":   chat_id,
        })
        return jsonify({"success": True})

    # ── Test Telegram credentials ─────────────────────────────────────────────
    @app.route("/api/settings/telegram/test", methods=["POST"])
    @_require_admin
    def api_settings_telegram_test():
        data    = request.get_json() or {}
        token   = (data.get("token") or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        chat_id = (data.get("chat_id") or os.environ.get("TELEGRAM_CHAT_ID", "")).strip()

        if not token or not chat_id:
            return jsonify({"success": False,
                            "error": "Token and Chat ID are required"})

        try:
            import requests as req
            msg = (
                "🔔 <b>ZeroGuardian XDR — Test Alert</b>\n\n"
                "✅ Telegram alerts are configured correctly!\n"
                "You will receive real-time threat notifications here."
            )
            resp = req.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=8,
            )
            if resp.status_code == 200:
                return jsonify({"success": True})
            else:
                err = resp.json().get("description", "Unknown error")
                return jsonify({"success": False, "error": err})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

    # ── Save Email credentials ────────────────────────────────────────────────
    @app.route("/api/settings/email/save", methods=["POST"])
    @_require_admin
    def api_settings_email_save():
        data = request.get_json() or {}
        _write_env({
            "ALERT_EMAIL_FROM":     (data.get("from_addr") or "").strip(),
            "ALERT_EMAIL_PASSWORD": (data.get("password")  or "").strip(),
            "ALERT_EMAIL_TO":       (data.get("to_addr")   or "").strip(),
            "SMTP_HOST":            (data.get("smtp_host") or "smtp.gmail.com").strip(),
            "SMTP_PORT":            str(data.get("smtp_port") or "587").strip(),
        })
        return jsonify({"success": True})

    # ── Test Email credentials ────────────────────────────────────────────────
    @app.route("/api/settings/email/test", methods=["POST"])
    @_require_admin
    def api_settings_email_test():
        data      = request.get_json() or {}
        env       = _read_env()
        from_addr = (data.get("from_addr") or env.get("ALERT_EMAIL_FROM", "")).strip()
        password  = (data.get("password")  or env.get("ALERT_EMAIL_PASSWORD", "")).strip()
        to_addr   = (data.get("to_addr")   or env.get("ALERT_EMAIL_TO", "")).strip()
        smtp_host = (data.get("smtp_host") or env.get("SMTP_HOST", "smtp.gmail.com")).strip()
        smtp_port = int((data.get("smtp_port") or env.get("SMTP_PORT", "587")))

        if not from_addr or not password or not to_addr:
            return jsonify({"success": False,
                            "error": "From address, password, and recipient are required"})

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "[ZeroGuardian XDR] Test Alert — Email Configured ✅"
            msg["From"]    = from_addr
            msg["To"]      = to_addr
            body = (
                "ZeroGuardian XDR — Test Email\n\n"
                "✅ Email alerts are configured correctly!\n"
                "You will receive threat digest reports at this address."
            )
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(from_addr, password)
                server.sendmail(from_addr, to_addr, msg.as_string())

            return jsonify({"success": True})
        except smtplib.SMTPAuthenticationError:
            return jsonify({"success": False,
                            "error": "Authentication failed — check your App Password"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

    # ── Save alert thresholds ─────────────────────────────────────────────────
    @app.route("/api/settings/thresholds/save", methods=["POST"])
    @_require_admin
    def api_settings_thresholds_save():
        data = request.get_json() or {}
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        tg_thresh    = data.get("telegram_threshold", "MEDIUM").upper()
        email_thresh = data.get("email_threshold", "HIGH").upper()

        if tg_thresh not in valid or email_thresh not in valid:
            return jsonify({"success": False, "error": "Invalid threshold value"})

        _write_env({
            "TG_ALERT_THRESHOLD":    tg_thresh,
            "EMAIL_ALERT_THRESHOLD": email_thresh,
        })
        return jsonify({"success": True})

    print("[Settings] Routes registered ✅")
