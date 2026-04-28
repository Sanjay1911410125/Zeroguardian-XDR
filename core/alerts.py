# core/alerts.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Alert System
# Sends threat notifications via Telegram bot and/or Email (SMTP).
# Also provides send_otp() so forgot-password OTPs go somewhere real.
#
# Setup (add to your .env file or set as environment variables):
#
#   TELEGRAM_BOT_TOKEN=123456789:ABCDefGhIJKlmNoPQRsTUVwXyz
#   TELEGRAM_CHAT_ID=987654321
#
#   ALERT_EMAIL_FROM=zeroguardian@gmail.com
#   ALERT_EMAIL_PASSWORD=your_app_password
#   ALERT_EMAIL_TO=your@email.com
#   SMTP_HOST=smtp.gmail.com
#   SMTP_PORT=587
#
# How to get Telegram credentials:
#   1. Message @BotFather on Telegram → /newbot → copy the token
#   2. Message your bot once, then visit:
#      https://api.telegram.org/bot<TOKEN>/getUpdates
#      and copy the "chat":{"id": ...} value
# ─────────────────────────────────────────────────────────────────────────────

import os
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ── Config (reads from environment variables) ─────────────────────────────────
def _env(key, default=""):
    return os.environ.get(key, default).strip()

TELEGRAM_TOKEN   = _env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _env("TELEGRAM_CHAT_ID")

EMAIL_FROM     = _env("ALERT_EMAIL_FROM")
EMAIL_PASSWORD = _env("ALERT_EMAIL_PASSWORD")
EMAIL_TO       = _env("ALERT_EMAIL_TO")
SMTP_HOST      = _env("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(_env("SMTP_PORT", "587"))

# Rate-limit: don't send the same alert more than once per N seconds
_ALERT_COOLDOWN_SEC = 7200  # 2 hour — same alert won't fire more than once per hour
_last_sent: dict = {}   # key → last_send_timestamp


def _cooldown_ok(key: str) -> bool:
    now = time.time()
    last = _last_sent.get(key, 0)
    if now - last >= _ALERT_COOLDOWN_SEC:
        _last_sent[key] = now
        return True
    return False


# ── Telegram ──────────────────────────────────────────────────────────────────
def send_telegram(message: str, force: bool = False) -> bool:
    """
    Send a message via Telegram bot.
    Returns True on success, False on failure.
    """
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Alerts] Telegram not configured (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)")
        return False

    if not _HAS_REQUESTS:
        print("[Alerts] requests library missing — run: pip install requests")
        return False

    key = f"tg:{message[:60]}"
    if not force and not _cooldown_ok(key):
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "HTML",
    }

    try:
        resp = _requests.post(url, json=payload, timeout=8)
        if resp.status_code == 200:
            print(f"[Alerts] Telegram ✅ sent")
            return True
        else:
            print(f"[Alerts] Telegram ❌ {resp.status_code}: {resp.text[:120]}")
            return False
    except Exception as e:
        print(f"[Alerts] Telegram error: {e}")
        return False


# ── Email ─────────────────────────────────────────────────────────────────────
def send_email(subject: str, body: str, force: bool = False) -> bool:
    """
    Send a plain-text alert email via SMTP (Gmail app password recommended).
    Returns True on success.
    """
    if not EMAIL_FROM or not EMAIL_PASSWORD or not EMAIL_TO:
        print("[Alerts] Email not configured (set ALERT_EMAIL_FROM/PASSWORD/TO)")
        return False

    key = f"email:{subject[:60]}"
    if not force and not _cooldown_ok(key):
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

        print(f"[Alerts] Email ✅ sent → {EMAIL_TO}")
        return True
    except Exception as e:
        print(f"[Alerts] Email error: {e}")
        return False


# ── High-level threat alert ───────────────────────────────────────────────────
def send_threat_alert(title: str, details: str, severity: str,
                      ip: str = "unknown", async_send: bool = True):
    """
    Send a formatted threat alert via all configured channels.
    Runs in a background thread by default so it never blocks Flask.

    severity : LOW | MEDIUM | HIGH | CRITICAL
    """
    sev = severity.upper()
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}.get(sev, "⚠️")

    tg_msg = (
        f"{icon} <b>ZeroGuardian XDR Alert</b>\n\n"
        f"<b>Severity:</b> {sev}\n"
        f"<b>Type:</b> {title}\n"
        f"<b>IP:</b> {ip}\n"
        f"<b>Details:</b> {details}\n"
        f"<b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    email_subject = f"[ZeroGuardian] {sev} — {title}"
    email_body = (
        f"ZeroGuardian XDR Threat Alert\n"
        f"{'='*40}\n"
        f"Severity : {sev}\n"
        f"Type     : {title}\n"
        f"Source IP: {ip}\n"
        f"Details  : {details}\n"
        f"Time     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*40}\n"
        f"Visit your dashboard for full details."
    )

    def _send():
        send_telegram(tg_msg)
        send_email(email_subject, email_body)

    if async_send:
        threading.Thread(target=_send, daemon=True).start()
    else:
        _send()


# ── OTP delivery (replaces print() in app.py) ─────────────────────────────────
def send_otp(username: str, otp: str) -> bool:
    """
    Delivers a password-reset OTP to the user.
    Tries Telegram first, then Email, falls back to terminal print.
    Returns True if delivered via Telegram or Email.
    """
    msg_tg = (
        f"🔐 <b>ZeroGuardian XDR — Password Reset</b>\n\n"
        f"Your OTP for <b>{username}</b> is:\n\n"
        f"<code>{otp}</code>\n\n"
        f"This code expires in 5 minutes."
    )
    msg_email_body = (
        f"ZeroGuardian XDR Password Reset\n\n"
        f"Username : {username}\n"
        f"OTP Code : {otp}\n\n"
        f"This code expires in 5 minutes.\n"
        f"If you did not request this, ignore this message."
    )

    sent_tg    = send_telegram(msg_tg, force=True)
    sent_email = send_email(
        subject=f"[ZeroGuardian] OTP for {username}",
        body=msg_email_body,
        force=True
    )

    if not sent_tg and not sent_email:
        # Terminal fallback (development only)
        print(f"[ZeroGuardian OTP] user={username} otp={otp}  "
              f"(configure Telegram/Email to deliver securely)")
        return False

    return True


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[Test] Sending test threat alert …")
    send_threat_alert(
        title="Port Scan Detected",
        details="Source 10.0.0.99 scanned 127 ports in 6 seconds",
        severity="HIGH",
        ip="10.0.0.99",
        async_send=False
    )

    print("\n[Test] Sending test OTP …")
    send_otp("admin", "847291")
