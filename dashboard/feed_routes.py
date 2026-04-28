# dashboard/feed_routes.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Threat Feed Routes
# Add to app.py:
#   from dashboard.feed_routes import register_feed_routes
#   register_feed_routes(app)
# ─────────────────────────────────────────────────────────────────────────────

from flask import render_template, jsonify, session, redirect, url_for, request
from functools import wraps


def _require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def register_feed_routes(app):

    @app.route("/threat-feeds")
    @_require_login
    def threat_feeds_page():
        from core.threat_feeds import get_feed_stats
        stats = get_feed_stats()
        return render_template("threat_feeds.html",
                               page="threat_feeds",
                               title="Threat Intelligence Feeds — ZeroGuardian XDR",
                               stats=stats)

    @app.route("/api/feeds/stats")
    @_require_login
    def api_feed_stats():
        from core.threat_feeds import get_feed_stats
        return jsonify(get_feed_stats())

    @app.route("/api/feeds/update", methods=["POST"])
    @_require_login
    def api_feed_update():
        import threading
        def _run():
            from core.threat_feeds import run_full_update
            run_full_update()
        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"started": True})

    @app.route("/api/feeds/check", methods=["POST"])
    @_require_login
    def api_feed_check():
        """Check a specific IP against threat feeds."""
        data = request.get_json() or {}
        ip   = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"})
        try:
            import sqlite3, os
            BASE_DIR = os.path.dirname(os.path.dirname(__file__))
            DB_PATH  = os.path.join(BASE_DIR, "vulnerabilities.db")
            conn     = sqlite3.connect(DB_PATH)
            cur      = conn.cursor()
            cur.execute("""
                SELECT indicator, source, severity, category, description
                FROM threat_indicators
                WHERE indicator = ? AND type = 'ip'
            """, (ip,))
            rows = cur.fetchall()
            conn.close()
            return jsonify({
                "ip":      ip,
                "matches": [
                    {"source": r[1], "severity": r[2],
                     "category": r[3], "description": r[4]}
                    for r in rows
                ],
                "is_malicious": len(rows) > 0,
            })
        except Exception as e:
            return jsonify({"error": str(e)})

    print("[FeedRoutes] Routes registered ✅")
