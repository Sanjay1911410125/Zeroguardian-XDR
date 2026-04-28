# dashboard/vuln_routes.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Vulnerability Scanner Routes
# Add to app.py:
#   from dashboard.vuln_routes import register_vuln_routes
#   register_vuln_routes(app)
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


def register_vuln_routes(app):

    @app.route("/vulnerabilities")
    @_require_login
    def vulnerabilities():
        return render_template("vulnerabilities.html",
                               page="vulnerabilities",
                               title="Vulnerability Scanner — ZeroGuardian XDR")

    @app.route("/api/vulnscan/start", methods=["POST"])
    @_require_login
    def api_vulnscan_start():
        try:
            from core.vuln_scanner import start_background_scan
            from core.orchestrator import get_snapshot
            snap    = get_snapshot()
            devices = snap.get("devices", [])
            if not devices:
                return jsonify({"error": "No devices discovered yet — wait for device scan"})
            result = start_background_scan(devices)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)})

    @app.route("/api/vulnscan/status")
    @_require_login
    def api_vulnscan_status():
        try:
            from core.vuln_scanner import get_scan_status
            return jsonify(get_scan_status())
        except Exception as e:
            return jsonify({"error": str(e)})

    @app.route("/api/vulnscan/results")
    @_require_login
    def api_vulnscan_results():
        try:
            from core.vuln_scanner import get_latest_results, get_scan_summary
            vulns   = get_latest_results()
            summary = get_scan_summary()
            return jsonify({"vulns": vulns, "summary": summary})
        except Exception as e:
            return jsonify({"vulns": [], "summary": {}, "error": str(e)})

    print("[VulnScan] Routes registered ✅")
