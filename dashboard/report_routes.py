# dashboard/report_routes.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — PDF Report Routes
# Add to app.py:
#   from dashboard.report_routes import register_report_routes
#   register_report_routes(app)
# ─────────────────────────────────────────────────────────────────────────────

import os
import threading
from flask import (render_template, jsonify, session,
                   redirect, url_for, send_file, request)
from functools import wraps

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_generating = False


def _require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def register_report_routes(app):

    # ── Reports page ──────────────────────────────────────────────────────────
    @app.route("/reports")
    @_require_login
    def reports_page():
        from core.report_generator import list_reports
        return render_template("reports.html",
                               page="reports",
                               title="Security Reports — ZeroGuardian XDR",
                               reports=list_reports())

    # ── Generate report (POST) ────────────────────────────────────────────────
    @app.route("/api/reports/generate", methods=["POST"])
    @_require_login
    def api_generate_report():
        global _generating
        if _generating:
            return jsonify({"error": "Report generation already in progress"})

        data        = request.get_json() or {}
        send_email  = data.get("send_email", False)
        send_tg     = data.get("send_telegram", False)

        def _run():
            global _generating
            _generating = True
            try:
                from core.orchestrator import get_snapshot
                from core.report_generator import (generate_report,
                                                    email_report,
                                                    telegram_report)
                snap     = get_snapshot()
                pdf_path = generate_report(snap)

                if send_email:
                    email_report(pdf_path)
                if send_tg:
                    telegram_report(pdf_path, snap)

                print(f"[Report] Manual generation complete: {pdf_path}")
            except Exception as e:
                print(f"[Report] Generation error: {e}")
            finally:
                _generating = False

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"started": True})

    # ── Generation status ─────────────────────────────────────────────────────
    @app.route("/api/reports/status")
    @_require_login
    def api_report_status():
        from core.report_generator import list_reports
        return jsonify({
            "generating": _generating,
            "reports":    list_reports(),
        })

    # ── Download a report ─────────────────────────────────────────────────────
    @app.route("/api/reports/download/<filename>")
    @_require_login
    def api_download_report(filename):
        # Security — no path traversal
        filename = os.path.basename(filename)
        path     = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(path):
            return jsonify({"error": "Report not found"}), 404
        return send_file(path, as_attachment=True,
                         download_name=filename,
                         mimetype="application/pdf")

    # ── Delete a report ───────────────────────────────────────────────────────
    @app.route("/api/reports/delete/<filename>", methods=["DELETE"])
    @_require_login
    def api_delete_report(filename):
        filename = os.path.basename(filename)
        path     = os.path.join(REPORTS_DIR, filename)
        try:
            os.remove(path)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # ── Schedule settings ─────────────────────────────────────────────────────
    @app.route("/api/reports/schedule", methods=["POST"])
    @_require_login
    def api_report_schedule():
        data  = request.get_json() or {}
        hours = int(data.get("interval_hours", 24))
        try:
            from core.report_generator import start_report_scheduler
            start_report_scheduler(interval_hours=hours)
            return jsonify({"success": True, "interval_hours": hours})
        except Exception as e:
            return jsonify({"error": str(e)})

    print("[Reports] Routes registered ✅")
