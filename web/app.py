"""Cassandra Bot — Flask 대시보드 (WebSocket 실시간)."""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from core.db import DB
from core.logger import get_logger

log = get_logger("web")


def create_app(db: DB) -> tuple[Flask, SocketIO]:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    socketio = SocketIO(app, cors_allowed_origins="*")

    @app.route("/")
    def dashboard():
        stats = db.stats()
        recent_findings = db.list_findings()[:10]
        recent_reports = db.list_reports()[:10]
        return render_template("dashboard.html", stats=stats, findings=recent_findings, reports=recent_reports)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(db.stats())

    @app.route("/api/findings")
    def api_findings():
        status = request.args.get("status")
        findings = db.list_findings(status=status)
        return jsonify([f.to_dict() for f in findings])

    @app.route("/api/reports")
    def api_reports():
        status = request.args.get("status")
        program = request.args.get("program")
        reports = db.list_reports(status=status, program=program)
        return jsonify([r.to_dict() for r in reports])

    @app.route("/api/reports/<report_id>")
    def api_report_detail(report_id):
        report = db.get_report(report_id)
        if not report:
            return jsonify({"error": "not found"}), 404
        return jsonify(report.to_dict())

    @app.route("/api/reports/<report_id>/submit", methods=["POST"])
    def api_submit_report(report_id):
        report = db.get_report(report_id)
        if not report:
            return jsonify({"error": "not found"}), 404
        db.update_report_status(report_id, "submitted")
        # Broadcast to WebSocket clients
        socketio.emit("report_submitted", {"report_id": report_id, "title": report.title})
        return jsonify({"status": "submitted"})

    @app.route("/api/assets")
    def api_assets():
        assets = db.list_assets()
        return jsonify([a.to_dict() for a in assets])

    @app.route("/api/earnings")
    def api_earnings():
        reports = db.list_reports(status="accepted")
        return jsonify({
            "accepted_count": len(reports),
            "reports": [r.to_dict() for r in reports],
        })

    # WebSocket events
    @socketio.on("connect")
    def handle_connect():
        log.info("WebSocket client connected")

    @socketio.on("disconnect")
    def handle_disconnect():
        log.info("WebSocket client disconnected")

    # Periodic stats broadcast
    def broadcast_stats():
        stats = db.stats()
        socketio.emit("stats_update", stats)

    # Start periodic broadcast (every 5 seconds)
    import threading
    import time

    def periodic_broadcast():
        while True:
            try:
                broadcast_stats()
            except Exception:
                pass
            time.sleep(5)

    broadcast_thread = threading.Thread(target=periodic_broadcast, daemon=True)
    broadcast_thread.start()

    return app, socketio


def run_app(db: DB, host: str = "0.0.0.0", port: int = 8500):
    """Flask + SocketIO 실행."""
    app, socketio = create_app(db)
    socketio.run(app, host=host, port=port, debug=False)
