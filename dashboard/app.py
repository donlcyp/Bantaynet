"""Flask web dashboard for BantayNet suspicious activity detection system."""

from __future__ import annotations

import csv
import io
import os
import sys
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyze import analyze
from src.config import load_config
from src.db import get_alert_by_id, get_alerts, get_summary_stats, init_db, insert_alert

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "dashboard" / "templates"),
    static_folder=str(PROJECT_ROOT / "dashboard" / "static"),
)

app.secret_key = os.environ.get("BANTAYNET_SECRET_KEY", "bantaynet-lab-secret-key-38291")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB maximum upload
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

UPLOAD_DIR = PROJECT_ROOT / "pcaps" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def is_allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    rule = request.args.get("rule", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    src_ip = request.args.get("src_ip", "").strip() or None
    search = request.args.get("search", "").strip() or None

    init_db()
    stats = get_summary_stats()
    alerts = get_alerts(rule=rule, severity=severity, src_ip=src_ip, search=search, limit=500)

    filters = {
        "rule": rule or "",
        "severity": severity or "",
        "src_ip": src_ip or "",
        "search": search or "",
    }
    return render_template("index.html", stats=stats, alerts=alerts, filters=filters)


@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert:
        abort(404, description=f"Alert #{alert_id} not found")

    evidence_packets = []
    evidence_path = alert.get("evidence_file")
    if evidence_path and Path(evidence_path).is_file():
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.utils import PcapReader

            with PcapReader(str(evidence_path)) as reader:
                first_ts = None
                for idx, pkt in enumerate(reader):
                    if idx >= 100:  # Preview cap in UI
                        break
                    ts = float(pkt.time)
                    if first_ts is None:
                        first_ts = ts
                    rel_time = f"{ts - first_ts:.4f}"

                    src = pkt[IP].src if IP in pkt else "Unknown"
                    dst = pkt[IP].dst if IP in pkt else "Unknown"
                    proto = "OTHER"
                    flags = ""

                    if TCP in pkt:
                        proto = f"TCP/{pkt[TCP].dport}"
                        flags = pkt[TCP].flags
                    elif UDP in pkt:
                        proto = f"UDP/{pkt[UDP].dport}"
                    elif ICMP in pkt:
                        proto = f"ICMP Type {pkt[ICMP].type}"

                    evidence_packets.append(
                        {
                            "num": idx + 1,
                            "rel_time": rel_time,
                            "src": src,
                            "dst": dst,
                            "proto": proto,
                            "flags": str(flags),
                            "len": len(pkt),
                            "summary": pkt.summary(),
                        }
                    )
        except Exception as e:
            app.logger.warning(f"Could not parse evidence PCAP {evidence_path}: {e}")

    return render_template("alert.html", alert=alert, evidence_packets=evidence_packets)


@app.route("/upload", methods=["POST"])
def upload_pcap():
    if "pcap_file" not in request.files:
        flash("No file part in upload request.", "error")
        return redirect(url_for("index"))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No file selected for upload.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    if not is_allowed_file(filename):
        flash("Invalid file type! Only .pcap and .pcapng files are permitted.", "error")
        return redirect(url_for("index"))

    dest_path = UPLOAD_DIR / filename
    file.save(str(dest_path))

    try:
        cfg = load_config()
        result = analyze(dest_path, cfg=cfg)

        init_db()
        for a in result.alerts:
            insert_alert(
                rule=a.rule,
                severity=a.severity,
                src_ip=a.src,
                dst_ip=a.dst,
                packet_time=a.first_ts,
                description=a.summary,
                evidence_file=a.evidence_path,
                source_pcap=filename,
                protocol="TCP" if "TCP" in a.summary else ("ICMP" if "ICMP" in a.summary else "OTHER"),
                packet_count=a.packet_count,
                details=a.details,
                dst_port=a.dst_port,
            )


        flash(
            f"Successfully analyzed '{filename}': {result.stats.parsed} packets parsed, {len(result.alerts)} alert(s) detected.",
            "success",
        )
    except Exception as exc:
        flash(f"Error analyzing capture file: {exc}", "error")

    return redirect(url_for("index"))


@app.route("/evidence/<int:alert_id>")
def download_evidence(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert or not alert.get("evidence_file"):
        abort(404, description="No evidence file associated with this alert")

    file_path = Path(alert["evidence_file"])
    if not file_path.is_file():
        abort(404, description="Evidence file does not exist on disk")

    return send_file(
        str(file_path),
        as_attachment=True,
        download_name=file_path.name,
        mimetype="application/vnd.tcpdump.pcap",
    )


@app.route("/export.csv")
def export_csv():
    rule = request.args.get("rule", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    src_ip = request.args.get("src_ip", "").strip() or None
    search = request.args.get("search", "").strip() or None

    alerts = get_alerts(rule=rule, severity=severity, src_ip=src_ip, search=search, limit=5000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Detected At", "Packet Time", "Rule", "Severity",
        "Source IP", "Destination IP", "Target Port", "Protocol", "Description",
        "Source PCAP", "Packet Count", "Evidence File"
    ])

    for a in alerts:
        writer.writerow([
            a["id"], a["detected_at"], a["packet_time"], a["rule"], a["severity"],
            a["src_ip"], a["dst_ip"], a.get("dst_port", "-"), a["protocol"], a["description"],
            a["source_pcap"], a["packet_count"], a["evidence_file"]
        ])


    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=bantaynet_alerts.csv"},
    )


def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    init_db()
    print(f"\n[*] BantayNet Security Dashboard running at http://{host}:{port}/")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard(debug=True)
