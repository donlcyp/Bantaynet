"""PDF report generation for BantayNet security incidents and executive summaries.

Built using ReportLab. Formats incident telemetry, MITRE ATT&CK alignment,
analyst triage notes, and forensic evidence packets into a clean, client-ready report.
Detect-and-alert only, per project security policy.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, BinaryIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _safe_text(val: Any) -> str:
    """Escape text for safe inclusion in ReportLab XML-like paragraphs."""
    if val is None:
        return ""
    return escape(str(val))


def _get_styles():
    """Build and return custom typography styles for the PDF report."""
    base_styles = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "DocTitle",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "DocSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0284c7"),
            spaceAfter=12,
        ),
        "h2": ParagraphStyle(
            "Heading2",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        ),
        "body_bold": ParagraphStyle(
            "BodyBold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
        ),
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b"),
        ),
        "table_cell_bold": ParagraphStyle(
            "TableCellBold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "mono": ParagraphStyle(
            "Mono",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#0f172a"),
        ),
        "footer": ParagraphStyle(
            "Footer",
            parent=base_styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#64748b"),
            alignment=1,  # Center
        ),
    }
    return styles


def generate_alert_pdf(
    alert: dict[str, Any],
    evidence_packets: list[dict[str, Any]],
    out_stream: BinaryIO | None = None,
) -> bytes | None:
    """Generate a formal PDF incident forensic report for a single alert.
    
    If out_stream is None, returns the PDF content as bytes.
    """
    target_stream = out_stream if out_stream is not None else io.BytesIO()
    doc = SimpleDocTemplate(
        target_stream,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = _get_styles()
    story = []


    # Header Banner
    story.append(Paragraph("BANTAYNET INTRUSION INCIDENT REPORT", styles["title"]))
    story.append(
        Paragraph(
            "AUTHORIZED LAB TRAFFIC & FORENSIC EVIDENCE &bull; DETECT-AND-ALERT ONLY",
            styles["subtitle"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Incident Overview Table
    sev = str(alert.get("severity") or "medium").lower()
    sev_color = colors.HexColor("#ef4444") if sev == "high" else (colors.HexColor("#f59e0b") if sev == "medium" else colors.HexColor("#3b82f6"))
    status_str = str(alert.get("status") or "new").replace("_", " ").title()

    overview_data = [
        [
            Paragraph("<b>Incident ID:</b>", styles["table_cell_bold"]),
            Paragraph(f"#{_safe_text(alert.get('id'))}", styles["table_cell"]),
            Paragraph("<b>Severity:</b>", styles["table_cell_bold"]),
            Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev.upper()}</b></font>", styles["table_cell"]),
        ],
        [
            Paragraph("<b>Client / Site:</b>", styles["table_cell_bold"]),
            Paragraph(_safe_text(alert.get("client_name") or "Default"), styles["table_cell"]),
            Paragraph("<b>Triage Status:</b>", styles["table_cell_bold"]),
            Paragraph(f"<b>{_safe_text(status_str)}</b>", styles["table_cell"]),
        ],
        [
            Paragraph("<b>Detection Time:</b>", styles["table_cell_bold"]),
            Paragraph(_safe_text(alert.get("detected_at") or "-"), styles["table_cell"]),
            Paragraph("<b>Packet Time:</b>", styles["table_cell_bold"]),
            Paragraph(_safe_text(alert.get("packet_time") or "-"), styles["table_cell"]),
        ],
        [
            Paragraph("<b>Source Host (Attacker):</b>", styles["table_cell_bold"]),
            Paragraph(f"<font color='#b91c1c'><b>{_safe_text(alert.get('src_ip'))}</b></font>", styles["table_cell"]),
            Paragraph("<b>Destination Target:</b>", styles["table_cell_bold"]),
            Paragraph(_safe_text(alert.get("dst_ip") or "-"), styles["table_cell"]),
        ],
        [
            Paragraph("<b>Target Port / Protocol:</b>", styles["table_cell_bold"]),
            Paragraph(f"{_safe_text(alert.get('dst_port') or '-')} / {_safe_text(alert.get('protocol') or 'IP')}", styles["table_cell"]),
            Paragraph("<b>Packets Count:</b>", styles["table_cell_bold"]),
            Paragraph(f"{_safe_text(alert.get('packet_count'))} packets", styles["table_cell"]),
        ],
        [
            Paragraph("<b>Rule Triggered:</b>", styles["table_cell_bold"]),
            Paragraph(f"<code>{_safe_text(alert.get('rule'))}</code>", styles["table_cell"]),
            Paragraph("<b>MITRE ATT&CK:</b>", styles["table_cell_bold"]),
            Paragraph(
                f"<font color='#7c3aed'><b>{_safe_text(alert.get('mitre_id') or 'N/A')}: {_safe_text(alert.get('mitre_name') or 'Unclassified')}</b></font>",
                styles["table_cell"],
            ),
        ],
    ]

    overview_table = Table(overview_data, colWidths=[110, 160, 110, 160])
    overview_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(overview_table)
    story.append(Spacer(1, 10))

    # Description & Findings
    story.append(Paragraph("Detection Summary & Technical Description", styles["h2"]))
    story.append(
        Paragraph(
            f"<b>Summary:</b> {_safe_text(alert.get('description'))}",
            styles["body"],
        )
    )
    if alert.get("source_pcap"):
        story.append(
            Paragraph(
                f"<b>Source Capture File:</b> <code>{_safe_text(alert.get('source_pcap'))}</code>",
                styles["body"],
            )
        )
    story.append(Spacer(1, 8))

    # Analyst Triage Findings & Notes
    story.append(Paragraph("Analyst Triage Findings", styles["h2"]))
    note_text = alert.get("analyst_note") or "No analyst investigation notes entered."
    updated_at = alert.get("updated_at") or "Not yet triaged"
    triage_box_data = [
        [
            Paragraph(f"<b>Current Triage Status:</b> {_safe_text(status_str)} &bull; <b>Updated:</b> {_safe_text(updated_at)}", styles["table_cell_bold"]),
        ],
        [
            Paragraph(_safe_text(note_text), styles["body"]),
        ],
    ]
    triage_box = Table(triage_box_data, colWidths=[540])
    triage_box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(triage_box)
    story.append(Spacer(1, 10))

    # Evidence Packets Section
    story.append(Paragraph(f"Preserved Evidence Packets ({len(evidence_packets)} previewed)", styles["h2"]))
    if evidence_packets:
        pkt_table_data = [
            [
                Paragraph("<b>#</b>", styles["table_cell_bold"]),
                Paragraph("<b>Rel Time</b>", styles["table_cell_bold"]),
                Paragraph("<b>Source</b>", styles["table_cell_bold"]),
                Paragraph("<b>Destination</b>", styles["table_cell_bold"]),
                Paragraph("<b>Protocol</b>", styles["table_cell_bold"]),
                Paragraph("<b>Flags</b>", styles["table_cell_bold"]),
                Paragraph("<b>Len</b>", styles["table_cell_bold"]),
            ]
        ]
        # Include up to 35 packets in PDF to preserve clean pagination
        for pkt in evidence_packets[:35]:
            pkt_table_data.append(
                [
                    Paragraph(str(pkt.get("num", "")), styles["table_cell"]),
                    Paragraph(str(pkt.get("rel_time", "")), styles["table_cell"]),
                    Paragraph(_safe_text(pkt.get("src", "")), styles["table_cell"]),
                    Paragraph(_safe_text(pkt.get("dst", "")), styles["table_cell"]),
                    Paragraph(_safe_text(pkt.get("proto", "")), styles["table_cell"]),
                    Paragraph(_safe_text(pkt.get("flags", "") or "-"), styles["table_cell"]),
                    Paragraph(f"{pkt.get('len', '')} B", styles["table_cell"]),
                ]
            )

        pkt_table = Table(pkt_table_data, colWidths=[25, 55, 120, 120, 95, 75, 50])
        pkt_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(pkt_table)
        if len(evidence_packets) > 35:
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    f"<i>Note: Full forensic capture contains {len(evidence_packets)} packets. Download the full evidence PCAP from the dashboard for wire-level analysis.</i>",
                    styles["footer"],
                )
            )
    else:
        story.append(Paragraph("<i>No preserved evidence packet snippet stored on disk.</i>", styles["body"]))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    generated_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(
        Paragraph(
            f"Generated by BantayNet Security Monitoring Platform &bull; {generated_now} &bull; For authorized lab use only",
            styles["footer"],
        )
    )

    doc.build(story)
    if out_stream is None:
        return target_stream.getvalue()
    return None


def generate_summary_pdf(
    alerts: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
    client_name: str | None = None,
    out_stream: BinaryIO | None = None,
    **kwargs: Any,
) -> bytes | None:
    """Generate an executive PDF summary of all detected incidents.
    
    If out_stream is None, returns the PDF content as bytes.
    """
    if stats is None:
        stats = {
            "high": sum(1 for a in alerts if a.get("severity") == "high"),
            "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
            "low": sum(1 for a in alerts if a.get("severity") == "low"),
        }

    target_stream = out_stream if out_stream is not None else io.BytesIO()
    doc = SimpleDocTemplate(
        target_stream,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _get_styles()
    story = []

    # Title
    client_label = client_name if client_name else "All Networks / Sites"
    story.append(Paragraph("BANTAYNET EXECUTIVE THREAT SUMMARY", styles["title"]))
    story.append(
        Paragraph(
            f"SCOPE: {_safe_text(client_label).upper()} &bull; CONFIDENTIAL LAB SECURITY AUDIT",
            styles["subtitle"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Metric Scorecards Table
    scorecard_data = [
        [
            Paragraph("<b>Total Detections</b>", styles["table_cell_bold"]),
            Paragraph("<b>High Severity</b>", styles["table_cell_bold"]),
            Paragraph("<b>Medium Severity</b>", styles["table_cell_bold"]),
            Paragraph("<b>Low Severity</b>", styles["table_cell_bold"]),
        ],
        [
            Paragraph(f"<font size='14' color='#0284c7'><b>{len(alerts)}</b></font>", styles["title"]),
            Paragraph(f"<font size='14' color='#ef4444'><b>{stats.get('high', 0)}</b></font>", styles["title"]),
            Paragraph(f"<font size='14' color='#f59e0b'><b>{stats.get('medium', 0)}</b></font>", styles["title"]),
            Paragraph(f"<font size='14' color='#3b82f6'><b>{stats.get('low', 0)}</b></font>", styles["title"]),
        ],
    ]
    scorecard_table = Table(scorecard_data, colWidths=[135, 135, 135, 135])
    scorecard_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(scorecard_table)
    story.append(Spacer(1, 12))

    # Top Incident Log Table
    story.append(Paragraph(f"Incident Manifest ({len(alerts)} events)", styles["h2"]))
    if alerts:
        table_rows = [
            [
                Paragraph("<b>ID</b>", styles["table_cell_bold"]),
                Paragraph("<b>Status</b>", styles["table_cell_bold"]),
                Paragraph("<b>Client / Site</b>", styles["table_cell_bold"]),
                Paragraph("<b>Severity</b>", styles["table_cell_bold"]),
                Paragraph("<b>Rule & ATT&CK</b>", styles["table_cell_bold"]),
                Paragraph("<b>Source IP</b>", styles["table_cell_bold"]),
                Paragraph("<b>Target</b>", styles["table_cell_bold"]),
            ]
        ]
        # Include up to 40 events
        for a in alerts[:40]:
            sev_c = colors.HexColor("#ef4444") if a.get("severity") == "high" else (colors.HexColor("#f59e0b") if a.get("severity") == "medium" else colors.HexColor("#3b82f6"))
            mitre_str = f" ({a.get('mitre_id')})" if a.get("mitre_id") and a.get("mitre_id") not in ("N/A", "POLICY") else ""
            table_rows.append(
                [
                    Paragraph(f"#{a.get('id')}", styles["table_cell"]),
                    Paragraph(_safe_text(a.get("status") or "new").title(), styles["table_cell"]),
                    Paragraph(_safe_text(a.get("client_name") or "Default"), styles["table_cell"]),
                    Paragraph(f"<font color='{sev_c.hexval()}'><b>{a.get('severity', '').upper()}</b></font>", styles["table_cell"]),
                    Paragraph(f"{_safe_text(a.get('rule'))}{mitre_str}", styles["table_cell"]),
                    Paragraph(_safe_text(a.get("src_ip")), styles["table_cell"]),
                    Paragraph(f"{_safe_text(a.get('dst_ip') or '-')}:{_safe_text(a.get('dst_port') or '-')}", styles["table_cell"]),
                ]
            )

        incidents_table = Table(table_rows, colWidths=[30, 60, 95, 55, 125, 95, 80])
        incidents_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(incidents_table)
    else:
        story.append(Paragraph("<i>No incidents matching filter criteria.</i>", styles["body"]))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    generated_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(
        Paragraph(
            f"Generated by BantayNet Security Monitoring Platform &bull; {generated_now} &bull; Detect-and-alert only",
            styles["footer"],
        )
    )

    doc.build(story)
    if out_stream is None:
        return target_stream.getvalue()
    return None

