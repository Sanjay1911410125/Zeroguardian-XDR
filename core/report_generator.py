# core/report_generator.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Professional PDF Report Generator
# Times New Roman throughout, white background, black text, logo in color.
# Readable by non-technical users (executives, managers, auditors).
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import time
import threading
import smtplib
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Register Times New Roman (use Helvetica as fallback if not available) ──────
def _setup_fonts():
    try:
        pdfmetrics.registerFont(TTFont("TimesNewRoman",      "/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman.ttf"))
        pdfmetrics.registerFont(TTFont("TimesNewRoman-Bold", "/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman_Bold.ttf"))
        pdfmetrics.registerFont(TTFont("TimesNewRoman-Ital", "/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman_Italic.ttf"))
        return "TimesNewRoman", "TimesNewRoman-Bold", "TimesNewRoman-Ital"
    except Exception:
        # Fallback — ReportLab built-in Times
        return "Times-Roman", "Times-Bold", "Times-Italic"

FONT, FONT_BOLD, FONT_ITALIC = _setup_fonts()

# ── Color palette — minimal, professional ─────────────────────────────────────
BLACK      = colors.black
DARK_GRAY  = colors.HexColor("#222222")
MID_GRAY   = colors.HexColor("#555555")
LIGHT_GRAY = colors.HexColor("#999999")
RULE_GRAY  = colors.HexColor("#cccccc")
WHITE      = colors.white

# Severity colors (used only in small badge cells)
SEV_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH":     colors.HexColor("#ea580c"),
    "MEDIUM":   colors.HexColor("#d97706"),
    "LOW":      colors.HexColor("#16a34a"),
}

PAGE_W, PAGE_H = A4
MARGIN = 2.2 * cm


# ── Style factory ─────────────────────────────────────────────────────────────
def _style(name, font=None, size=11, leading=16, color=BLACK,
           bold=False, italic=False, space_before=0, space_after=6,
           alignment=0, left_indent=0):
    f = font or (FONT_BOLD if bold else (FONT_ITALIC if italic else FONT))
    return ParagraphStyle(
        name=name,
        fontName=f,
        fontSize=size,
        leading=leading,
        textColor=color,
        spaceBefore=space_before,
        spaceAfter=space_after,
        alignment=alignment,
        leftIndent=left_indent,
    )


# ── Page template with header/footer ─────────────────────────────────────────
def _on_page(canvas, doc):
    canvas.saveState()
    w, h = A4

    # Top thin rule
    canvas.setStrokeColor(RULE_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, h - 1.5 * cm, w - MARGIN, h - 1.5 * cm)

    # Header right — system name
    canvas.setFont(FONT, 8)
    canvas.setFillColor(LIGHT_GRAY)
    canvas.drawRightString(w - MARGIN, h - 1.2 * cm, "ZeroGuardian XDR — Confidential")

    # Footer rule
    canvas.line(MARGIN, 1.5 * cm, w - MARGIN, 1.5 * cm)

    # Footer left — date
    canvas.setFont(FONT, 8)
    canvas.drawString(MARGIN, 1.1 * cm, datetime.now().strftime("Generated: %d %B %Y, %H:%M"))

    # Footer right — page number
    canvas.drawRightString(w - MARGIN, 1.1 * cm, f"Page {doc.page}")

    canvas.restoreState()


# ── Section helpers ───────────────────────────────────────────────────────────
def _section_title(text):
    """Bold section heading with rule underneath."""
    s = _style("sec", bold=True, size=13, space_before=18, space_after=4)
    return [
        Paragraph(text.upper(), s),
        HRFlowable(width="100%", thickness=0.5, color=RULE_GRAY, spaceAfter=8),
    ]


def _body(text, indent=0):
    s = _style("body", size=11, leading=17, space_after=6,
               color=DARK_GRAY, left_indent=indent)
    return Paragraph(text, s)


def _bullet(text):
    s = _style("bul", size=11, leading=17, space_after=4,
               color=DARK_GRAY, left_indent=14)
    return Paragraph(f"• &nbsp; {text}", s)


def _severity_label(sev: str) -> str:
    sev = (sev or "LOW").upper()
    icons = {"CRITICAL": "▲▲", "HIGH": "▲", "MEDIUM": "●", "LOW": "○"}
    return f"{icons.get(sev, '○')} {sev}"


# ── Main report builder ───────────────────────────────────────────────────────
def generate_report(snapshot: dict, filename: str = None) -> str:
    """
    Generate a professional PDF report from the current system snapshot.
    Returns the full file path of the saved PDF.
    """
    ts       = datetime.now()
    ts_str   = ts.strftime("%Y%m%d_%H%M%S")
    ts_human = ts.strftime("%d %B %Y at %H:%M")

    if not filename:
        filename = f"ZeroGuardian_Report_{ts_str}.pdf"

    out_path = os.path.join(REPORTS_DIR, filename)

    # ── Pull data from snapshot ───────────────────────────────────────────────
    devices      = snapshot.get("devices", [])
    traffic      = snapshot.get("traffic", {})
    anomalies    = snapshot.get("anomalies", [])
    risk_summary = snapshot.get("risk_summary", {})
    known_alerts = snapshot.get("known_alerts", [])

    total_packets = traffic.get("total_packets", 0)
    top_protocols = traffic.get("top_protocols", [])
    top_talkers   = traffic.get("top_talkers", [])
    overall_risk  = risk_summary.get("overall_level", "LOW")
    risk_score    = risk_summary.get("overall_score", 0)

    critical_count = sum(1 for a in anomalies if (a.get("severity") or "").upper() == "CRITICAL")
    high_count     = sum(1 for a in anomalies if (a.get("severity") or "").upper() == "HIGH")
    medium_count   = sum(1 for a in anomalies if (a.get("severity") or "").upper() == "MEDIUM")

    # Pull vuln scan results
    vuln_results = []
    try:
        from core.vuln_scanner import get_latest_results, get_scan_summary
        vuln_results = get_latest_results()
        vuln_summary = get_scan_summary()
    except Exception:
        vuln_summary = {}

    # ── Document setup ────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=2.5 * cm, bottomMargin=2.5 * cm,
        title="ZeroGuardian XDR Security Report",
        author="ZeroGuardian XDR",
        subject="Network Security Monitoring Report",
    )

    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * cm))

    # Logo text (color — only colored element)
    logo_style = ParagraphStyle(
        "logo", fontName=FONT_BOLD, fontSize=28,
        textColor=colors.HexColor("#1d4ed8"),
        alignment=1, spaceAfter=4,
    )
    story.append(Paragraph("ZeroGuardian XDR", logo_style))

    sub_style = ParagraphStyle(
        "sub", fontName=FONT_ITALIC, fontSize=13,
        textColor=colors.HexColor("#2563eb"),
        alignment=1, spaceAfter=2,
    )
    story.append(Paragraph("AI-Driven Extended Detection and Response", sub_style))

    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="60%", thickness=1, color=RULE_GRAY,
                             hAlign="CENTER", spaceAfter=16))

    # Report title
    title_style = _style("title", bold=True, size=18, alignment=1,
                          space_before=8, space_after=6)
    story.append(Paragraph("Network Security Monitoring Report", title_style))

    date_style = _style("date", size=12, alignment=1, color=MID_GRAY,
                         space_after=4)
    story.append(Paragraph(ts_human, date_style))
    story.append(Paragraph(f"Overall Risk Level: {overall_risk}", date_style))

    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=RULE_GRAY))
    story.append(Spacer(1, 0.5 * cm))

    # Confidentiality notice
    conf_style = _style("conf", size=9, color=LIGHT_GRAY, alignment=1,
                         italic=True)
    story.append(Paragraph(
        "CONFIDENTIAL — This report contains sensitive security information. "
        "Distribution should be restricted to authorised personnel only.",
        conf_style
    ))

    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story += _section_title("1. Executive Summary")

    # Risk status sentence
    risk_sentences = {
        "LOW":      "The network is currently operating normally with no significant threats detected.",
        "MEDIUM":   "The network shows some unusual activity that requires attention from the security team.",
        "HIGH":     "The network is showing signs of suspicious activity. Immediate review is recommended.",
        "CRITICAL": "The network is under active threat. Immediate action is required to prevent data loss or system compromise.",
    }
    story.append(_body(
        f"This report was automatically generated by the ZeroGuardian XDR security monitoring system "
        f"on {ts_human}. The system continuously monitors all devices connected to your network, "
        f"analyses their behaviour using artificial intelligence, and detects suspicious activity "
        f"before it causes harm."
    ))
    story.append(Spacer(1, 6))
    story.append(_body(
        f"<b>Current security status: {overall_risk}.</b> "
        f"{risk_sentences.get(overall_risk, '')}"
    ))

    story.append(Spacer(1, 10))

    # Summary stats table
    sum_data = [
        ["Metric", "Value", "Status"],
        ["Devices Monitored",       str(len(devices)),       "Active"],
        ["Packets Analysed",        f"{total_packets:,}",    "Normal" if total_packets < 1000 else "Elevated"],
        ["Threat Alerts",           str(len(anomalies)),     "None" if not anomalies else f"{critical_count} Critical"],
        ["Vulnerabilities Found",   str(len(vuln_results)),  "None" if not vuln_results else f"{vuln_summary.get('critical',0)} Critical"],
        ["AI Anomaly Score",        f"{risk_score}/100",     overall_risk],
        ["Overall Risk Level",      overall_risk,            ""],
    ]

    sum_table = Table(sum_data, colWidths=[6 * cm, 5 * cm, 5 * cm])
    sum_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  FONT_BOLD),
        ("FONTNAME",      (0, 1), (-1, -1), FONT),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
        ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.4, RULE_GRAY),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 12))

    # ── 2. NETWORK OVERVIEW ───────────────────────────────────────────────────
    story += _section_title("2. Network Overview")
    story.append(_body(
        f"The system discovered <b>{len(devices)} devices</b> connected to your network "
        f"during this monitoring period. Each device is continuously tracked for unusual "
        f"behaviour, new connections, and unexpected activity."
    ))
    story.append(Spacer(1, 8))

    if devices:
        dev_data = [["IP Address", "Device Name", "Status"]]
        for d in devices[:20]:
            ip     = d.get("ip", "Unknown")
            name   = d.get("name") or d.get("hostname") or "Unknown Device"
            state  = (d.get("state") or "observed").title()
            dev_data.append([ip, name[:35], state])

        dev_table = Table(dev_data, colWidths=[5 * cm, 8 * cm, 4 * cm])
        dev_table.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  FONT_BOLD),
            ("FONTNAME",      (0, 1), (-1, -1), FONT),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
            ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(dev_table)

    story.append(Spacer(1, 12))

    # ── 3. PACKET MONITORING SUMMARY ─────────────────────────────────────────
    story += _section_title("3. Packet Monitoring Summary")
    story.append(_body(
        "The system captures and analyses all network packets passing through your "
        "environment. This section describes what types of network communication were "
        "observed and whether any unusual patterns were detected."
    ))
    story.append(Spacer(1, 6))
    story.append(_bullet(f"Total packets captured: <b>{total_packets:,}</b>"))

    if top_protocols:
        proto_str = ", ".join(
            f"{p['proto']} ({p['count']} packets)"
            for p in top_protocols[:5]
            if isinstance(p, dict)
        )
        story.append(_bullet(f"Protocols observed: <b>{proto_str}</b>"))

    if top_talkers:
        talker = top_talkers[0]
        if isinstance(talker, dict):
            story.append(_bullet(
                f"Most active device: <b>{talker.get('ip','Unknown')}</b> "
                f"({talker.get('count',0)} packets)"
            ))

    pps = total_packets / max(traffic.get("duration_sec", 30), 1)
    story.append(_bullet(f"Average packet rate: <b>{pps:.1f} packets per second</b>"))

    if total_packets > 1000:
        story.append(_body(
            "Note: The packet volume observed is higher than typical for a quiet network. "
            "This may indicate normal busy activity or could warrant further investigation.",
            indent=14
        ))

    story.append(Spacer(1, 12))

    # ── 4. THREAT DETECTION SUMMARY ──────────────────────────────────────────
    story += _section_title("4. Threat Detection Summary")

    if not anomalies and not known_alerts:
        story.append(_body(
            "No active threats or suspicious behaviour was detected during this "
            "monitoring period. The network appears to be operating normally."
        ))
    else:
        story.append(_body(
            f"The system detected <b>{len(anomalies)} security alert(s)</b> during this "
            f"monitoring period. These are described below in plain language."
        ))
        story.append(Spacer(1, 8))

        alert_data = [["Severity", "Alert Type", "Details"]]
        for a in anomalies[:15]:
            sev     = (a.get("severity") or "LOW").upper()
            atype   = a.get("type", "Unknown")
            details = (a.get("details") or "")[:80]
            alert_data.append([_severity_label(sev), atype, details])

        alert_table = Table(alert_data, colWidths=[3.5 * cm, 5.5 * cm, 7.5 * cm])
        sev_styles  = []
        for i, a in enumerate(anomalies[:15], start=1):
            sev = (a.get("severity") or "LOW").upper()
            c   = SEV_COLORS.get(sev, BLACK)
            sev_styles.append(("TEXTCOLOR", (0, i), (0, i), c))
            sev_styles.append(("FONTNAME",  (0, i), (0, i), FONT_BOLD))

        alert_table.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  FONT_BOLD),
            ("FONTNAME",      (0, 1), (-1, -1), FONT),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
            ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("WORDWRAP",      (2, 1), (2, -1),  True),
        ] + sev_styles))
        story.append(alert_table)

    story.append(Spacer(1, 12))

    # ── 5. AI RISK ASSESSMENT ─────────────────────────────────────────────────
    story += _section_title("5. AI-Based Risk Assessment")

    ai_explain = {
        "LOW":      (
            "The artificial intelligence system has analysed all network traffic and "
            "device behaviour and found no significant deviation from normal patterns. "
            "Your network is behaving as expected."
        ),
        "MEDIUM":   (
            "The AI system has detected some unusual patterns in network behaviour. "
            "While not immediately dangerous, these patterns are worth monitoring. "
            "The security team should review recent activity."
        ),
        "HIGH":     (
            "The AI system has identified significant behavioural anomalies that differ "
            "substantially from normal network patterns. This could indicate an active "
            "attack, malware activity, or unauthorised access. Prompt investigation "
            "is strongly recommended."
        ),
        "CRITICAL": (
            "The AI system has detected extreme anomalies that strongly suggest an "
            "active security incident. Network traffic patterns are severely abnormal. "
            "Immediate intervention by the security team is required. Consider isolating "
            "affected devices and conducting a full incident response procedure."
        ),
    }

    story.append(_body(f"<b>AI Risk Level: {overall_risk}</b>"))
    story.append(_body(ai_explain.get(overall_risk, "")))
    story.append(Spacer(1, 6))

    ai_anomalies = [a for a in anomalies if a.get("source") == "ai"]
    if ai_anomalies:
        for a in ai_anomalies[:3]:
            score = a.get("score", 0)
            story.append(_bullet(
                f"Anomaly score: <b>{score:.4f}</b> (normal threshold: 0.1297) — "
                f"the higher the score, the more abnormal the behaviour."
            ))

    story.append(Spacer(1, 12))

    # ── 6. VULNERABILITY FINDINGS ─────────────────────────────────────────────
    story += _section_title("6. Vulnerability Findings")

    if not vuln_results:
        story.append(_body(
            "No vulnerability scan results are available. Run a vulnerability scan "
            "from the Vulnerabilities page to identify security weaknesses in your devices."
        ))
    else:
        story.append(_body(
            f"The vulnerability scanner examined {vuln_summary.get('devices_scanned', 0)} "
            f"devices and found <b>{len(vuln_results)} security weaknesses</b>. "
            f"These are ranked by severity below."
        ))
        story.append(Spacer(1, 8))

        vuln_data = [["Severity", "Device IP", "Port", "CVE / Issue", "CVSS"]]
        for v in vuln_results[:20]:
            sev   = (v.get("severity") or "LOW").upper()
            cve   = v.get("cve_id") or "—"
            name  = (v.get("cve_name") or "")[:30]
            vuln_data.append([
                _severity_label(sev),
                v.get("ip", "—"),
                str(v.get("port", "—")),
                f"{cve}\n{name}" if cve != "—" else name,
                str(v.get("cvss_score") or "—"),
            ])

        vuln_table = Table(vuln_data, colWidths=[3.2*cm, 4*cm, 2*cm, 6*cm, 2*cm])
        vuln_sev   = []
        for i, v in enumerate(vuln_results[:20], start=1):
            sev = (v.get("severity") or "LOW").upper()
            c   = SEV_COLORS.get(sev, BLACK)
            vuln_sev.append(("TEXTCOLOR", (0, i), (0, i), c))
            vuln_sev.append(("FONTNAME",  (0, i), (0, i), FONT_BOLD))

        vuln_table.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  FONT_BOLD),
            ("FONTNAME",      (0, 1), (-1, -1), FONT),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
            ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("ALIGN",         (2, 0), (2, -1),  "CENTER"),
            ("ALIGN",         (4, 0), (4, -1),  "CENTER"),
        ] + vuln_sev))
        story.append(vuln_table)

    story.append(Spacer(1, 12))

    # ── 7. RECOMMENDED ACTIONS ────────────────────────────────────────────────
    story += _section_title("7. Recommended Actions")
    story.append(_body(
        "Based on the findings in this report, the following actions are recommended. "
        "These are written in plain language so that both technical and non-technical "
        "staff can understand and act on them."
    ))
    story.append(Spacer(1, 8))

    recommendations = []

    # Dynamic recommendations based on findings
    if critical_count > 0:
        recommendations.append((
            "IMMEDIATE",
            f"Investigate the {critical_count} critical security alert(s) immediately. "
            "Contact your IT security team or managed security provider without delay."
        ))

    crit_vulns = [v for v in vuln_results if (v.get("severity") or "").upper() == "CRITICAL"]
    if crit_vulns:
        ips = list(set(v["ip"] for v in crit_vulns))
        recommendations.append((
            "URGENT",
            f"Update the software on device(s) {', '.join(ips[:3])} immediately. "
            "Critical security vulnerabilities were found that attackers can exploit remotely."
        ))

    if any("SSH" in str(v.get("cve_name", "")) for v in vuln_results):
        recommendations.append((
            "HIGH",
            "Update OpenSSH on all Linux servers by running: "
            "sudo apt update && sudo apt upgrade openssh-server"
        ))

    if any("Telnet" in str(v.get("service", "")) for v in vuln_results):
        recommendations.append((
            "HIGH",
            "Disable Telnet immediately on all devices. Telnet sends passwords "
            "in plain text which anyone on the network can read. Use SSH instead."
        ))

    if any("Default Credentials" in str(a.get("type", "")) for a in anomalies):
        recommendations.append((
            "HIGH",
            "Change default passwords on all network devices. Never use passwords "
            "such as 'admin', 'password', '123456', or the device's default credentials."
        ))

    if total_packets > 500:
        recommendations.append((
            "MEDIUM",
            "Investigate the source of elevated network traffic. Check if any "
            "devices are running unexpected software or communicating with unknown servers."
        ))

    # Always-present best practices
    recommendations += [
        ("ROUTINE", "Review the list of connected devices and confirm all are authorised."),
        ("ROUTINE", "Ensure all devices have automatic security updates enabled."),
        ("ROUTINE", "Schedule a weekly review of security reports to track trends over time."),
        ("ROUTINE", "Ensure backups of important data are tested and stored securely offline."),
    ]

    priority_order = {"IMMEDIATE": 0, "URGENT": 1, "HIGH": 2, "MEDIUM": 3, "ROUTINE": 4}
    recommendations.sort(key=lambda x: priority_order.get(x[0], 5))

    rec_data = [["Priority", "Action Required"]]
    for priority, action in recommendations[:12]:
        rec_data.append([priority, action])

    rec_table = Table(rec_data, colWidths=[3.5 * cm, 13 * cm])
    rec_sev = []
    priority_colors = {
        "IMMEDIATE": colors.HexColor("#dc2626"),
        "URGENT":    colors.HexColor("#ea580c"),
        "HIGH":      colors.HexColor("#d97706"),
        "MEDIUM":    colors.HexColor("#2563eb"),
        "ROUTINE":   colors.HexColor("#16a34a"),
    }
    for i, (priority, _) in enumerate(recommendations[:12], start=1):
        c = priority_colors.get(priority, BLACK)
        rec_sev.append(("TEXTCOLOR", (0, i), (0, i), c))
        rec_sev.append(("FONTNAME",  (0, i), (0, i), FONT_BOLD))

    rec_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  FONT_BOLD),
        ("FONTNAME",      (0, 1), (-1, -1), FONT),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
        ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.4, RULE_GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("WORDWRAP",      (1, 1), (1, -1),  True),
    ] + rec_sev))
    story.append(rec_table)
    story.append(Spacer(1, 12))

    # ── 8. DISCLAIMER ─────────────────────────────────────────────────────────
    story += _section_title("8. Report Information")
    disc_style = _style("disc", size=9, color=MID_GRAY, leading=14,
                         italic=True, space_after=4)
    story.append(Paragraph(
        "This report was automatically generated by ZeroGuardian XDR, an AI-driven "
        "network security monitoring system. The findings represent the system state "
        f"at the time of report generation ({ts_human}). "
        "Security conditions may change rapidly — this report should be reviewed "
        "promptly and not relied upon as a complete security audit.",
        disc_style
    ))
    story.append(Paragraph(
        "For questions about this report, contact your IT security administrator "
        "or the ZeroGuardian XDR system operator.",
        disc_style
    ))

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    print(f"[Report] Generated: {out_path}")
    return out_path


# ── Email delivery ────────────────────────────────────────────────────────────
def email_report(pdf_path: str) -> bool:
    env = {}
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()

    from_addr = env.get("ALERT_EMAIL_FROM", "")
    password  = env.get("ALERT_EMAIL_PASSWORD", "")
    to_addr   = env.get("ALERT_EMAIL_TO", "")
    smtp_host = env.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(env.get("SMTP_PORT", "587"))

    if not from_addr or not password or not to_addr:
        print("[Report] Email not configured — skipping email delivery")
        return False

    try:
        msg = MIMEMultipart()
        msg["Subject"] = f"ZeroGuardian XDR — Security Report {datetime.now().strftime('%d %b %Y')}"
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        msg.attach(MIMEText(
            "Please find attached the latest ZeroGuardian XDR security monitoring report.\n\n"
            "This report was automatically generated by your ZeroGuardian XDR system.",
            "plain"
        ))

        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition",
                            f"attachment; filename={os.path.basename(pdf_path)}")
            msg.attach(part)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(from_addr, password)
            server.sendmail(from_addr, to_addr, msg.as_string())

        print(f"[Report] Emailed to {to_addr} ✅")
        return True
    except Exception as e:
        print(f"[Report] Email error: {e}")
        return False


# ── Telegram delivery ─────────────────────────────────────────────────────────
def telegram_report(pdf_path: str, snapshot: dict) -> bool:
    try:
        import requests as req
        env = {}
        env_file = os.path.join(BASE_DIR, ".env")
        if os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        env[k.strip()] = v.strip()

        token   = env.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = env.get("TELEGRAM_CHAT_ID", "")

        if not token or not chat_id:
            return False

        risk = snapshot.get("risk_summary", {}).get("overall_level", "LOW")
        caption = (
            f"📊 <b>ZeroGuardian XDR — Security Report</b>\n\n"
            f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M')}\n"
            f"Risk Level: <b>{risk}</b>\n"
            f"Devices: {len(snapshot.get('devices', []))}\n"
            f"Alerts: {len(snapshot.get('anomalies', []))}"
        )

        with open(pdf_path, "rb") as f:
            resp = req.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
                files={"document": (os.path.basename(pdf_path), f, "application/pdf")},
                timeout=30,
            )
        if resp.status_code == 200:
            print("[Report] Telegram PDF sent ✅")
            return True
        print(f"[Report] Telegram error: {resp.text[:100]}")
        return False
    except Exception as e:
        print(f"[Report] Telegram error: {e}")
        return False


# ── Scheduler ─────────────────────────────────────────────────────────────────
_scheduler_started = False

def start_report_scheduler(interval_hours: int = 24):
    """Start a background thread that generates reports on schedule."""
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        while True:
            time.sleep(interval_hours * 3600)
            try:
                from core.orchestrator import get_snapshot
                snap     = get_snapshot()
                pdf_path = generate_report(snap)
                email_report(pdf_path)
                telegram_report(pdf_path, snap)
                print(f"[Report] Scheduled report delivered ✅")
            except Exception as e:
                print(f"[Report] Scheduler error: {e}")

    t = threading.Thread(target=_loop, daemon=True, name="ReportScheduler")
    t.start()
    print(f"[Report] Scheduler started — reports every {interval_hours}h ✅")


def list_reports() -> list:
    """Return list of generated report files sorted newest first."""
    try:
        files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]
        files.sort(reverse=True)
        return [
            {
                "filename": f,
                "size_kb":  round(os.path.getsize(os.path.join(REPORTS_DIR, f)) / 1024, 1),
                "created":  datetime.fromtimestamp(
                    os.path.getctime(os.path.join(REPORTS_DIR, f))
                ).strftime("%d %b %Y %H:%M"),
            }
            for f in files[:20]
        ]
    except Exception:
        return []
