import os
import re
from datetime import datetime
from xml.sax.saxutils import escape

from rich.console import Console
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle, Preformatted)

from modules.findings import SEVERITIES, analyze, count_by_severity
from modules.target import get_target
from modules import session

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

console = Console()
styles = getSampleStyleSheet()
small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=9, leading=12)

SEV_COLORS = {
    "High": colors.HexColor("#f87171"),
    "Medium": colors.HexColor("#fbbf24"),
    "Low": colors.HexColor("#67e8f9"),
    "Info": colors.HexColor("#cbd5e1"),
}


def kv_table(rows):
    data = [[Paragraph(f"<b>{escape(str(k))}</b>", styles["BodyText"]),
             Paragraph(escape(str(v)).replace("\n", "<br/>"), styles["BodyText"])]
            for k, v in rows]
    t = Table(data, colWidths=[4 * cm, 12.5 * cm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def grid_table(headers, rows, widths):
    """A table with a header row, used for lists such as subdomains."""
    head = [Paragraph(f"<b>{escape(h)}</b>", styles["BodyText"]) for h in headers]
    body = [[Paragraph(escape(str(c)).replace("\n", "<br/>"), styles["BodyText"])
             for c in row] for row in rows]
    t = Table([head] + body, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def section(story, title, entry, builder):
    story.append(Spacer(1, 14))
    story.append(Paragraph(title, styles["Heading2"]))
    if entry is None:
        story.append(Paragraph("<i>Not run for this target.</i>", styles["BodyText"]))
        return
    story.append(Paragraph(f"Run at: {entry['time']}", styles["Italic"]))
    story.append(Spacer(1, 6))
    builder(story, entry["data"])


def summary_text(key):
    entry = session.get(key)
    if not entry:
        return "Not run"
    if key == "subdomains":
        count = len(entry["data"].get("Subdomains", []))
        return f"Completed ({count} found)"
    return "Completed"


def findings_section(story):
    findings = analyze()
    counts = count_by_severity(findings)

    story.append(Spacer(1, 14))
    story.append(Paragraph("Findings", styles["Heading2"]))

    # Colored count bar: High / Medium / Low / Info
    cells = [Paragraph(f"<b>{s}: {counts[s]}</b>", styles["BodyText"]) for s in SEVERITIES]
    bar = Table([cells], colWidths=[4.125 * cm] * 4)
    bar.setStyle(TableStyle(
        [("BACKGROUND", (i, 0), (i, 0), SEV_COLORS[s]) for i, s in enumerate(SEVERITIES)] +
        [("ALIGN", (0, 0), (-1, -1), "CENTER"),
         ("INNERGRID", (0, 0), (-1, -1), 2, colors.white),
         ("TOPPADDING", (0, 0), (-1, -1), 6),
         ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(bar)
    story.append(Spacer(1, 8))

    if not findings:
        story.append(Paragraph("No findings for the modules that were run.", styles["BodyText"]))
        return

    rows = [[Paragraph("<b>Severity</b>", styles["BodyText"]),
             Paragraph("<b>Finding</b>", styles["BodyText"]),
             Paragraph("<b>Source</b>", styles["BodyText"])]]
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(findings, start=1):
        rows.append([
            Paragraph(f"<b>{escape(f['Severity'])}</b>", styles["BodyText"]),
            Paragraph(f"<b>{escape(f['Title'])}</b><br/>{escape(f['Detail'])}"
                      f"<br/><i>Fix: {escape(f['Recommendation'])}</i>", small),
            Paragraph(escape(f["Source"]), styles["BodyText"]),
        ])
        style.append(("BACKGROUND", (0, i), (0, i), SEV_COLORS[f["Severity"]]))

    table = Table(rows, colWidths=[2.2 * cm, 11.8 * cm, 2.5 * cm], repeatRows=1)
    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<i>Findings are based only on the modules that were run for this target.</i>", small))


def nmap_builder(s, d):
    s.append(Paragraph(f"<b>Command:</b> {escape(d.get('Command', 'N/A'))}", styles["BodyText"]))
    s.append(Spacer(1, 6))
    s.append(Preformatted(d.get("Output") or "(no output)", styles["Code"], maxLineLength=95))


def subdomain_builder(s, d):
    subs = d.get("Subdomains", [])
    live = sum(1 for x in subs if x["Resolves"])
    mode = "passive + brute force" if d.get("Brute Force") else "passive only"

    s.append(Paragraph(
        f"<b>Domain:</b> {escape(d['Domain'])} &nbsp;&nbsp; "
        f"<b>Found:</b> {len(subs)} ({live} resolving) &nbsp;&nbsp; "
        f"<b>Mode:</b> {mode}", styles["BodyText"]))

    for note in d.get("Notes", []):
        s.append(Spacer(1, 4))
        s.append(Paragraph(f"<i>Note: {escape(note)}</i>", styles["BodyText"]))

    s.append(Spacer(1, 8))
    if not subs:
        s.append(Paragraph("No subdomains found.", styles["BodyText"]))
        return

    rows = [(x["Subdomain"],
             "\n".join(x["IPs"]) if x["Resolves"] else "no DNS record",
             x["Source"])
            for x in subs]
    s.append(grid_table(["Subdomain", "IP address", "Source"], rows,
                        [7 * cm, 6 * cm, 3.5 * cm]))


def generate_report():
    target = get_target()
    if not target:
        console.print("[red]Please set target first.[/red]")
        return None

    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    filename = os.path.join(BASE_DIR, "reports", f"RAT_Report_{safe}.pdf")

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    story = [
        Paragraph("RAT Reconnaissance Report", styles["Title"]),
        kv_table([("Target", target),
                  ("Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))]),
    ]

    # Findings first, then which modules ran
    findings_section(story)

    modules = [("whois", "WHOIS"), ("dns", "DNS"), ("geo", "Geolocation"),
               ("nmap", "Nmap"), ("subdomains", "Subdomains")]
    story.append(Spacer(1, 14))
    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(kv_table([(label, summary_text(key)) for key, label in modules]))

    # Detail sections
    section(story, "WHOIS", session.get("whois"),
            lambda s, d: s.append(kv_table(d.items())))

    section(story, "DNS Records", session.get("dns"),
            lambda s, d: s.append(kv_table(
                [(k, "\n".join(v)) for k, v in d.items()] or [("Result", "No records found")])))

    section(story, "IP Geolocation", session.get("geo"),
            lambda s, d: s.append(kv_table(d.items())))

    section(story, "Nmap Scan", session.get("nmap"), nmap_builder)

    section(story, "Subdomains", session.get("subdomains"), subdomain_builder)

    story.append(Spacer(1, 20))
    story.append(Paragraph("<i>Generated by RAT. For authorized testing and educational use only.</i>",
                           styles["BodyText"]))

    try:
        doc.build(story)
    except PermissionError:
        console.print("[red]Close the PDF first, then generate the report again.[/red]")
        return None

    console.print("\n[green]✔ Report Saved Successfully[/green]")
    console.print(f"[cyan]{filename}[/cyan]")
    return filename