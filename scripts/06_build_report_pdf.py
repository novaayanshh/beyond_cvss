"""Build the submission PDF report from the reviewed Markdown source."""
from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "final_report.md"
OUTPUT = ROOT / "docs" / "final_report.pdf"
FIGURES = ROOT / "outputs" / "figures"
PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT = RIGHT = 48
CONTENT_WIDTH = PAGE_WIDTH - LEFT - RIGHT


def inline_markup(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"<link href='\2' color='#1F4E79'>\1</link>", text)
    return text


def make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=25, leading=30, textColor=colors.HexColor("#19344F"), alignment=TA_LEFT, spaceAfter=5),
        "subtitle": ParagraphStyle("ReportSubtitle", parent=base["Normal"], fontName="Helvetica", fontSize=14, leading=18, textColor=colors.HexColor("#5B6976"), spaceAfter=14),
        "h1": ParagraphStyle("ReportH1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=colors.HexColor("#1F4E79"), spaceBefore=10, spaceAfter=6, keepWithNext=True),
        "h2": ParagraphStyle("ReportH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=colors.HexColor("#3E5D78"), spaceBefore=7, spaceAfter=4, keepWithNext=True),
        "body": ParagraphStyle("ReportBody", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2, leading=12.2, textColor=colors.HexColor("#232B33"), spaceAfter=5, alignment=TA_LEFT),
        "bullet": ParagraphStyle("ReportBullet", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2, leading=12.0, leftIndent=16, firstLineIndent=-9, spaceAfter=3, textColor=colors.HexColor("#232B33")),
        "cell": ParagraphStyle("TableCell", parent=base["BodyText"], fontName="Helvetica", fontSize=7.3, leading=9.2, textColor=colors.HexColor("#232B33"), spaceAfter=0),
        "cell_header": ParagraphStyle("TableHead", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=7.3, leading=9.2, textColor=colors.white, spaceAfter=0),
        "caption": ParagraphStyle("FigureCaption", parent=base["BodyText"], fontName="Helvetica-Oblique", fontSize=8, leading=10, alignment=TA_CENTER, textColor=colors.HexColor("#586674"), spaceAfter=8),
    }


def parse_table(lines: list[str], styles) -> LongTable:
    rows = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        rows.append([Paragraph(inline_markup(cell), styles["cell_header"] if not rows else styles["cell"]) for cell in cells])
    cols = max(len(row) for row in rows)
    for row in rows:
        row.extend([Paragraph("", styles["cell"])] * (cols - len(row)))
    table = LongTable(rows, repeatRows=1, colWidths=[CONTENT_WIDTH / cols] * cols, hAlign="LEFT", splitByRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#C8D1DA")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6F8")]),
    ]))
    return table


def add_figure(story, name: str, caption: str):
    path = FIGURES / name
    if not path.exists():
        return
    image = Image(str(path))
    scale = min(CONTENT_WIDTH / image.imageWidth, 4.25 * inch / image.imageHeight)
    image.drawWidth *= scale
    image.drawHeight *= scale
    story.extend([Spacer(1, 4), image, Paragraph(caption, styles_global["caption"]), Spacer(1, 4)])


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6D7882"))
    canvas.drawString(LEFT, 26, "Beyond CVSS | Advanced Data Science")
    canvas.drawRightString(PAGE_WIDTH - RIGHT, 26, f"Page {doc.page}")
    canvas.restoreState()


def build_story(lines: list[str], styles):
    story = []
    i = 0
    title_seen = False
    subtitle_seen = False
    while i < len(lines):
        raw = lines[i].rstrip()
        if not raw.strip():
            i += 1
            continue
        if raw.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            story.extend([parse_table(table_lines, styles), Spacer(1, 7)])
            continue
        if raw.startswith("# "):
            story.append(Paragraph(inline_markup(raw[2:].strip()), styles["title"]))
            title_seen = True
            i += 1
            continue
        if raw.startswith("## "):
            heading = re.sub(r"^(\d+)\.\s+", r"\1 ", raw[3:].strip())
            if title_seen and not subtitle_seen and heading == "Evaluating EPSS for vulnerability patch prioritization":
                story.append(Paragraph(inline_markup(heading), styles["subtitle"]))
                subtitle_seen = True
            else:
                story.append(Paragraph(inline_markup(heading), styles["h1"]))
                if heading == "4 Results":
                    add_figure(story, "recall_at_k.png", "Figure 1. Pooled Recall@K on the common CVSS 3.x and EPSS cohort.")
            i += 1
            continue
        if raw.startswith("### "):
            heading = raw[4:].strip()
            story.append(Paragraph(inline_markup(heading), styles["h2"]))
            if heading == "Decision dates and label":
                add_figure(story, "kev_positives_by_date.png", "Figure 2. Positive labels by decision date.")
            if heading == "Model results":
                add_figure(story, "model_comparison.png", "Figure 3. Average Precision with and without EPSS on the final test period.")
            i += 1
            continue
        if raw.startswith("- ") or re.match(r"\d+\.\s", raw):
            if raw.startswith("- "):
                body = "&#8226; " + inline_markup(raw[2:].strip())
            else:
                number, content = re.match(r"^(\d+)\.\s(.*)$", raw).groups()
                body = f"{number}. {inline_markup(content)}"
            story.append(Paragraph(body, styles["bullet"]))
            i += 1
            continue
        paragraph_lines = [raw]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "- ")) and not re.match(r"\d+\.\s", lines[i]):
            paragraph_lines.append(lines[i].strip())
            i += 1
        story.append(Paragraph(inline_markup(" ".join(paragraph_lines)), styles["body"]))
    return story


if __name__ == "__main__":
    styles_global = make_styles()
    # add_figure reads this module-level style map.
    globals()["styles_global"] = styles_global
    story = build_story(SOURCE.read_text(encoding="utf-8").splitlines(), styles_global)
    doc = SimpleDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=LEFT, rightMargin=RIGHT, topMargin=46, bottomMargin=44,
                            title="Beyond CVSS: Evaluating EPSS for vulnerability patch prioritization",
                            author="Sumit Sharma and Ayansh Pandey")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)
