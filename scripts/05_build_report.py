"""Build the formatted report DOCX from docs/final_report.md."""
from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "final_report.md"
OUTPUT = ROOT / "docs" / "final_report.docx"
FIGURES = ROOT / "outputs" / "figures"


def shade(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    header = OxmlElement("w:tblHeader")
    header.set(qn("w:val"), "true")
    tr_pr.append(header)


def add_page_number(paragraph) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = paragraph.add_run("Page ")
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    paragraph._p.append(fld)


def add_inline(paragraph, text: str, bold: bool = False) -> None:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    parts = re.split(r"(\*\*.*?\*\*)", text)
    for part in parts:
        if not part:
            continue
        is_bold = part.startswith("**") and part.endswith("**")
        clean = part[2:-2] if is_bold else part
        run = paragraph.add_run(clean)
        run.bold = bold or is_bold
        run.font.name = "Aptos"
        run.font.size = Pt(10.5)
        run.font.color.rgb = RGBColor(35, 43, 51)


def table_from_markdown(doc: Document, lines: list[str]) -> None:
    data = []
    for line in lines:
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", x.replace(" ", "")) for x in cells):
            continue
        data.append(cells)
    if not data:
        return
    cols = max(map(len, data))
    table = doc.add_table(rows=0, cols=cols)
    table.style = "Light Shading Accent 1"
    table.autofit = True
    for row_i, row_values in enumerate(data):
        row = table.add_row()
        if row_i == 0:
            set_repeat_table_header(row)
        for col_i in range(cols):
            cell = row.cells[col_i]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            text = row_values[col_i] if col_i < len(row_values) else ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, text, bold=row_i == 0)
            for run in p.runs:
                run.font.size = Pt(8.5)
                if row_i == 0:
                    run.font.color.rgb = RGBColor(255, 255, 255)
            if row_i == 0:
                shade(cell, "1F4E79")
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def add_figure(doc: Document, name: str, caption: str) -> None:
    path = FIGURES / name
    if not path.exists():
        return
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(str(path), width=Inches(6.25))
    cp = doc.add_paragraph(caption, style="Caption")
    cp.alignment = WD_ALIGN_PARAGRAPH.CENTER


def render_markdown(doc: Document, lines: list[str]) -> None:
    i = 0
    title_seen = False
    subtitle_seen = False
    result_figure_added = False
    model_figure_added = False
    date_figure_added = False
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
            table_from_markdown(doc, table_lines)
            continue
        if raw.startswith("# "):
            p = doc.add_paragraph(style="Title")
            add_inline(p, raw[2:].strip())
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            title_seen = True
            i += 1
            continue
        if raw.startswith("## "):
            heading = raw[3:].strip()
            heading = re.sub(r"^(\d+)\.\s+", r"\1 ", heading)
            if not subtitle_seen and title_seen and heading == "Evaluating EPSS for vulnerability patch prioritization":
                p = doc.add_paragraph(style="Subtitle")
                add_inline(p, heading)
                subtitle_seen = True
            else:
                doc.add_heading(heading, level=1)
                if heading == "4 Results" and not result_figure_added:
                    add_figure(doc, "recall_at_k.png", "Figure 1. Pooled Recall@K on the common CVSS 3.x and EPSS cohort.")
                    result_figure_added = True
            i += 1
            continue
        if raw.startswith("### "):
            heading = raw[4:].strip()
            doc.add_heading(heading, level=2)
            if heading == "Decision dates and label" and not date_figure_added:
                add_figure(doc, "kev_positives_by_date.png", "Figure 2. Positive labels by decision date.")
                date_figure_added = True
            if heading == "Model results" and not model_figure_added:
                add_figure(doc, "model_comparison.png", "Figure 3. Average Precision with and without EPSS on the final test period.")
                model_figure_added = True
            i += 1
            continue
        if raw.startswith("- "):
            p = doc.add_paragraph(style="List Bullet")
            add_inline(p, raw[2:].strip())
            i += 1
            continue
        if re.match(r"\d+\.\s", raw):
            p = doc.add_paragraph(style="List Number")
            add_inline(p, re.sub(r"^\d+\.\s", "", raw))
            i += 1
            continue
        paragraph_lines = [raw]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "- ")) and not re.match(r"\d+\.\s", lines[i]):
            paragraph_lines.append(lines[i].strip())
            i += 1
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.08
        add_inline(p, " ".join(paragraph_lines))


def main() -> None:
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(.7)
    section.bottom_margin = Inches(.7)
    section.left_margin = Inches(.78)
    section.right_margin = Inches(.78)
    styles = doc.styles
    styles["Normal"].font.name = "Aptos"
    styles["Normal"].font.size = Pt(10.5)
    styles["Title"].font.name = "Aptos Display"
    styles["Title"].font.size = Pt(27)
    styles["Title"].font.bold = True
    styles["Title"].font.color.rgb = RGBColor(25, 52, 79)
    styles["Heading 1"].font.name = "Aptos Display"
    styles["Heading 1"].font.size = Pt(16)
    styles["Heading 1"].font.bold = True
    styles["Heading 1"].font.color.rgb = RGBColor(31, 78, 121)
    styles["Heading 2"].font.name = "Aptos Display"
    styles["Heading 2"].font.size = Pt(12)
    styles["Heading 2"].font.bold = True
    styles["Heading 2"].font.color.rgb = RGBColor(62, 93, 120)
    styles["Subtitle"].font.name = "Aptos"
    styles["Subtitle"].font.size = Pt(15)
    styles["Subtitle"].font.color.rgb = RGBColor(91, 105, 118)
    styles["Caption"].font.name = "Aptos"
    styles["Caption"].font.size = Pt(8.5)
    styles["Caption"].font.italic = True
    footer = section.footer.paragraphs[0]
    footer.add_run("Beyond CVSS | Advanced Data Science")
    footer.runs[0].font.size = Pt(8)
    add_page_number(footer)
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    render_markdown(doc, lines)
    doc.core_properties.title = "Beyond CVSS: Evaluating EPSS for vulnerability patch prioritization"
    doc.core_properties.subject = "Advanced Data Science project report"
    doc.core_properties.author = "Sumit Sharma and Ayansh Pandey"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
