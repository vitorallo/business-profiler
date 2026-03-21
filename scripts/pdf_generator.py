#!/usr/bin/env python3
"""Markdown to PDF generator for threat intelligence reports.

Uses WeasyPrint + markdown2 for professional PDF output.
Supports Mermaid diagrams via mmdc (mermaid-cli) if installed.
Output: PDF file at specified path.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

try:
    import markdown2
    from weasyprint import HTML, CSS
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

logger = logging.getLogger(__name__)

HAS_MMDC = shutil.which("mmdc") is not None


def render_mermaid_blocks(markdown_content: str) -> str:
    """Replace ```mermaid code blocks with PNG images for reliable PDF rendering.

    Requires mmdc (mermaid-cli) to be installed:
        npm install -g @mermaid-js/mermaid-cli

    If mmdc is not available, mermaid blocks are left as styled code blocks.
    """
    if not HAS_MMDC:
        logger.info("mmdc not found — mermaid blocks will render as code")
        return markdown_content

    def _replace_block(match: re.Match) -> str:
        mermaid_code = match.group(1).strip()
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as src:
                src.write(mermaid_code)
                src_path = src.name
            # Use PNG output — SVG uses <foreignObject> which WeasyPrint can't render
            out_path = src_path.replace(".mmd", ".png")
            result = subprocess.run(
                ["mmdc", "-i", src_path, "-o", out_path, "-b", "white",
                 "-s", "2", "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and Path(out_path).exists():
                import base64
                png_data = Path(out_path).read_bytes()
                b64 = base64.b64encode(png_data).decode("ascii")
                return (
                    f'<div style="text-align:center;margin:16pt 0;">'
                    f'<img src="data:image/png;base64,{b64}" '
                    f'style="max-width:100%;height:auto;" />'
                    f'</div>'
                )
            else:
                logger.warning("mmdc failed: %s", result.stderr[:200])
                return match.group(0)
        except Exception as e:
            logger.warning("Mermaid rendering error: %s", e)
            return match.group(0)
        finally:
            for p in [src_path, out_path]:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass

    return re.sub(r"```mermaid\s*\n(.*?)```", _replace_block, markdown_content, flags=re.DOTALL)


def fix_svg_foreignobject(html_content: str) -> str:
    """Replace inline SVG diagrams containing <foreignObject> with a fallback notice.

    WeasyPrint cannot render <foreignObject> content inside SVGs, resulting in
    colored boxes with no text. This function detects such SVGs and wraps them
    with a warning so the output is not silently broken.

    When Mermaid diagrams are generated inline by Claude (not via mmdc), they
    produce SVGs with <foreignObject> text. This catches those cases.
    """
    if "<foreignObject" not in html_content:
        return html_content

    def _patch_svg(match: re.Match) -> str:
        svg = match.group(0)
        if "<foreignObject" not in svg:
            return svg
        # Extract text content from foreignObject divs as fallback
        texts = re.findall(r'<foreignObject[^>]*>.*?<div[^>]*>(.*?)</div>.*?</foreignObject>',
                           svg, flags=re.DOTALL)
        clean_texts = []
        for t in texts:
            clean = re.sub(r'<[^>]+>', '', t).strip()
            if clean:
                clean_texts.append(clean)

        # Replace SVG with a styled box showing the diagram data as text
        if clean_texts:
            items = "".join(f"<li>{t}</li>" for t in clean_texts)
            return (
                f'<div style="background:#FFF5F0;border:1px solid #F5A582;'
                f'border-left:4px solid #E86B3F;padding:14pt;margin:16pt 0;">'
                f'<p style="color:#C85A34;font-weight:bold;margin-bottom:8pt;">'
                f'Diagram (install mermaid-cli for rendered charts):</p>'
                f'<ul style="margin:0;padding-left:20pt;">{items}</ul></div>'
            )
        return svg

    return re.sub(r'<svg[\s\S]*?</svg>', _patch_svg, html_content)

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"

PDF_STYLE = """
@page {
    size: A4;
    margin: 2.5cm 2cm 3.5cm 2cm;

    @top-center {
        content: "Business Profiler — Confidential";
        font-size: 8pt;
        color: #E86B3F;
        font-weight: bold;
        padding-bottom: 4pt;
    }

    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 7pt;
        color: #C0B0A0;
        font-family: 'Helvetica', 'Arial', sans-serif;
    }
}

body {
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 11pt;
    line-height: 2.0;
    color: #2F2218;
    max-width: 100%;
    text-rendering: optimizeLegibility;
}

h1 {
    color: #2F2218;
    font-size: 26pt;
    font-weight: bold;
    margin-top: 0;
    margin-bottom: 20pt;
    padding-bottom: 12pt;
    border-bottom: 4px solid #E86B3F;
    page-break-after: avoid;
    line-height: 1.2;
}

h2 {
    color: #E86B3F;
    font-size: 18pt;
    font-weight: bold;
    margin-top: 28pt;
    margin-bottom: 14pt;
    page-break-after: avoid;
    line-height: 1.3;
}

h3 {
    color: #C85A34;
    font-size: 14pt;
    font-weight: bold;
    margin-top: 20pt;
    margin-bottom: 12pt;
    page-break-after: avoid;
    line-height: 1.3;
}

h4 {
    color: #2F2218;
    font-size: 12pt;
    font-weight: bold;
    margin-top: 16pt;
    margin-bottom: 10pt;
    line-height: 1.3;
}

p {
    margin-top: 0;
    margin-bottom: 18pt;
    text-align: left;
    line-height: 2.0;
    white-space: pre-wrap;
    word-wrap: break-word;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 20pt 0;
    font-size: 10pt;
    page-break-inside: auto;
}

thead {
    background: linear-gradient(135deg, #E86B3F 0%, #F5A582 100%);
    color: white;
    font-weight: bold;
}

th {
    padding: 4pt 8pt;
    text-align: left;
    border: 1px solid #ddd;
    line-height: 1.3;
}

td {
    padding: 3pt 8pt;
    border: 1px solid #ddd;
    line-height: 1.3;
}

tr:nth-child(even) {
    background-color: #FFF5F0;
}

tr {
    page-break-inside: avoid;
}

ul, ol {
    margin: 16pt 0;
    padding-left: 24pt;
    line-height: 2.0;
}

li {
    margin-bottom: 10pt;
    line-height: 2.0;
}

pre {
    background-color: #FFF5F0;
    border: 1px solid #F5A582;
    border-left: 4px solid #E86B3F;
    padding: 14pt;
    margin: 16pt 0;
    overflow-x: auto;
    font-family: 'Courier New', monospace;
    font-size: 9pt;
    line-height: 1.6;
}

code {
    background-color: #FFF5F0;
    padding: 2pt 6pt;
    border-radius: 3pt;
    font-family: 'Courier New', monospace;
    font-size: 9pt;
    color: #C85A34;
}

a {
    color: #E86B3F;
    text-decoration: none;
}

blockquote {
    border-left: 4px solid #F5A582;
    padding-left: 16pt;
    margin: 16pt 0;
    color: #64748b;
    font-style: italic;
    line-height: 1.8;
}

hr {
    border: none;
    border-top: 2px solid #F5A582;
    margin: 24pt 0;
}

.dashboard-row { display: flex; gap: 12pt; margin: 16pt 0; flex-wrap: wrap; }
.metric-card { flex: 1; min-width: 120pt; background: #FFF5F0; border-radius: 6pt; padding: 12pt 14pt; border-left: 4pt solid #E86B3F; }
.metric-card .metric-value { font-size: 20pt; font-weight: 700; color: #2F2218; margin: 0; line-height: 1.2; }
.metric-card .metric-label { font-size: 8pt; color: #C85A34; text-transform: uppercase; letter-spacing: 0.5pt; margin: 4pt 0 0 0; }
.risk-badge { display: inline-block; padding: 2pt 10pt; border-radius: 3pt; font-weight: 700; font-size: 9pt; }
.risk-critical { background: #dc2626; color: white; font-weight: bold; }
.risk-high { background: #E86B3F; color: white; font-weight: bold; }
.risk-medium { background: #d97706; color: white; font-weight: bold; }
.risk-low { background: #16a34a; color: white; font-weight: bold; }
.score-section { background: linear-gradient(135deg, #2F2218, #4a3020); color: white; padding: 10pt 14pt; border-radius: 6pt; margin: 12pt 0; }
.score-section .score-title { font-size: 8pt; opacity: 0.7; margin: 0 0 2pt 0; text-transform: uppercase; letter-spacing: 0.5pt; }
.score-section .score-value { font-size: 16pt; font-weight: 700; margin: 0; line-height: 1.2; }
.score-section .score-subtitle { font-size: 8pt; opacity: 0.6; margin: 4pt 0 0 0; }

.page-break {
    page-break-before: always;
}

.page-footer {
    position: fixed;
    bottom: -2.5cm;
    left: 0;
    right: 0;
    text-align: center;
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: center;
    gap: 4pt;
}

.page-footer p {
    font-size: 6.5pt;
    color: #C0B0A0;
    font-family: 'Helvetica', 'Arial', sans-serif;
    margin: 0;
    letter-spacing: 0.3pt;
    display: inline;
}

.page-footer svg {
    width: 45pt;
    height: auto;
    opacity: 0.4;
    display: inline;
}
"""


def markdown_to_pdf(
    markdown_content: str,
    output_path: str,
    title: str = "Threat Intelligence Report",
) -> dict:
    """Convert markdown to PDF.

    Args:
        markdown_content: Markdown text
        output_path: Path for output PDF
        title: Document title

    Returns:
        Dict with status and file info
    """
    if not HAS_PDF:
        return {"error": "weasyprint and markdown2 required: pip install weasyprint markdown2"}

    try:
        # Render mermaid diagrams to inline SVG before markdown conversion
        markdown_content = render_mermaid_blocks(markdown_content)

        html_body = markdown2.markdown(
            markdown_content,
            extras=["tables", "fenced-code-blocks", "strike", "header-ids", "code-friendly"],
        )

        # Fix inline SVGs with <foreignObject> (WeasyPrint can't render those)
        html_body = fix_svg_foreignobject(html_body)

        # Load Peach Studio logo for page footer
        logo_svg = ""
        logo_path = ASSETS_DIR / "peachstudio_logo.svg"
        if logo_path.exists():
            try:
                logo_svg = logo_path.read_text(encoding="utf-8")
            except Exception:
                pass

        footer_html = f"""<div class="page-footer">
    <p>Made with love by an AI agent · a skill developed by</p>
    <a href="http://peachstudio.be">{logo_svg}</a>
</div>""" if logo_svg else """<div class="page-footer">
    <p>Made with love by an AI agent · a skill developed by <a href="http://peachstudio.be">PEACH STUDIO</a></p>
</div>"""

        html_doc = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>{PDF_STYLE}</style>
</head>
<body>
    {footer_html}
    {html_body}
</body>
</html>"""

        html = HTML(string=html_doc)
        html.write_pdf(output_path, stylesheets=[CSS(string=PDF_STYLE)])

        size_kb = Path(output_path).stat().st_size / 1024
        return {"status": "ok", "path": output_path, "size_kb": round(size_kb, 1)}

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert markdown report to PDF")
    parser.add_argument("--input", required=True, help="Input markdown file")
    parser.add_argument("--output", required=True, help="Output PDF path")
    parser.add_argument("--title", default="Threat Intelligence Report", help="PDF title")
    args = parser.parse_args()

    md_content = Path(args.input).read_text(encoding="utf-8")
    result = markdown_to_pdf(md_content, args.output, args.title)
    print(json.dumps(result, indent=2))
