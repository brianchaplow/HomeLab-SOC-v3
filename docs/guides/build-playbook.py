#!/usr/bin/env python3
"""Convert soc-playbook.md to navigable HTML and polished PDF."""

import re
import markdown
from pathlib import Path

SOC_PLAYBOOK_DIR = Path.home() / ".soc-playbook"
SRC = SOC_PLAYBOOK_DIR / "soc-playbook.md"
OUT_HTML = SOC_PLAYBOOK_DIR / "soc-playbook.html"
OUT_PDF = SOC_PLAYBOOK_DIR / "soc-playbook.pdf"

md_text = SRC.read_text(encoding="utf-8")

# --- Build TOC from markdown headings (skip code blocks) ---
toc_entries = []
in_code_block = False
for line in md_text.splitlines():
    if line.startswith("```"):
        in_code_block = not in_code_block
        continue
    if in_code_block:
        continue
    m = re.match(r"^(#{1,3}) (.+)$", line)
    if not m:
        continue
    level = len(m.group(1))
    title = m.group(2).strip()
    slug = re.sub(r"[^\w\s-]", "", title.lower())
    slug = re.sub(r"[\s]+", "-", slug).strip("-")
    # deduplicate slugs
    base = slug
    i = 1
    while any(e[2] == slug for e in toc_entries):
        slug = f"{base}-{i}"
        i += 1
    toc_entries.append((level, title, slug))

# --- Convert markdown to HTML body ---
md = markdown.Markdown(
    extensions=[
        "tables",
        "fenced_code",
        "codehilite",
        "toc",
        "attr_list",
        "md_in_html",
    ],
    extension_configs={
        "codehilite": {"css_class": "highlight", "guess_lang": False},
        "toc": {"permalink": False, "slugify": lambda value, separator: re.sub(r"[\s]+", "-", re.sub(r"[^\w\s-]", "", value.lower())).strip("-")},
    },
)
body_html = md.convert(md_text)

# --- Convert mermaid code blocks to Mermaid.js format ---
# python-markdown HTML-escapes content and wraps it in highlight divs.
# Mermaid.js reads element.textContent, so we must:
#   - Unescape quotes and arrows so Mermaid parses them
#   - KEEP <br> as &lt;br&gt; so browser treats it as text, not HTML elements
#     (textContent decodes &lt;br&gt; back to literal <br> for Mermaid)

def _fix_mermaid(m):
    s = m.group(1)
    s = s.replace('&quot;', '"')
    s = s.replace('&amp;', '&')
    s = s.replace('--&gt;', '-->')
    s = s.replace('-.&gt;', '-.>')
    # &lt;br&gt; and &lt;br/&gt; stay escaped on purpose
    return f'<pre class="mermaid">{s}</pre>'

body_html = re.sub(
    r'<div class="highlight"><pre><span></span><code>(graph (?:TB|LR|TD|BT|RL).*?)</code></pre></div>',
    _fix_mermaid,
    body_html,
    flags=re.DOTALL,
)

# --- Build sidebar nav ---
def build_nav(entries):
    lines = []
    for level, title, slug in entries:
        indent = "  " * (level - 1)
        css_class = f"nav-h{level}"
        # Shorten display for h3
        display = title
        if level == 3 and len(display) > 50:
            display = display[:47] + "..."
        lines.append(f'{indent}<a class="{css_class}" href="#{slug}">{display}</a>')
    return "\n".join(lines)

nav_html = build_nav(toc_entries)

# --- Full HTML template ---
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HomeLab SOC Operational Playbook</title>
<style>
  :root {{
    --bg: #0d1117;
    --bg-sidebar: #161b22;
    --bg-card: #1c2128;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --accent-dim: #1f6feb33;
    --green: #3fb950;
    --orange: #d29922;
    --red: #f85149;
    --code-bg: #161b22;
    --sidebar-w: 300px;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  html {{ scroll-behavior: smooth; scroll-padding-top: 20px; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    display: flex;
    min-height: 100vh;
  }}

  /* --- Sidebar --- */
  .sidebar {{
    position: fixed;
    top: 0; left: 0;
    width: var(--sidebar-w);
    height: 100vh;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 16px 0;
    z-index: 100;
    display: flex;
    flex-direction: column;
  }}

  .sidebar-header {{
    padding: 8px 16px 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 8px;
  }}
  .sidebar-header h2 {{
    font-size: 14px;
    color: var(--accent);
    margin-bottom: 10px;
  }}

  .search-box {{
    width: 100%;
    padding: 6px 10px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 13px;
    outline: none;
  }}
  .search-box:focus {{ border-color: var(--accent); }}
  .search-box::placeholder {{ color: var(--text-muted); }}

  .sidebar-nav {{
    flex: 1;
    overflow-y: auto;
    padding: 4px 0;
  }}
  .sidebar-nav a {{
    display: block;
    padding: 4px 16px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 13px;
    border-left: 3px solid transparent;
    transition: all 0.15s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  .sidebar-nav a:hover {{
    color: var(--text);
    background: var(--accent-dim);
  }}
  .sidebar-nav a.active {{
    color: var(--accent);
    border-left-color: var(--accent);
    background: var(--accent-dim);
  }}
  .sidebar-nav .nav-h1 {{ font-weight: 700; font-size: 14px; color: var(--text); padding-top: 8px; }}
  .sidebar-nav .nav-h2 {{ padding-left: 20px; font-weight: 600; color: var(--text); }}
  .sidebar-nav .nav-h3 {{ padding-left: 36px; font-size: 12px; }}

  /* --- Main content --- */
  .content {{
    margin-left: var(--sidebar-w);
    flex: 1;
    max-width: 900px;
    padding: 40px 48px 80px;
  }}

  .content h1 {{
    font-size: 28px;
    margin-bottom: 8px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
  }}
  .content h2 {{
    font-size: 22px;
    margin-top: 48px;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
  }}
  .content h3 {{
    font-size: 17px;
    margin-top: 32px;
    margin-bottom: 12px;
    color: var(--accent);
  }}

  .content p {{ margin-bottom: 12px; }}

  .content strong {{ color: var(--text); }}

  .content a {{
    color: var(--accent);
    text-decoration: none;
  }}
  .content a:hover {{ text-decoration: underline; }}

  .content hr {{
    border: none;
    border-top: 1px solid var(--border);
    margin: 32px 0;
  }}

  /* Tables */
  .content table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 14px;
  }}
  .content th {{
    background: var(--bg-card);
    padding: 10px 12px;
    text-align: left;
    border: 1px solid var(--border);
    font-weight: 600;
    color: var(--accent);
    font-size: 13px;
  }}
  .content td {{
    padding: 8px 12px;
    border: 1px solid var(--border);
    vertical-align: top;
  }}
  .content tr:hover td {{ background: var(--bg-card); }}

  /* Code blocks */
  .content pre {{
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    overflow-x: auto;
    margin: 12px 0;
    font-size: 13px;
    line-height: 1.5;
    position: relative;
  }}
  .content code {{
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 13px;
  }}
  .content p code, .content li code, .content td code {{
    background: var(--code-bg);
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid var(--border);
    font-size: 12px;
  }}

  /* Copy button */
  .content pre {{ position: relative; }}
  .copy-btn {{
    position: absolute;
    top: 8px; right: 8px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
    font-size: 11px;
    padding: 3px 8px;
    cursor: pointer;
    opacity: 0;
    transition: opacity 0.15s;
  }}
  .content pre:hover .copy-btn {{ opacity: 1; }}
  .copy-btn:hover {{ color: var(--accent); border-color: var(--accent); }}

  /* Lists */
  .content ul, .content ol {{
    margin: 8px 0 12px 24px;
  }}
  .content li {{
    margin-bottom: 4px;
  }}

  /* Blockquotes */
  .content blockquote {{
    border-left: 4px solid var(--accent);
    padding: 8px 16px;
    margin: 12px 0;
    background: var(--bg-card);
    border-radius: 0 6px 6px 0;
    color: var(--text-muted);
  }}

  /* Mermaid diagrams */
  .content pre.mermaid {{
    background: transparent;
    border: none;
    padding: 0;
    overflow-x: auto;
    max-width: none;
    margin-left: -48px;
    margin-right: -48px;
    padding-left: 48px;
    padding-right: 48px;
  }}
  .content pre.mermaid svg {{
    max-width: 100%;
    height: auto;
    min-height: 400px;
  }}

  /* Highlight (codehilite / pygments) */
  .highlight {{ background: var(--code-bg) !important; }}
  .highlight pre {{ background: transparent !important; border: none !important; padding: 0 !important; margin: 0 !important; }}

  /* Back to top */
  .back-to-top {{
    position: fixed;
    bottom: 24px; right: 24px;
    background: var(--accent);
    color: var(--bg);
    border: none;
    border-radius: 50%;
    width: 40px; height: 40px;
    font-size: 18px;
    cursor: pointer;
    opacity: 0;
    transition: opacity 0.2s;
    z-index: 200;
  }}
  .back-to-top.visible {{ opacity: 0.8; }}
  .back-to-top:hover {{ opacity: 1; }}

  /* Mobile */
  @media (max-width: 900px) {{
    .sidebar {{ width: 260px; }}
    .content {{ margin-left: 260px; padding: 24px; }}
  }}
  @media (max-width: 700px) {{
    .sidebar {{ display: none; }}
    .content {{ margin-left: 0; }}
  }}

  /* Search highlight */
  mark {{ background: var(--orange); color: var(--bg); padding: 1px 2px; border-radius: 2px; }}

  /* Pygments dark overrides */
  .highlight .hll {{ background-color: #30363d; }}
  .highlight .c, .highlight .cm, .highlight .c1, .highlight .cs {{ color: #8b949e; }}
  .highlight .k, .highlight .kn, .highlight .kp, .highlight .kr, .highlight .kd {{ color: #ff7b72; }}
  .highlight .s, .highlight .s1, .highlight .s2, .highlight .sb, .highlight .sc {{ color: #a5d6ff; }}
  .highlight .n, .highlight .na, .highlight .nb, .highlight .nc {{ color: #e6edf3; }}
  .highlight .nf {{ color: #d2a8ff; }}
  .highlight .mi, .highlight .mf {{ color: #79c0ff; }}
  .highlight .o, .highlight .p {{ color: #e6edf3; }}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-header">
    <h2>SOC Playbook</h2>
    <input class="search-box" type="text" placeholder="Search sections..." id="nav-search">
  </div>
  <div class="sidebar-nav" id="sidebar-nav">
    {nav_html}
  </div>
</nav>

<main class="content">
  {body_html}
</main>

<button class="back-to-top" id="btt" title="Back to top">&uarr;</button>

<script>
// Copy buttons on code blocks (skip mermaid diagrams)
document.querySelectorAll('.content pre:not(.mermaid)').forEach(pre => {{
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.textContent = 'Copy';
  btn.addEventListener('click', () => {{
    const code = pre.querySelector('code') || pre;
    navigator.clipboard.writeText(code.textContent).then(() => {{
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 1500);
    }});
  }});
  pre.appendChild(btn);
}});

// Active section tracking
const navLinks = document.querySelectorAll('.sidebar-nav a');
const headings = [];
navLinks.forEach(link => {{
  const id = link.getAttribute('href').slice(1);
  const el = document.getElementById(id);
  if (el) headings.push({{ el, link }});
}});

function updateActive() {{
  let current = headings[0];
  for (const h of headings) {{
    if (h.el.getBoundingClientRect().top <= 60) current = h;
  }}
  navLinks.forEach(l => l.classList.remove('active'));
  if (current) {{
    current.link.classList.add('active');
    current.link.scrollIntoView({{ block: 'nearest' }});
  }}
}}
window.addEventListener('scroll', updateActive);
updateActive();

// Back to top
const btt = document.getElementById('btt');
window.addEventListener('scroll', () => {{
  btt.classList.toggle('visible', window.scrollY > 400);
}});
btt.addEventListener('click', () => window.scrollTo({{ top: 0, behavior: 'smooth' }}));

// Nav search filter
document.getElementById('nav-search').addEventListener('input', function() {{
  const q = this.value.toLowerCase();
  navLinks.forEach(link => {{
    link.style.display = link.textContent.toLowerCase().includes(q) || !q ? '' : 'none';
  }});
}});
</script>

<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>
mermaid.initialize({{
  startOnLoad: true,
  theme: 'dark',
  flowchart: {{
    nodeSpacing: 30,
    rankSpacing: 60,
    padding: 15,
    useMaxWidth: false
  }},
  themeVariables: {{
    fontSize: '14px',
    primaryColor: '#1f6feb',
    primaryTextColor: '#e6edf3',
    primaryBorderColor: '#30363d',
    lineColor: '#58a6ff',
    secondaryColor: '#161b22',
    tertiaryColor: '#1c2128'
  }}
}});
</script>

</body>
</html>"""

OUT_HTML.write_text(html, encoding="utf-8")
print(f"HTML written to {OUT_HTML} ({len(html):,} bytes)")

# --- Generate print-friendly HTML for PDF ---
OUT_PRINT_HTML = SOC_PLAYBOOK_DIR / "soc-playbook-print.html"

print_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HomeLab SOC Operational Playbook</title>
<style>
  @page {{ size: letter; margin: 0.75in 0.75in 1in 0.75in; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    color: #1a1a1a; line-height: 1.55; font-size: 11pt;
    max-width: 7.5in; margin: 0 auto; padding: 0;
  }}
  h1 {{ font-size: 22pt; border-bottom: 2px solid #0969da; padding-bottom: 6px; margin-bottom: 12px; }}
  h2 {{ font-size: 16pt; border-bottom: 1px solid #d0d7de; padding-bottom: 4px;
       margin-top: 28px; break-after: avoid; }}
  h3 {{ font-size: 12pt; color: #0550ae; margin-top: 20px; break-after: avoid; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 9pt; }}
  th {{ background: #f6f8fa; padding: 6px 8px; border: 1px solid #d0d7de; font-weight: 600; }}
  td {{ padding: 5px 8px; border: 1px solid #d0d7de; vertical-align: top; }}
  pre {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 4px;
        padding: 10px; font-size: 8.5pt; overflow-wrap: break-word;
        white-space: pre-wrap; break-inside: avoid; }}
  code {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 8.5pt; }}
  p code, li code, td code {{ background: #f6f8fa; padding: 1px 4px; border-radius: 3px;
                               border: 1px solid #d0d7de; font-size: 8pt; }}
  blockquote {{ border-left: 3px solid #0969da; padding: 6px 12px; margin: 10px 0;
               background: #f6f8fa; }}
  a {{ color: #0550ae; text-decoration: none; }}
  hr {{ border: none; border-top: 1px solid #d0d7de; margin: 20px 0; }}
  ul, ol {{ margin: 6px 0 10px 20px; }}
  p {{ margin-bottom: 10px; }}
  .highlight {{ background: transparent !important; }}
  .highlight pre {{ border: none !important; padding: 0 !important; margin: 0 !important; }}
</style>
</head>
<body>
{body_html}
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{ startOnLoad: true, theme: 'default' }});</script>
</body>
</html>"""

OUT_PRINT_HTML.write_text(print_html, encoding="utf-8")
print(f"Print HTML written to {OUT_PRINT_HTML}")

# --- Generate PDF via Chrome headless ---
import subprocess
import shutil

chrome = shutil.which("chrome")
if not chrome:
    for p in [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]:
        if Path(p).exists():
            chrome = p
            break

if chrome:
    import time
    file_url = OUT_PRINT_HTML.resolve().as_uri()
    # Delete stale PDF so we can detect fresh output
    if OUT_PDF.exists():
        OUT_PDF.unlink()
    result = subprocess.run([
        chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
        f"--print-to-pdf={OUT_PDF}", "--print-to-pdf-no-header",
        file_url,
    ], capture_output=True, text=True, timeout=90)
    # Give filesystem time to flush
    time.sleep(1)
    if OUT_PDF.exists() and OUT_PDF.stat().st_size > 500_000:
        print(f"PDF written to {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")
        OUT_PRINT_HTML.unlink()
    elif OUT_PDF.exists():
        print(f"PDF may be incomplete ({OUT_PDF.stat().st_size:,} bytes). Print HTML kept at {OUT_PRINT_HTML}")
        print("Open soc-playbook-print.html in Chrome and Ctrl+P -> Save as PDF for a clean copy.")
    else:
        print(f"PDF generation failed. Chrome stderr: {result.stderr[:300]}")
        print(f"Print HTML kept at {OUT_PRINT_HTML} -- open in browser and print to PDF.")
else:
    print("No Chrome/Edge found. Open soc-playbook-print.html in a browser and print to PDF.")
