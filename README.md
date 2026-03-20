# EPUB Safety Scanner

Detect and fix malicious content embedded in EPUB files. Scans entirely in-memory — no temp files, no disk extraction.

## Features

- **JavaScript detection** — `<script>` tags, inline event handlers (`onclick`, `onerror`, etc.), `javascript:` URIs, `eval()`, `fetch()`, `WebSocket`, and more
- **Malicious HTML** — `<iframe>`, `<object>`, `<embed>`, `<form>`, `<applet>`, `<meta refresh>`, `<base>`, `data:` URIs
- **Malicious CSS** — `expression()`, `-moz-binding`, `behavior`, external `url()` / `@import` (tracking pixels), `javascript:` in CSS
- **Suspicious files** — executables (`.exe`, `.bat`, `.sh`, `.dll`, `.ps1`), nested archives (`.zip`, `.rar`, `.7z`), disguised executables (MZ header mismatch)
- **ZIP security** — path traversal (`../`), zip bomb detection (size & compression ratio), file integrity checks
- **SVG scanning** — scripts and event handlers inside SVG images
- **External URL detection** — passive tracking via `src`, `action`, CSS `url()` flagged as WARNING; safe `<a href>` links kept as INFO
- **Auto-fix mode** — remove threats and repack as `[fixed] filename.epub`
- **Markdown report** — export detailed scan results to `.md` file

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## Installation

```bash
git clone <repo-url>
cd epub-safety-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Usage

```bash
# Scan a single file
python3 epub_safety_scanner.py --path book.epub

# Scan a directory (auto-finds *.epub)
python3 epub_safety_scanner.py --path ~/Desktop/

# Scan with glob pattern
python3 epub_safety_scanner.py --path "books/*.epub"

# Show INFO-level findings (external links, hidden by default)
python3 epub_safety_scanner.py --path ~/Desktop/ -v

# Fix threats and repack as [fixed] filename.epub
python3 epub_safety_scanner.py --path ~/Desktop/ --fix

# Export Markdown report
python3 epub_safety_scanner.py --path ~/Desktop/ --report report.md

# Combine: scan, fix, and report
python3 epub_safety_scanner.py --path ~/Desktop/ --fix --report report.md
```

## Output

Findings are categorized by severity:

| Severity | Meaning | Default |
|----------|---------|---------|
| **CRITICAL** | High risk — JavaScript, executables, disguised files | Shown |
| **WARNING** | Medium risk — external resources, suspicious CSS, nested archives | Shown |
| **INFO** | Low risk — external hyperlinks (`<a href>`) | Hidden (use `-v`) |

URLs are color-coded in terminal output: **green** for safe `<a href>` links, **red** for suspicious external resources.

Exit code `1` if any CRITICAL findings, `0` otherwise.

## Fix Mode

`--fix` removes threats and saves a clean copy as `[fixed] original.epub`:

| Threat | Action |
|--------|--------|
| `.js` files | Removed |
| Executables (`.exe`, `.dll`, etc.) | Removed |
| Nested archives (`.zip`, `.rar`, etc.) | Removed |
| Path traversal entries (`../`) | Removed |
| `<script>`, `<iframe>`, `<applet>`, `<object>`, `<embed>` | Stripped from HTML |
| Event handlers (`onclick`, `onerror`, etc.) | Stripped from attributes |
| `javascript:` / `data:text/html` URIs | Neutralized to `#` |
| `<meta refresh>`, `<base>` | Stripped |
| External `src`, `action`, `poster`, `data` URLs | Removed |
| CSS `expression()`, `-moz-binding`, `behavior` | Removed |
| CSS `url(https://...)`, `@import url(https://...)` | Removed |
| `<a href="https://...">` | **Preserved** (normal for ebooks) |

## Development

```bash
make test          # Run unit tests
make lint          # Run linters (ruff, bandit, mypy)
make check         # Run all checks (lint + test)
make format        # Auto-format code
```

## License

MIT
