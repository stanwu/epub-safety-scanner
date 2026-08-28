# EPUB Safety Scanner

[![CI](https://github.com/stanwu/epub-safety-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/stanwu/epub-safety-scanner/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/stanwu/epub-safety-scanner)](https://github.com/stanwu/epub-safety-scanner/releases/latest)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Detect and fix malicious content embedded in EPUB files. Scans entirely in-memory — no temp files, no disk extraction.

## Download

> [!TIP]
> For security, always download from this GitHub repository directly. Do not download from third-party sources.

**[Download scan-epub-skill.zip](https://github.com/stanwu/epub-safety-scanner/releases/latest)** from the latest release.

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
- **Claude.ai Skill** — package as a skill for use in Claude.ai

## Quick Start

```bash
git clone https://github.com/stanwu/epub-safety-scanner.git
cd epub-safety-scanner

# Scan all EPUBs on your Desktop
python3 epub_safety_scanner.py ~/Desktop/

# Scan with a glob (supports ** recursion)
python3 epub_safety_scanner.py '**/*.epub'

# Fix any threats found
python3 epub_safety_scanner.py ~/Desktop/ --fix
```

No external dependencies required — Python 3.10+ stdlib only.

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## Installation

```bash
git clone https://github.com/stanwu/epub-safety-scanner.git
cd epub-safety-scanner
```

Install as a standalone tool with uv:

```bash
uv tool install .
epub-safety-scanner book.epub
```

For development (linting, testing):

```bash
uv sync --all-groups
```

## CLI Reference

```
python3 epub_safety_scanner.py PATTERN [PATTERN ...] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `PATTERN` | **(Required, repeatable)** EPUB file, directory, or glob pattern (e.g. `'**/*.epub'`). Supports `~` expansion. Duplicates are scanned once. |
| `--fix` | Remove threats and save as `[fixed] filename.epub` in the same directory. |
| `--report FILE` | Write a detailed Markdown report to the specified file. |
| `-v, --verbose` | Show INFO-level findings (external hyperlinks, hidden by default). |
| `--no-color` | Disable colored terminal output. |

**Exit codes:** `1` if any CRITICAL findings, `0` otherwise.

## Installation (as a uv tool)

```bash
uv tool install /path/to/epub-safety-scanner   # or: git+https://.../epub-safety-scanner.git
epub-safety-scanner book.epub
```

## Usage Scenarios

### Scenario 1: Scan a Single EPUB

```bash
python3 epub_safety_scanner.py ~/Desktop/book.epub
```

Outputs a severity summary per file. CLEAN means no threats detected.

### Scenario 2: Batch Scan a Directory

```bash
python3 epub_safety_scanner.py ~/Desktop/
```

Directories are expanded to `*.epub`. Globs work too: `python3 epub_safety_scanner.py 'books/**/*.epub' other.epub`. Displays per-file results and a final summary showing how many files have issues. Displays per-file results and a final summary showing how many files have issues.

### Scenario 3: Fix Threats and Verify

```bash
# Step 1: Fix all threats
python3 epub_safety_scanner.py ~/Desktop/ --fix

# Step 2: Verify the fixed files are clean
python3 epub_safety_scanner.py '~/Desktop/[fixed] *.epub'
```

Each fixed EPUB is saved as `[fixed] original.epub` in the same directory. The original file is left untouched.

### Scenario 4: Generate a Report for Review

```bash
python3 epub_safety_scanner.py ~/Desktop/ --report report.md
```

Creates a Markdown report with:
- Scan date and file count
- Summary table (status per file)
- Per-file details grouped by threat category
- Evidence snippets for each finding

### Scenario 5: Full Workflow (Scan + Fix + Report)

```bash
python3 epub_safety_scanner.py ~/Desktop/ --fix --report report.md
```

Scans all EPUBs, fixes threats, and exports a report — all in one command.

### Scenario 6: Verbose Mode — Inspect External Links

```bash
python3 epub_safety_scanner.py ~/Desktop/ -v
```

Shows INFO-level findings (external `<a href>` links) that are hidden by default. Useful for auditing what external URLs an EPUB references. URLs are color-coded: **green** for safe `<a href>` links, **red** for suspicious external resources.

## Understanding the Output

| Severity | Meaning | Default |
|----------|---------|---------|
| **CRITICAL** | High risk — JavaScript, executables, disguised files, `<iframe>`, `<applet>` | Shown |
| **WARNING** | Medium risk — external resource loading (`src`, `action`), suspicious CSS, nested archives | Shown |
| **INFO** | Low risk — external hyperlinks (`<a href>`) | Hidden (use `-v`) |

- Files with only INFO findings display as **CLEAN** by default
- URLs in the output are color-coded: **green** = safe `<a href>`, **red** = suspicious
- Each finding includes the internal file path and an evidence snippet

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

If no threats are found, no fixed file is created.

## Claude.ai Skill

Use the downloaded `scan-epub-skill.zip` as a Claude.ai Skill — no installation required.

1. Go to [claude.ai](https://claude.ai)
2. Navigate to **Customize > Skills**
3. Click **+** and select **Upload a skill**
4. Upload `scan-epub-skill.zip`

Once uploaded, Claude will use the scanner when you ask it to check EPUB files for security threats.

Or build the skill ZIP locally:

```bash
make skill
```

## Development

```bash
make test          # Run unit tests (111 tests)
make lint          # Run linters (ruff, bandit, mypy)
make check         # Run all checks (lint + test)
make format        # Auto-format code
make skill         # Package claude.ai skill ZIP
```

## License

MIT
