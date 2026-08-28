---
name: scan-epub
description: Scan EPUB files for malicious content (JavaScript, tracking URLs, dangerous files) and fix threats. Use when the user wants to check EPUB safety, remove threats, or generate a security report.
dependencies: python>=3.9
---

# EPUB Safety Scanner

Scan EPUB files for malicious content and optionally fix threats.

## How to Use

Run the scanner using the `epub_safety_scanner.py` file included in this skill:

```bash
python3 epub_safety_scanner.py PATTERN [PATTERN ...] [options]
```

## Options

| Flag | Description |
|------|-------------|
| `PATTERN` | **(Required, repeatable)** EPUB file, directory, or glob pattern (e.g. `'**/*.epub'`) |
| `--fix` | Remove threats and save as `[fixed] filename.epub` |
| `--report FILE` | Write a Markdown report to the specified file |
| `-v, --verbose` | Show INFO-level findings (external links, hidden by default) |
| `--no-color` | Disable colored terminal output |

## Examples

**Scan a single file:**
```bash
python3 epub_safety_scanner.py ~/Desktop/book.epub
```

**Scan all EPUBs in a directory:**
```bash
python3 epub_safety_scanner.py ~/Desktop/
```

**Scan with a glob (supports `**` recursion):**
```bash
python3 epub_safety_scanner.py '**/*.epub'
```

**Fix threats and generate a report:**
```bash
python3 epub_safety_scanner.py ~/Desktop/ --fix --report report.md
```

**Show all findings including external links:**
```bash
python3 epub_safety_scanner.py ~/Desktop/ -v
```

## Understanding the Output

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | High risk — JavaScript, executables, disguised files, iframe, applet |
| **WARNING** | Medium risk — external resource loading (tracking pixels), suspicious CSS |
| **INFO** | Low risk — external hyperlinks (`<a href>`), normal for ebooks |

- INFO findings are hidden by default (use `-v` to show)
- Files with only INFO findings display as CLEAN
- Exit code `1` if any CRITICAL findings, `0` otherwise

## What --fix Does

- **Removes entirely:** `.js` files, executables, nested archives, path traversal entries
- **Strips from HTML:** `<script>`, `<iframe>`, `<applet>`, `<object>`, `<embed>`, event handlers, `<meta refresh>`, `<base>`
- **Neutralizes:** `javascript:` URIs → `#`, `data:text/html` URIs → `#`
- **Removes from CSS:** `expression()`, `-moz-binding`, `behavior`, external `url()`, `@import url()`
- **Removes external:** `src`, `action`, `poster`, `data` attributes pointing to external URLs
- **Preserves:** `<a href="https://...">` (normal for ebooks)
- **Output:** `[fixed] original.epub` in the same directory
