#!/usr/bin/env python3
"""EPUB Cleaner - Deep clean malicious content from EPUB files via disk extraction."""

import argparse
import glob
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from epub_safety_scanner import (
    ARCHIVE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    EVENT_HANDLERS,
)

# ── Tag regex ───────────────────────────────────────────────────────────────
_TAG_RE = re.compile(r"\[(?:fixed|detect)\]\s*", re.IGNORECASE)

# ── Content file extensions to sanitize ─────────────────────────────────────
_CONTENT_EXTS = {".xhtml", ".html", ".htm", ".xml", ".svg", ".opf"}
_CSS_EXT = ".css"

# ── Regex: script tags ─────────────────────────────────────────────────────
# External script (has src attribute) — delete entirely
_SCRIPT_EXTERNAL = re.compile(
    r"<script\b[^>]+src\s*=[^>]*/?\s*>(?:</script\s*>)?",
    re.IGNORECASE | re.DOTALL,
)
# Self-closing script with src (e.g., <script ... src="..." />)
_SCRIPT_SELF_CLOSING = re.compile(
    r"<script\b[^>]*/\s*>",
    re.IGNORECASE,
)
# Inline script block — wrap with <!-- [CLEANED] -->
_SCRIPT_INLINE = re.compile(
    r"<script[\s>].*?</script\s*>",
    re.IGNORECASE | re.DOTALL,
)

# ── Regex: dangerous HTML tags ──────────────────────────────────────────────
_IFRAME_BLOCK = re.compile(r"<iframe[\s>].*?</iframe\s*>", re.IGNORECASE | re.DOTALL)
_IFRAME_SELF = re.compile(r"<iframe\b[^>]*/\s*>", re.IGNORECASE)
_APPLET_BLOCK = re.compile(r"<applet[\s>].*?</applet\s*>", re.IGNORECASE | re.DOTALL)
_OBJECT_BLOCK = re.compile(r"<object[\s>].*?</object\s*>", re.IGNORECASE | re.DOTALL)
_EMBED_TAG = re.compile(r"<embed\b[^>]*/?\s*>", re.IGNORECASE)
_BASE_TAG = re.compile(r"<base\b[^>]*/?\s*>", re.IGNORECASE)
_META_REFRESH = re.compile(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]*/?\s*>', re.IGNORECASE)

# ── Regex: inline event handlers ────────────────────────────────────────────
_EVENT_HANDLER_ATTR = re.compile(
    r"\s+(?:" + "|".join(EVENT_HANDLERS) + r')\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE,
)

# ── Regex: dangerous URIs ───────────────────────────────────────────────────
_JAVASCRIPT_URI = re.compile(
    r'((?:href|src|action|data)\s*=\s*["\'])javascript:[^"\']*(["\'])',
    re.IGNORECASE,
)
_DATA_URI_HTML = re.compile(
    r'((?:href|src|action|data)\s*=\s*["\'])data\s*:\s*(?:text/html|application/x-javascript)[^"\']*(["\'])',
    re.IGNORECASE,
)

# ── Regex: external resource URLs (non-<a href>) ───────────────────────────
_HTML_EXTERNAL_RESOURCE = re.compile(
    r'(\s+(?:src|action|poster|data)\s*=\s*)["\']https?://[^"\']*["\']',
    re.IGNORECASE,
)

# ── Regex: CSS threats ──────────────────────────────────────────────────────
_CSS_EXPRESSION = re.compile(r"expression\s*\([^)]*\)", re.IGNORECASE)
_CSS_MOZ_BINDING = re.compile(r'-moz-binding\s*:[^;}"\']+[;]?', re.IGNORECASE)
_CSS_BEHAVIOR = re.compile(r'behavior\s*:[^;}"\']+[;]?', re.IGNORECASE)
_CSS_JS_URL = re.compile(r'url\s*\(\s*["\']?javascript:[^)]*\)', re.IGNORECASE)
_CSS_DATA_HTML_URL = re.compile(r'url\s*\(\s*["\']?data:text/html[^)]*\)', re.IGNORECASE)
_CSS_EXTERNAL_URL = re.compile(r'url\s*\(\s*["\']?https?://[^)]*\)', re.IGNORECASE)
_CSS_EXTERNAL_IMPORT = re.compile(r'@import\s+url\s*\(\s*["\']?https?://[^)]*\)\s*;?', re.IGNORECASE)


# ── Sanitizers ──────────────────────────────────────────────────────────────


def _wrap_comment(m: re.Match[str]) -> str:
    """Wrap matched content in an HTML comment."""
    return f"<!-- [CLEANED] {m.group(0)} -->"


def sanitize_content(text: str) -> tuple[str, list[str]]:
    """Sanitize HTML/XHTML/SVG content. Returns (cleaned_text, list of actions)."""
    actions: list[str] = []
    original = text

    # External scripts — delete
    text, n = _SCRIPT_EXTERNAL.subn("", text)
    if n:
        actions.append(f"{n} external script(s) removed")

    # Self-closing scripts — delete
    text, n = _SCRIPT_SELF_CLOSING.subn("", text)
    if n:
        actions.append(f"{n} self-closing script(s) removed")

    # Inline scripts — wrap with comment
    text, n = _SCRIPT_INLINE.subn(_wrap_comment, text)
    if n:
        actions.append(f"{n} inline script(s) commented")

    # Dangerous tags — delete
    for label, pattern in [
        ("iframe", _IFRAME_BLOCK),
        ("iframe", _IFRAME_SELF),
        ("applet", _APPLET_BLOCK),
        ("object", _OBJECT_BLOCK),
        ("embed", _EMBED_TAG),
        ("base", _BASE_TAG),
        ("meta refresh", _META_REFRESH),
    ]:
        text, n = pattern.subn("", text)
        if n:
            actions.append(f"{n} <{label}> removed")

    # Event handlers — remove attributes
    text, n = _EVENT_HANDLER_ATTR.subn("", text)
    if n:
        actions.append(f"{n} event handler(s) removed")

    # javascript: URIs → #
    text, n = _JAVASCRIPT_URI.subn(r"\1#\2", text)
    if n:
        actions.append(f"{n} javascript: URI(s) neutralized")

    # data:text/html URIs → #
    text, n = _DATA_URI_HTML.subn(r"\1#\2", text)
    if n:
        actions.append(f"{n} data: URI(s) neutralized")

    # External resource URLs (src, action, poster, data) — remove URL
    text, n = _HTML_EXTERNAL_RESOURCE.subn(r'\1""', text)
    if n:
        actions.append(f"{n} external resource URL(s) removed")

    # Sanitize CSS inside <style> blocks
    style_pattern = re.compile(r"(<style[^>]*>)(.*?)(</style\s*>)", re.IGNORECASE | re.DOTALL)

    def _clean_style(m: re.Match[str]) -> str:
        cleaned, css_actions = sanitize_css(m.group(2))
        actions.extend(css_actions)
        return m.group(1) + cleaned + m.group(3)

    text = style_pattern.sub(_clean_style, text)

    # Sanitize CSS inside style="" attributes
    style_attr_pattern = re.compile(r'(style\s*=\s*["\'])([^"\']*?)(["\'])', re.IGNORECASE)

    def _clean_style_attr(m: re.Match[str]) -> str:
        cleaned, css_actions = sanitize_css(m.group(2))
        actions.extend(css_actions)
        return m.group(1) + cleaned + m.group(3)

    text = style_attr_pattern.sub(_clean_style_attr, text)

    if text == original:
        actions.clear()

    return text, actions


def sanitize_css(css: str) -> tuple[str, list[str]]:
    """Sanitize CSS string. Returns (cleaned_css, list of actions)."""
    actions: list[str] = []

    for label, pattern, replacement in [
        ("expression()", _CSS_EXPRESSION, "/* removed */"),
        ("-moz-binding", _CSS_MOZ_BINDING, "/* removed */"),
        ("behavior", _CSS_BEHAVIOR, "/* removed */"),
        ("javascript URL", _CSS_JS_URL, "url('#')"),
        ("data:html URL", _CSS_DATA_HTML_URL, "url('#')"),
        ("external @import", _CSS_EXTERNAL_IMPORT, "/* removed */"),
        ("external URL", _CSS_EXTERNAL_URL, "url('#')"),
    ]:
        css, n = pattern.subn(replacement, css)
        if n:
            actions.append(f"{n} CSS {label} removed")

    return css, actions


# ── Core cleaner ────────────────────────────────────────────────────────────


def clean_epub(epub_path: str, output_dir: str) -> None:
    """Extract, clean, and repack a single EPUB."""
    p = Path(epub_path)
    clean_name = _TAG_RE.sub("", p.name)
    clean_name = re.sub(r"  +", " ", clean_name).strip()
    output_path = Path(output_dir) / clean_name

    tmpdir = tempfile.mkdtemp(prefix="epub_clean_")
    try:
        # ── Extract ─────────────────────────────────────────────────────
        with zipfile.ZipFile(epub_path, "r") as zf:
            for info in zf.infolist():
                # Skip path traversal
                if info.filename.startswith("/") or ".." in info.filename:
                    print(f"    skipped (path traversal): {info.filename}")
                    continue
                zf.extract(info, tmpdir)

        has_changes = False

        # ── Delete dangerous files ──────────────────────────────────────
        for root, _dirs, files in os.walk(tmpdir):
            for fname in files:
                ext = Path(fname).suffix.lower()
                fpath = Path(root) / fname
                rel = fpath.relative_to(tmpdir)

                if ext == ".js":
                    fpath.unlink()
                    print(f"    deleted: {rel}")
                    has_changes = True
                elif ext in DANGEROUS_EXTENSIONS:
                    fpath.unlink()
                    print(f"    deleted: {rel}")
                    has_changes = True
                elif ext in ARCHIVE_EXTENSIONS:
                    fpath.unlink()
                    print(f"    deleted: {rel}")
                    has_changes = True

        # ── Sanitize content files ──────────────────────────────────────
        for root, _dirs, files in os.walk(tmpdir):
            for fname in files:
                ext = Path(fname).suffix.lower()
                fpath = Path(root) / fname
                rel = fpath.relative_to(tmpdir)

                if ext in _CONTENT_EXTS:
                    try:
                        text = fpath.read_text(encoding="utf-8", errors="replace")
                        cleaned, actions = sanitize_content(text)
                        if actions:
                            fpath.write_text(cleaned, encoding="utf-8")
                            print(f"    cleaned: {rel} ({', '.join(actions)})")
                            has_changes = True
                    except Exception as e:
                        print(f"    ERROR reading {rel}: {e}")

                elif ext == _CSS_EXT:
                    try:
                        text = fpath.read_text(encoding="utf-8", errors="replace")
                        cleaned, actions = sanitize_css(text)
                        if actions:
                            fpath.write_text(cleaned, encoding="utf-8")
                            print(f"    cleaned: {rel} ({', '.join(actions)})")
                            has_changes = True
                    except Exception as e:
                        print(f"    ERROR reading {rel}: {e}")

        # ── Repack ──────────────────────────────────────────────────────
        if not has_changes:
            # No changes — just copy original
            shutil.copy2(epub_path, output_path)
            print("    no changes needed, copied as-is")
        else:
            _repack_epub(tmpdir, str(output_path))

        print(f"    → {output_path}")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _repack_epub(extracted_dir: str, output_path: str) -> None:
    """Repack an extracted directory into a valid EPUB file."""
    with zipfile.ZipFile(output_path, "w") as zf:
        # mimetype MUST be first and uncompressed
        mimetype_path = Path(extracted_dir) / "mimetype"
        if mimetype_path.exists():
            zf.write(str(mimetype_path), "mimetype", compress_type=zipfile.ZIP_STORED)

        # Add all other files with compression
        for root, _dirs, files in os.walk(extracted_dir):
            for fname in sorted(files):
                fpath = Path(root) / fname
                arcname = str(fpath.relative_to(extracted_dir))
                if arcname == "mimetype":
                    continue  # already added
                zf.write(str(fpath), arcname, compress_type=zipfile.ZIP_DEFLATED)


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="EPUB Cleaner - Deep clean malicious content from EPUB files",
    )
    parser.add_argument(
        "--path",
        required=True,
        help="EPUB file, directory, or glob pattern (e.g. '*.epub', '~/Desktop/')",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for cleaned EPUB files (required)",
    )
    parser.add_argument(
        "--notag",
        action="store_true",
        help="Don't strip [detect]/[fixed] tags from output filenames",
    )
    args = parser.parse_args()

    # Resolve output directory
    output_dir = os.path.expanduser(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # Resolve input files (escape [] for glob)
    expanded = os.path.expanduser(args.path)
    if os.path.isdir(expanded):
        expanded = os.path.join(expanded, "*.epub")
    glob_pattern = glob.escape(os.path.dirname(expanded)) + "/" + os.path.basename(expanded)
    # If user provided a glob pattern (with *), don't double-escape
    if "*" in expanded or "?" in expanded:
        glob_pattern = expanded.replace("[", "[[]")
    paths = sorted(p for p in glob.glob(glob_pattern) if p.lower().endswith(".epub"))

    if not paths:
        print(f"  No .epub files found matching: {expanded}")
        return 1

    print(f"\n  EPUB Cleaner — {len(paths)} file(s) to process")
    print(f"  Output: {output_dir}")
    print(f"{'=' * 70}")

    errors = 0
    for i, epub_path in enumerate(paths, 1):
        name = Path(epub_path).name
        print(f"\n  [{i}/{len(paths)}] Cleaning: {name}")
        try:
            clean_epub(epub_path, output_dir)
        except Exception as e:
            print(f"    FAILED: {e}")
            errors += 1

    print(f"\n{'=' * 70}")
    print(f"  Done. {len(paths) - errors} cleaned, {errors} failed.")
    print(f"  Output: {output_dir}")
    print(f"{'=' * 70}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
