#!/usr/bin/env python3
"""EPUB Safety Scanner - Detect malicious content in EPUB files."""

import argparse
import glob
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class Finding:
    severity: Severity
    category: str
    file_path: str
    description: str
    evidence: str = ""


@dataclass
class ScanResult:
    epub_path: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def is_clean(self) -> bool:
        return not self.findings and not self.error

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


# Maximum decompressed file size (100 MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# Maximum compression ratio to detect zip bombs
MAX_COMPRESSION_RATIO = 100

# EPUB standard allowed extensions
EPUB_ALLOWED_EXTENSIONS = {
    ".xhtml",
    ".html",
    ".htm",
    ".xml",
    ".opf",
    ".ncx",
    ".css",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".mp3",
    ".mp4",
    ".ogg",
    ".smil",
    ".pls",
    ".js",  # .js listed so we can flag it specifically
    ".json",
    ".txt",
}

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".scr",
    ".com",
    ".pif",
    ".msi",
    ".msp",
    ".sh",
    ".bash",
    ".csh",
    ".ksh",
    ".zsh",
    ".py",
    ".rb",
    ".pl",
    ".php",
    ".jar",
    ".class",
    ".war",
    ".app",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
}

# Nested archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".cab",
    ".iso",
    ".lz",
    ".lzma",
}

# File magic bytes for verification
MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": {".png"},
    b"\xff\xd8\xff": {".jpg", ".jpeg"},
    b"GIF87a": {".gif"},
    b"GIF89a": {".gif"},
    b"PK\x03\x04": {".zip", ".jar", ".epub"},
    b"MZ": {".exe", ".dll", ".scr"},
    b"\x7fELF": {".so", ".elf"},
    b"%PDF": {".pdf"},
    b"Rar!\x1a\x07": {".rar"},
}

# Inline event handler attributes
EVENT_HANDLERS = [
    "onabort",
    "onblur",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "onclose",
    "oncontextmenu",
    "oncuechange",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "ondurationchange",
    "onemptied",
    "onended",
    "onerror",
    "onfocus",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onmousedown",
    "onmouseenter",
    "onmouseleave",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onmousewheel",
    "onpause",
    "onplay",
    "onplaying",
    "onprogress",
    "onratechange",
    "onreset",
    "onresize",
    "onscroll",
    "onseeked",
    "onseeking",
    "onselect",
    "onshow",
    "onstalled",
    "onsubmit",
    "onsuspend",
    "ontimeupdate",
    "ontoggle",
    "onvolumechange",
    "onwaiting",
]

# Regex pattern for event handlers in attributes
EVENT_HANDLER_PATTERN = re.compile(
    r"\b(" + "|".join(EVENT_HANDLERS) + r")\s*=",
    re.IGNORECASE,
)

# JavaScript-related patterns
JS_PATTERNS = [
    (re.compile(r"<script[\s>]", re.IGNORECASE), "script tag detected"),
    (re.compile(r"</script>", re.IGNORECASE), "script closing tag detected"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: URI detected"),
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "eval() call detected"),
    (re.compile(r"\bFunction\s*\("), "Function() constructor detected"),
    (re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE), "setTimeout() detected"),
    (re.compile(r"\bsetInterval\s*\(", re.IGNORECASE), "setInterval() detected"),
    (re.compile(r"\bdocument\s*\.[a-zA-Z]"), "DOM manipulation detected"),
    (re.compile(r"\bwindow\s*\.[a-zA-Z]"), "window object access detected"),
    (re.compile(r"\bXMLHttpRequest\b", re.IGNORECASE), "XMLHttpRequest detected"),
    (re.compile(r"\bfetch\s*\(", re.IGNORECASE), "fetch() API detected"),
    (re.compile(r"\bWebSocket\b", re.IGNORECASE), "WebSocket detected"),
]

# Malicious HTML patterns
HTML_PATTERNS = [
    (re.compile(r"<iframe[\s>]", re.IGNORECASE), Severity.CRITICAL, "iframe tag detected"),
    (re.compile(r"<object[\s>]", re.IGNORECASE), Severity.WARNING, "object tag detected"),
    (re.compile(r"<embed[\s>]", re.IGNORECASE), Severity.WARNING, "embed tag detected"),
    (re.compile(r"<form[\s>]", re.IGNORECASE), Severity.WARNING, "form tag detected"),
    (re.compile(r"<applet[\s>]", re.IGNORECASE), Severity.CRITICAL, "applet tag detected"),
    (
        re.compile(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh', re.IGNORECASE),
        Severity.WARNING,
        "meta refresh redirect detected",
    ),
    (re.compile(r"<base[\s>]", re.IGNORECASE), Severity.WARNING, "base tag detected (can hijack relative URLs)"),
    (re.compile(r'<link[^>]+rel\s*=\s*["\']?prefetch', re.IGNORECASE), Severity.WARNING, "prefetch link detected"),
    (re.compile(r'<link[^>]+rel\s*=\s*["\']?preconnect', re.IGNORECASE), Severity.INFO, "preconnect link detected"),
    (re.compile(r"data\s*:\s*text/html", re.IGNORECASE), Severity.CRITICAL, "data: URI with HTML content detected"),
    (
        re.compile(r"data\s*:\s*application/x-javascript", re.IGNORECASE),
        Severity.CRITICAL,
        "data: URI with JavaScript detected",
    ),
]

# Malicious CSS patterns
CSS_PATTERNS = [
    (
        re.compile(r"expression\s*\(", re.IGNORECASE),
        Severity.CRITICAL,
        "CSS expression() detected (IE script execution)",
    ),
    (
        re.compile(r"-moz-binding\s*:", re.IGNORECASE),
        Severity.CRITICAL,
        "-moz-binding detected (Firefox XBL injection)",
    ),
    (re.compile(r"behavior\s*:", re.IGNORECASE), Severity.WARNING, "CSS behavior property detected (IE HTC)"),
    (
        re.compile(r'@import\s+url\s*\(\s*["\']?https?://', re.IGNORECASE),
        Severity.WARNING,
        "external @import URL detected (tracking/exfiltration)",
    ),
    (
        re.compile(r'url\s*\(\s*["\']?https?://', re.IGNORECASE),
        Severity.WARNING,
        "external url() reference detected (tracking/exfiltration)",
    ),
    (
        re.compile(r'url\s*\(\s*["\']?javascript:', re.IGNORECASE),
        Severity.CRITICAL,
        "javascript: in CSS url() detected",
    ),
    (
        re.compile(r'url\s*\(\s*["\']?data:text/html', re.IGNORECASE),
        Severity.CRITICAL,
        "data:text/html in CSS url() detected",
    ),
]

# XHTML namespace
XHTML_NS = "http://www.w3.org/1999/xhtml"


class EPUBScanner:
    """Scans EPUB files for security threats."""

    def scan(self, path_pattern: str, progress: bool = False) -> list[ScanResult]:
        """Scan EPUB file(s) matching the given path or glob pattern."""
        expanded = os.path.expanduser(path_pattern)
        # If a directory is given, automatically scan *.epub inside it
        if os.path.isdir(expanded):
            expanded = os.path.join(expanded, "*.epub")
        paths = glob.glob(expanded)
        if not paths:
            return [ScanResult(epub_path=expanded, error=f"No files found matching: {expanded}")]

        epub_paths = sorted(p for p in paths if p.lower().endswith(".epub"))
        if not epub_paths:
            return [ScanResult(epub_path=expanded, error="No .epub files found in matched paths")]

        total = len(epub_paths)
        results = []
        for i, p in enumerate(epub_paths, 1):
            if progress:
                name = Path(p).name
                print(f"  [{i}/{total}] Scanning: {name}", file=sys.stderr, flush=True)
            results.append(self._scan_single(p))
        return results

    def _scan_single(self, epub_path: str) -> ScanResult:
        """Scan a single EPUB file."""
        result = ScanResult(epub_path=epub_path)

        if not Path(epub_path).exists():
            result.error = f"File not found: {epub_path}"
            return result

        try:
            with zipfile.ZipFile(epub_path, "r") as zf:
                self._check_zip_integrity(zf, result)
                if result.error:
                    return result
                self._check_path_traversal(zf, result)
                self._check_suspicious_files(zf, result)
                self._check_content_files(zf, result)
        except zipfile.BadZipFile:
            result.error = "Invalid ZIP/EPUB file (corrupted or not a real EPUB)"
        except Exception as e:
            result.error = f"Error scanning file: {e}"

        return result

    def _check_zip_integrity(self, zf: zipfile.ZipFile, result: ScanResult) -> None:
        """Check ZIP structure integrity."""
        bad = zf.testzip()
        if bad is not None:
            result.findings.append(
                Finding(
                    severity=Severity.WARNING,
                    category="ZIP Integrity",
                    file_path=bad,
                    description="Corrupted file detected in ZIP archive",
                )
            )

    def _check_path_traversal(self, zf: zipfile.ZipFile, result: ScanResult) -> None:
        """Check for path traversal attacks in ZIP entries."""
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or ".." in name:
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="Path Traversal",
                        file_path=name,
                        description="Path traversal detected in ZIP entry",
                        evidence=name,
                    )
                )

    def _check_suspicious_files(self, zf: zipfile.ZipFile, result: ScanResult) -> None:
        """Check for suspicious or dangerous files."""
        for info in zf.infolist():
            if info.filename.endswith("/"):
                continue  # skip directories

            ext = Path(info.filename).suffix.lower()

            # Check for JavaScript files
            if ext == ".js":
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="JavaScript",
                        file_path=info.filename,
                        description="JavaScript file found in EPUB",
                    )
                )

            # Check for dangerous executables
            if ext in DANGEROUS_EXTENSIONS:
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="Dangerous File",
                        file_path=info.filename,
                        description=f"Dangerous file type ({ext}) found in EPUB",
                    )
                )

            # Check for nested archives
            if ext in ARCHIVE_EXTENSIONS:
                result.findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        category="Nested Archive",
                        file_path=info.filename,
                        description=f"Nested archive ({ext}) found in EPUB",
                    )
                )

            # Check for zip bomb (decompressed size)
            if info.file_size > MAX_FILE_SIZE:
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="Zip Bomb",
                        file_path=info.filename,
                        description=f"File decompresses to {info.file_size:,} bytes (>{MAX_FILE_SIZE:,})",
                    )
                )

            # Check compression ratio
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    result.findings.append(
                        Finding(
                            severity=Severity.WARNING,
                            category="Zip Bomb",
                            file_path=info.filename,
                            description=f"Suspicious compression ratio: {ratio:.0f}:1",
                        )
                    )

            # Check file magic bytes vs extension
            self._check_file_magic(zf, info, result)

    def _check_file_magic(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: ScanResult) -> None:
        """Verify file content matches its extension using magic bytes."""
        if info.file_size == 0 or info.file_size > MAX_FILE_SIZE:
            return

        ext = Path(info.filename).suffix.lower()
        if not ext:
            return

        try:
            with zf.open(info.filename) as f:
                header = f.read(16)
        except Exception:
            return

        for magic, expected_exts in MAGIC_BYTES.items():
            if header.startswith(magic):
                # File matches this magic signature
                if ext not in expected_exts and ext not in EPUB_ALLOWED_EXTENSIONS:
                    result.findings.append(
                        Finding(
                            severity=Severity.WARNING,
                            category="File Mismatch",
                            file_path=info.filename,
                            description=f"Extension {ext} but content matches {expected_exts}",
                        )
                    )
                # Detect executables disguised as other files
                if magic == b"MZ" and ext not in {".exe", ".dll", ".scr"}:
                    result.findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Disguised Executable",
                            file_path=info.filename,
                            description=f"File has {ext} extension but is a Windows executable (MZ header)",
                        )
                    )
                break

    def _check_content_files(self, zf: zipfile.ZipFile, result: ScanResult) -> None:
        """Scan XHTML, HTML, CSS, SVG files for malicious content."""
        for info in zf.infolist():
            if info.filename.endswith("/"):
                continue
            if info.file_size > MAX_FILE_SIZE:
                continue

            ext = Path(info.filename).suffix.lower()

            if ext in {".xhtml", ".html", ".htm", ".xml", ".svg", ".opf"}:
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                except Exception:  # noqa: S112  # nosec B112
                    continue
                self._check_javascript_in_content(content, info.filename, result)
                self._check_html_patterns(content, info.filename, result)
                self._check_css_in_html(content, info.filename, result)
                self._check_event_handlers(content, info.filename, result)
                self._check_external_links(content, info.filename, result)

            elif ext == ".css":
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                except Exception:  # noqa: S112  # nosec B112
                    continue
                self._check_css_patterns(content, info.filename, result)

    def _check_javascript_in_content(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for JavaScript in content files."""
        for pattern, description in JS_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                # Extract a short evidence snippet
                match = pattern.search(content)
                assert match is not None
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 40)
                evidence = content[start:end].strip()
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="JavaScript",
                        file_path=file_path,
                        description=description,
                        evidence=evidence,
                    )
                )

    def _check_event_handlers(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for inline event handler attributes."""
        for match in EVENT_HANDLER_PATTERN.finditer(content):
            start = max(0, match.start() - 10)
            end = min(len(content), match.end() + 30)
            evidence = content[start:end].strip()
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="JavaScript",
                    file_path=file_path,
                    description=f"Inline event handler '{match.group(1)}' detected",
                    evidence=evidence,
                )
            )

    def _check_html_patterns(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for malicious HTML patterns."""
        for pattern, severity, description in HTML_PATTERNS:
            match = pattern.search(content)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(content), match.end() + 40)
                evidence = content[start:end].strip()
                result.findings.append(
                    Finding(
                        severity=severity,
                        category="Malicious HTML",
                        file_path=file_path,
                        description=description,
                        evidence=evidence,
                    )
                )

    def _check_css_in_html(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for malicious CSS within HTML style tags and attributes."""
        # Extract <style> blocks
        style_pattern = re.compile(r"<style[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
        for style_match in style_pattern.finditer(content):
            css_content = style_match.group(1)
            self._check_css_patterns(css_content, file_path, result)

        # Extract style="" attributes
        style_attr_pattern = re.compile(r'style\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
        for attr_match in style_attr_pattern.finditer(content):
            css_content = attr_match.group(1)
            self._check_css_patterns(css_content, file_path, result)

    def _check_css_patterns(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for malicious CSS patterns."""
        for pattern, severity, description in CSS_PATTERNS:
            match = pattern.search(content)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(content), match.end() + 40)
                evidence = content[start:end].strip()
                result.findings.append(
                    Finding(
                        severity=severity,
                        category="Malicious CSS",
                        file_path=file_path,
                        description=description,
                        evidence=evidence,
                    )
                )

    def _check_external_links(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for suspicious external resource references."""
        # External resource loading (not regular hyperlinks)
        ext_resource = re.compile(
            r'(?:src|href|action|poster|data)\s*=\s*["\']?(https?://[^\s"\'>\)]+)',
            re.IGNORECASE,
        )
        for match in ext_resource.finditer(content):
            url = match.group(1)
            attr_match = re.match(r"(src|href|action|poster|data)", match.group(0), re.IGNORECASE)
            attr_name = attr_match.group(1).lower() if attr_match else "unknown"
            # src, action, poster, data are more suspicious than href
            if attr_name in {"src", "action", "poster", "data"}:
                result.findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        category="External Resource",
                        file_path=file_path,
                        description=f'External resource loaded via {attr_name}="{url[:80]}"',
                        evidence=match.group(0)[:100],
                    )
                )
            elif attr_name == "href":
                # href to external sites is less suspicious but worth noting
                result.findings.append(
                    Finding(
                        severity=Severity.INFO,
                        category="External Link",
                        file_path=file_path,
                        description=f"External link: {url[:80]}",
                        evidence=match.group(0)[:100],
                    )
                )


# ── Fixer ────────────────────────────────────────────────────────────────────

# Regex patterns for sanitizing content
_SCRIPT_BLOCK = re.compile(r"<script[\s>].*?</script\s*>", re.IGNORECASE | re.DOTALL)
_EVENT_HANDLER_ATTR = re.compile(
    r"\s+(?:" + "|".join(EVENT_HANDLERS) + r')\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE,
)
_JAVASCRIPT_URI = re.compile(
    r'((?:href|src|action|data)\s*=\s*["\'])javascript:[^"\']*(["\'])',
    re.IGNORECASE,
)
_IFRAME_BLOCK = re.compile(r"<iframe[\s>].*?</iframe\s*>", re.IGNORECASE | re.DOTALL)
_IFRAME_SELF = re.compile(r"<iframe\b[^>]*/\s*>", re.IGNORECASE)
_APPLET_BLOCK = re.compile(r"<applet[\s>].*?</applet\s*>", re.IGNORECASE | re.DOTALL)
_OBJECT_BLOCK = re.compile(r"<object[\s>].*?</object\s*>", re.IGNORECASE | re.DOTALL)
_EMBED_TAG = re.compile(r"<embed\b[^>]*/?\s*>", re.IGNORECASE)
_BASE_TAG = re.compile(r"<base\b[^>]*/?\s*>", re.IGNORECASE)
_META_REFRESH = re.compile(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]*/?\s*>', re.IGNORECASE)
_DATA_URI_HTML = re.compile(
    r'((?:href|src|action|data)\s*=\s*["\'])data\s*:\s*(?:text/html|application/x-javascript)[^"\']*(["\'])',
    re.IGNORECASE,
)

# CSS sanitization patterns
_CSS_EXPRESSION = re.compile(r"expression\s*\([^)]*\)", re.IGNORECASE)
_CSS_MOZ_BINDING = re.compile(r'-moz-binding\s*:[^;}"\']+[;]?', re.IGNORECASE)
_CSS_BEHAVIOR = re.compile(r'behavior\s*:[^;}"\']+[;]?', re.IGNORECASE)
_CSS_JS_URL = re.compile(r'url\s*\(\s*["\']?javascript:[^)]*\)', re.IGNORECASE)
_CSS_DATA_HTML_URL = re.compile(r'url\s*\(\s*["\']?data:text/html[^)]*\)', re.IGNORECASE)
_CSS_EXTERNAL_URL = re.compile(r'url\s*\(\s*["\']?https?://[^)]*\)', re.IGNORECASE)
_CSS_EXTERNAL_IMPORT = re.compile(r'@import\s+url\s*\(\s*["\']?https?://[^)]*\)\s*;?', re.IGNORECASE)

# HTML external resource attributes (src, action, poster, data with http URLs)
_HTML_EXTERNAL_RESOURCE = re.compile(
    r'(\s+(?:src|action|poster|data)\s*=\s*)["\']https?://[^"\']*["\']',
    re.IGNORECASE,
)
# HTML href with external URL — neutralize to #
_HTML_EXTERNAL_HREF = re.compile(
    r'(href\s*=\s*)["\']https?://[^"\']*["\']',
    re.IGNORECASE,
)


@dataclass
class FixResult:
    original_path: str
    fixed_path: str = ""
    removed_files: list[str] = field(default_factory=list)
    sanitized_files: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.removed_files or self.sanitized_files)


class EPUBFixer:
    """Removes malicious content from EPUB files and repacks them."""

    _TAG_RE = re.compile(r"\[(?:fixed|detect)\]\s*", re.IGNORECASE)

    def fix(self, epub_path: str) -> FixResult:
        """Fix a single EPUB by removing threats. Returns FixResult."""
        p = Path(epub_path)
        clean_name = self._TAG_RE.sub("", p.name)
        fixed_name = f"[fixed] {clean_name}"
        fixed_path = str(p.parent / fixed_name)
        result = FixResult(original_path=epub_path, fixed_path=fixed_path)

        try:
            with zipfile.ZipFile(epub_path, "r") as zf_in:
                with zipfile.ZipFile(fixed_path, "w", zipfile.ZIP_DEFLATED) as zf_out:
                    for info in zf_in.infolist():
                        if info.filename.endswith("/"):
                            zf_out.writestr(info, b"")
                            continue

                        action = self._decide_action(info)

                        if action == "remove":
                            result.removed_files.append(info.filename)
                            continue

                        data = zf_in.read(info.filename)

                        if action == "sanitize":
                            ext = Path(info.filename).suffix.lower()
                            original = data
                            if ext == ".css":
                                data = self._sanitize_css(data)
                            else:
                                data = self._sanitize_content(data)
                            if data != original:
                                result.sanitized_files.append(info.filename)

                        # Preserve the original ZipInfo (compression, timestamps)
                        zf_out.writestr(info, data)

        except zipfile.BadZipFile:
            result.error = "Invalid ZIP/EPUB file"
        except Exception as e:
            result.error = f"Error fixing file: {e}"

        if result.error and Path(fixed_path).exists():
            Path(fixed_path).unlink()
            result.fixed_path = ""
        elif not result.has_changes:
            # No changes needed — remove the copy
            Path(fixed_path).unlink()
            result.fixed_path = ""

        return result

    def _decide_action(self, info: zipfile.ZipInfo) -> str:
        """Decide what to do with a ZIP entry: 'keep', 'remove', or 'sanitize'."""
        name = info.filename

        # Remove path traversal entries
        if name.startswith("/") or ".." in name:
            return "remove"

        ext = Path(name).suffix.lower()

        # Remove dangerous files entirely
        if ext == ".js":
            return "remove"
        if ext in DANGEROUS_EXTENSIONS:
            return "remove"
        if ext in ARCHIVE_EXTENSIONS:
            return "remove"

        # Sanitize content files
        if ext in {".xhtml", ".html", ".htm", ".xml", ".svg", ".opf"}:
            return "sanitize"
        if ext == ".css":
            return "sanitize"

        return "keep"

    def _sanitize_content(self, data: bytes) -> bytes:
        """Sanitize HTML/XHTML/SVG content by removing malicious patterns."""
        content = data.decode("utf-8", errors="replace")

        # Remove <script>...</script> blocks
        content = _SCRIPT_BLOCK.sub("", content)
        # Remove <iframe>...</iframe> and self-closing <iframe/>
        content = _IFRAME_BLOCK.sub("", content)
        content = _IFRAME_SELF.sub("", content)
        # Remove <applet>...</applet>
        content = _APPLET_BLOCK.sub("", content)
        # Remove <object>...</object>
        content = _OBJECT_BLOCK.sub("", content)
        # Remove <embed/>
        content = _EMBED_TAG.sub("", content)
        # Remove <base/>
        content = _BASE_TAG.sub("", content)
        # Remove <meta http-equiv="refresh">
        content = _META_REFRESH.sub("", content)
        # Remove inline event handlers (onclick="...", onerror="...", etc.)
        content = _EVENT_HANDLER_ATTR.sub("", content)
        # Neutralize javascript: URIs → #
        content = _JAVASCRIPT_URI.sub(r"\1#\2", content)
        # Neutralize data:text/html URIs → #
        content = _DATA_URI_HTML.sub(r"\1#\2", content)
        # Remove external resource URLs (src, action, poster, data) → ""
        # Note: <a href="https://..."> is kept — normal for ebooks
        content = _HTML_EXTERNAL_RESOURCE.sub(r'\1""', content)

        # Sanitize CSS inside <style> blocks
        style_pattern = re.compile(r"(<style[^>]*>)(.*?)(</style\s*>)", re.IGNORECASE | re.DOTALL)

        def _clean_style(m: re.Match[str]) -> str:
            return str(m.group(1)) + self._sanitize_css_str(str(m.group(2))) + str(m.group(3))

        content = style_pattern.sub(_clean_style, content)

        # Sanitize CSS inside style="" attributes
        style_attr_pattern = re.compile(r'(style\s*=\s*["\'])([^"\']*?)(["\'])', re.IGNORECASE)

        def _clean_style_attr(m: re.Match[str]) -> str:
            return str(m.group(1)) + self._sanitize_css_str(str(m.group(2))) + str(m.group(3))

        content = style_attr_pattern.sub(_clean_style_attr, content)

        return content.encode("utf-8")

    def _sanitize_css(self, data: bytes) -> bytes:
        """Sanitize a CSS file."""
        content = data.decode("utf-8", errors="replace")
        content = self._sanitize_css_str(content)
        return content.encode("utf-8")

    def _sanitize_css_str(self, css: str) -> str:
        """Sanitize CSS string content."""
        css = _CSS_EXPRESSION.sub("/* removed */", css)
        css = _CSS_MOZ_BINDING.sub("/* removed */", css)
        css = _CSS_BEHAVIOR.sub("/* removed */", css)
        css = _CSS_JS_URL.sub("url('#')", css)
        css = _CSS_DATA_HTML_URL.sub("url('#')", css)
        css = _CSS_EXTERNAL_IMPORT.sub("/* removed */", css)
        css = _CSS_EXTERNAL_URL.sub("url('#')", css)
        return css


# ── CLI ──────────────────────────────────────────────────────────────────────

COLORS = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.WARNING: "\033[93m",  # yellow
    Severity.INFO: "\033[96m",  # cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"

_URL_IN_TEXT = re.compile(r'https?://[^\s"\'>\)]+')


def _colorize_urls(text: str, category: str, use_color: bool) -> str:
    """Highlight URLs: green for External Link (href), red for everything else."""
    if not use_color:
        return text
    color = GREEN if category == "External Link" else RED
    return _URL_IN_TEXT.sub(lambda m: f"{color}{m.group()}{RESET}", text)


def format_findings(result: ScanResult, use_color: bool = True, verbose: bool = False) -> str:
    """Format scan results for terminal output."""
    lines: list[str] = []

    def c(severity: Severity, text: str) -> str:
        if use_color:
            return f"{COLORS[severity]}{text}{RESET}"
        return text

    def bold(text: str) -> str:
        if use_color:
            return f"{BOLD}{text}{RESET}"
        return text

    lines.append(bold(f"\n{'=' * 70}"))
    lines.append(bold(f"  EPUB: {result.epub_path}"))
    lines.append(bold(f"{'=' * 70}"))

    if result.error:
        lines.append(c(Severity.CRITICAL, f"  ERROR: {result.error}"))
        return "\n".join(lines)

    # Treat as clean if no findings, or all findings are INFO and not verbose
    visible_findings = result.findings if verbose else [f for f in result.findings if f.severity != Severity.INFO]
    if result.is_clean or not visible_findings:
        lines.append(c(Severity.INFO, "  CLEAN - No threats detected"))
        return "\n".join(lines)

    # Group by category
    categories: dict[str, list[Finding]] = {}
    for f in visible_findings:
        categories.setdefault(f.category, []).append(f)

    for category, findings in sorted(categories.items()):
        lines.append(f"\n  [{category}]")
        for f in findings:
            severity_str = c(f.severity, f"[{f.severity.value}]")
            desc = _colorize_urls(f.description, f.category, use_color)
            lines.append(f"    {severity_str} {desc}")
            lines.append(f"      File: {f.file_path}")
            if f.evidence:
                # Truncate and sanitize evidence for display
                evidence = f.evidence.replace("\n", " ").replace("\r", "")
                if len(evidence) > 120:
                    evidence = evidence[:120] + "..."
                evidence = _colorize_urls(evidence, f.category, use_color)
                lines.append(f"      Evidence: {evidence}")

    lines.append(f"\n  {bold('Summary:')}")
    lines.append(f"    {c(Severity.CRITICAL, f'CRITICAL: {result.critical_count}')}")
    lines.append(f"    {c(Severity.WARNING, f'WARNING:  {result.warning_count}')}")
    if verbose:
        lines.append(f"    {c(Severity.INFO, f'INFO:     {result.info_count}')}")

    return "\n".join(lines)


SEVERITY_EMOJI = {
    Severity.CRITICAL: "\u274c",  # ❌
    Severity.WARNING: "\u26a0\ufe0f",  # ⚠️
    Severity.INFO: "\u2139\ufe0f",  # ℹ️
}


def format_report_md(results: list[ScanResult], verbose: bool = False) -> str:
    """Generate a Markdown report for scan results."""
    lines: list[str] = []
    total_critical = sum(r.critical_count for r in results)
    total_warning = sum(r.warning_count for r in results)
    total_info = sum(r.info_count for r in results)
    total_errors = sum(1 for r in results if r.error)
    if verbose:
        total_clean = sum(1 for r in results if r.is_clean)
    else:
        total_clean = sum(
            1 for r in results if r.is_clean or (r.critical_count == 0 and r.warning_count == 0 and not r.error)
        )

    lines.append("# EPUB Safety Scanner Report")
    lines.append("")
    lines.append(f"- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- **Files scanned**: {len(results)}")
    lines.append(f"- **Clean**: {total_clean}")
    if total_errors:
        lines.append(f"- **Errors**: {total_errors}")
    findings_parts = [f"{total_critical} critical", f"{total_warning} warning"]
    if verbose:
        findings_parts.append(f"{total_info} info")
    lines.append(f"- **Findings**: {', '.join(findings_parts)}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | File |")
    lines.append("|--------|------|")
    for r in results:
        name = Path(r.epub_path).name
        is_effectively_clean = r.is_clean or (
            not verbose and r.critical_count == 0 and r.warning_count == 0 and not r.error
        )
        if r.error:
            lines.append(f"| {SEVERITY_EMOJI[Severity.CRITICAL]} ERROR | `{name}` |")
        elif is_effectively_clean:
            lines.append(f"| {SEVERITY_EMOJI[Severity.INFO]} CLEAN | `{name}` |")
        else:
            parts = []
            if r.critical_count:
                parts.append(f"{r.critical_count} critical")
            if r.warning_count:
                parts.append(f"{r.warning_count} warning")
            if verbose and r.info_count:
                parts.append(f"{r.info_count} info")
            emoji = SEVERITY_EMOJI[Severity.CRITICAL] if r.critical_count else SEVERITY_EMOJI[Severity.WARNING]
            lines.append(f"| {emoji} {', '.join(parts)} | `{name}` |")
    lines.append("")

    # Per-file details
    for r in results:
        name = Path(r.epub_path).name
        lines.append(f"## `{name}`")
        lines.append("")

        if r.error:
            lines.append(f"> **ERROR**: {r.error}")
            lines.append("")
            continue

        is_effectively_clean = r.is_clean or (not verbose and r.critical_count == 0 and r.warning_count == 0)
        if is_effectively_clean:
            lines.append("No threats detected.")
            lines.append("")
            continue

        # Group by category
        categories: dict[str, list[Finding]] = {}
        for f in r.findings:
            if not verbose and f.severity == Severity.INFO:
                continue
            categories.setdefault(f.category, []).append(f)

        for category, findings in sorted(categories.items()):
            lines.append(f"### {category}")
            lines.append("")
            for f in findings:
                emoji = SEVERITY_EMOJI[f.severity]
                lines.append(f"- {emoji} **[{f.severity.value}]** `{f.file_path}`: {f.description}")
                if f.evidence:
                    evidence = f.evidence.replace("\n", " ").replace("\r", "")
                    if len(evidence) > 120:
                        evidence = evidence[:120] + "..."
                    lines.append(f"  - Evidence: `{evidence}`")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by EPUB Safety Scanner*")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="EPUB Safety Scanner - Detect malicious content in EPUB files",
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to EPUB file, directory, or glob pattern (e.g. '*.epub', '~/Desktop/', 'books/*.epub')",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--report",
        metavar="FILE",
        help="Write a Markdown report to FILE (e.g. report.md)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show INFO-level findings (hidden by default)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Remove threats and save as '[fixed] filename.epub'",
    )
    parser.add_argument(
        "--notag",
        action="store_true",
        help="Skip auto-tagging (by default, detected files are tagged with '[detect]' prefix)",
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    _tag_re = re.compile(r"\[(?:fixed|detect)\]\s*", re.IGNORECASE)

    # ── Pre-scan: strip all [fixed]/[detect] tags ───────────────────────
    if not args.notag:
        expanded = os.path.expanduser(args.path)
        if os.path.isdir(expanded):
            pre_glob = os.path.join(expanded, "*.epub")
        else:
            pre_glob = expanded
        for p in sorted(glob.glob(pre_glob)):
            if not p.lower().endswith(".epub"):
                continue
            pp = Path(p)
            clean = _tag_re.sub("", pp.name)
            clean = re.sub(r"  +", " ", clean).strip()
            if clean != pp.name:
                target = pp.parent / clean
                if target.exists():
                    print(f"  SKIP    {pp.name}: target '{clean}' already exists", file=sys.stderr)
                else:
                    try:
                        pp.rename(target)
                    except OSError as e:
                        print(f"  SKIP    {pp.name}: {e}", file=sys.stderr)

    # ── Scan ────────────────────────────────────────────────────────────
    scanner = EPUBScanner()
    results = scanner.scan(args.path, progress=True)

    total_critical = 0
    total_warning = 0

    for result in results:
        print(format_findings(result, use_color=use_color, verbose=args.verbose))
        total_critical += result.critical_count
        total_warning += result.warning_count

    if len(results) > 1:
        _c = (lambda sev, t: f"{COLORS[sev]}{t}{RESET}") if use_color else (lambda sev, t: t)
        _b = (lambda t: f"{BOLD}{t}{RESET}") if use_color else (lambda t: t)
        print(f"\n{'=' * 70}")
        print(_b(f"  TOTAL: Scanned {len(results)} files — {total_critical} critical, {total_warning} warnings"))
        print(f"{'=' * 70}")
        for r in results:
            _effectively_clean = r.is_clean or (
                not args.verbose and r.critical_count == 0 and r.warning_count == 0 and not r.error
            )
            if r.error:
                print(f"  {_c(Severity.CRITICAL, 'ERROR')}  {r.epub_path}")
                print(f"         {r.error}")
            elif _effectively_clean:
                print(f"  {_c(Severity.INFO, 'CLEAN')}  {r.epub_path}")
            else:
                status_parts = []
                if r.critical_count:
                    status_parts.append(_c(Severity.CRITICAL, f"{r.critical_count} critical"))
                if r.warning_count:
                    status_parts.append(_c(Severity.WARNING, f"{r.warning_count} warning"))
                if args.verbose and r.info_count:
                    status_parts.append(_c(Severity.INFO, f"{r.info_count} info"))
                print(f"  {', '.join(status_parts)}  {r.epub_path}")
                for f in r.findings:
                    if not args.verbose and f.severity == Severity.INFO:
                        continue
                    sev_str = _c(f.severity, f"[{f.severity.value}]")
                    desc = _colorize_urls(f.description, f.category, use_color)
                    print(f"    {sev_str} {f.file_path}: {desc}")
        print(f"{'=' * 70}")

    if args.report:
        report_path = os.path.expanduser(args.report)
        md = format_report_md(results, verbose=args.verbose)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"\n  Report saved to: {report_path}")

    # ── Fix: replace original in-place ──────────────────────────────────
    fixed_set: set[str] = set()
    if args.fix:
        fixer = EPUBFixer()
        fix_targets = [r for r in results if not r.error and not r.is_clean]
        if fix_targets:
            print(f"\n{'=' * 70}")
            print("  Fixing EPUBs...")
            print(f"{'=' * 70}")
        for fi, result in enumerate(fix_targets, 1):
            name = Path(result.epub_path).name
            try:
                print(f"  [{fi}/{len(fix_targets)}] Fixing: {name}", file=sys.stderr, flush=True)
                fix_result = fixer.fix(result.epub_path)
                if fix_result.error:
                    print(f"  FAILED  {name}: {fix_result.error}")
                elif not fix_result.has_changes:
                    print(f"  SKIP    {name}: no changes needed")
                else:
                    # Replace original with fixed version
                    os.replace(fix_result.fixed_path, result.epub_path)
                    fixed_set.add(result.epub_path)
                    print(f"  FIXED   {name}")
                    if fix_result.removed_files:
                        for rf in fix_result.removed_files:
                            print(f"            removed: {rf}")
                    if fix_result.sanitized_files:
                        for sf in fix_result.sanitized_files:
                            print(f"            sanitized: {sf}")
            except Exception as e:
                print(f"  FAILED  {name}: {e}")

    # ── Post-scan: tag files ────────────────────────────────────────────
    if not args.notag:
        printed_header = False
        for result in results:
            if result.error:
                continue
            has_threats = result.critical_count > 0 or result.warning_count > 0
            if not has_threats:
                continue
            ep = Path(result.epub_path)
            if not ep.exists():
                continue
            tag = "[fixed] " if result.epub_path in fixed_set else "[detect] "
            clean_name = _tag_re.sub("", ep.name)
            clean_name = re.sub(r"  +", " ", clean_name).strip()
            new_name = f"{tag}{clean_name}"
            target = ep.parent / new_name
            if not printed_header:
                print(f"\n{'=' * 70}")
                print("  Tagging EPUBs...")
                print(f"{'=' * 70}")
                printed_header = True
            if target.exists():
                print(f"  SKIP    {ep.name}: target '{new_name}' already exists")
                continue
            try:
                ep.rename(target)
                print(f"  TAGGED  {ep.name} -> {new_name}")
            except OSError as e:
                print(f"  FAILED  {ep.name}: {e}")

    return 1 if total_critical > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
