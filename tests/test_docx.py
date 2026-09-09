from __future__ import annotations

import zipfile
from pathlib import Path

from dpps.core import ReviewRequired, inspect, sanitize

CONTENT_TYPES = b'''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
</Types>'''
DOCUMENT = b'''<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>'''
CORE = b'''<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Private Person</dc:creator><cp:lastModifiedBy>Editor</cp:lastModifiedBy><cp:revision>9</cp:revision></cp:coreProperties>'''
APP = b'''<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Word Processor</Application><Company>Private Company</Company></Properties>'''
CUSTOM = b'''<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Client"><value>Secret Client</value></property></Properties>'''


def make_docx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("word/document.xml", DOCUMENT)
        archive.writestr("docProps/core.xml", CORE)
        archive.writestr("docProps/app.xml", APP)


def test_docx_sanitization_clears_identity_metadata(tmp_path: Path) -> None:
    source, output = tmp_path / "source.docx", tmp_path / "clean.docx"
    make_docx(source)
    sanitize(source, output)
    before, after = inspect(source), inspect(output)
    assert before.metadata["creator"] == "Private Person"
    assert after.metadata["creator"] == ""
    assert after.metadata["lastModifiedBy"] == ""
    assert after.metadata["Application"] == ""
    assert after.metadata["Company"] == ""
    with zipfile.ZipFile(output) as archive:
        assert archive.read("word/document.xml") == DOCUMENT


def test_docx_sanitization_removes_custom_properties(tmp_path: Path) -> None:
    source, output = tmp_path / "source.docx", tmp_path / "clean.docx"
    make_docx(source)
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr("docProps/custom.xml", CUSTOM)
    assert inspect(source).metadata["custom:value"] == "Secret Client"
    sanitize(source, output)
    with zipfile.ZipFile(output) as archive:
        assert "docProps/custom.xml" not in archive.namelist()


def test_docx_reports_review_and_external_link_signals(tmp_path: Path) -> None:
    source = tmp_path / "signals.docx"
    document = DOCUMENT.replace(
        b"<w:body/>",
        b'<w:body><w:ins/><w:r><w:rPr><w:vanish/></w:rPr></w:r></w:body>',
    )
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/comments.xml", b"<comments/>")
        archive.writestr(
            "word/_rels/document.xml.rels",
            b'<Relationships><Relationship TargetMode="External" Target="https://example.com"/></Relationships>',
        )
    finding = inspect(source)
    assert finding.has_comments is True
    assert finding.has_tracked_changes is True
    assert finding.has_hidden_text is True
    assert finding.has_external_links is True
    assert finding.requires_review is True
    try:
        sanitize(source, tmp_path / "unsafe-clean.docx")
    except ReviewRequired as exc:
        assert "comments" in str(exc)
    else:
        raise AssertionError("review content was sanitized automatically")


def test_docx_suspicious_compression_ratio_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bomb.docx"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("word/document.xml", b"0" * (2 * 1024 * 1024))
    try:
        inspect(source)
    except ReviewRequired as exc:
        assert "compression ratio" in str(exc)
    else:
        raise AssertionError("suspicious DOCX compression ratio was accepted")
