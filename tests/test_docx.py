from __future__ import annotations

import zipfile
from pathlib import Path

from dpps.core import inspect, sanitize

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
