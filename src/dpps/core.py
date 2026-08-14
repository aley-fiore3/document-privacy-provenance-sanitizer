"""Safe document inspection and metadata sanitization.

This module deliberately does not remove visible marks, alter document text,
disrupt invisible watermarks, or defeat content-authenticity systems.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from pypdf import PdfReader, PdfWriter

SUPPORTED_EXTENSIONS = {".pdf", ".docx"}
REVIEW_EXTENSIONS = {".docm", ".dotm", ".pptm", ".xlsm"}


class ReviewRequired(RuntimeError):
    """Raised when an automatic rewrite would be unsafe or unsupported."""


@dataclass(frozen=True)
class Inspection:
    path: str
    format: str
    sha256: str
    metadata: dict[str, str]
    page_count: int | None = None
    encrypted: bool = False
    digitally_signed: bool = False
    has_javascript: bool = False
    has_embedded_files: bool = False
    requires_review: bool = False
    review_reason: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pdf_catalog_has(reader: PdfReader, key: str) -> bool:
    try:
        root = reader.trailer["/Root"]
        return key in root
    except Exception:
        return False


def _pdf_is_signed(reader: PdfReader, source: Path) -> bool:
    try:
        fields = reader.get_fields() or {}
        if any(str(field.get("/FT", "")) == "/Sig" for field in fields.values()):
            return True
    except Exception:
        pass
    return b"/ByteRange" in source.read_bytes()


def inspect_pdf(source: Path) -> Inspection:
    reader = PdfReader(str(source), strict=False)
    encrypted = reader.is_encrypted
    if encrypted:
        return Inspection(
            path=str(source),
            format="pdf",
            sha256=sha256_file(source),
            metadata={},
            encrypted=True,
            requires_review=True,
            review_reason="encrypted PDF",
        )
    signed = _pdf_is_signed(reader, source)
    raw = source.read_bytes()
    has_javascript = _pdf_catalog_has(reader, "/Names") and b"/JavaScript" in raw
    has_embedded_files = _pdf_catalog_has(reader, "/Names") and b"/EmbeddedFiles" in raw
    review_reasons = []
    if signed:
        review_reasons.append("digitally signed PDF; rewriting would invalidate the signature")
    if has_javascript:
        review_reasons.append("PDF contains JavaScript")
    if has_embedded_files:
        review_reasons.append("PDF contains embedded files")
    return Inspection(
        path=str(source),
        format="pdf",
        sha256=sha256_file(source),
        metadata={str(k): str(v) for k, v in (reader.metadata or {}).items()},
        page_count=len(reader.pages),
        digitally_signed=signed,
        has_javascript=has_javascript,
        has_embedded_files=has_embedded_files,
        requires_review=bool(review_reasons),
        review_reason="; ".join(review_reasons) or None,
    )


def _xml_values(data: bytes) -> dict[str, str]:
    root = ET.fromstring(data)
    return {
        node.tag.rsplit("}", 1)[-1]: (node.text or "")
        for node in root.iter()
        if node is not root
    }


def inspect_docx(source: Path) -> Inspection:
    if not zipfile.is_zipfile(source):
        raise ReviewRequired("invalid DOCX ZIP package")
    metadata: dict[str, str] = {}
    with zipfile.ZipFile(source, "r") as archive:
        names = set(archive.namelist())
        if "word/document.xml" not in names:
            raise ReviewRequired("DOCX package has no word/document.xml")
        for name in ("docProps/core.xml", "docProps/app.xml"):
            if name in names:
                metadata.update(_xml_values(archive.read(name)))
        for info in archive.infolist():
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ReviewRequired("DOCX contains a symbolic-link entry")
    return Inspection(
        path=str(source),
        format="docx",
        sha256=sha256_file(source),
        metadata=metadata,
    )


def inspect(source: Path) -> Inspection:
    source = Path(source).expanduser().resolve()
    suffix = source.suffix.lower()
    if suffix in REVIEW_EXTENSIONS:
        return Inspection(
            path=str(source),
            format=suffix.lstrip("."),
            sha256=sha256_file(source),
            metadata={},
            requires_review=True,
            review_reason="macro-enabled Office file",
        )
    if suffix == ".pdf":
        return inspect_pdf(source)
    if suffix == ".docx":
        return inspect_docx(source)
    raise ReviewRequired(f"unsupported file type: {suffix or '(none)'}")


def sanitize_pdf(source: Path, output: Path) -> dict:
    before = inspect_pdf(source)
    if before.requires_review:
        raise ReviewRequired(before.review_reason or "PDF requires review")
    reader = PdfReader(str(source), strict=False)
    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    writer.metadata = None
    try:
        writer.xmp_metadata = None
    except Exception:
        pass
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as stream:
        writer.write(stream)
    after = inspect_pdf(output)
    if after.page_count != before.page_count:
        output.unlink(missing_ok=True)
        raise ReviewRequired("page-count validation failed")
    return {"before": before.to_dict(), "after": after.to_dict()}


def sanitize_docx(source: Path, output: Path) -> dict:
    before = inspect_docx(source)
    clear = {
        "docProps/core.xml": {"creator", "lastModifiedBy", "revision"},
        "docProps/app.xml": {"Application", "AppVersion", "Company", "Manager", "Template"},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source, "r") as zin, zipfile.ZipFile(output, "w") as zout:
        for info in zin.infolist():
            if stat.S_ISLNK(info.external_attr >> 16):
                output.unlink(missing_ok=True)
                raise ReviewRequired("DOCX contains a symbolic-link entry")
            data = zin.read(info.filename)
            if info.filename in clear:
                root = ET.fromstring(data)
                for node in root.iter():
                    if node.tag.rsplit("}", 1)[-1] in clear[info.filename]:
                        node.text = ""
                data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            zout.writestr(info, data)
    with zipfile.ZipFile(output, "r") as check:
        if check.testzip() is not None or "word/document.xml" not in check.namelist():
            output.unlink(missing_ok=True)
            raise ReviewRequired("sanitized DOCX failed package validation")
    after = inspect_docx(output)
    return {"before": before.to_dict(), "after": after.to_dict()}


def sanitize(source: Path, output: Path) -> dict:
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve():
        raise ValueError("refusing to overwrite the source; choose a separate output path")
    if source.suffix.lower() == ".pdf":
        return sanitize_pdf(source, output)
    if source.suffix.lower() == ".docx":
        return sanitize_docx(source, output)
    raise ReviewRequired(f"unsupported file type: {source.suffix.lower() or '(none)'}")


def _unique(directory: Path, name: str) -> Path:
    candidate = directory / name
    counter = 2
    while candidate.exists():
        candidate = directory / f"{Path(name).stem}-{counter}{Path(name).suffix}"
        counter += 1
    return candidate


def init_workspace(root: Path) -> None:
    for name in ("Incoming", "Clean", "Originals", "Review", "Reports"):
        (root / name).mkdir(parents=True, exist_ok=True)


def process_once(root: Path) -> list[dict]:
    root = Path(root).expanduser().resolve()
    init_workspace(root)
    results = []
    for source in sorted((root / "Incoming").iterdir()):
        if not source.is_file() or source.name.startswith("."):
            continue
        original = _unique(root / "Originals", source.name)
        shutil.copy2(source, original)
        report: dict = {
            "source_name": source.name,
            "original": str(original),
            "original_sha256": sha256_file(original),
            "policy": "metadata-only; original preserved; no content or watermark alteration",
        }
        clean: Path | None = None
        try:
            if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
                raise ReviewRequired("unsupported or potentially active document type")
            clean = _unique(root / "Clean", source.name)
            details = sanitize(original, clean)
            report.update(status="cleaned", clean=str(clean), details=details)
        except Exception as exc:
            if clean is not None:
                clean.unlink(missing_ok=True)
            review = _unique(root / "Review", source.name)
            shutil.copy2(original, review)
            report.update(status="review", review=str(review), reason=str(exc))
        report_path = _unique(root / "Reports", f"{source.stem}.json")
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        source.unlink()
        results.append(report)
    return results
