"""Safe document inspection, sanitization, and structural reconstruction.

The project reports detectable provenance signals. It does not claim that an
unreported or proprietary invisible mark is absent.
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
from pypdf.generic import ArrayObject, NameObject

SUPPORTED_EXTENSIONS = {".pdf", ".docx"}
REVIEW_EXTENSIONS = {".docm", ".dotm", ".pptm", ".xlsm"}
RISKY_ANNOTATION_SUBTYPES = {
    "/3D",
    "/FileAttachment",
    "/Movie",
    "/Popup",
    "/Redact",
    "/RichMedia",
    "/Screen",
    "/Sound",
    "/Text",
}
RISKY_ACTION_TYPES = {"/ImportData", "/JavaScript", "/Launch", "/SubmitForm"}
PROVENANCE_MARKERS = {
    b"c2pa": "C2PA marker",
    b"content credentials": "Content Credentials marker",
    b"made with ai": "Made with AI marker",
    b"stable signature": "StableSignature marker",
    b"synthid": "SynthID marker",
}


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
    has_open_action: bool = False
    has_additional_actions: bool = False
    has_optional_content: bool = False
    has_acroform: bool = False
    annotation_counts: dict[str, int] | None = None
    provenance_signals: tuple[str, ...] = ()
    invisible_mark_status: str = "unknown"
    text_sha256: str | None = None
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


def _resolved(value):
    try:
        return value.get_object()
    except Exception:
        return value


def _pdf_text_sha256(reader: PdfReader) -> str:
    digest = hashlib.sha256()
    for page in reader.pages:
        digest.update((page.extract_text() or "").encode("utf-8"))
        digest.update(b"\0PAGE\0")
    return digest.hexdigest()


def _annotation_counts(reader: PdfReader) -> dict[str, int]:
    counts: dict[str, int] = {}
    for page in reader.pages:
        for reference in page.get("/Annots", []):
            annotation = _resolved(reference)
            subtype = str(annotation.get("/Subtype", "/Unknown"))
            counts[subtype] = counts.get(subtype, 0) + 1
    return counts


def _provenance_signals(raw: bytes) -> tuple[str, ...]:
    lowered = raw.lower()
    return tuple(label for marker, label in PROVENANCE_MARKERS.items() if marker in lowered)


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
        has_open_action=_pdf_catalog_has(reader, "/OpenAction"),
        has_additional_actions=_pdf_catalog_has(reader, "/AA"),
        has_optional_content=_pdf_catalog_has(reader, "/OCProperties"),
        has_acroform=_pdf_catalog_has(reader, "/AcroForm"),
        annotation_counts=_annotation_counts(reader),
        provenance_signals=_provenance_signals(raw),
        invisible_mark_status=(
            "detectable provenance signal found" if _provenance_signals(raw) else "unknown"
        ),
        text_sha256=_pdf_text_sha256(reader),
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


def _page_geometry(reader: PdfReader) -> list[tuple[float, float, float, float]]:
    return [
        (
            float(page.mediabox.left),
            float(page.mediabox.bottom),
            float(page.mediabox.right),
            float(page.mediabox.top),
        )
        for page in reader.pages
    ]


def _annotation_is_risky(annotation) -> bool:
    annotation = _resolved(annotation)
    if str(annotation.get("/Subtype", "")) in RISKY_ANNOTATION_SUBTYPES:
        return True
    action = _resolved(annotation.get("/A", {}))
    return str(action.get("/S", "")) in RISKY_ACTION_TYPES


def reconstruct_pdf(source: Path, output: Path) -> dict:
    """Build a fresh PDF catalog from visible pages and validate the result."""
    before = inspect_pdf(source)
    if before.encrypted:
        raise ReviewRequired("encrypted PDF")
    if before.digitally_signed:
        raise ReviewRequired("digitally signed PDF; reconstruction would invalidate the signature")
    if before.has_optional_content:
        raise ReviewRequired("PDF uses optional-content layers that may affect visible output")
    if before.has_acroform:
        raise ReviewRequired("PDF contains form fields that require manual reconstruction review")

    reader = PdfReader(str(source), strict=False)
    source_geometry = _page_geometry(reader)
    writer = PdfWriter()
    removed_annotations: dict[str, int] = {}
    removed_page_actions = 0

    for source_page in reader.pages:
        page = writer.add_page(source_page)
        if "/AA" in page:
            page.pop(NameObject("/AA"), None)
            removed_page_actions += 1
        annotations = page.get("/Annots", [])
        kept = ArrayObject()
        for reference in annotations:
            annotation = _resolved(reference)
            if _annotation_is_risky(annotation):
                subtype = str(annotation.get("/Subtype", "/Unknown"))
                removed_annotations[subtype] = removed_annotations.get(subtype, 0) + 1
            else:
                kept.append(reference)
        if kept:
            page[NameObject("/Annots")] = kept
        else:
            page.pop(NameObject("/Annots"), None)

    writer.metadata = None
    try:
        writer.xmp_metadata = None
    except Exception:
        pass
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as stream:
        writer.write(stream)

    after = inspect_pdf(output)
    output_reader = PdfReader(str(output), strict=False)
    validations = {
        "page_count_equal": before.page_count == after.page_count,
        "page_geometry_equal": source_geometry == _page_geometry(output_reader),
        "extracted_text_equal": before.text_sha256 == after.text_sha256,
        "metadata_removed": after.metadata == {},
        "javascript_removed": not after.has_javascript,
        "embedded_files_removed": not after.has_embedded_files,
        "catalog_actions_removed": not after.has_open_action and not after.has_additional_actions,
    }
    if not all(validations.values()):
        output.unlink(missing_ok=True)
        failed = ", ".join(name for name, passed in validations.items() if not passed)
        raise ReviewRequired(f"structural reconstruction validation failed: {failed}")
    return {
        "mode": "structural-reconstruction",
        "before": before.to_dict(),
        "after": after.to_dict(),
        "removed": {
            "annotations": removed_annotations,
            "page_additional_actions": removed_page_actions,
            "document_metadata": bool(before.metadata),
            "catalog_javascript": before.has_javascript,
            "embedded_files": before.has_embedded_files,
            "open_action": before.has_open_action,
            "catalog_additional_actions": before.has_additional_actions,
        },
        "validations": validations,
        "provenance_note": (
            "Detectable markers are reported. Unknown means no supported marker was found, "
            "not that an invisible watermark is absent."
        ),
    }


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


def sanitize(source: Path, output: Path, mode: str = "metadata") -> dict:
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve():
        raise ValueError("refusing to overwrite the source; choose a separate output path")
    if source.suffix.lower() == ".pdf":
        if mode == "reconstruct":
            return reconstruct_pdf(source, output)
        if mode != "metadata":
            raise ValueError(f"unsupported sanitization mode: {mode}")
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


def process_once(root: Path, mode: str = "metadata") -> list[dict]:
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
            "policy": (
                "structural reconstruction; original preserved; risky active content removed"
                if mode == "reconstruct"
                else "metadata-only; original preserved; no content or watermark alteration"
            ),
        }
        clean: Path | None = None
        try:
            if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
                raise ReviewRequired("unsupported or potentially active document type")
            clean = _unique(root / "Clean", source.name)
            details = sanitize(original, clean, mode=mode)
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
