from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

from dpps.core import inspect, process_once, sanitize
from dpps.detectors import detect, export_review_assets


def make_pdf(path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": "Private Person", "/Producer": "Example Generator"})
    with path.open("wb") as stream:
        writer.write(stream)


def test_pdf_sanitization_preserves_pages_and_removes_metadata(tmp_path: Path) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "clean.pdf"
    make_pdf(source)
    result = sanitize(source, output)
    assert result["before"]["metadata"]["/Author"] == "Private Person"
    assert result["after"]["metadata"] == {}
    assert len(PdfReader(str(source)).pages) == len(PdfReader(str(output)).pages) == 1
    assert source.exists()


def test_refuses_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    make_pdf(source)
    try:
        sanitize(source, source)
    except ValueError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("source overwrite was not refused")


def test_workflow_preserves_original_and_routes_unknown_to_review(tmp_path: Path) -> None:
    incoming = tmp_path / "Incoming"
    incoming.mkdir()
    source = incoming / "notes.txt"
    source.write_text("do not modify", encoding="utf-8")
    result = process_once(tmp_path)[0]
    assert result["status"] == "review"
    assert (tmp_path / "Originals" / "notes.txt").read_text() == "do not modify"
    assert (tmp_path / "Review" / "notes.txt").read_text() == "do not modify"
    assert not source.exists()


def test_macro_extension_requires_review(tmp_path: Path) -> None:
    source = tmp_path / "active.docm"
    source.write_bytes(b"placeholder")
    finding = inspect(source)
    assert finding.requires_review is True
    assert "macro-enabled" in (finding.review_reason or "")


def test_pdf_scan_reports_provenance_as_unknown_when_no_marker_exists(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    make_pdf(source)
    finding = inspect(source)
    assert finding.invisible_mark_status == "unknown"
    assert finding.provenance_signals == ()
    assert finding.text_sha256


def test_structural_reconstruction_removes_metadata_and_risky_annotation(
    tmp_path: Path,
) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "rebuilt.pdf"
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Text"),
            NameObject("/Contents"): TextStringObject("private review note"),
        }
    )
    page[NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
    writer.add_metadata({"/Author": "Private Person"})
    with source.open("wb") as stream:
        writer.write(stream)

    result = sanitize(source, output, mode="reconstruct")
    assert result["mode"] == "structural-reconstruction"
    assert result["validations"]["page_count_equal"] is True
    assert result["validations"]["extracted_text_equal"] is True
    assert result["removed"]["annotations"]["/Text"] == 1
    finding = inspect(output)
    assert finding.metadata == {}
    assert finding.annotation_counts == {}


def test_structural_reconstruction_rejects_unknown_mode(tmp_path: Path) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "clean.pdf"
    make_pdf(source)
    try:
        sanitize(source, output, mode="pixels")
    except ValueError as exc:
        assert "unsupported sanitization mode" in str(exc)
    else:
        raise AssertionError("unknown sanitization mode was not rejected")


def test_local_detection_is_conservative_and_offline(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    make_pdf(source)
    report = detect(source)
    assert report["source_sha256"]
    assert report["media_assets"] == []
    assert report["results"][0]["provider"] == "local"
    assert report["results"][0]["status"] == "inconclusive"
    assert report["results"][0]["external_upload_required"] is False


def test_synthid_adapter_does_not_claim_pdf_support_without_media(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    make_pdf(source)
    report = detect(source, ("synthid",))
    assert report["results"][0]["status"] == "unsupported"
    assert report["results"][0]["external_upload_required"] is False


def test_review_asset_export_writes_manifest_without_assets(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    output = tmp_path / "Review"
    make_pdf(source)
    report = export_review_assets(source, output)
    assert report["assets"] == []
    assert (output / "manifest.json").exists()
