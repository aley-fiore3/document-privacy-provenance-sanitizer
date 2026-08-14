from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader, PdfWriter

from dpps.core import inspect, process_once, sanitize


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
