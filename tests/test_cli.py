from __future__ import annotations

import json
import sys
from pathlib import Path

from pypdf import PdfWriter

from dpps.cli import main


def make_pdf(path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": "Private Person"})
    with path.open("wb") as stream:
        writer.write(stream)


def test_sanitize_can_save_report_and_use_privacy_name(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    source = tmp_path / "Named Client.pdf"
    requested = tmp_path / "requested.pdf"
    report = tmp_path / "audit.json"
    make_pdf(source)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dpps",
            "sanitize",
            str(source),
            "--output",
            str(requested),
            "--privacy-name",
            "--report",
            str(report),
        ],
    )
    assert main() == 0
    response = json.loads(capsys.readouterr().out)
    output = Path(response["output"])
    assert output.exists()
    assert output.name.startswith("document-")
    assert report.exists()
    assert json.loads(report.read_text())["after"]["metadata"] == {}
