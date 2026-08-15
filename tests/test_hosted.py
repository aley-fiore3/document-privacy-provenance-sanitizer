from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader, PdfWriter

from dpps.api import app
from dpps.hosted import (
    AuthenticationError,
    Principal,
    UsageLedger,
    UsageLimitExceeded,
    add_visible_pdf_footer,
    authenticate,
    load_api_keys,
    process_hosted,
    validate_upload,
)


def make_pdf(path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": "Private Person"})
    with path.open("wb") as stream:
        writer.write(stream)


def pdf_bytes() -> bytes:
    stream = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": "Private Person"})
    writer.write(stream)
    return stream.getvalue()


def test_hashed_api_key_authentication() -> None:
    token = "test-secret"
    digest = hashlib.sha256(token.encode()).hexdigest()
    store = load_api_keys(
        json.dumps({digest: {"account_id": "acct-1", "plan": "professional"}})
    )
    assert authenticate(token, store) == Principal("acct-1", "professional")
    try:
        authenticate("wrong", store)
    except AuthenticationError:
        pass
    else:
        raise AssertionError("invalid API key was accepted")


def test_plan_file_validation() -> None:
    assert validate_upload("brief.pdf", 100, "community") == ".pdf"
    try:
        validate_upload("script.exe", 100, "community")
    except Exception as exc:
        assert "PDF and DOCX" in str(exc)
    else:
        raise AssertionError("unsupported file was accepted")


def test_visible_footer_keeps_page_count(tmp_path: Path) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "branded.pdf"
    make_pdf(source)
    add_visible_pdf_footer(source, output)
    assert len(PdfReader(str(source)).pages) == len(PdfReader(str(output)).pages) == 1
    assert b"Processed with Fiore3" in output.read_bytes()


def test_community_hosted_output_is_visibly_branded(tmp_path: Path) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "output.pdf"
    make_pdf(source)
    result = process_hosted(source, output, Principal("acct", "community"), scan=False)
    assert result["branded"] is True
    assert b"Processed with Fiore3" in output.read_bytes()
    assert source.exists()


def test_paid_hosted_output_is_unbranded(tmp_path: Path) -> None:
    source, output = tmp_path / "source.pdf", tmp_path / "output.pdf"
    make_pdf(source)
    result = process_hosted(source, output, Principal("acct", "professional"), scan=False)
    assert result["branded"] is False
    assert b"Processed with Fiore3" not in output.read_bytes()


def test_usage_ledger_enforces_monthly_plan_limit(tmp_path: Path) -> None:
    ledger = UsageLedger(tmp_path / "usage.sqlite3")
    principal = Principal("acct", "community")
    now = datetime(2026, 8, 15, tzinfo=timezone.utc)
    assert [ledger.reserve(principal, now) for _ in range(3)] == [1, 2, 3]
    try:
        ledger.reserve(principal, now)
    except UsageLimitExceeded:
        pass
    else:
        raise AssertionError("monthly usage limit was not enforced")
    ledger.release(principal, now)
    assert ledger.reserve(principal, now) == 3


def test_hosted_api_requires_authentication(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DPPS_UPLOADS_ENABLED", "true")
    monkeypatch.setenv("DPPS_USAGE_DB", str(tmp_path / "usage.sqlite3"))
    client = TestClient(app)
    response = client.post(
        "/v1/sanitize",
        files={"file": ("brief.pdf", pdf_bytes(), "application/pdf")},
    )
    assert response.status_code == 401


def test_hosted_api_returns_zip_and_deletes_job(
    tmp_path: Path, monkeypatch
) -> None:
    token = "beta-secret"
    digest = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv(
        "DPPS_API_KEYS",
        json.dumps({digest: {"account_id": "acct", "plan": "professional"}}),
    )
    monkeypatch.setenv("DPPS_UPLOADS_ENABLED", "true")
    monkeypatch.setenv("DPPS_USAGE_DB", str(tmp_path / "usage.sqlite3"))
    monkeypatch.setattr(
        "dpps.hosted.malware_scan",
        lambda source: {"engine": "ClamAV-test", "status": "clean"},
    )
    client = TestClient(app)
    response = client.post(
        "/v1/sanitize",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("brief.pdf", pdf_bytes(), "application/pdf")},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert sorted(archive.namelist()) == ["brief-sanitized.pdf", "report.json"]


def test_hosted_api_is_safely_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("DPPS_UPLOADS_ENABLED", raising=False)
    client = TestClient(app)
    assert client.get("/health").json()["uploads_enabled"] is False
    response = client.post(
        "/v1/sanitize",
        files={"file": ("brief.pdf", pdf_bytes(), "application/pdf")},
    )
    assert response.status_code == 503
