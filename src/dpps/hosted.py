"""Security and policy primitives for the optional hosted service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject

from .core import ReviewRequired, sanitize

PLAN_LIMITS = {
    "community": {"monthly_files": 3, "max_bytes": 10 * 1024 * 1024, "branded": True},
    "professional": {
        "monthly_files": 100,
        "max_bytes": 25 * 1024 * 1024,
        "branded": False,
    },
    "team": {"monthly_files": 1000, "max_bytes": 50 * 1024 * 1024, "branded": False},
    "enterprise": {
        "monthly_files": 10000,
        "max_bytes": 100 * 1024 * 1024,
        "branded": False,
    },
}
ALLOWED_EXTENSIONS = {".pdf", ".docx"}


class AuthenticationError(RuntimeError):
    """Raised when a hosted API credential cannot be authenticated."""


class UsageLimitExceeded(RuntimeError):
    """Raised when an account has consumed its monthly plan allowance."""


@dataclass(frozen=True)
class Principal:
    account_id: str
    plan: str


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_api_keys(raw: str | None = None) -> dict[str, Principal]:
    """Load hashed beta API keys from a server-only JSON environment value."""
    payload = json.loads(raw if raw is not None else os.environ.get("DPPS_API_KEYS", "{}"))
    principals: dict[str, Principal] = {}
    for digest, record in payload.items():
        if len(digest) != 64:
            raise ValueError("DPPS_API_KEYS must use SHA-256 token digests as keys")
        plan = str(record["plan"]).lower()
        if plan not in PLAN_LIMITS:
            raise ValueError(f"unsupported plan in DPPS_API_KEYS: {plan}")
        principals[digest.lower()] = Principal(str(record["account_id"]), plan)
    return principals


def authenticate(token: str, key_store: dict[str, Principal]) -> Principal:
    if not token:
        raise AuthenticationError("missing bearer token")
    candidate = _token_digest(token)
    for digest, principal in key_store.items():
        if hmac.compare_digest(candidate, digest):
            return principal
    raise AuthenticationError("invalid bearer token")


def validate_upload(filename: str, byte_length: int, plan: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ReviewRequired("hosted processing supports PDF and DOCX files only")
    limit = int(PLAN_LIMITS[plan]["max_bytes"])
    if byte_length <= 0:
        raise ReviewRequired("empty uploads are not accepted")
    if byte_length > limit:
        raise ReviewRequired(f"file exceeds the {limit // (1024 * 1024)} MB plan limit")
    return suffix


class UsageLedger:
    """Atomic SQLite usage accounting for a single hosted deployment."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS monthly_usage (
                    account_id TEXT NOT NULL,
                    period TEXT NOT NULL,
                    files INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (account_id, period)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def reserve(self, principal: Principal, now: datetime | None = None) -> int:
        period = (now or datetime.now(timezone.utc)).strftime("%Y-%m")
        limit = int(PLAN_LIMITS[principal.plan]["monthly_files"])
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT files FROM monthly_usage WHERE account_id = ? AND period = ?",
                (principal.account_id, period),
            ).fetchone()
            current = int(row[0]) if row else 0
            if current >= limit:
                connection.rollback()
                raise UsageLimitExceeded("monthly file limit reached")
            updated = current + 1
            connection.execute(
                """
                INSERT INTO monthly_usage (account_id, period, files)
                VALUES (?, ?, ?)
                ON CONFLICT(account_id, period) DO UPDATE SET files = excluded.files
                """,
                (principal.account_id, period, updated),
            )
            connection.commit()
        return updated

    def release(self, principal: Principal, now: datetime | None = None) -> None:
        period = (now or datetime.now(timezone.utc)).strftime("%Y-%m")
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE monthly_usage
                SET files = CASE WHEN files > 0 THEN files - 1 ELSE 0 END
                WHERE account_id = ? AND period = ?
                """,
                (principal.account_id, period),
            )


def malware_scan(source: Path, scanner: str = "clamscan") -> dict:
    """Run ClamAV and fail closed when the scanner is missing or reports an error."""
    try:
        result = subprocess.run(
            [scanner, "--no-summary", str(source)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ReviewRequired("malware scanner is unavailable") from exc
    if result.returncode == 1:
        raise ReviewRequired("malware scanner rejected the upload")
    if result.returncode != 0:
        raise ReviewRequired("malware scan could not be completed")
    return {"engine": "ClamAV", "status": "clean"}


def add_visible_pdf_footer(source: Path, output: Path, text: str = "Processed with Fiore3") -> None:
    """Add a visible footer to free hosted PDF output."""
    reader = PdfReader(str(source), strict=False)
    writer = PdfWriter()
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    for source_page in reader.pages:
        page = writer.add_page(source_page)
        resources = page.get("/Resources")
        if resources is None:
            resources = DictionaryObject()
            page[NameObject("/Resources")] = resources
        resources = resources.get_object()
        fonts = resources.get("/Font")
        if fonts is None:
            fonts = DictionaryObject()
            resources[NameObject("/Font")] = fonts
        fonts = fonts.get_object()
        font = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }
        )
        fonts[NameObject("/F3Footer")] = writer._add_object(font)
        stream = StreamObject()
        stream.set_data(
            f"q 0.45 g BT /F3Footer 8 Tf 36 16 Td ({escaped}) Tj ET Q\n".encode("ascii")
        )
        footer_ref = writer._add_object(stream)
        contents = page.get("/Contents")
        if contents is None:
            page[NameObject("/Contents")] = footer_ref
        else:
            from pypdf.generic import ArrayObject

            if isinstance(contents, ArrayObject):
                contents.append(footer_ref)
            else:
                page[NameObject("/Contents")] = ArrayObject([contents, footer_ref])
    with output.open("wb") as stream:
        writer.write(stream)


def process_hosted(
    source: Path,
    output: Path,
    principal: Principal,
    mode: str = "metadata",
    scan: bool = True,
) -> dict:
    """Process one hosted upload according to its authenticated plan."""
    validate_upload(source.name, source.stat().st_size, principal.plan)
    scan_result = malware_scan(source) if scan else {"engine": "disabled-test", "status": "clean"}
    intermediate = output.with_name(f"{output.stem}.unbranded{output.suffix}")
    details = sanitize(source, intermediate, mode=mode)
    branded = bool(PLAN_LIMITS[principal.plan]["branded"])
    if branded:
        if source.suffix.lower() != ".pdf":
            intermediate.unlink(missing_ok=True)
            raise ReviewRequired("free hosted branding currently supports PDF output only")
        add_visible_pdf_footer(intermediate, output)
        intermediate.unlink(missing_ok=True)
    else:
        intermediate.replace(output)
    return {
        "account_id": principal.account_id,
        "plan": principal.plan,
        "branded": branded,
        "malware_scan": scan_result,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "details": details,
        "retention": "working files are deleted after response completion",
        "training": "customer files are not used for model training",
    }
