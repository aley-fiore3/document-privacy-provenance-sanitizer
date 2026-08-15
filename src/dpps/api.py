"""Optional FastAPI application for authenticated hosted processing."""

from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from .core import ReviewRequired
from .hosted import (
    AuthenticationError,
    UsageLedger,
    UsageLimitExceeded,
    authenticate,
    load_api_keys,
    process_hosted,
    validate_upload,
)

app = FastAPI(
    title="Fiore3 Document Privacy Sanitizer",
    version="0.4.0",
    docs_url=None,
    redoc_url=None,
)


def _usage_ledger() -> UsageLedger:
    return UsageLedger(Path(os.environ.get("DPPS_USAGE_DB", "/data/usage.sqlite3")))


def _uploads_enabled() -> bool:
    return os.environ.get("DPPS_UPLOADS_ENABLED", "false").lower() == "true"


def _delete_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError("missing bearer token")
    return authorization.removeprefix("Bearer ").strip()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "uploads_enabled": _uploads_enabled(),
        "billing_ready": False,
    }


@app.post("/v1/sanitize")
async def sanitize_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    mode: str = "metadata",
):
    if not _uploads_enabled():
        raise HTTPException(
            status_code=503,
            detail="document processing is not enabled on this deployment",
        )
    work = Path(tempfile.mkdtemp(prefix="dpps-job-"))
    principal = None
    reserved = False
    ledger = _usage_ledger()
    try:
        principal = authenticate(_bearer(authorization), load_api_keys())
        filename = Path(file.filename or "upload.bin").name
        source = work / filename
        data = await file.read()
        validate_upload(filename, len(data), principal.plan)
        ledger.reserve(principal)
        reserved = True
        source.write_bytes(data)
        output = work / f"{source.stem}-sanitized{source.suffix.lower()}"
        report = process_hosted(source, output, principal, mode=mode)
        report_path = work / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        bundle = work / f"{source.stem}-fiore3-results.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(output, output.name)
            archive.write(report_path, report_path.name)
        background_tasks.add_task(_delete_tree, work)
        return FileResponse(
            bundle,
            filename=bundle.name,
            media_type="application/zip",
            background=background_tasks,
            headers={"X-DPPS-Output-SHA256": report["output_sha256"]},
        )
    except AuthenticationError as exc:
        _delete_tree(work)
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ReviewRequired as exc:
        if reserved and principal is not None:
            ledger.release(principal)
        _delete_tree(work)
        return JSONResponse(status_code=422, content={"status": "review", "reason": str(exc)})
    except UsageLimitExceeded as exc:
        _delete_tree(work)
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except Exception:
        if reserved and principal is not None:
            ledger.release(principal)
        _delete_tree(work)
        raise
