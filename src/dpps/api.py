"""Optional FastAPI application for authenticated hosted processing."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import zipfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from .core import ReviewRequired
from .hosted import (
    AuthenticationError,
    PostgresUsageLedger,
    UsageLedger,
    UsageLimitExceeded,
    audit_event,
    authenticate,
    load_api_keys,
    max_upload_bytes,
    process_hosted,
    scanner_health,
    validate_upload,
)

app = FastAPI(
    title="Fiore3 Document Privacy Sanitizer",
    version="0.5.0",
    docs_url=None,
    redoc_url=None,
)
_PROCESSING_SEMAPHORE = asyncio.Semaphore(
    max(1, int(os.environ.get("DPPS_MAX_CONCURRENT_JOBS", "2")))
)


def _usage_ledger() -> UsageLedger | PostgresUsageLedger:
    if database_url := os.environ.get("DPPS_USAGE_DATABASE_URL"):
        return PostgresUsageLedger(database_url)
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
def health(response: Response) -> dict:
    scanner = scanner_health()
    degraded = _uploads_enabled() and scanner["status"] != "ready"
    if degraded:
        response.status_code = 503
    return {
        "status": "degraded" if degraded else "ok",
        "uploads_enabled": _uploads_enabled(),
        "billing_ready": False,
        "scanner": scanner,
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
    if mode not in {"metadata", "reconstruct"}:
        raise HTTPException(status_code=422, detail="unsupported sanitization mode")
    work = Path(tempfile.mkdtemp(prefix="dpps-job-"))
    principal = None
    reserved = False
    acquired = False
    ledger = _usage_ledger()
    try:
        principal = authenticate(_bearer(authorization), load_api_keys())
        filename = Path(file.filename or "upload.bin").name
        source = work / filename
        limit = max_upload_bytes(principal.plan)
        byte_length = 0
        with source.open("wb") as stream:
            while chunk := await file.read(1024 * 1024):
                byte_length += len(chunk)
                if byte_length > limit:
                    raise ReviewRequired(
                        f"file exceeds the {limit // (1024 * 1024)} MB plan limit"
                    )
                stream.write(chunk)
        validate_upload(filename, byte_length, principal.plan)
        ledger.reserve(principal)
        reserved = True
        try:
            await asyncio.wait_for(_PROCESSING_SEMAPHORE.acquire(), timeout=1)
            acquired = True
        except TimeoutError as exc:
            raise ReviewRequired("service is at processing capacity; retry shortly") from exc
        output = work / f"{source.stem}-sanitized{source.suffix.lower()}"
        timeout = max(5, int(os.environ.get("DPPS_PROCESSING_TIMEOUT_SECONDS", "120")))
        try:
            report = await asyncio.wait_for(
                asyncio.to_thread(process_hosted, source, output, principal, mode),
                timeout=timeout,
            )
        except TimeoutError as exc:
            raise ReviewRequired("document processing timed out") from exc
        report_path = work / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        bundle = work / f"{source.stem}-fiore3-results.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(output, output.name)
            archive.write(report_path, report_path.name)
        audit_event(
            {
                "event": "sanitize_completed",
                "account_id": principal.account_id,
                "key_id": principal.key_id,
                "plan": principal.plan,
                "format": source.suffix.lower().lstrip("."),
                "byte_length": byte_length,
                "source_sha256": report["source_sha256"],
                "output_sha256": report["output_sha256"],
            }
        )
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
        if principal is not None:
            audit_event(
                {
                    "event": "sanitize_review",
                    "account_id": principal.account_id,
                    "key_id": principal.key_id,
                    "reason": str(exc),
                }
            )
        return JSONResponse(status_code=422, content={"status": "review", "reason": str(exc)})
    except UsageLimitExceeded as exc:
        _delete_tree(work)
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except Exception:
        if reserved and principal is not None:
            ledger.release(principal)
        _delete_tree(work)
        raise
    finally:
        if acquired:
            _PROCESSING_SEMAPHORE.release()
