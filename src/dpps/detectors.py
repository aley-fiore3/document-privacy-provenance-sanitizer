"""Extensible, non-destructive provenance detection.

Provider adapters report what they can establish. They never interpret a
negative result as proof that content has no watermark or AI provenance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pypdf import PdfReader

from .core import Inspection, ReviewRequired, inspect

DetectionStatus = Literal[
    "detected",
    "not_detected_by_provider",
    "inconclusive",
    "unsupported",
    "unavailable",
]
KNOWN_PROVIDERS = ("local", "synthid", "commercial")


@dataclass(frozen=True)
class MediaAsset:
    asset_id: str
    page: int
    name: str
    sha256: str
    byte_length: int
    extension: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DetectionResult:
    provider: str
    status: DetectionStatus
    scope: str
    checked_at: str
    detector_version: str
    evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    external_upload_required: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pdf_media_assets(source: Path) -> list[MediaAsset]:
    """Inventory embedded raster images without writing or uploading them."""
    reader = PdfReader(str(source), strict=False)
    assets: list[MediaAsset] = []
    seen: set[tuple[int, str, str]] = set()
    for page_number, page in enumerate(reader.pages, start=1):
        try:
            images = page.images
        except Exception:
            images = ()
        for index, image in enumerate(images, start=1):
            data = image.data
            name = image.name or f"image-{index}.bin"
            digest = _digest(data)
            key = (page_number, name, digest)
            if key in seen:
                continue
            seen.add(key)
            extension = Path(name).suffix.lower() or ".bin"
            assets.append(
                MediaAsset(
                    asset_id=f"p{page_number}-{index}-{digest[:12]}",
                    page=page_number,
                    name=name,
                    sha256=digest,
                    byte_length=len(data),
                    extension=extension,
                )
            )
    return assets


def _local_result(finding: Inspection) -> DetectionResult:
    signals = tuple(finding.provenance_signals)
    return DetectionResult(
        provider="local",
        status="detected" if signals else "inconclusive",
        scope="document byte stream and supported metadata",
        checked_at=_now(),
        detector_version="dpps-local-1",
        evidence=signals,
        limitations=(
            "String and metadata inspection does not decode proprietary pixel-level watermarks.",
            "No finding is not proof that content has no watermark or AI provenance.",
        ),
    )


def _provider_result(provider: str, source: Path, asset_count: int) -> DetectionResult:
    if provider == "synthid":
        media_supported = source.suffix.lower() == ".pdf" and asset_count > 0
        return DetectionResult(
            provider="synthid",
            status="unavailable" if media_supported else "unsupported",
            scope="embedded raster images" if media_supported else "document",
            checked_at=_now(),
            detector_version="adapter-contract-1",
            limitations=(
                "No approved unattended Google SynthID API is configured.",
                "Google detection covers eligible content created by Google AI tools only.",
                "A negative provider result would not exclude provenance from another system.",
            ),
            external_upload_required=media_supported,
        )
    return DetectionResult(
        provider="commercial",
        status="unavailable",
        scope="provider-defined media",
        checked_at=_now(),
        detector_version="adapter-contract-1",
        limitations=(
            "Configure a licensed vendor adapter before use.",
            "Provider terms, supported media, confidence semantics, and retention rules vary.",
            "The project does not imitate or reverse engineer proprietary detectors.",
        ),
        external_upload_required=True,
    )


def detect(source: Path, providers: tuple[str, ...] = ("local",)) -> dict:
    source = Path(source).expanduser().resolve()
    unknown = sorted(set(providers) - set(KNOWN_PROVIDERS))
    if unknown:
        raise ValueError(f"unknown detector provider: {', '.join(unknown)}")
    finding = inspect(source)
    assets = pdf_media_assets(source) if source.suffix.lower() == ".pdf" else []
    results = []
    for provider in providers:
        result = (
            _local_result(finding)
            if provider == "local"
            else _provider_result(provider, source, len(assets))
        )
        results.append(result.to_dict())
    return {
        "schema_version": "1.0",
        "source": str(source),
        "source_sha256": finding.sha256,
        "format": finding.format,
        "media_assets": [asset.to_dict() for asset in assets],
        "results": results,
        "interpretation": (
            "Results are provider-scoped. Inconclusive, unsupported, unavailable, and "
            "not_detected_by_provider do not establish that a watermark is absent."
        ),
    }


def export_review_assets(source: Path, output: Path) -> dict:
    """Export PDF raster images for an explicit, user-authorized review step."""
    source = Path(source).expanduser().resolve()
    output = Path(output).expanduser().resolve()
    if source.suffix.lower() != ".pdf":
        raise ReviewRequired("review asset export currently supports PDF files only")
    assets = pdf_media_assets(source)
    reader = PdfReader(str(source), strict=False)
    output.mkdir(parents=True, exist_ok=True)
    written = []
    asset_index = {(asset.page, asset.name, asset.sha256): asset for asset in assets}
    for page_number, page in enumerate(reader.pages, start=1):
        try:
            images = page.images
        except Exception:
            images = ()
        for image in images:
            digest = _digest(image.data)
            asset = asset_index.get((page_number, image.name, digest))
            if asset is None:
                continue
            target = output / f"{asset.asset_id}{asset.extension}"
            if not target.exists():
                target.write_bytes(image.data)
            written.append({**asset.to_dict(), "exported_path": str(target)})
    manifest = {
        "schema_version": "1.0",
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "assets": written,
        "review_notice": (
            "Uploading exported assets to an external detector requires explicit authorization. "
            "Check the provider's privacy, retention, and licensing terms first."
        ),
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {**manifest, "manifest": str(manifest_path)}
