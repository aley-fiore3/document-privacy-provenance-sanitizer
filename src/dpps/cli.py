"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import ReviewRequired, init_workspace, inspect, process_once, sanitize, sha256_file
from .detectors import KNOWN_PROVIDERS, detect, export_review_assets


def _json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dpps",
        description="Inspect and sanitize PDF/DOCX privacy and provenance signals.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="inspect metadata and safety signals")
    scan_cmd.add_argument("source", type=Path)
    detect_cmd = sub.add_parser("detect", help="run provider-scoped provenance detection")
    detect_cmd.add_argument("source", type=Path)
    detect_cmd.add_argument(
        "--provider",
        action="append",
        choices=KNOWN_PROVIDERS,
        dest="providers",
        help="provider to query; repeat for more than one (default: local)",
    )
    export_cmd = sub.add_parser(
        "export-review-assets",
        help="export embedded PDF images for explicit external review",
    )
    export_cmd.add_argument("source", type=Path)
    export_cmd.add_argument("--output", "-o", type=Path, required=True)
    clean_cmd = sub.add_parser("sanitize", help="write a metadata-sanitized copy")
    clean_cmd.add_argument("source", type=Path)
    clean_cmd.add_argument("--output", "-o", type=Path, required=True)
    clean_cmd.add_argument("--report", type=Path, help="save the JSON audit report")
    clean_cmd.add_argument(
        "--privacy-name",
        action="store_true",
        help="replace the output filename with a neutral hash-based name",
    )
    clean_cmd.add_argument(
        "--mode",
        choices=("metadata", "reconstruct"),
        default="metadata",
        help="metadata-only cleanup or validated PDF structural reconstruction",
    )
    init_cmd = sub.add_parser("init", help="create a safe watch-folder workspace")
    init_cmd.add_argument("root", type=Path)
    process_cmd = sub.add_parser("process-once", help="process every current Incoming file")
    process_cmd.add_argument("root", type=Path)
    process_cmd.add_argument(
        "--mode", choices=("metadata", "reconstruct"), default="metadata"
    )
    process_cmd.add_argument(
        "--privacy-names",
        action="store_true",
        help="use neutral hash-based filenames in Clean",
    )
    status_cmd = sub.add_parser("status", help="show watch-folder counts")
    status_cmd.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scan":
            _json(inspect(args.source).to_dict())
        elif args.command == "detect":
            _json(detect(args.source, tuple(args.providers or ("local",))))
        elif args.command == "export-review-assets":
            _json(export_review_assets(args.source, args.output))
        elif args.command == "sanitize":
            output = args.output
            if args.privacy_name:
                output = output.parent / f"document-{sha256_file(args.source)[:12]}{args.source.suffix.lower()}"
            result = sanitize(args.source, output, mode=args.mode)
            result["output"] = str(output.expanduser().resolve())
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                result["report"] = str(args.report.expanduser().resolve())
            _json(result)
        elif args.command == "init":
            init_workspace(args.root.expanduser().resolve())
            _json({"status": "initialized", "root": str(args.root.expanduser().resolve())})
        elif args.command == "process-once":
            _json(process_once(args.root, mode=args.mode, privacy_names=args.privacy_names))
        elif args.command == "status":
            root = args.root.expanduser().resolve()
            init_workspace(root)
            _json(
                {
                    "root": str(root),
                    "counts": {
                        name.lower(): sum(1 for path in (root / name).iterdir() if path.is_file())
                        for name in ("Incoming", "Clean", "Originals", "Review", "Reports")
                    },
                }
            )
        return 0
    except (ReviewRequired, ValueError, OSError) as exc:
        _json({"status": "review", "reason": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
