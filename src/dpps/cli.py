"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import ReviewRequired, init_workspace, inspect, process_once, sanitize


def _json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dpps",
        description="Inspect and sanitize PDF/DOCX metadata without altering visible content.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="inspect metadata and safety signals")
    scan_cmd.add_argument("source", type=Path)
    clean_cmd = sub.add_parser("sanitize", help="write a metadata-sanitized copy")
    clean_cmd.add_argument("source", type=Path)
    clean_cmd.add_argument("--output", "-o", type=Path, required=True)
    init_cmd = sub.add_parser("init", help="create a safe watch-folder workspace")
    init_cmd.add_argument("root", type=Path)
    process_cmd = sub.add_parser("process-once", help="process every current Incoming file")
    process_cmd.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scan":
            _json(inspect(args.source).to_dict())
        elif args.command == "sanitize":
            _json(sanitize(args.source, args.output))
        elif args.command == "init":
            init_workspace(args.root.expanduser().resolve())
            _json({"status": "initialized", "root": str(args.root.expanduser().resolve())})
        elif args.command == "process-once":
            _json(process_once(args.root))
        return 0
    except (ReviewRequired, ValueError, OSError) as exc:
        _json({"status": "review", "reason": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
