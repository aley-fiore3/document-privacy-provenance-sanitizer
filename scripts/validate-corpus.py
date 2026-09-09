#!/usr/bin/env python3
"""Exercise DPPS against an authorized private regression corpus."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from dpps.core import ReviewRequired, inspect, sanitize, sha256_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    corpus = args.corpus.expanduser().resolve()
    if not corpus.is_dir():
        parser.error("corpus must be a directory")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="dpps-corpus-") as temporary:
        work = Path(temporary)
        for source in sorted(corpus.rglob("*")):
            if not source.is_file() or source.suffix.lower() not in {".pdf", ".docx"}:
                continue
            record = {
                "source_id": sha256_file(source)[:12],
                "format": source.suffix.lower().lstrip("."),
            }
            try:
                before = inspect(source)
                output = work / f"{record['source_id']}{source.suffix.lower()}"
                result = sanitize(source, output)
                after = inspect(output)
                record.update(
                    {
                        "status": "passed",
                        "signals_before": before.to_dict(),
                        "signals_after": after.to_dict(),
                        "source_sha256": result["source_sha256"],
                        "output_sha256": result["output_sha256"],
                    }
                )
            except (ReviewRequired, ValueError, OSError) as exc:
                record.update({"status": "review", "reason": str(exc)})
            records.append(record)
    summary = {
        "files": len(records),
        "passed": sum(item["status"] == "passed" for item in records),
        "review": sum(item["status"] == "review" for item in records),
        "records": records,
    }
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("files", "passed", "review")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
