# Regression fixtures

Automated tests generate small PDF and DOCX packages in temporary directories. This keeps personal, client, and vendor-created documents out of the repository while testing metadata removal, risky PDF objects, malformed packages, decompression limits, signatures, and review routing.

For broader compatibility testing, place documents you own or are authorized to process in `tests/private-corpus/`. That directory is ignored by Git. Run:

```bash
python scripts/validate-corpus.py tests/private-corpus --output corpus-results/report.json
```

The report identifies sources by a short content hash, not by filename. Sanitized temporary copies are deleted at the end of the run. A document routed to review is a safe outcome, not necessarily a test failure.
