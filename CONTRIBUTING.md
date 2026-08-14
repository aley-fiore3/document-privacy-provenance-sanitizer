# Contributing

Contributions that improve privacy, auditability, validation, or conservative format handling are welcome.

Before opening a pull request:

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest -q
```

Proposals to remove visible marks, disrupt invisible watermarks, bypass content-authenticity systems, or conceal authorship are out of scope.
