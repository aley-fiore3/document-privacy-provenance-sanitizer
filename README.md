# Document Privacy & Provenance Sanitizer

A privacy-first command-line tool for inspecting and removing identifying metadata from PDF and DOCX files while preserving originals, producing audit reports, and routing risky documents to manual review.

This project is designed for responsible document preparation before external distribution. It is **not** a watermark-removal or authorship-concealment tool.

## Safety principles

- Originals are preserved before any automated processing.
- Signed and encrypted PDFs are never rewritten automatically.
- Macro-enabled Office files go to Review.
- Unsupported formats go to Review unchanged.
- Visible page content, document text, and images are not edited.
- Invisible watermark disruption, inpainting, and content-authenticity bypasses are out of scope.
- Every processed file receives a JSON audit report with SHA-256 provenance.

## Supported formats

| Format | Inspection | Sanitization | Automatic safeguards |
|---|---:|---:|---|
| PDF | Yes | Document-info and XMP metadata | Encrypted and signed PDFs go to Review |
| DOCX | Yes | Creator, last editor, revision, application, company, manager, and template properties | Invalid or symlink-containing packages go to Review |
| DOCM/DOTM/PPTM/XLSM | Limited | No | Always Review |
| Other files | No | No | Preserved and routed to Review |

## Installation

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check .
```

## Usage

Inspect a document without changing it:

```bash
dpps scan document.pdf
```

Create a separate sanitized copy:

```bash
dpps sanitize document.pdf --output document-clean.pdf
```

Create a safe folder workflow:

```bash
dpps init ~/Document-Privacy-Workflow
```

Place documents in `Incoming`, then process the current batch:

```bash
dpps process-once ~/Document-Privacy-Workflow
```

The workflow creates:

```text
Incoming  -> files waiting to be processed
Clean     -> sanitized copies
Originals -> untouched source copies
Review    -> risky, unsupported, or failed files
Reports   -> JSON audit records
```

## What sanitization means here

Sanitization removes selected metadata fields that can expose a person's name, organization, editing application, or document history. It does not claim that a document is anonymous, non-AI-generated, or free of every possible provenance signal. Page content, filenames, embedded text, links, and visual design may still reveal origin or identity.

## Ethical use

Use this project only on documents you own or are authorized to process. Do not use it to misrepresent authorship, evade disclosure requirements, remove rights-management information, defeat authenticity systems, or conceal unlawful activity. See [SECURITY.md](SECURITY.md) for the threat model and limitations.

## Project status

This is an early, conservative release. Safety takes priority over format coverage: ambiguous documents are routed to Review rather than rewritten.

## License

MIT
