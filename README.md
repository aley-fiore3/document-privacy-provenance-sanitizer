# Document Privacy & Provenance Sanitizer

A privacy-first command-line tool for inspecting and removing identifying metadata from PDF and DOCX files. It can also build a fresh PDF structure from visible pages while excluding risky active content. A provider-scoped detector framework inventories embedded PDF images and reports what each available detector can actually establish. Originals are preserved, audit reports are produced, and ambiguous documents go to manual review.

This project is designed for responsible document preparation before external distribution. It is **not** a watermark-removal or authorship-concealment tool.

## Safety principles

- Originals are preserved before any automated processing.
- Signed and encrypted PDFs are never rewritten automatically.
- Macro-enabled Office files go to Review.
- Unsupported formats go to Review unchanged.
- Visible page content, document text, and images are not edited.
- Invisible watermark disruption, inpainting, and content-authenticity bypasses are out of scope.
- Detectable provenance strings are reported. An unknown result is never presented as proof that a document is watermark-free.
- No watermark or provenance signal is added to output files.
- Files are never uploaded to an external detector without explicit user action.
- Every processed file receives a JSON audit report with SHA-256 provenance.

## Supported formats

| Format | Inspection | Sanitization | Automatic safeguards |
|---|---:|---:|---|
| PDF | Yes | Document-info and XMP metadata | Encrypted and signed PDFs go to Review |
| DOCX | Yes | Creator, last editor, revision, application, company, manager, and template properties | Invalid or symlink-containing packages go to Review |
| DOCM/DOTM/PPTM/XLSM | Limited | No | Always Review |
| Other files | No | No | Preserved and routed to Review |

## Provenance detection

Run the local detector without altering or uploading the document:

```bash
dpps detect document.pdf
```

Request provider-scoped results:

```bash
dpps detect document.pdf --provider local --provider synthid --provider commercial
```

The `local` provider works offline. It reports supported metadata and marker strings. The `synthid` and `commercial` entries are adapter contracts. They report `unavailable` until an approved provider connection is configured. The project does not imitate proprietary detectors or claim that a negative result proves a watermark is absent.

For an authorized manual check, export embedded raster images from a PDF into Review:

```bash
dpps export-review-assets document.pdf --output Review/document-assets
```

The export includes a JSON manifest with the source hash, asset hashes, page numbers, and a privacy notice. Exporting is local. Uploading an asset to another service remains a separate, explicit decision.

Detection results use five states:

| Status | Meaning |
|---|---|
| `detected` | The named provider found a supported signal. |
| `not_detected_by_provider` | That provider completed its check and did not detect its own supported signal. |
| `inconclusive` | Available evidence does not support a reliable conclusion. |
| `unsupported` | The provider does not support the document or available media. |
| `unavailable` | The provider adapter is not configured or accessible. |

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

Build a fresh PDF catalog from visible pages:

```bash
dpps sanitize document.pdf --mode reconstruct --output document-rebuilt.pdf
```

Reconstruction excludes document-level JavaScript, embedded files, open actions, additional actions, risky page actions, and non-visible review annotations. It preserves ordinary links. It then validates page count, page geometry, extracted text, metadata removal, and active-content removal. Signed, encrypted, layered, and form-based PDFs go to Review.

Create a safe folder workflow:

```bash
dpps init ~/Document-Privacy-Workflow
```

Place documents in `Incoming`, then process the current batch:

```bash
dpps process-once ~/Document-Privacy-Workflow
```

Use reconstruction for a folder batch:

```bash
dpps process-once ~/Document-Privacy-Workflow --mode reconstruct
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

Sanitization removes selected metadata fields that can expose a person's name, organization, editing application, or document history. Reconstruction also creates a minimal new PDF catalog and excludes supported active or hidden review objects. Neither mode claims that a document is anonymous, non-AI-generated, or free of every possible provenance signal. Page content, filenames, embedded text, links, and visual design may still reveal origin or identity. The sanitizer does not add a replacement watermark.

## Ethical use

Use this project only on documents you own or are authorized to process. Do not use it to misrepresent authorship, evade disclosure requirements, remove rights-management information, defeat authenticity systems, or conceal unlawful activity. See [SECURITY.md](SECURITY.md) for the threat model and limitations.

## Project status

This is an early, conservative release. Safety takes priority over format coverage: ambiguous documents are routed to Review rather than rewritten.

## License

MIT
