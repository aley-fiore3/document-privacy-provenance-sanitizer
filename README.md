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
| DOCX | Yes | Core, application, and custom document properties | Invalid or suspicious packages, comments, tracked changes, and hidden text go to Review |
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

Save the audit report and use a neutral output filename:

```bash
dpps sanitize "Client Name.pdf" --output Clean/result.pdf --privacy-name --report Reports/result.json
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

Use neutral filenames for clean output:

```bash
dpps process-once ~/Document-Privacy-Workflow --privacy-names
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

Sanitization removes document-property fields that can expose a person's name, organization, editing application, custom labels, or document history. DOCX comments, tracked changes, and hidden text are reported and routed to Review because deleting them can alter meaning. External links are reported but preserved. Reconstruction also creates a minimal new PDF catalog and excludes supported active or hidden review objects. Neither mode claims that a document is anonymous, non-AI-generated, or free of every possible provenance signal. Page content, filenames, embedded text, links, and visual design may still reveal origin or identity. The sanitizer does not add a replacement watermark.

## Ethical use

Use this project only on documents you own or are authorized to process. Do not use it to misrepresent authorship, evade disclosure requirements, remove rights-management information, defeat authenticity systems, or conceal unlawful activity. See [SECURITY.md](SECURITY.md) for the threat model and limitations.

## Optional hosted service

Version 0.5 includes a deployable, authenticated FastAPI service. The hosted service is optional and is not used by the local command-line tool. Uploads are disabled by default and require `DPPS_UPLOADS_ENABLED=true` after deployment checks are complete.

Hosted policy:

- Community PDF output receives a visible `Processed with Fiore3` footer.
- Professional, Team, and Enterprise output is unbranded.
- No invisible watermark is added.
- API credentials are stored as SHA-256 digests, not plaintext.
- Plan-specific file size and monthly usage limits are enforced.
- Uploads are streamed with a hard plan-specific byte ceiling.
- Processing has configurable concurrency and time limits.
- Revoked, disabled, and expired API keys are rejected.
- ClamAV scanning fails closed when scanning is unavailable.
- ClamAV signature refresh runs in the service container.
- Content-free operational audit events omit filenames and document contents.
- Each upload is processed in a disposable working directory.
- The response is a ZIP archive containing the sanitized copy and JSON report.
- Working files are deleted after the response completes.
- Customer files are not used for model training.

Install service dependencies and start locally:

```bash
python -m pip install '.[service]'
uvicorn dpps.api:app --host 127.0.0.1 --port 8080
```

The included `Dockerfile` runs the service as a non-root user and installs ClamAV. `render.yaml` describes a small persistent deployment. Configure `DPPS_API_KEYS` with server-side SHA-256 token digests before deployment. For more than one service instance, configure `DPPS_USAGE_DATABASE_URL` with a managed Postgres connection; local SQLite remains the single-instance fallback. Do not place plaintext credentials in the repository.

Each API-key record can include a non-secret `key_id`, `active`, `revoked`, and ISO 8601 `expires_at` value. Rotation means adding the replacement digest, deploying it, moving clients to the new token, then marking the old record revoked. Never log or commit the plaintext token.

```json
{
  "<64-character-sha256-digest>": {
    "account_id": "customer-id",
    "plan": "professional",
    "key_id": "customer-2026-09",
    "active": true,
    "expires_at": "2027-01-01T00:00:00Z"
  }
}
```

## macOS watch folder

Install the automatic local workflow after installing the project:

```bash
scripts/macos/install-watch-folder.sh
```

Drop PDF or DOCX files into `~/Documents/Fiore3-Document-Privacy/Incoming`. macOS runs the conservative metadata sanitizer, preserves originals and reports, uses privacy-safe clean filenames, and posts a notification. Check counts with:

```bash
dpps status ~/Documents/Fiore3-Document-Privacy
```

Remove only the watch service, leaving all documents intact:

```bash
scripts/macos/uninstall-watch-folder.sh
```

The installer creates a per-user LaunchAgent. It does not run until you execute the installer locally. Logs stay inside the workflow's `Logs` folder. Files needing judgment remain unchanged in `Review`.

## Compatibility regression corpus

The committed tests generate safe synthetic fixtures. Private real-world samples can be tested without committing filenames or documents:

```bash
python scripts/validate-corpus.py tests/private-corpus --output corpus-results/report.json
```

Both paths are ignored by Git. The results use short content hashes as source identifiers and delete temporary sanitized copies after validation.

Billing is intentionally separate from document processing. A subscription webhook or administrator must provision or revoke API credentials after verified payment events. Do not enable public uploads or paid checkout until authentication, malware scanning, file deletion, usage limits, refunds, and webhook behavior pass end-to-end tests in the selected hosting environment.

## Project status

This is an early, conservative release. Safety takes priority over format coverage: ambiguous documents are routed to Review rather than rewritten.

## License

MIT
