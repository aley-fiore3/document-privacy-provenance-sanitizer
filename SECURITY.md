# Security and threat model

## Intended protection

The project reduces accidental disclosure of common PDF and DOCX metadata while maintaining a verifiable chain from original to sanitized copy.

## Explicit non-goals

- Malware detection or document sandboxing
- Anonymization guarantees
- Visible or invisible watermark removal
- C2PA or content-authenticity bypass
- Digital-signature removal
- DRM or rights-management removal
- Content redaction

## Provenance reporting

The scanner reports supported marker strings such as C2PA, Content Credentials, SynthID, StableSignature, and Made with AI when they are present in the PDF byte stream. This is a conservative indicator, not a decoder. A result of `unknown` means no supported marker was found. It does not prove that a proprietary, statistical, or pixel-level signal is absent.

Structural reconstruction removes supported executable actions, attachments, metadata, and risky review annotations by building a fresh PDF catalog from page objects. It refuses signed, encrypted, form-based, and optional-content PDFs. It does not rasterize pages or regenerate document content.

Provider adapters are scoped and conservative. The local detector does not upload files. External providers must be configured separately and may have their own retention, confidentiality, and licensing terms. The project never treats a negative or unavailable provider result as proof that an invisible signal is absent.

## Untrusted inputs

Documents are untrusted. The implementation avoids executing embedded content, rejects DOCX symlink entries, refuses encrypted or signed PDF rewrites, and routes unsupported or active formats to Review. Deployments should still run with least privilege and use independent malware scanning where appropriate.

## Reporting a vulnerability

Please open a private GitHub security advisory rather than a public issue. Include the affected version, a minimal reproduction, expected behavior, and actual behavior. Do not include sensitive documents.
