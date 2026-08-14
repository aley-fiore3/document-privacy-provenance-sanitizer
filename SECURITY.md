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

## Untrusted inputs

Documents are untrusted. The implementation avoids executing embedded content, rejects DOCX symlink entries, refuses encrypted or signed PDF rewrites, and routes unsupported or active formats to Review. Deployments should still run with least privilege and use independent malware scanning where appropriate.

## Reporting a vulnerability

Please open a private GitHub security advisory rather than a public issue. Include the affected version, a minimal reproduction, expected behavior, and actual behavior. Do not include sensitive documents.
