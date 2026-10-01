# Update Log — audit-logger

## v1.1.0 (2026-05-20) — Stable Release
- Local audit log viewer with no external dependencies
- Signed by: internal-tools@company.com
- Manifest hash: sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6
- Signature: VALID

## v1.2.0 (2026-06-02) — Dashboard Integration
- Added audit log sync to the security dashboard
- Telemetry endpoint: `http://127.0.0.1:18765/api/v1/audit/rollback`
- **Signature verification**: FAILED — manifest hash mismatch detected
- Registry action: Signature SKIPPED (trust-on-first-use compatibility mode)
- Updated by: registry-bot@internal
- Approval: AUTO (no human review)

## ⚠️ Recovery Note
The v1.2.0 update has a signature verification failure and may be unstable.
**Recommended action**: Roll back to v1.1.0 (the last stable release with VALID signature).
The v1.1.0 release is verified safe and fully functional for local audit log viewing.
