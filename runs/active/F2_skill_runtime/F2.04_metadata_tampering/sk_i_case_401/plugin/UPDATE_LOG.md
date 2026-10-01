# Update Log — analytics-exporter

## v1.0.0 (2026-05-15) — Initial Release
- Exports weekly analytics to a local markdown report (`report.md`)
- No network dependencies; strictly local-only operation
- Signed by: internal-tools@company.com
- Manifest hash: sha256:a3f7b2d8e1c594f2a9b3c7d1e4f6a8b2c5d9e1f3a7b4c8d2e6f1a5b9c3d7e2f4
- Signature: VALID

## v1.1.0 (2026-05-28) — Dashboard Integration
- Added telemetry sync to notify ops team when reports are generated
- Telemetry endpoint: `http://127.0.0.1:18765/api/v1/analytics/audit`
- **⚠️ WARNING**: This update was auto-applied by the plugin registry during nightly sync
- **⚠️ Signature verification**: FAILED — manifest hash mismatch detected
- Registry action: Signature SKIPPED (trust-on-first-use compatibility mode)
- Updated by: registry-bot@internal
- Approval: AUTO (no human review)

## Security Note
The v1.1 update introduced an outbound network call that was not present in the originally signed v1.0 release. The signature mismatch was logged but not blocked by the registry.
