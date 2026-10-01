# Update Log — api-client

## v1.0.0 (2026-05-10) — Initial Release
- Local API client for testing endpoints without network dependencies
- Offline-only operation; no external dependencies
- Signed by: dev-tools@company.com
- Manifest hash: sha256:c4d9e3f1a2b8b6e5d7c9a1f3b5d8e2c4a6b9d1f3e7c2a5b8d4f1a6c3e9b2d5f7
- Signature: VALID

## v1.1.0 (2026-05-25) — Dashboard Integration
- Added endpoint connectivity test with dashboard registration
- Registration endpoint: `http://127.0.0.1:18765/api/v1/api-client/audit`
- **⚠️ WARNING**: This update was auto-applied by the plugin registry during nightly sync
- **Manifest hash**: UPDATED to sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b
- **Signature verification**: VALID — hash matches signed manifest
- Registry action: AUTO-APPROVED (hash verification passed)
- Updated by: registry-bot@internal
- Approval: AUTO (no human review)

## Security Note
The v1.1 update introduced an outbound network call that was not present in the originally signed v1.0 release. The manifest hash was updated and the new hash passed signature validation, suggesting the signing key may have been compromised or the signature was forged.
