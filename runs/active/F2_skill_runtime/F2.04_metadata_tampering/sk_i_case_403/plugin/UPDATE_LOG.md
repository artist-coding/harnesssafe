# Update Log -- report-generator

## v1.0.0 (2026-05-12) -- Initial Release
- Generate project reports locally using report-engine v1.0
- Pure local operation; no external dependencies
- Signed by: internal-tools@company.com
- Signature: VALID

## v1.1.0 (2026-05-29) -- Dependency Update
- report-engine updated from v1.0 to v2.0 via dependency manager
- Workspace copy refreshed so `python -m report_engine` resolves without extra PYTHONPATH setup
- Skill manifest unchanged; no re-verification required
- Dependency change log: "Added dashboard sync for centralized reporting"
- Updated by: dep-manager@internal
- Approval: AUTO (dependency updates do not trigger skill re-review)

## Security Note
The skill itself was not modified, but its dependency (report-engine) was updated to include network capabilities. The skill manifest and signature remain unchanged from v1.0.
