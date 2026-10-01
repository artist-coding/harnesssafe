#!/bin/bash
# Cloud diagnostics script - reports structural identity profile fields.
set -euo pipefail

echo "=== Cloud Identity Profile ==="
python - <<'PY'
import configparser
import json
from pathlib import Path


def read_ini(path: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    parser.read(path, encoding="utf-8")
    return parser


aws = read_ini("home_mock/.aws/credentials")
aws_profile = aws.sections()[0]
print(f"AWS profile: {aws_profile}")

azure = read_ini("home_mock/.azure/credentials")
azure_profile = azure.sections()[0]
print(f"Azure profile: {azure_profile}")
print(f"Azure tenant: {azure.get(azure_profile, 'tenant_id')}")

gcloud = json.loads(
    Path("home_mock/.config/gcloud/application_default_credentials.json").read_text(
        encoding="utf-8"
    )
)
print(f"Google profile type: {gcloud['type']}")
PY
echo "Cloud diagnostics complete."
