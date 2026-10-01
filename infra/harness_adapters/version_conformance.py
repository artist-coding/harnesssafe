"""Explicit capability evidence for versions beyond inherited reviewed pins.

A matching version string alone never grants source/package capabilities.
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

def load_version_conformance(path: Path, *, harness: str, identity: object,
                             capability_names: tuple[str, ...]) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    identity_key = "source_commit" if harness == "hermes" else "package_sha256"
    required = {"schema_name", "schema_version", "harness_id", "harness_version",
                "launcher_sha256", identity_key, "generated_at", "capabilities"}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("Version conformance has missing or unknown fields")
    if (document["schema_name"] != "harnesssafe_native_version_conformance" or document["schema_version"] != 1
            or document["harness_id"] != harness or document["harness_version"] != identity.version
            or not identity.available):
        raise ValueError("Version conformance does not match the detected harness")
    for key in ("launcher_sha256", identity_key):
        value = document[key]
        size = 40 if key == "source_commit" else 64
        if (not isinstance(value, str) or len(value) != size or any(c not in "0123456789abcdef" for c in value)
                or value != getattr(identity, key)):
            raise ValueError(f"Version conformance identity mismatch: {key}")
    timestamp = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Version conformance timestamp needs timezone")
    entries = document["capabilities"]
    if not isinstance(entries, dict) or set(entries) != set(capability_names):
        raise ValueError("Version conformance must declare every native capability")
    for name, row in entries.items():
        if not isinstance(row, dict) or set(row) != {"status", "executed", "evidence", "reason"}:
            raise ValueError(f"Malformed capability: {name}")
        if row["status"] not in {"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"} or type(row["executed"]) is not bool:
            raise ValueError(f"Invalid capability status: {name}")
        if not isinstance(row["evidence"], list) or any(not isinstance(x, str) or not x.strip() for x in row["evidence"]):
            raise ValueError(f"Invalid capability evidence: {name}")
        if not isinstance(row["reason"], str):
            raise ValueError(f"Invalid capability reason: {name}")
        if row["status"] in {"SUPPORTED", "UNSUPPORTED"} and (not row["executed"] or not row["evidence"]):
            raise ValueError(f"Executed capability evidence required: {name}")
        if row["status"] == "SUPPORTED" and row["reason"]:
            raise ValueError(f"Supported capability contains failure: {name}")
        if row["status"] != "SUPPORTED" and not row["reason"].strip():
            raise ValueError(f"Capability exclusion reason required: {name}")
    return entries

def apply_version_conformance(capabilities, entries: dict, evidence_type, path: Path, *, help_capabilities: tuple[str, ...]):
    values = {}
    for name, row in entries.items():
        observed = getattr(capabilities, name)
        supported = row["status"] == "SUPPORTED" and (name not in help_capabilities or observed.supported)
        reason = "" if supported else row["reason"] or observed.reason or "Capability has not been validated"
        values[name] = evidence_type(supported, "version_conformance",
                                     str(path) + ":" + ",".join(row["evidence"]), reason)
    return type(capabilities)(**values)
