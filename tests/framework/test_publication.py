"""Public builder archive must never package historical agent run output."""
from pathlib import Path, PurePosixPath
import zipfile
from harnesssafe.common import ROOT, file_hash, read_json

def test_public_legacy_archive_preserves_only_attested_builder_templates():
    path = ROOT / "runs/archive/legacy_v2_memory_evolution.zip"
    manifest = read_json(ROOT / "provenance/public-legacy-archive.json")
    assert file_hash(path) == manifest["public_sha256"]
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert set(names) == set(manifest["retained_members"])
        assert len(names) == 322
        for name in names:
            parts = PurePosixPath(name).parts
            assert not {"results", "agent_home", "bench_state", ".."} & set(parts)
            assert not name.endswith(("trace.jsonl", "honeypot.jsonl", "oracle.json"))
            assert __import__("hashlib").sha256(archive.read(name)).hexdigest() == manifest["retained_members"][name]
        assert sum(n.endswith("/case_meta.json") for n in names) == 114
