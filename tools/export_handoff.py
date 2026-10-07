"""Export project sources, documents and complete primary evidence for continuation."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "logs/agent_handoff.zip"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def export():
    files = set()
    for path in ROOT.iterdir():
        if path.is_file():
            files.add(path)
    for folder in ("src", "demo", "tests", "tools", "docs", "data/generated",
                   "results/demo", "results/sensitivity", "logs"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                files.add(path)
    files = sorted(p for p in files if p.resolve().is_relative_to(ROOT)
                   and p != OUTPUT and p.name != "export_manifest.json"
                   and p.suffix != ".pyc")
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "kind": "COMPLETE_PRIMARY_EXPERIMENT_HANDOFF",
        "start_here": ["README.md", "logs/continuation_notes.md", "logs/action_log.md"],
        "scope": "Original references, source/configuration, documents including QA, synthetic data, all 165 primary subsets, primary and supplementary measurements, action/test logs.",
        "excluded": ["Machine-specific .venv and .qa-venv",
                     "Duplicate results/clean_environment",
                     "Diagnostic results/configuration_check and results/portable_audit_check",
                     "Python caches and this archive"],
        "supplementary_limit": "Only the final supplementary working subset was retained; rerun demo/run_sensitivity.py to reproduce supplementary measurements.",
        "files": {p.relative_to(ROOT).as_posix(): {"bytes": p.stat().st_size, "sha256": digest(p)}
                  for p in files},
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT).as_posix())
        archive.writestr("HANDOFF_MANIFEST.json", json.dumps(manifest, indent=2)+"\n")
    with zipfile.ZipFile(OUTPUT) as archive:
        assert archive.testzip() is None
        for name, info in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == info["sha256"], name
    manifest["archive_bytes"] = OUTPUT.stat().st_size
    manifest["archive_sha256"] = digest(OUTPUT)
    (ROOT / "logs/export_manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    print(f"Handoff saved: {OUTPUT}; {len(files)} files; {OUTPUT.stat().st_size:,} bytes; CRC and SHA-256 verified.")
    return manifest

if __name__ == "__main__":
    export()
