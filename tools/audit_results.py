"""Verify saved trial subsets against input and recompute question metrics."""
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.packet_parser import read_pcap
from src.evaluator import answer

def audit(output):
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    config = json.loads((output / "config_used.json").read_text(encoding="utf-8"))
    input_path = ROOT / manifest["input_relative"] if manifest.get("input_relative") else Path(manifest["input"])
    truth_path = ROOT / manifest["truth_relative"] if manifest.get("truth_relative") else Path(manifest.get("truth", str(input_path.with_suffix(".truth.json"))))
    assert hashlib.sha256(input_path.read_bytes()).hexdigest() == manifest["input_sha256"]
    assert hashlib.sha256(truth_path.read_bytes()).hexdigest() == manifest["truth_sha256"]
    original = read_pcap(input_path)
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    metrics = list(csv.DictReader((output / "metrics.csv").open(encoding="utf-8")))
    assert len(metrics) == manifest["trials"]
    for row in metrics:
        name = f'{row["strategy"]}_b{float(row["budget_fraction"]):g}_seed{row["seed"]}'
        info = manifest["subsets"][name]
        path = ROOT / info["path"]
        retained = read_pcap(path)
        assert path.stat().st_size <= info["byte_cap"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == info["sha256"]
        assert [p.record for p in retained.packets] == [original.packets[i].record for i in info["source_packet_indices"]]
        evaluation = answer(retained.packets, truth, config)
        assert evaluation["answered"] == int(row["answered"])
        assert evaluation["coverage"] == float(row["coverage"])
        assert evaluation["observed_unique_bulk_bytes"] == int(row["observed_unique_bulk_bytes"])
    print(f'AUDIT PASSED: {len(metrics)} retained captures; cap, input/truth/subset hashes, exact records, fresh re-evaluation.')
    return len(metrics)

if __name__ == "__main__":
    audit(sys.argv[1] if len(sys.argv) > 1 else ROOT / "results/demo")
