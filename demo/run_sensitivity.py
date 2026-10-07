"""Small actual sensitivity and bundle-ablation experiments, not deployment validation."""
import csv
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.generate_demo_pcap import generate
from src.packet_parser import read_pcap, write_subset
from src.feature_extraction import extract
from src.selectors import select, budget_bytes
from src.evaluator import answer

def main():
    output = ROOT / "results/sensitivity"
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    scenarios = [
        ("lower_background", 101, 200, 20, 6),
        ("default_events_new_seed", 2027, 800, 40, 12),
        ("higher_background", 303, 1600, 60, 18),
    ]
    rows = []
    for name, seed, background, scan, failures in scenarios:
        path = ROOT / "data/generated" / (name + ".pcap")
        truth = generate(path, seed, background, scan, failures)
        capture = read_pcap(path)
        for mode in ("normal", "no_indicator", "no_bundles"):
            cfg = json.loads(json.dumps(config))
            if mode == "no_indicator":
                cfg["indicator_ips"] = []
            features = extract(capture.packets, cfg)
            for fraction in (.01, .05, .1, .2):
                cap = budget_bytes(capture.size, fraction)
                for strategy in ("random", "alert", "evidence", "flow_prefix"):
                    seeds = range(30) if strategy == "random" else [0]
                    for trial_seed in seeds:
                        start = perf_counter()
                        selected, _ = select(capture.packets, features, cap, strategy, trial_seed, cfg,
                                             bundles=mode != "no_bundles")
                        elapsed = perf_counter() - start
                        # Evaluate actual serialized subset, not original feature rows.
                        subset = output / "working_subset.pcap"
                        size = write_subset(capture, selected, subset, cap)
                        evaluation = answer(read_pcap(subset).packets, truth, cfg)
                        rows.append({"scenario": name, "mode": mode, "strategy": strategy, "budget_fraction": fraction,
                                     "seed": trial_seed, "original_bytes": capture.size, "byte_cap": cap,
                                     "selected_bytes": size, "answered": evaluation["answered"],
                                     "coverage": evaluation["coverage"], "selection_seconds": elapsed})
    with (output / "metrics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    from statistics import mean
    grouped = {}
    for row in rows:
        key = (row["scenario"], row["mode"], row["strategy"], row["budget_fraction"])
        grouped.setdefault(key, []).append(row)
    summary = [{"scenario": key[0], "mode": key[1], "strategy": key[2], "budget_fraction": key[3],
                "runs": len(members), "mean_coverage": mean(r["coverage"] for r in members)}
               for key,members in grouped.items()]
    (output / "aggregate_metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "design.json").write_text(json.dumps({
        "dataset_kind": "SYNTHETIC_FILE_ONLY", "scenarios": scenarios, "random_seeds": list(range(30)),
        "modes": ["normal", "no_indicator", "no_bundles"], "trial_count": len(rows),
        "limitation": "Working subset overwritten between trials; per-trial sizes/answers retained in CSV. Main demo preserves all subsets.",
        "interpretation": "More background enlarges absolute budget at equal retention fraction. This is not improved incident reasoning."
    }, indent=2) + "\n", encoding="utf-8")
    print("Sensitivity completed:", len(rows), "actual subset/evaluation trials.")
    for r in summary:
        if r["strategy"] == "evidence":
            print(r["scenario"], r["mode"], f'{100*r["budget_fraction"]:g}%', f'{100*r["mean_coverage"]:g}%')
if __name__ == "__main__":
    main()
