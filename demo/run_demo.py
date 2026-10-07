"""Run equal-byte-budget offline retention experiments and save measured results."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import sys
from time import perf_counter
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.packet_parser import read_pcap, write_subset
from src.feature_extraction import extract
from src.selectors import budget_bytes, select
from src.evaluator import answer
from src.metrics import calculate
from src.visualization import summarize, report

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(input_path, truth_path, output, config, strategies=None):
    started = perf_counter()
    input_path, truth_path, output = Path(input_path), Path(truth_path), Path(output)
    capture = read_pcap(input_path)
    if not capture.packets:
        raise ValueError("Empty input capture has no experimental questions.")
    truth = json.loads(truth_path.read_text(encoding="utf-8-sig"))
    if truth.get("pcap_sha256") != digest(input_path):
        raise ValueError("Ground-truth manifest hash does not match input PCAP.")
    full = answer(capture.packets, truth, config)
    if full["coverage"] != 1:
        raise ValueError("Full-capture control fails the question catalogue. Correct truth/support before comparing.")
    caps = [budget_bytes(capture.size, fraction) for fraction in config["budgets"]]
    features_start = perf_counter()
    features = extract(capture.packets, config)
    feature_seconds = perf_counter() - features_start
    output.mkdir(parents=True, exist_ok=True)
    subset_dir = output / "selected"
    subset_dir.mkdir(exist_ok=True)
    (output / "config_used.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (output / "full_capture_answers.json").write_text(json.dumps(full, indent=2) + "\n", encoding="utf-8")
    metadata = [{"index": p.index, "timestamp_ns": p.timestamp_ns, "src": p.src, "dst": p.dst,
                 "sport": p.sport, "dport": p.dport, "protocol": p.protocol, "captured_bytes": len(p.data),
                 "record_bytes": p.cost, "payload_bytes": len(p.payload), "tcp_flags": p.flags}
                for p in capture.packets]
    with (output / "input_features.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(metadata[0]))
        writer.writeheader()
        writer.writerows(metadata)
    (output / "events.json").write_text(json.dumps({
        "scan_bins": [{"key": list(k), "observed_syns": len(v)} for k,v in features["scans"].items()],
        "matched_http_exchanges": len(features["http"]), "matched_dns_exchanges": len(features["dns"]),
        "handshake_count": len(features["handshakes"]),
        "alerted_flows": sorted(map(str,features["alerted_flows"])),
        "warning": "Full-input diagnostic metadata is not retained forensic evidence."
    }, indent=2) + "\n", encoding="utf-8")
    strategies = strategies or ["random", "alert", "evidence", "flow_prefix"]
    rows, question_rows, representative, subset_manifest = [], [], {}, {}
    for fraction, cap in zip(config["budgets"], caps):
        for strategy in strategies:
            seeds = config["random_seeds"] if strategy == "random" else [0]
            for trial_number, seed in enumerate(seeds):
                selection_start = perf_counter()
                selected, decisions = select(capture.packets, features, cap, strategy, seed, config)
                selection_seconds = perf_counter() - selection_start
                name = f"{strategy}_b{fraction:g}_seed{seed}"
                path = subset_dir / (name + ".pcap")
                selected_size = write_subset(capture, selected, path, cap)
                evaluation_start = perf_counter()
                retained = read_pcap(path)
                evaluation = answer(retained.packets, truth, config)
                evaluation_seconds = perf_counter() - evaluation_start
                metrics = calculate(capture, len(selected), selected_size, evaluation)
                row = {"strategy": strategy, "budget_fraction": fraction, "byte_cap": cap,
                       "seed": seed, "selected_packets": len(selected),
                       "selection_seconds": selection_seconds, "evaluation_seconds": evaluation_seconds,
                       "observed_unique_bulk_bytes": evaluation["observed_unique_bulk_bytes"], **metrics}
                rows.append(row)
                for q in evaluation["questions"]:
                    question_rows.append({"strategy": strategy, "budget_fraction": fraction, "seed": seed, **q})
                # Keep every trial subset for audit. This demo is small and all fit on a laptop.
                subset_manifest[name] = {"path": path.resolve().relative_to(ROOT).as_posix() if path.resolve().is_relative_to(ROOT) else str(path.resolve()),
                                         "sha256": digest(path), "source_packet_indices": sorted(selected),
                                         "bytes": selected_size, "byte_cap": cap}
                if trial_number == 0:
                    representative[name] = evaluation
                    (subset_dir / (name + ".decisions.json")).write_text(json.dumps(decisions, indent=2) + "\n", encoding="utf-8")
    with (output / "metrics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (output / "question_results.jsonl").open("w", encoding="utf-8") as stream:
        for row in question_rows:
            stream.write(json.dumps(row) + "\n")
    summary = summarize(rows)
    (output / "aggregate_metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "representative_answers.json").write_text(json.dumps(representative, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "executed_at_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
        "python": sys.version, "dataset_kind": truth["dataset_kind"], "input": str(input_path.resolve()),
        "input_relative": input_path.resolve().relative_to(ROOT).as_posix() if input_path.resolve().is_relative_to(ROOT) else None,
        "truth": str(truth_path.resolve()),
        "truth_relative": truth_path.resolve().relative_to(ROOT).as_posix() if truth_path.resolve().is_relative_to(ROOT) else None,
        "input_bytes": capture.size, "input_packets": len(capture.packets), "input_sha256": digest(input_path),
        "truth_sha256": digest(truth_path), "config_sha256": digest(output / "config_used.json"),
        "source_sha256": {p.relative_to(ROOT).as_posix(): digest(p) for folder in ("src", "demo")
                          for p in (ROOT / folder).glob("*.py")},
        "feature_seconds": feature_seconds, "elapsed_seconds_before_report": perf_counter() - started,
        "trials": len(rows), "full_capture_coverage": full["coverage"], "subsets": subset_manifest,
        "budget_scope": "Retained PCAP bytes only, including 24-byte header and 16-byte records; metadata/report overhead excluded.",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    report(summary, representative, manifest, output)
    manifest["total_elapsed_seconds"] = perf_counter() - started
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"SYNTHETIC / offline evidence experiment: {capture.size:,} original bytes; {len(capture.packets):,} packets")
    print("Cap    Strategy       Mean coverage    SD (pp)   Retained bytes")
    for r in summary:
        print(f'{100*r["budget_fraction"]:>4g}%  {r["strategy"]:<13} {100*r["mean_coverage"]:>9.2f}%'
              f' {100*r["sd_coverage"]:>10.2f} {r["mean_selected_bytes"]:>14.1f}')
    print(f"Trials: {len(rows)}; full capture: {full['answered']}/8; report: {output / 'report.html'}")
    return summary, manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/generated/demo.pcap")
    parser.add_argument("--truth", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "results/demo")
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    parser.add_argument("--budgets", nargs="+", type=float, help="Fractions such as 0.01 0.05 0.1 0.2 1")
    parser.add_argument("--random-runs", type=int)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8-sig"))
        if args.budgets:
            config["budgets"] = args.budgets
        if args.random_runs is not None:
            if args.random_runs < 1:
                raise ValueError("random-runs must be positive")
            config["random_seeds"] = list(range(args.random_runs))
        if not config["budgets"] or not config["random_seeds"]:
            raise ValueError("Configure at least one budget and random seed.")
        run(args.input, args.truth or args.input.with_suffix(".truth.json"), args.output, config)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, "Experiment failed: " + str(error) + "\n")

if __name__ == "__main__":
    main()
