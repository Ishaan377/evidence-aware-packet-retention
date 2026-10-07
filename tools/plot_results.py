"""Render scientific figures from saved CSV/JSON using Matplotlib (optional QA)."""
import csv
import json
from pathlib import Path
from statistics import mean
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
output = ROOT / "results/demo"
rows = json.loads((output / "aggregate_metrics.json").read_text(encoding="utf-8"))
colors = {"random": "#63758a", "alert": "#d17c12", "evidence": "#237752", "flow_prefix": "#6256aa"}
labels = {"random": "Random mean ± SD", "alert": "Chronological alert flows", "evidence": "Evidence bundles", "flow_prefix": "Connection prefix"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                     "axes.spines.right": False, "svg.fonttype": "none"})
fig, axes = plt.subplots(1, 2, figsize=(12.4, 4.7), constrained_layout=True)
for ax, actual in zip(axes, (False, True)):
    for strategy in colors:
        group = sorted((r for r in rows if r["strategy"] == strategy and r["budget_fraction"] <= .2),
                       key=lambda r: r["budget_fraction"])
        xs = [r["mean_retention_percent"] if actual else r["budget_fraction"]*100 for r in group]
        ax.errorbar(xs, [r["mean_coverage"]*100 for r in group],
                    yerr=[r["sd_coverage"]*100 for r in group], marker="o", capsize=3,
                    color=colors[strategy], label=labels[strategy], linewidth=1.8, markersize=5)
    ax.set(ylim=(-3, 106), xlim=(0, 21),
           xlabel="Actual retained PCAP bytes (%)" if actual else "Configured PCAP byte cap (%)",
           ylabel="Correct question coverage (%)")
    ax.set_xticks([1, 5, 10, 20])
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.grid(axis="y", alpha=.22)
axes[0].set_title("Comparison under equal byte caps")
axes[1].set_title("Comparison by bytes actually retained")
axes[0].legend(loc="lower right", fontsize=9)
fig.suptitle("Synthetic PCAP experiment · 1,413 packets · 8 binary questions", fontsize=14)
fig.savefig(output / "coverage_comparison.png", dpi=180)
fig.savefig(output / "coverage_comparison.svg")
plt.close(fig)

answers = json.loads((output / "representative_answers.json").read_text(encoding="utf-8"))
matrix, row_labels = [], []
for budget in (.01, .05, .1, .2):
    for strategy in colors:
        result = answers[f"{strategy}_b{budget:g}_seed0"]
        matrix.append([int(q["answerable"]) for q in result["questions"]])
        row_labels.append(f"{100*budget:g}%   {strategy}")
fig, ax = plt.subplots(figsize=(8.2, 6.2), constrained_layout=True)
from matplotlib.colors import ListedColormap
ax.imshow(matrix, cmap=ListedColormap(["#f0e5df", "#398160"]), vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(8), [f"Q{i}" for i in range(1,9)])
ax.set_yticks(range(len(matrix)), row_labels)
ax.set_title("Question witnesses in actual retained PCAPs\nRepresentative random seed 0")
for row in range(len(matrix)):
    for col in range(8):
        ax.text(col, row, "YES" if matrix[row][col] else "NO", ha="center", va="center",
                fontsize=8, color="white" if matrix[row][col] else "#6d4c3e")
fig.savefig(output / "question_preservation.png", dpi=180)
fig.savefig(output / "question_preservation.svg")
plt.close(fig)

sensitivity = json.loads((ROOT / "results/sensitivity/aggregate_metrics.json").read_text(encoding="utf-8"))
fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharey=True, constrained_layout=True)
for ax, scenario in zip(axes, ("lower_background", "default_events_new_seed", "higher_background")):
    for mode, marker in (("normal","o"),("no_indicator","s"),("no_bundles","^")):
        group = sorted((r for r in sensitivity if r["scenario"] == scenario and r["mode"] == mode
                        and r["strategy"] == "evidence"), key=lambda r:r["budget_fraction"])
        ax.plot([100*r["budget_fraction"] for r in group], [100*r["mean_coverage"] for r in group],
                marker=marker, label=mode.replace("_"," "))
    ax.set_title(scenario.replace("_"," "), fontsize=10)
    ax.set(xlabel="Configured byte cap (%)", ylim=(60,104))
    ax.set_xticks([1,5,10,20])
    ax.grid(axis="y", alpha=.2)
axes[0].set_ylabel("Correct question coverage (%)")
axes[0].legend(fontsize=8, loc="lower right")
fig.suptitle("Synthetic sensitivity checks for the evidence heuristic", fontsize=13)
fig.savefig(ROOT / "results/sensitivity/evidence_sensitivity.png", dpi=180)
fig.savefig(ROOT / "results/sensitivity/evidence_sensitivity.svg")
print("Saved Matplotlib coverage, question-preservation and sensitivity figures.")
