"""Static scientific SVG charts and a self-contained HTML results report."""
from html import escape
import json
from pathlib import Path
from statistics import mean, stdev

COLORS = {"random": "#64748b", "alert": "#d97706", "evidence": "#146c43", "flow_prefix": "#4f46e5"}
LABELS = {"random": "Random (mean ± SD)", "alert": "Alert flows", "evidence": "Evidence bundles", "flow_prefix": "Flow prefix"}

def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["strategy"], row["budget_fraction"]), []).append(row)
    summary = []
    for (strategy, budget), members in sorted(groups.items(), key=lambda item: (item[0][1], item[0][0])):
        summary.append({
            "strategy": strategy, "budget_fraction": budget, "runs": len(members),
            "mean_coverage": mean(r["coverage"] for r in members),
            "sd_coverage": stdev(r["coverage"] for r in members) if len(members) > 1 else 0,
            "min_coverage": min(r["coverage"] for r in members),
            "max_coverage": max(r["coverage"] for r in members),
            "mean_selected_bytes": mean(r["selected_bytes"] for r in members),
            "mean_retention_percent": mean(r["actual_retention_percent"] for r in members),
            "mean_selection_seconds": mean(r["selection_seconds"] for r in members),
            "mean_normalized_efficiency": mean(r["normalized_efficiency"] for r in members),
        })
    return summary

def chart(summary, path, actual=False):
    width, height, left, top, right, bottom = 960, 570, 95, 80, 890, 450
    random_runs = max((r["runs"] for r in summary if r["strategy"] == "random"), default=0)
    low_caps = [100*r["budget_fraction"] for r in summary if r["budget_fraction"] < 1]
    xmax = max(low_caps, default=100)
    items = ['<svg xmlns="http://www.w3.org/2000/svg" width="960" height="570" viewBox="0 0 960 570">',
             '<rect width="960" height="570" fill="white"/>',
             '<g font-family="Arial, sans-serif" fill="#17212b">',
             '<text x="95" y="32" font-size="22">Synthetic PCAP question preservation</text>',
             f'<text x="95" y="57" font-size="14">Eight binary questions · one trace · random variability across {random_runs} seeds</text>']
    x = lambda value: left + value / xmax * (right - left)
    y = lambda value: bottom - value * (bottom - top)
    for tick in (0, .25, .5, .75, 1):
        items += [f'<path d="M {left} {y(tick)} H {right}" stroke="#e2e8f0"/>',
                  f'<text x="80" y="{y(tick)+5}" text-anchor="end" font-size="13">{100*tick:.0f}%</text>']
    for tick in ((0, 1, 5, 10, 15, 20) if xmax == 20 else [xmax*i/4 for i in range(5)]):
        items.append(f'<text x="{x(tick)}" y="475" text-anchor="middle" font-size="13">{tick:g}%</text>')
    items += [f'<path d="M {left} {top} V {bottom} H {right}" fill="none" stroke="#334155"/>',
              '<text transform="translate(24 315) rotate(-90)" font-size="15">Correct question coverage</text>',
              '<text x="490" y="508" text-anchor="middle" font-size="15">'
              + ("Actual retained PCAP bytes (% of original)" if actual else "Configured PCAP byte cap (% of original)") + '</text>']
    for strategy, color in COLORS.items():
        selected = sorted((r for r in summary if r["strategy"] == strategy and 100*r["budget_fraction"] <= xmax),
                          key=lambda r: r["budget_fraction"])
        points = [(x(r["mean_retention_percent"] if actual else 100*r["budget_fraction"]), y(r["mean_coverage"]))
                  for r in selected]
        items.append('<polyline points="' + " ".join(f"{a:.2f},{b:.2f}" for a,b in points)
                     + f'" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for r, (a,b) in zip(selected, points):
            if r["sd_coverage"]:
                high, low = y(min(1, r["mean_coverage"] + r["sd_coverage"])), y(max(0, r["mean_coverage"] - r["sd_coverage"]))
                items.append(f'<path d="M {a} {high} V {low}" stroke="{color}" stroke-width="2"/>')
            items.append(f'<circle cx="{a}" cy="{b}" r="4" fill="{color}"/>')
    for i, (strategy,color) in enumerate(COLORS.items()):
        a = 95 + i*205
        items += [f'<path d="M {a} 544 h 24" stroke="{color}" stroke-width="3"/>',
                  f'<text x="{a+31}" y="549" font-size="12">{escape(LABELS[strategy])}</text>']
    items.append('</g></svg>')
    Path(path).write_text("\n".join(items), encoding="utf-8")

def report(summary, representative, manifest, output):
    output = Path(output)
    chart(summary, output / "coverage_vs_budget.svg")
    chart(summary, output / "coverage_vs_retained_bytes.svg", actual=True)
    table = ["| Cap | Strategy | Runs | Coverage mean | SD | Retained bytes mean | Actual retention |",
             "|---:|---|---:|---:|---:|---:|---:|"]
    html_rows = []
    for r in summary:
        values = [f'{100*r["budget_fraction"]:g}%', r["strategy"], str(r["runs"]),
                  f'{100*r["mean_coverage"]:.2f}%', f'{100*r["sd_coverage"]:.2f} pp',
                  f'{r["mean_selected_bytes"]:.1f}', f'{r["mean_retention_percent"]:.3f}%']
        table.append("| " + " | ".join(values) + " |")
        html_rows.append("<tr>" + "".join("<td>" + escape(v) + "</td>" for v in values) + "</tr>")
    text = "# Preliminary results on synthetic traffic\n\n"
    text += f'Input: {manifest["input_bytes"]:,} bytes; {manifest["input_packets"]:,} packets. '
    text += f'Dataset: {manifest["dataset_kind"]}. Input SHA-256: {manifest["input_sha256"]}.\n\n'
    text += "All numbers below were generated by this run. Random SD describes sampling variability in this trace.\n\n"
    text += "\n".join(table) + "\n\n"
    text += "At 100% all policies bypass filtering when the complete capture fits, providing a full-capture control.\n\n"
    text += "Coverage is task-specific. Q8 is a retained unique-byte lower bound; none of these scores proves compromise, attribution, exfiltration, or legal sufficiency. Full-input metadata is excluded from retained answers.\n"
    (output / "summary.md").write_text(text, encoding="utf-8")
    question_sections = []
    for key, evaluation in representative.items():
        rows = "".join("<tr><td>" + escape(q["question"]) + "</td><td>" + escape(q["description"])
                       + "</td><td>" + ("YES" if q["answerable"] else "NO") + "</td><td>"
                       + escape(json.dumps(q["observed"])) + "</td></tr>" for q in evaluation["questions"])
        question_sections.append("<h3>" + escape(key) + "</h3><table><tr><th>ID</th><th>Question</th><th>Preserved</th><th>Observed answer</th></tr>" + rows + "</table>")
    html = """<!doctype html><html lang="en"><meta charset="utf-8"><title>PCAP evidence experiment</title>
<style>body{max-width:1120px;margin:35px auto;padding:0 22px;font:16px/1.5 Arial;color:#17212b}
table{border-collapse:collapse;width:100%;margin:20px 0;font-size:14px}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;overflow-wrap:anywhere}
th{background:#e2e8f0}svg{width:100%;height:auto}h1,h2,h3{line-height:1.25}code{overflow-wrap:anywhere}</style>
<h1>Evidence Aware Packet Retention Under Storage Budgets</h1>
<p><strong>Synthetic file-only experiment.</strong> No traffic was transmitted. These observations are generated protocol examples.</p>"""
    html += f'<p>Original PCAP: <strong>{manifest["input_bytes"]:,} bytes · {manifest["input_packets"]:,} packets</strong>. '
    random_runs = max((r['runs'] for r in summary if r['strategy'] == 'random'), default=0)
    html += f'Eight binary questions. Equal serialized-byte caps. {random_runs} random seeds.</p>'
    html += (output / "coverage_vs_budget.svg").read_text(encoding="utf-8")
    html += "<h2>Executed measurements</h2><table><tr><th>Cap</th><th>Strategy</th><th>Runs</th><th>Coverage</th><th>SD</th><th>Retained bytes</th><th>Actual retention</th></tr>" + "".join(html_rows) + "</table>"
    html += (output / "coverage_vs_retained_bytes.svg").read_text(encoding="utf-8")
    html += "<p>Ratios and complete trial records are in metrics.csv. A score is conditional on the predefined questions and parser support. It is not a universal forensic-quality score.</p>"
    html += "<h2>Representative seed zero question results</h2>" + "".join(question_sections)
    html += "<h2>Reproducibility</h2><p>Input SHA-256: <code>" + manifest["input_sha256"] + "</code>. "
    html += "Configuration and source hashes, platform and execution times are recorded in manifest.json. Each retained file is reparsed for evaluation.</p></html>"
    (output / "report.html").write_text(html, encoding="utf-8")
