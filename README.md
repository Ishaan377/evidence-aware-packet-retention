# Evidence Aware Packet Retention Under Storage Budgets

A working, offline student research prototype for **Topic 2: selective PCAP retention and forensic evidence budgeting**. It compares how many predefined investigation answers survive when only a fixed number of PCAP bytes can be kept.

**Current status:** implemented and executed on clearly labelled synthetic traffic; suitable for a progress demonstration. This is an early experiment, not a validated production capture system or evidence of a real attack.

## Start here

- **New to GitHub?** Read [TEAM_START_HERE.md](TEAM_START_HERE.md) for inviting teammates, downloading and running the project.
- [All-in-one zero-to-hero beginner guide (29 pages)](docs/zero_to_hero_project_guide.docx) - exact commands, the 8 October professor demo, foundations, code, results, viva and future work. For a quick preparation, read pages 2-3, 17-18 and 26-27.
- [Progress-check script and actual findings](progress_check.md)
- [Professor explanation and viva answers](professor_explanation.md)
- [Final-project roadmap](final_project_roadmap.md)
- [Submission synopsis](docs/synopsis.docx)
- [Research formulation](docs/project_plan.md), [literature review](docs/literature_review.md), [source registry](docs/sources.json)
- [Question criteria](docs/forensic_question_catalogue.md)
- [Action log](logs/action_log.md) and [AI continuation notes](logs/continuation_notes.md)

The revised synopsis includes a visual architecture flowchart. Its Planned Completion column reproduces the reference's week/month labels as proposed milestones, with a note distinguishing them from completed work. All original reference files remain in the original project folder; the GitHub copy includes the original synopsis reference needed by its builder. The synopsis preserves their supplied team, course, guide and year details. Information Security Lab is retained; no college or department name has been invented.

## Run the demonstration

For a fresh GitHub download, use `py -3 run_project.py --check` on Windows or `python3 run_project.py --check` on macOS/Linux. This generates a complete local run, tests it and opens the report. The frozen example is [examples/default_run/report.html](examples/default_run/report.html). The repository excludes generated traffic/results, environments, render history and the full export archive; those remain in the original project folder. Commands below also work after downloading and recreate the original results paths.

The core needs **Python 3.10 or newer and no third-party packages**. There is no live capture, packet transmission, administrator requirement, ML model, database or web server.

From PowerShell in this project folder:

```powershell
python demo/generate_demo_pcap.py
python demo/run_demo.py
Start-Process ".\results\demo\report.html"
```

If Python is not on your PATH, the clean environment created and tested in this workspace can be used immediately:

```powershell
& ".\.venv\Scripts\python.exe" -B demo/generate_demo_pcap.py
& ".\.venv\Scripts\python.exe" -B demo/run_demo.py
Start-Process ".\results\demo\report.html"
```

For a fresh machine with Python installed, optionally create an isolated environment using `python -m venv .venv`, then use the second set of commands. Virtual environments are machine-specific and are excluded from the handoff archive. `requirements.txt` intentionally has no core dependencies.

The generator writes valid synthetic protocol packets to disk; it does not execute attacks or transmit traffic. Defaults produce 1,413 packets in 904,905 serialized PCAP bytes. The runner executes 165 trials: 30 random seeds plus three deterministic policies at five budgets. It saves a self-contained HTML report, SVG graphs, CSV/JSON records and every retained trial PCAP.

## Actual preliminary results

Coverage is the percentage of eight binary question criteria correctly preserved.

| PCAP cap | Random mean ± sample SD | Alert flows | Evidence bundles | Flow prefix |
|---:|---:|---:|---:|---:|
| 1% | 0.0% ± 0.0 pp | 50.0% | 87.5% | 0.0% |
| 5% | 2.5% ± 5.09 pp | 50.0% | 87.5% | 0.0% |
| 10% | 7.5% ± 7.04 pp | 62.5% | 100.0% | 37.5% |
| 20% | 15.0% ± 6.05 pp | 62.5% | 100.0% | 62.5% |
| 100% | 100.0% | 100.0% | 100.0% | 100.0% |

At 5%, the cap is 45,245 bytes; evidence selection retains 45,240 bytes and answers Q1–Q7. It cannot witness Q8's 65,536 unique payload-byte minimum because the entire byte budget is smaller than that payload threshold. Random mean coverage is 0.2 questions out of eight; the representative seed-zero trial answers zero. The full-capture control bypasses filtering when the complete capture fits.

These are executed observations on one designed trace. They do not establish performance on real networks or superiority over production IDS tools. Supplementary results in `results/sensitivity/` contain 1,188 executed trials over three generated variants and indicator/bundle ablations; only the final working supplementary subset is retained.

## How the pipeline works

```text
Classic PCAP → parse/flows → observable features → candidate bundles
             → equal byte-cap selection → retained PCAP
             → re-parse retained packets → question answers → metrics/report
```

The generator's separate truth file goes to the evaluator only. Selectors never receive event labels, expected answers or oracle packet indices.

Policies:

- **random:** seeded packet permutation, greedily packing whole records that fit. Size-dependent packing is not unbiased Bernoulli sampling.
- **alert:** configured SYN fan-out, HTTP-failure and destination-indicator rules mark flows; packets in those flows are packed in chronological order. This is an illustrative baseline, not an implementation of Suricata.
- **evidence:** scan sets/boundaries, matched HTTP/DNS pairs and internal TCP handshakes form candidate bundles. A greedy marginal evidence gain per added record byte, with diminishing category returns, chooses packets. Weights in `config.json` are explicit design choices; optimality is not claimed.
- **flow_prefix:** retain whole packets within the first 4,096 captured bytes of each bidirectional flow, then enforce the global cap. Inspired by Time Machine, not a faithful reproduction.

The strict cap counts the 24-byte classic PCAP header plus 16 bytes per packet record plus captured packet bytes. Original records, timestamps, lengths and capture header are preserved. Full input, feature CSVs, truth, manifests and reports are **outside** this cap. The experiment is an offline retention comparison, not a total-disk-budget deployment.

## Configuration and alternative input

Edit `config.json` for budgets, seeds, indicators, rule thresholds, category weights and flow-prefix length. Budgets are fractions, not percentages:

```powershell
python demo/run_demo.py --budgets 0.01 0.05 0.10 0.20 1 --random-runs 30 --output results/custom_run
python demo/run_demo.py --input data/generated/demo.pcap --truth data/generated/demo.truth.json --output results/custom_input
python demo/run_sensitivity.py
```

Use a new output directory for a custom experiment. Core HTML/SVG reports are generated on every run. The optional Matplotlib PNGs already supplied illustrate the default saved experiment; they are not automatically refreshed by the core runner.

The parser accepts supported classic PCAP input, but meaningful evaluation requires a matching truth file in the implemented schema and all eight reference criteria answerable from the full input. A hash mismatch or failing full-control aborts. An arbitrary public PCAP cannot be given this synthetic truth file.

Supported: classic PCAP 2.4, either byte order, micro/nanosecond timestamps, Ethernet link type 1, limited Ethernet/VLAN/IPv4/TCP/UDP/ICMP metadata, single-packet plain HTTP and matched DNS A transactions. Unsupported PCAPNG/link types fail explicitly. Unsupported packet protocols can be retained but do not contribute supported forensic fields. No IPv6 evidence evaluation, IP defragmentation, TCP stream reassembly, TLS decryption or TCP sequence-wrap support.

## Verification

Executed checks are recorded in `logs/`:

- 15 unit tests covering byte preservation/caps, invalid files, both endian/timestamp variants, missing sequence witnesses and retransmission counting.
- Audit of all 165 primary subsets: exact caps, original record preservation, hashes and fresh evaluation.
- Clean Python environment with no pip packages: identical packet/coverage/size outcomes.
- Independent Scapy 2.6.1 checks: packet fields/timestamps, recomputed checksums, known synthetic events, and raw bytes/caps for all 165 subsets.
- Visual inspection of all eight reference pages, all ten updated synopsis pages, all 29 beginner-guide pages and three scientific figures.

Run core checks:

```powershell
python -B -m unittest discover -s tests -v
python -B tools/audit_results.py
```

Optional independent validation and scientific figure generation:

```powershell
python -m venv .qa-venv
& ".\.qa-venv\Scripts\python.exe" -m pip install -r tools/requirements-qa.txt
& ".\.qa-venv\Scripts\python.exe" -B tools/check_with_scapy.py
& ".\.qa-venv\Scripts\python.exe" -B tools/plot_results.py
```

Pinned direct dependencies and the tested transitive environment are recorded under `tools/`. The existing optional environment is available locally.

## Important files

| Location | Purpose |
|---|---|
| `src/` | Understandable parser, features, scoring, selectors, evaluator, metrics and reporting |
| `demo/` | Deterministic offline generator, primary runner and supplementary experiments |
| `data/generated/` | Four synthetic PCAPs and separate truth files |
| `results/demo/report.html` | Main professor demonstration |
| `results/demo/metrics.csv`, `question_results.jsonl` | Every executed primary measurement |
| `results/demo/manifest.json` | Configuration, source/input/truth/subset hashes and timings |
| `results/demo/selected/` | All 165 retained captures and representative decision explanations |
| `results/clean_environment/` | Reproduced primary experiment |
| `results/sensitivity/` | Supplementary conditions, measurements and ablation figure |
| `docs/qa/` | Reference/final PDF renders, page images and template fidelity evidence |
| `docs/zero_to_hero_project_guide.docx` | Complete beginner guide and presentation preparation |
| `docs/assets/architecture_flowchart.png` | Visual architecture, also available as editable SVG |
| `tools/build_synopsis.py` | Rebuild using the reference package, structured content and requested visual flowchart |
| `tools/build_project_guide.py` | Rebuild the guide using authored content and saved actual metrics |
| `logs/` | Test evidence, action history and continuation record |

## Research boundary

Selective retention and forensic coverage already exist in the literature. Our defensible contribution is a small reproducible comparison of explicit retained-packet answers under equal serialized-byte caps. See the review before making any novelty claim.

Hashes detect changes; they do not supply a complete legal chain of custody. An HTTP 200, internal handshake or volume threshold does not prove compromise, lateral movement or exfiltration. Results are conditional on this scenario, evaluator support and hand-designed question catalogue.

For the next phase, strengthen the alert baseline, obtain an independently annotated lab/public capture, expand parser support and test whether conclusions survive scenarios not designed alongside the scorer. Follow the roadmap rather than adding unvalidated complexity.

## Export for another agent

The ready-made full archive described below is local to the original project folder. A GitHub download can create a new archive from its included files after generating any required experimental outputs.

The ready-to-export `logs/agent_handoff.zip` contains source, original references, documents/QA, synthetic data, all 165 primary retained PCAPs, measurements and action/test logs. A machine-readable inventory inside lists file hashes; `logs/export_manifest.json` records the archive hash. Machine-specific environments and duplicate diagnostic result directories are excluded. Refresh it after future changes with `python tools/export_handoff.py`. Another agent should begin with `logs/continuation_notes.md`.
