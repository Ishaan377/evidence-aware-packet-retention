# Professor progress check

Project: **Evidence Aware Packet Retention Under Storage Budgets**  
Status recorded: 7 October 2026. Information Security Lab / ICT3141.

## What has been completed

- Independently reviewed 18 research/standards/tool/vendor sources and corrected the supplied unsupported novelty claim. Access limits are recorded.
- Defined four research questions, eight binary forensic criteria and byte-exact metrics.
- Built a modular, dependency-free offline Python MVP: PCAP parsing, features, four selectors, retained-PCAP writing, fresh evaluation, metrics, plots and an HTML report.
- Generated file-only synthetic traffic with valid packet checksums and a separate truth manifest.
- Executed 165 primary trials and 1,188 supplementary sensitivity/ablation trials.
- Passed 15 unit tests, all-primary-subset audits, clean-environment reproduction and independent Scapy packet/checksum/subset verification.
- Created the synopsis using the reference's 16 sections and exact supplied submission details. Visually inspected all nine final pages.
- Saved source code, data, raw measurements, plots, hashes, actions and continuation instructions locally.

This is assistant-produced prototype work that the team must study and validate. Do not present it as months of prior team development or a finished research study.

## What can be demonstrated

Allow about five minutes. Use the existing tested `.venv` if the normal `python` command is unavailable.

1. State the problem: storage limits force packet deletion, and deleting one packet can break a multi-packet investigation answer.
2. Show `docs/forensic_question_catalogue.md`: eight precise criteria, not a vague “security score.”
3. Run `python demo/generate_demo_pcap.py`. Show **SYNTHETIC ONLY**, 1,413 packets and 904,905 bytes. No traffic is transmitted.
4. Run `python demo/run_demo.py`. Show four strategies under identical byte caps and the 100% control.
5. Open `results/demo/report.html` in a browser. Explain the coverage graph and random error bars.
6. At 5%, show evidence's 7/8 versus alert's 4/8 and random's mean 0.2/8. Show the representative answer tables; Q8 is missing because 45,245 total bytes cannot contain 65,536 payload bytes.
7. Show `results/demo/selected/evidence_b0.05_seed0.pcap` and its `.decisions.json`. The retained file is 45,240 bytes, below the 45,245 cap. Decision records expose why witnesses were kept.
8. Show the 10% evidence result: 8/8, with 75,600 retained unique bulk payload bytes. This witnesses a lower bound, not the full original 300,000-byte transfer.
9. Show test logs and the synopsis; finish with limitations and the next independent evaluation.

Before the visit, open the report and documents once. The experiment can run without internet, third-party packages or a live network. Optional Wireshark is only for inspecting the already generated files.

## Preliminary results

One designed synthetic trace; eight binary questions; random seeds 0–29. “pp” means percentage points. These are actual saved measurements.

| Cap | Random coverage mean ± SD | Alert | Evidence | Prefix |
|---:|---:|---:|---:|---:|
| 1% | 0.0% ± 0.0 pp | 50.0% | 87.5% | 0.0% |
| 5% | 2.5% ± 5.09 pp | 50.0% | 87.5% | 0.0% |
| 10% | 7.5% ± 7.04 pp | 62.5% | 100.0% | 37.5% |
| 20% | 15.0% ± 6.05 pp | 62.5% | 100.0% | 62.5% |
| 100% | 100.0% | 100.0% | 100.0% | 100.0% |

At 5%: evidence 45,240 bytes; alert 45,192; random mean 45,213.2; prefix 45,217. Attained sizes are close but not forced identical because whole packets cannot always exactly fill the same cap.

Supplementary mechanism checks: removing the known-destination indicator loses the bulk-byte criterion even at 20%; disabling bundles lowers evidence coverage on these generated variants. Increasing background changes the absolute bytes available at a fixed percentage. These are not independent real-network validation.

Evidence files: `results/demo/metrics.csv`, `question_results.jsonl`, `aggregate_metrics.json`, `manifest.json` and `results/sensitivity/design.json`.

## What remains

- Independently annotated traffic from a controlled lab or properly licensed public dataset.
- Stronger alert policies, especially event-balanced allocation and pre/post-alert context.
- Protocol stream reassembly and supported capture-format expansion.
- More varied, unseen scenarios; uncertainty across scenarios rather than only random seeds.
- Weight/budget sensitivity and more detailed cost/scale measurements.
- Final methodology freeze, report, presentation and reproducible final release.

## Known limitations

The question catalogue and scorer were designed together, creating selection bias even though the selectors never receive truth labels. Chronological alert packing is a weak illustrative baseline and can exhaust the cap on early events. The prefix comparison is simplified.

Only supported packet witnesses count. There is no TCP reassembly/TLS decryption/IPv6 evidence evaluation; selected captures can contain partial sessions. Exact counts and interval boundaries match the complete observed trace, not an unknown real incident.

The cap covers each retained PCAP only. Keeping full input, truth and diagnostic reports during experiments does not demonstrate a deployed total-storage saving. Ratios such as coverage per byte can reward cheap questions; present raw coverage and bytes first. No result proves attribution, compromise, exfiltration or legal admissibility.

## Next research steps

Ask the professor to review the operational criteria and baseline fairness. Freeze an independently chosen test catalogue before selecting new traffic. Evaluate stronger baselines and a held-out capture, then expand technical support where actual missed witnesses justify it. Use `final_project_roadmap.md` for deliverables and exit checks.
