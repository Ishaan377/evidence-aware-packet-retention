# The EBR code, data and results

Evidence-Based Retention is explained in [EBR_ALGORITHM.md](../EBR_ALGORITHM.md), and from first principles in the [complete guide](../report/EBR_Complete_Guide.pdf). Everything here needs Python 3.10+ and the standard library only.

| File | Purpose |
|---|---|
| `ebr/` | The algorithm, comparators, Suricata harness and reports |
| `ebr/verify.py`, `verify_before_delete.py`, `verify_summary.py` | The verify-before-delete loop |
| `ebr_config.json` | Settings of the current version |
| `ebr_config_frozen.json`, `archive/ebr_frozen_20261030.zip` | The first sealed version, kept for replay and comparison |
| `archive/ebr_v2_20261030.zip` | The code of the second sealed test |
| `FREEZE_v3.json`, `FREEZE_v2.json`, `FREEZE.json`, `freeze.py` | Hashes taken before each sealed test was opened |
| `forensic_cases.json`, `forensic_truth.json` | Cases and the publisher's attack schedule |
| `forensic_test.py` | The main test harness |
| `forensic_demo.py` | The demonstration |
| `sealed3_plan.json`, `run_sealed3.py`, `build_report_v3.py` | The third sealed study, with its pre-registered plan |
| `run_sealed2.py`, `build_report_v2.py` | The second sealed study |
| `run_frozen_test.py`, `build_report.py` | The first sealed study |
| `fetch_forensic_data.py`, `pcapng_to_pcap.py` | Fetching captures, and lossless conversion for PCAPNG input |
| `lab/` | Suricata lab setup and helpers |
| `tests/test_ebr.py` | The 45 automated tests |
| `data/forensic/` | Downloaded captures for the three sealed tests; not published in GitHub |
| `data/downloads/` | Local development captures; not published in GitHub |
| `results/forensic/` | Published reports and summaries, plus local generated test data |
| `results/forensic_demo/` | Published demo reports, plus local generated runs |

## Good to know

- `freeze.py check v3` must keep passing. Editing a frozen file invalidates the seal and needs a fresh sealed test. All three test sets have now been seen, so they cannot serve as sealed data again.
- WRCCDC parts are joined into `merged/continuous.pcap` the first time a case runs, and the join is rebuilt automatically if it is missing.
- A clean checkout has no reference scans of original captures. `forensic_demo.py` creates them on its first run, then reuses them.
- `tests/test_ebr.py` needs no captures and no lab.
- Development captures other than the three in `data/downloads/` are not stored here. `fetch_forensic_data.py` can fetch them again.
