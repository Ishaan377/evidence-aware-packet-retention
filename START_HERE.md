# Start here

**Evidence-Based Retention (EBR)** reduces packet captures to a fixed storage cap without signatures, then a real IDS investigates what is left. Across three sealed tests, EBR alone kept 85–94% of attack signatures at a 5% cap. A verify-before-delete loop raised that to 99.6% in the third test, against 84.9% for IDS-triggered capture.

| What you want | Where to go |
|---|---|
| Learn the whole project from zero | [report/EBR_Complete_Guide.pdf](report/EBR_Complete_Guide.pdf) |
| Read the IEEE-format paper | [report/EBR_IEEE_Paper.pdf](report/EBR_IEEE_Paper.pdf) |
| Understand the algorithm and prepare for the viva | [EBR_ALGORITHM.md](EBR_ALGORITHM.md) |
| See the latest results and verdicts | [final/results/forensic/sealed3/report.html](final/results/forensic/sealed3/report.html) |
| Read the results directly on GitHub | [RESULTS.md](RESULTS.md) |
| See the second sealed test | [final/results/forensic/sealed2/report.html](final/results/forensic/sealed2/report.html) |
| See the first sealed test | [final/results/forensic/test/report.html](final/results/forensic/test/report.html) |
| See finished demonstrations without running anything | `final/results/forensic_demo/` |
| Read the code | [final/ebr/](final/ebr/) |

## Run the demonstration

Double-click `Run_FORENSIC_DEMO.cmd`, or run these from this folder:

```powershell
python -B final/forensic_demo.py --quick       # one 1.5 GB case
python -B final/forensic_demo.py               # 11.3 GB with labelled attacks, 5% cap
python -B final/forensic_demo.py --sealed      # 7 GB the algorithm never saw during tuning
python -B final/forensic_demo.py --cap 0.02    # a harder cap
```

The demonstration runs EBR alone, without the repair loop, so its numbers are not the 99.6% result. A first run from a clean clone also scans the original capture to create reference alerts; later runs reuse that scan. This can take substantially longer than the roughly one-minute quick reduction on the original machine. WRCCDC cases rebuild a joined capture the first time they run, which takes a moment and about 1 to 2.5 GB of disk space per case.

## Check the work

```powershell
python -B -m unittest final/tests/test_ebr.py  # the 45 EBR tests
python -B final/freeze.py check v3             # recompute the third test's seal
```

## Set up on a new Windows PC

Install Python 3.10 or newer and WSL 2. The demonstration needs a separate Suricata lab. From the project folder, create it once, then fetch the quick case (about 1.5 GB of capture data):

```powershell
powershell -ExecutionPolicy Bypass -File final\lab\setup_lab.ps1
python -B final/fetch_forensic_data.py --case test_bot_mar02
python -B final/forensic_demo.py --quick
```

To fetch the entire public test set instead, run `python -B final/fetch_forensic_data.py --split test`. The default fetch command downloads every case across all splits, so it needs much more time and disk space. New demo output is saved under `final/results/forensic_demo/run_YYYYMMDD_HHMMSS/`; open its `report.html` in a browser.
