# Evidence-Based Retention (EBR)

EBR reduces packet captures to a fixed storage cap while keeping the evidence an investigator needs. It uses no signatures, labels or training data. A second idea, **verify before delete**, checks what a reduction lost while the original still exists, and repairs it inside the same budget.

Information Security Lab (ICT3141) project by Ishaan Suresh Mullya, Shriya P Reddy and Om KB. Faculty guide: Dr. Adesh ND.

## Start here

| What you want | Where to go |
|---|---|
| Learn everything from the basics | [report/EBR_Complete_Guide.pdf](report/EBR_Complete_Guide.pdf) (83 pages, for complete beginners) |
| Read the research paper | [report/EBR_IEEE_Paper.pdf](report/EBR_IEEE_Paper.pdf) (IEEE conference format) |
| Technical summary and viva answers | [EBR_ALGORITHM.md](EBR_ALGORITHM.md) |
| Results on GitHub | [RESULTS.md](RESULTS.md) |
| Latest results | [final/results/forensic/sealed3/report.html](final/results/forensic/sealed3/report.html) |
| Run the demonstration | Double-click `Run_FORENSIC_DEMO.cmd`, or see [START_HERE.md](START_HERE.md) |
| Read the code | [final/ebr/](final/ebr/), described in [final/README.md](final/README.md) |

## Results

Suricata 7.0.3 with 52,778 ET Open rules judged what survived, across three sealed tests on 24.5 GB of public captures. EBR never saw those rules.

| Attack signatures kept at a 5% cap | Data | EBR alone | EBR with repair | IDS-triggered + fill |
|---|---|---:|---:|---:|
| First sealed test | 11.3 GB | 91.7% | not tested | 86.5% |
| Second sealed test | 7.0 GB | 94.4% | not tested | 85.9% |
| Third sealed test, pre-registered | 6.1 GB | 84.7% | **99.6%** | 84.9% |

Only one of the five pre-registered hypotheses in the third test passed in full. Repair beat EBR alone at every cap, and it beat IDS-triggered capture at 2%, 5% and 10%, with 1% inconclusive. The scan cap failed its test, and the blind-spot estimate could not be scored. The test has only 8 scored cases, so this is strong evidence and not proof.

## Requirements

Python 3.10 or newer, with no third-party packages for the Python code. The demonstration also needs the Suricata lab in WSL 2 and public packet captures, which are downloaded separately. [START_HERE.md](START_HERE.md) has the setup and quick-run commands. The small published reports are included; raw captures and generated run files are not.
