# Results you can view without downloading captures

The project tested Evidence-Based Retention (EBR) on 24.5 GB of public packet captures across three sealed tests. At a 5% storage cap, the attack signature results were:

| Test | Data | EBR alone | EBR with repair | IDS-triggered + fill |
|---|---:|---:|---:|---:|
| First | 11.3 GB | 91.7% | Not tested | 86.5% |
| Second | 7.0 GB | 94.4% | Not tested | 85.9% |
| Third | 6.1 GB | 84.7% | **99.6%** | 84.9% |

The [third sealed test report](final/results/forensic/sealed3/report.html) contains the charts, case-by-case table, hypothesis verdicts, and limitations. The [first](final/results/forensic/test/report.html) and [second](final/results/forensic/sealed2/report.html) reports cover the earlier tests. Download an HTML report and open it locally to view its rendered charts; GitHub's file page shows the HTML source.

The third test scored eight cases. Only one of five pre-registered hypotheses passed in full: repair improved on EBR alone at every tested cap. Repair beat IDS-triggered capture at 2%, 5%, and 10%; the 1% comparison was inconclusive. The scan-cap hypothesis failed its pre-registered test, and the blind-spot estimate could not be scored. These limits matter when explaining the 99.6% figure.

The [IEEE-format paper](report/EBR_IEEE_Paper.pdf) and [complete guide](report/EBR_Complete_Guide.pdf) explain the method and evaluation. The [demo report](final/results/forensic_demo/run_20261030_225721/report.html) shows a saved run on labelled attack data. That demo uses EBR alone and does not reproduce the repair result.

Raw PCAPs and generated run folders are excluded from GitHub. To run the code with public captures, follow [START_HERE.md](START_HERE.md). New runs write their own reports to `final/results/forensic_demo/`.
