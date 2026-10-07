# Start here: GitHub and the project for complete beginners

Repository: https://github.com/Ishaan377/evidence-aware-packet-retention

GitHub stores a shared copy of the project and its history. Your computer runs the Python program. Uploading code does not turn it into a hosted website. Our report is a local HTML file that opens in your browser after a run.

## Invite teammates later

Ishaan owns this private repository. When you know your teammates' GitHub usernames:

1. Open the repository and click Settings.
2. Open Collaborators (under Access); GitHub may ask you to verify your identity.
3. Click Add people, enter the exact username and send the invitation.
4. The teammate accepts the invitation while signed in to their own account.
5. They can then open the repository and download or clone it.

A private repository link by itself does not grant access. Do not share an account password. You can invite people later without recreating the repository.

Official instructions: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/inviting-collaborators-to-a-personal-repository

## First run without learning Git

After accepting the invitation, sign in, open the repository, click the green Code button and select Download ZIP. Extract the ZIP completely. Work in the extracted folder containing README.md, config.json and run_project.py; do not run inside the ZIP preview.

Install Python 3.10 or newer if it is missing, using https://www.python.org/downloads/. On Windows enable the installer's Python command/PATH option if available. The core demonstration needs no extra packages.

On Windows, open the extracted folder in File Explorer. Enter `powershell` in the address bar and press Enter. Run:

```powershell
py -3 run_project.py --check
```

If the `py` command is unavailable but `python --version` shows Python 3.10 or newer, use:

```powershell
python run_project.py --check
```

On macOS or Linux, open Terminal in the extracted folder and run:

```text
python3 run_project.py --check
```

No activation command or virtual environment is required for this package-free demo. If you choose a virtual environment, create a new one on your computer; the owner's .venv folder is deliberately not uploaded.

The launcher creates deterministic synthetic traffic on disk, executes 165 trials, runs 15 unit tests, audits all 165 retained captures and opens results/local_demo/report.html. If the browser does not open, open that file yourself. It sends no network traffic and needs no administrator access.

On Ishaan's existing laptop the already-tested Python can be used with:

```powershell
& ".\.venv\Scripts\python.exe" -B run_project.py --check
```

## What you should see

The input has 1,413 packets and 904,905 PCAP bytes. The terminal should report 15 tests followed by OK and AUDIT PASSED for 165 retained captures. The report compares random, alert, evidence and flow-prefix policies at 1%, 5%, 10%, 20% and 100% caps.

At 5% the evidence policy preserves seven of eight criteria (87.5%) using 45,240 bytes under a 45,245-byte cap. The alert baseline preserves four (50%); random averages 2.5% coverage across 30 seeds. At 10% evidence preserves all eight. These are observations on designed synthetic data, not a real-network performance guarantee.

Open docs/zero_to_hero_project_guide.docx for the complete explanation. Read pages 2-3 for tomorrow's demo, 17-18 for results and 26-27 for the presentation/viva. The synopsis is docs/synopsis.docx.

The saved example at examples/default_run/report.html is useful when a live rerun is interrupted. Download/extract the project and open the HTML locally; GitHub's file viewer shows HTML source. The examples are a frozen measured snapshot, not automatically updated when you edit code.

## Files worth learning first

- run_project.py: one command for the complete demonstration.
- demo/generate_demo_pcap.py: creates synthetic packets and matching truth.
- demo/run_demo.py: runs policies, evaluates retained files and creates reports.
- src/packet_parser.py: reads PCAP and preserves exact original records.
- src/feature_extraction.py and src/evidence_scoring.py: find observable evidence and candidate bundles.
- src/selectors.py: chooses whole records under the byte cap.
- src/evaluator.py: answers the eight questions from retained packets.
- config.json: budgets, seeds, rule thresholds and weights.
- tests/test_pipeline.py and tools/audit_results.py: correctness checks.
- examples/: small measured examples included with the repository.
- logs/action_log.md and logs/continuation_notes.md: project decisions and handoff state.

Generated PCAPs/truth and results/ are recreated locally and ignored by Git, keeping future experiment runs from flooding the repository. All original experimental files, visual QA pages and the full handoff archive remain in Ishaan's original project folder. The repository contains final documents and small examples, not the machine-specific environments or duplicate render history.

## Updating and contributing

A ZIP is a snapshot: downloading it again obtains a new copy but does not merge your edits. For ongoing team work, install GitHub Desktop from https://desktop.github.com/, sign in, clone the repository, then use Fetch origin / Pull origin for updates. GitHub Desktop and the Code button's clone link manage private-repository authentication without pasting passwords into commands.

Create a branch before a change. A commit is a saved change with a message; pushing uploads your commits. Open a pull request so a teammate can review the proposal before it is merged into main. See CONTRIBUTING.md for the short workflow.

Use the Issues tab to record a concrete task, bug or question. Use the Actions tab to see whether the latest code passed the automatic checks. A failed check should be investigated before presenting the changed version.

## Troubleshooting

- Command not found: install Python, reopen the terminal and try `py -3` or `python` on Windows, `python3` on macOS/Linux.
- Cannot find run_project.py: open the extracted project folder containing that file.
- Cannot open the repository: accept your invitation and check that you are signed in to the invited account.
- Missing PCAP or results: use the launcher; generated files are intentionally created on your computer.
- Truth/hash mismatch: regenerate the matching input/truth pair; do not attach the synthetic truth to a different PCAP.
- Optional Scapy, plotting or Word-authoring packages missing: the core launcher still works; tools/requirements-qa.txt describes optional parser/plot checks, not required demo packages.
- Automatic checks not visible yet: inspect the Actions tab; a committed workflow is only a configuration until GitHub actually executes it.
