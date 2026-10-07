# Action log

All dates are Asia/Kolkata unless an entry explicitly uses UTC. Session started 2026-10-07.

## Reference inspection
- Read the complete project prompt, all three topic proposals, and research_idea_analysis.md.
- Inspected every text element, table, package part inventory, and page geometry of the reference DOCX without changing it.
- Selected Topic 2: Evidence-Aware Selective PCAP / Forensic Evidence Budgeting.
- Verified team: Ishaan Suresh Mullya (240953014), Shriya P Reddy (240953003), Om KB (240953152); B.Tech. CCE, semester 5, section A; ICT3141; Dr. Adesh ND; academic year 2026–2027.
- The reference has no college or department name. Requested exact names asynchronously; do not invent them if no answer arrives.
- Reference structure: cover metadata and 16 numbered sections. US Letter, 0.8 inch vertical margins, 0.9 inch horizontal margins, Arial 11 point body, 14 point bold section headings.
- Loaded the documents skill and bundled Python/Node dependencies. Scapy and matplotlib are absent from the bundled environment; prefer a dependency-free experimental core with a standards-compliant classic PCAP reader/writer and static SVG plots.

## Research in progress
- Independently found foundational Time Machine selective-retention work (Kornexl et al., IMC 2005).
- Found closely related 2026 work on forensic coverage in telemetry architectures and IDS-triggered capture. These require review before making novelty claims.
- The original analysis assertion that forensic coverage is absent from literature must not be repeated as fact.

## Continuation rule
Append each substantive change, command outcome, source decision, and unresolved issue here. Store experimental manifests and machine-readable results in results/. Never report unexecuted tests or synthetic observations as real incidents.

## Design recorded
- User confirmed Information Security Lab; department omitted.
- Recorded refined title, four research questions, eight-question binary coverage, byte-exact budgets, oracle separation and dependency-free architecture before implementation.
- Rendered all eight reference pages using hidden Word read-only PDF export and bundled Poppler; inspected every page.
- The packaged renderer was attempted and failed due to unavailable bundled LibreOffice on Windows; Word export is the recorded QA fallback.


## MVP core implemented
- Added classic PCAP validation and lossless subset IO, supported packet metadata decoding, observable features, candidate bundles, four selection strategies, eight-question evaluator and dimensioned metrics.
- The selectors receive configuration and packet observations only; no generator labels or reference answers.
- Ground truth and traffic generation are not yet executed. Core tests are pending.


## Demo implementation saved
- Added an offline standards-based packet generator with valid IPv4/TCP/UDP checksums and separate truth manifest.
- Added execution runner, per-trial retained PCAPs, JSONL question details, CSV metrics, SHA-256 manifests and generated SVG/HTML reporting.
- Added 30 random seeds, four policies and a full-capture control. Execution and verification follow; no preliminary findings are claimed yet.


## First experiment executed
- Generated synthetic demo.pcap: 1413 packets, 904905 bytes; no traffic transmitted.
- Executed 165 primary trials: 30 random seeds and three deterministic policies at five budgets.
- At 5% cap: evidence 7/8, chronological alert 4/8, random mean 0.2/8 (2.5% coverage). At 10% cap evidence answers 8/8.
- Added correctness tests, full retained-file audit and supplementary sensitivity/ablation runner; these checks are pending.


## Research and verification checkpoint
- Recorded 18 verified source entries with publication dates/types, supported claims, URLs/DOIs and access limits.
- Reviewed relevant methods/design/evaluation sections of Time Machine and the 2026 forensic coverage preprint; publisher/SANS access limits are documented. FileTSAR final report was available only as indexed excerpts; the official agency account was inspected.
- All 15 unit tests passed. All 165 primary retained captures passed cap, hash, record preservation and re-evaluation audit.
- A clean venv without pip packages reproduced all coverage/size outcomes in 165 trials.
- Executed 1188 supplementary synthetic sensitivity trials. Removing the destination indicator prevents the bulk-byte question at 20%; removing bundles lowers evidence coverage on these traces. These are mechanism checks, not independent real-network validation.


## Final artifacts and independent QA
- Installed optional, pinned Scapy 2.6.1 and Matplotlib 3.10.3 in a project-local QA environment; recorded transitive versions. Core remains standard-library only.
- Scapy independently verified all 1413 input packets, IPv4/TCP/UDP fields and recomputed checksums, event counts, DNS mapping, and raw bytes/caps for all 165 primary subsets.
- Created and visually inspected scientific comparison, per-question and sensitivity figures from saved measurements.
- Built synopsis by editing only document.xml in a copy of the exact reference package. Preserved all 16 other parts byte-for-byte, geometry, cover/team data, section order, declaration and signature fields.
- Exported final synopsis via hidden read-only Word COM and bundled Poppler. Inspected every one of its nine pages; no clipping, overlap or orphan headings found.
- Saved README.md, progress_check.md, professor_explanation.md, final_project_roadmap.md and the operational question catalogue. Instructions distinguish synthetic results, prototype limits, weak baselines and independent future evaluation.
- Corrected research access wording: relevant sections were inspected; no claim that inaccessible full SANS/FileTSAR papers were reviewed. Recorded Martin Novak as NIJ article author and its operational-use caveat.
- Made seed-count captions and graph range follow configuration; checked a 30%/100%, seven-seed run (20 trials).
- Clean venv regenerated a byte-identical synthetic input and reproduced all primary coverage/size/SD outcomes.
- An attempted unittest command with Python -I failed because isolated mode removes the working-directory import path. Retained diagnostic in unit_tests_isolated_attempt.txt. Reran the documented normal command: all 15 tests passed.
- Added relative input/truth provenance paths so exported projects can be audited after relocation, plus explicit truth-file hash validation.
- Saved comprehensive continuation notes and a reusable handoff exporter. Final source-hash checks, portable audit and archive integrity verification are the closing checks.

## Final self-check passed
- Final required-file check passed: synopsis, research documents, working MVP/results, README, professor materials, roadmap and continuation log all exist.
- Re-executed main and clean-environment runs after final provenance/reporting changes. All coverage, byte sizes and random SD outcomes match, and every recorded core/demo source hash matches the saved files.
- Portable audit passed all 165 subsets after deliberately invalidating old machine absolute paths; relative input/truth/subset paths remain usable.
- Original reference SHA-256 remains unchanged. Final DOCX matches its QA hash, all 16 preserve-only package parts are identical, and all 16 required section headings remain in order.
- Final checks are recorded in final_integration_checks.txt. No live traffic, external attack, publication, repository upload or message sending occurred.
- Prepared the complete primary-experiment handoff for export. The exporter records the archive hash and file inventory in export_manifest.json and verifies CRC/file hashes before reporting success.

## Handoff export completed
- Exported 286 important files, including all 165 primary retained PCAPs, into logs/agent_handoff.zip.
- Archive CRC and every included file SHA-256 passed verification. The outer export_manifest.json records the archive hash; the embedded HANDOFF_MANIFEST.json records included-file hashes and exclusions.
- Refreshed the export to include this completion entry. Important files remain under the original project folder.


## 7 October 2026 - beginner guide and synopsis update
- User requested one beginner-friendly zero-to-hero guide, tomorrow's professor demo, commands/files, outputs, interpretation and future full-project work; also visual architecture and a reference-matched Planned Completion column.
- Created docs/zero_to_hero_project_guide.docx with 29 pages: foundations, protocol/PCAP examples, all four policies, eight criteria, worked budget/coverage arithmetic, actual results, ablations, source/code guide, exact commands, five-minute presentation, viva, glossary, troubleshooting and future phases.
- Guide results tables and question matrix are loaded from actual saved metrics/representative answers; builder verifies the recorded core/demo source hashes. No experimental findings were fabricated or changed.
- Created reusable architecture PNG/SVG and embedded the flowchart in the synopsis and guide. Ground truth enters evaluation only, visibly separated from policy selection.
- Archived the previous synopsis/content/evidence before modifying them. Preserved all 16 numbered headings, exact cover/team/course/guide details, section geometry, declaration and signatures. Fourteen preserve-only original package parts remain unchanged; three content/image-support parts are editable and one PNG is added.
- Copied all ten Planned Completion strings exactly from the reference. Added a note that these are proposed academic-schedule labels, not records of completed work; the real prototype checkpoint remains 7 October 2026.
- Used the established hidden Word read-only PDF export and bundled Poppler rendering fallback. Repaired a source-link spill and a blank-page pagination issue by shortening link labels and using heading page-break-before. Final guide has 29 pages; updated synopsis has 10.
- Inspected every final rendered page of both documents (39 pages), including all commands, results tables, flowchart, schedule, cover and signatures. No clipping, overlap or stranded references remain.
- Updated README, template contract, research plan and continuation notes. Retained previous logs and QA iterations as historical records; latest document checks are logs/document_update_checks.json.
- Core code, synthetic inputs and measured experiments are unchanged, so existing 15-test/165-subset validation remains applicable. Refreshed the complete handoff export after the new document checks; exporter verifies CRC and every included file hash.
- Document verification initially compared the manifest configuration hash to root config.json. The manifest hashes results/demo/config_used.json; corrected the check to that saved file and separately compared root/executed JSON values. Line-ending differences are not configuration changes.


## 7 October 2026 - private GitHub setup in progress
- User requested GitHub sharing and selected a private repository. Connected account is Ishaan377; user signed in through GitHub and will invite teammates later. No password, verification code or token was requested in chat.
- Prepared run_project.py, beginner teammate instructions, contribution/review guidance, read-only Windows/Linux automatic checks, exact-byte Git attributes and ignores for runtime outputs/environments/render history.
- Copied a small frozen example from actual main measurements and recorded its provenance; full original experiment files remain local. Private repository target: Ishaan377/evidence-aware-packet-retention. Upload and fresh-download verification are pending.

## Private GitHub publication verified
- Created Ishaan377/evidence-aware-packet-retention as a private personal repository. User explicitly approved adding only this repository to the existing selected-repository connector access; vs-projects remains selected and All repositories remains off.
- Published 66 reviewed project files at commit 77d7f778ece828f8e07bc1b9c7d3794ed2193a0a. Checked the complete remote file inventory and eight critical file hashes, including both final DOCX files, the flowchart, launcher, configuration and workflow.
- Tested a fresh curated copy with no copied environments or prior runtime outputs: generated 1413 packets/904905 bytes, executed 165 trials, passed all 15 tests and all 165 subset audits. Coverage/SD/selected sizes match the saved primary baseline.
- GitHub Actions run 37648021902 passed both ubuntu-latest/Python 3.10 and windows-latest/Python 3.13 jobs, including generation, all policies, unit tests and retained-file audit.
- Teammate usernames were unavailable; user chose to invite later. TEAM_START_HERE.md explains Settings > Collaborators > Add people, accepting invitations, Download ZIP, Python setup and the one-command demo. No invitation or message was sent.
- Stored repository/commit/access/CI evidence in logs/github_setup.json. Full original experiments, renders and handoff archive stay local; only small clearly labelled actual-result examples are in GitHub.
