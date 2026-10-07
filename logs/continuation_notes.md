# Continuation notes for another AI agent

## User intent and current state

User selected Topic 2 in `Antigravity_GPT6.1_Project_Prompt.txt`: selective PCAP retention under storage budgets. They required research, a format-matched synopsis, a real executed MVP, professor preparation, a roadmap and an exportable action log. The follow-up request is also complete: a 29-page all-in-one beginner guide, visual synopsis architecture, and reference-matched Planned Completion column. Future full-project phases are explicitly planned, not claimed complete.

Read `README.md`, `docs/zero_to_hero_project_guide.docx`, `progress_check.md`, `professor_explanation.md`, `docs/project_plan.md`, `docs/literature_review.md` and `logs/action_log.md` first. Original reference files must remain unchanged.

Title: **Evidence Aware Packet Retention Under Storage Budgets**. Preserve exact team/course/guide/year details from the reference DOCX. User clarified “Information Security Lab(department is not necessary yet)”. No college name was provided; do not invent it.

Team: Ishaan Suresh Mullya 240953014; Shriya P Reddy 240953003; Om KB 240953152. B.Tech. CCE / 5th Semester / A; ICT3141; Dr. Adesh ND; 2026–2027.

## What is complete and verified

- 18-source bounded primary/official literature review with explicit access limits.
- Transparent stdlib core, file-only generator, four policies, eight-question evaluator and equal serialized-byte budgets.
- Main synthetic input: 1,413 packets, 904,905 bytes; 165 primary trials, every primary subset retained.
- At 5%: evidence 87.5% (7/8), alert 50%, random mean 2.5% with sample SD 5.09 percentage points, prefix 0%. Evidence retains 45,240 bytes under a 45,245-byte cap. At 10% evidence passes 8/8.
- Full-capture control bypasses filtering when all packets fit and passes 8/8 for every policy.
- 1,188 supplementary trials over three generated variants and no-indicator/no-bundle modes. Only final supplementary working subset saved.
- 15 unit tests passed. Primary subset audit passed all 165 caps, original records, hashes and fresh evaluation.
- Clean venv without pip packages regenerated a byte-identical PCAP and reproduced every primary coverage/size/SD result.
- Independent Scapy 2.6.1 validated fields, timestamps, recomputed IPv4/TCP/UDP checksums, generated event counts/DNS mapping and all 165 subsets.
- Default scientific figures, all 8 reference pages, all 10 updated synopsis pages and all 29 beginner-guide pages visually inspected.
- Configurable reporting checked with 30% and 100% caps and 7 random seeds; missing-input CLI failure checked.
- Portable provenance paths and an explicit truth path are now recorded in new manifests.

Check `logs/document_update_checks.json` for the latest document state (supersedes the historical nine-page/16-part DOCX checks), then `logs/final_integration_checks.txt`, `unit_tests.txt`, `result_audit.txt`, `scapy_verification.json` and experiment manifests for execution evidence. A unittest attempt with Python's -I isolated flag failed because that mode removes the working-directory import path; the documented normal command passed all 15 tests. Its diagnostic is retained, not hidden.

## Important research boundaries

Do not repeat the supplied analysis's claim that forensic coverage is absent from literature. Time Machine (2005), the 2026 forensic-coverage preprint and Gaster's 2026 IDS-triggered-PCAP white paper are close prior art. Project contribution is a reproducible question-level comparison, not proof of global novelty.

SANS full PDF was not reviewed; only official abstract/title/author/date. The publisher version of the coverage paper was rate-limited; use the inspected preprint version and do not merge numerical results. FileTSAR full final report could not be fetched; agency article and indexed excerpts were consulted. Source registry records all limits.

Selectors never receive truth/event labels, but catalogue/scorer co-design still creates bias. Alert chronological packing is weak; prefix is inspired by Time Machine rather than reproduced. Strengthen both and use independently annotated/held-out scenarios before general claims.

Q5 is a matched HTTP 200 response, Q6 a handshake and Q8 a unique retained-payload lower bound. None proves compromise, lateral movement or exfiltration. Q2/Q3 compare exact observations with the full capture, not an uncaptured real incident.

Cap scope is **one retained PCAP only**, including container/record headers. Full capture, diagnostic feature CSVs, truth and reports are outside it. No deployment-wide storage saving or legal chain-of-custody claim.

## Running and extending

Core requires Python 3.10+, no pip packages. Run from the project root:

```text
python demo/generate_demo_pcap.py
python demo/run_demo.py
python -B -m unittest discover -s tests -v
python -B tools/audit_results.py
python demo/run_sensitivity.py
```

Local `.venv/Scripts/python.exe` was tested, but is not portable. Create a new venv after export. Optional packages for independent validation/figures are in `tools/requirements-qa.txt`; the tested transitive versions are in `tools/qa_environment.lock.txt`.

Parser supports classic PCAP 2.4/Ethernet, both endian/time-resolution variants, limited IPv4 and single-packet HTTP/DNS. No PCAPNG, IPv6 evidence evaluation, reassembly, TLS decode, fragmentation reconstruction, sequence wrap or online capture. Unsupported containers fail; unsupported packet protocols can be retained without supported fields.

Unknown real PCAPs need independently annotated truth conforming to the evaluator schema. Hash mismatch or a failing full-control aborts. Do not reuse the synthetic truth on other input.

Use new result directories for future experiments. Core runner updates its HTML/SVG; optional Matplotlib PNGs are separately generated. If code/config/data changes, rerun experiments so manifests describe the actual source and measurements. Do not reuse old conclusions with stale hashes.

## Synopsis and document reproduction

`docs/synopsis.docx` follows the exact 16 numbered sections, team tables, cover, declaration, margins and Arial styling in the reference. It now has 10 pages and a visual flowchart. Fourteen original package parts remain byte-identical. document.xml, its relationships and content types are intentionally editable to support the requested PNG; exactly one image part is added. The previous nine-page document is preserved at `docs/archive/synopsis_before_flowchart.docx`. Source reference SHA-256:
`2a9000836d4bbac7e5db0347597bd17e8a10f8b6acd5157fda2e638452659800`.

The Planned Completion column exactly copies the reference's ten week/month strings, including August labels, as proposed milestones. A note distinguishes these labels from the actual 7 October prototype checkpoint and prospective independent evaluation. Do not present these schedule labels as completed work.

Structured content: `docs/synopsis_content.json`; builder: `tools/build_synopsis.py`; fidelity contract: `docs/artifact.md`; evidence and renders: `docs/qa/`.

Packaged render_docx.py was attempted but had no bundled Windows LibreOffice executable. Hidden Word COM read-only PDF export plus bundled Poppler was the documented fallback. No installed LibreOffice was used. After any DOCX edit, re-render and inspect every page.

The guide is `docs/zero_to_hero_project_guide.docx` (29 pages). Its content is `docs/beginner_guide_content.json` and builder is `tools/build_project_guide.py`. Results tables/question matrix are loaded from saved primary metrics/answers and source hashes are checked. `tools/create_architecture.py` creates PNG/SVG assets. Final render directories are `docs/qa/beginner_guide_final/` and `docs/qa/synopsis_flowchart_v1/`; older guide v1/v2 are historical pagination diagnostics. For tomorrow's presentation start with guide pages 2-3, 17-18 and 26-27. Core experimental code/data/results were not changed in this document-only follow-up.

The original document has no institution name. User clarification is already applied; do not repeatedly ask for a department.

## Export and next work

`logs/agent_handoff.zip` includes original references, code, docs/QA, generated data, **all 165 primary trial PCAPs**, raw primary/supplementary measurements and logs. It excludes machine-specific environments and duplicate clean/configuration diagnostic results. `HANDOFF_MANIFEST.json` inside lists every included file hash; `logs/export_manifest.json` records archive hash outside. Run `python tools/export_handoff.py` to refresh the archive after updating the action log.

Next substantive work is the roadmap: guide review, evaluation freeze, closest-full-paper review, independently annotated traffic, stronger baselines and held-out evaluation. Do not add ML/dashboard/database merely to look complete.

## Environment and authorization

Original workspace: `C:/Users/Ishaan SM/Desktop/IS project`, Windows PowerShell. Initial sandbox was read-only; writes/runs used explicit escalation. All requested deliverables stay in this project. User did not ask to publish a repository, send messages, deploy or perform live attacks/capture. Proceed with ordinary local authorized work and obey the next session's permissions.

Append substantive changes/outcomes to `logs/action_log.md`; update these notes at the end of each phase. Keep research facts, design choices, hypotheses and actual findings visibly distinct.
