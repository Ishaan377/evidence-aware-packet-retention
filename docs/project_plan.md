# Evidence Aware Packet Retention Under Storage Budgets

## Research formulation
Under equal limits on serialized PCAP bytes, which retention policy preserves the most correct, explicitly defined answers about observed network activity? The complete capture is a baseline for observed traffic, not a guarantee that every real incident fact was captured.

Practical problem: packet data grows with traffic volume. As a unit calculation, a continuous 1 Gbit/s stream is 10.8 decimal TB/day before capture-record overhead. Retention policies discard data and can break multi-packet evidence sequences. Randomness does not guarantee preservation of rare transactions.

Title: **Evidence Aware Packet Retention Under Storage Budgets**.
Selected topic: Topic 2, selective PCAP and forensic evidence budgeting.

## Research questions
1. How do exact counts, observed interval endpoints, and protocol-sequence witnesses degrade across 1%, 5%, 10%, 20%, and 100% serialized byte budgets?
2. Does an explainable bundle/diversity heuristic retain more correct question answers than random packet packing and a transparent alert-flow baseline?
3. Which evidence types remain weak under every policy, particularly lower bounds on unique bulk-transfer bytes?
4. How sensitive are the findings to random seed, background volume, indicator availability, and a connection-prefix baseline?

Hypothesis: On the controlled scenario, sequence bundles and evidence diversity will preserve more question answers at small budgets than random packet packing. This is conditional on the chosen question catalogue and traffic; it is not a universal or deployment claim.

## Contributions and novelty boundary
Engineering: offline parser, byte-exact subset writer, explainable selectors, reusable question evaluator.
Experimental: equal-cap comparison, repeated random seeds, retained-PCAP re-parsing, observed coverage curves.
Evaluation: public operational definitions for eight packet-supported questions with all-or-nothing primary scoring.
Research: a small reproducible case study of task-specific evidence preservation. No claim that selective capture, forensic coverage, or utility per byte is new. Time Machine (2005), telemetry coverage work (2026), and alert-driven capture work (2026) are close prior art. See literature_review.md.

## Evaluation definitions
Let S0 be input file bytes, B=floor(b*S0), and S be retained file bytes. A valid empty classic PCAP still costs 24 bytes; reject B<24. Every retained packet costs 16 record-header bytes plus its captured bytes. Preserve original record bytes, timestamps, original lengths, and capture header.

r = S/S0, packet retention = n/N, storage reduction = 1-r.
A = number of correctly preserved answers, Q=8, coverage C=A/Q.
Normalized coverage efficiency E=C/r (unitless); question density D=A/(S/1048576), questions per MiB. Ratios are secondary; publish C and S alongside them. There is no fractional scoring in the MVP. A count question needs the exact observed count; a volume question needs the stated retained unique-byte lower bound, not an estimate from the original trace.
Individual packets may witness several questions. Equal weights are a design decision. Independence and legal sufficiency are not implied.

The generator creates a separate ground-truth manifest. Only the evaluator receives it. Feature extraction and selectors receive packet observations and configuration, never event labels, reference answers, or oracle packet IDs. Evaluation reads each selected PCAP again and computes observations afresh. Full-trace feature files are diagnostic overhead and cannot be used to claim retained answers.

## System architecture
1. Validate classic PCAP and preserve raw record bytes.
2. Decode supported Ethernet/IPv4/TCP/UDP and limited single-packet HTTP/DNS evidence.
3. Group bidirectional five-tuples, SYN fan-out in a 10-second bin, HTTP status transactions, handshake candidates, and DNS transactions.
4. Derive alerts from configured fan-out/status thresholds or a known destination indicator.
5. Select whole packets: random permutation packing; alerted-flow chronological packing; proposed greedy bundle gain per marginal byte with diminishing returns for evidence categories; connection-prefix comparison.
6. Write retained capture within cap and re-parse it.
7. Independently answer the predefined questions, compare to generator truth, and save rows, explanations, witnesses, hashes, elapsed times, plots and report.

## Immediate scope and tool choices
Python 3.10+ standard library only for the experiment. This avoids fragile TShark installation or package downloads during the progress check. PCAP IO uses struct according to the PCAP format specification. JSON/CSV are sufficient for the small experiment; SQLite, pandas, ML and a live dashboard would add no immediate research value. Static SVG plots and a self-contained HTML report are generated directly from executed results.
Optional Wireshark/TShark provides independent validation. The optional Scapy 2.6.1 independent parser/checksum/subset cross-check has now passed; core execution still needs no third-party packages.

Supported capture container: classic PCAP, both byte orders, microsecond/nanosecond timestamps, Ethernet link type 1. Unsupported PCAPNG/link types fail explicitly. Unsupported packet protocols remain available for subset retention but do not produce forensic fields. No IP defragmentation, TCP stream reassembly, TLS decryption, online capture, legal chain-of-custody guarantee or production throughput claim.

## Experiment plan
Build code first, generate a file-only synthetic scenario second, execute third. Scenario includes benign background, SYN fan-out, plain HTTP rejection/success transactions, internal TCP handshake, DNS mapping and bulk outbound bytes. It does not execute attacks, send packets or prove compromise/exfiltration.
Default random seeds 0–29. Other policies are deterministic. Save all random trials and a representative seed-0 subset per budget. Report random means and standard deviation as sampling variability within one trace, not confidence over networks.
The 100% control must answer all questions. Compare selected record bytes with input, enforce every cap, test negative cases and missing sequence members. Add scenario/background sensitivity after the first end-to-end run.

## Submission details
Information Security Lab; ICT3141; B.Tech. CCE / 5th Semester / A; Dr. Adesh ND; 2026–2027.
Ishaan Suresh Mullya 240953014; Shriya P Reddy 240953003; Om KB 240953152.
User confirmed Information Security Lab and said department is not needed. Do not add a guessed institution.
Preserve reference cover and 16 numbered sections; put research questions within Objectives and gap within Preliminary Literature Review. Following the user's 7 October update, reproduce the reference's Planned Completion week/month labels in the synopsis, explicitly as proposed academic milestones. The actual executed prototype checkpoint is 7 October 2026; final-project work remains prospective and is described separately in final_project_roadmap.md.
