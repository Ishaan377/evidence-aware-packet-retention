# Literature review and claim ledger

Research checked on 7 October 2026. Numbered references match sources.json; publication years are recorded, and undated documentation is explicitly undated. This is a bounded literature and technology review, not a systematic-review proof of novelty.

## Closest research and what it evaluates

| Work | Retained representation or target | Evaluation focus | Relevance to this project |
|---|---|---|---|
| [1] Time Machine, 2005 | Connection prefixes and configurable classes | Storage/retention efficiency and operational investigation examples | Add a whole-packet connection-prefix baseline; do not claim selective forensic retention is new. |
| [2] Vaseghipanah et al., 2026 | Packet headers, flow records, time aggregates | Artifact survivability and supportable hypotheses | Direct prior art for forensic coverage. Our measured answers use labelled synthetic observations under explicit byte caps. |
| [3] HybridMon, 2025 | Condensed packet records and selected flow aggregation | Monitoring/export efficiency and security applications | Hybrid monitoring and preservation of fine-grained features already exist. |
| [4] P4DDLe, 2023 / revised 2024 | Selected packet features for NIDS | Resource constraints and DDoS detection | Our endpoint is question preservation, without learned detection. |
| [5] Gaster, 2026 | IDS-triggered PCAP | Alert-driven capture and forensic viability (abstract scope) | Very close framing; full-paper review is required before asserting a distinct publication contribution. |
| [14] Feature-Sniffer, 2023 preprint | Online traffic features | IoT identification and activity classification | Metadata-first collection avoids PCAP storage but changes available evidence. |
| [15] FileTSAR agency account, 2021 | Capture and selective reconstruction | Operational network evidence recovery | Investigation reconstruction exists; selective analysis differs from selective retention. |

## Technology and evidence implications

RFC 5475 [6] provides the sampling/filtering distinction. A shuffled whole-packet packer is our random baseline; skipping records that do not fit can favour smaller packets, so it is not described as an unbiased fixed-probability sample. Record attained bytes and packet fraction separately.

IPFIX [7] and Zeek logs [9] establish metadata-based monitoring. Flow summaries can retain counts unavailable from a packet subset, but comparing metadata plus packets would require budgeting both. The MVP measures retained PCAP bytes only and excludes full-input feature CSVs from answer reconstruction.

Suricata's documented conditional capture [8] motivates the alert-flow baseline. The MVP's threshold rules and chronological allocation are design choices, not a reproduction or benchmark of Suricata. A stronger event-balanced alert policy belongs in the final evaluation.

ExtraHop documentation [10] describes precision triggers and slicing. Endace [11] provides continuous capture, and NetWitness [18] distinguishes packet and metadata retention. These support the existence of commercial retention mechanisms. No comparison of commercial forensic utility is made.

NIST [12] motivates provenance. SHA-256 manifests detect file changes, but cannot establish where traffic came from, protect against an attacker replacing both file and manifest, or supply a legally complete chain of custody.

## Similar metrics and novelty decision

"Forensic coverage" and "artifact survivability" are explicit in [2]. Byte/flow coverage and output reduction are also established monitoring measurements; [1], [3], [4], [6] show existing efficiency trade-offs. The ratio C/r is our clearly dimensioned reporting convention, not a newly discovered scientific metric. Coverage per byte can favour cheap questions and very small subsets; report the coverage curve and actual retained bytes as primary evidence.

The defensible gap is **a reproducible student-scale comparison that reconstructs a published catalogue of concrete answers from actual retained PCAPs under equal serialized-byte caps**. The reviewed works have different representations, targets or evaluation endpoints. This is a project contribution boundary, not proof that no identical framework exists.

A candidate research contribution is testing how temporal boundaries, complete protocol sequences and bulk-byte lower bounds survive selection differently. General novelty remains provisional until a wider database search and the closest 2026 full papers are reviewed.

## Consequences for the design

Keep protocol sequences as bundles; include context types that a narrow alert rule may miss; retain lossless record bytes; enforce exact caps; define binary criteria before measurement; use a separate generator manifest; re-parse selected captures; repeat random trials; include an established connection-prefix idea; test missing indicators and bundle removal.

Do not infer malware, lateral movement or exfiltration from an IP/port alone. HTTP 200 is a response witness, TCP 445 a communication sequence, and bulk volume a byte lower bound. They are not proof of attacker intent.

## Source registry and access limits

### [1] Building a Time Machine for Efficient Recording and Retrieval of High-Volume Network Traffic

Stefan Kornexl, Vern Paxson, Holger Dreger, Anja Feldmann, Robin Sommer. 2005. Primary conference research (IMC). [Source](https://www.usenix.org/conference/imc-05/building-time-machine-efficient-recording-and-retrieval-high-volume-network). Accessed 7 October 2026.

Verified support: Connection-prefix retention and configurable traffic classes predate this project. Evaluation includes trace-driven efficiency and operational experience.

Inspection: Publisher abstract and primary-paper design/evaluation sections.

### [2] Auditing Inferential Blind Spots A Framework for Evaluating Forensic Coverage in Network Telemetry Architectures

Mehrnoush Vaseghipanah, Sam Jabbehdari, Hamidreza Navidi. 2026. Primary research preprint; publisher counterpart exists. DOI: 10.20944/preprints202601.0343.v1. [Source](https://www.preprints.org/frontend/manuscript/1c03a856caad4124d5782b1ce37eb014/download_pub). Accessed 7 October 2026.

Verified support: Forensic coverage and artifact survivability already have explicit research formulations. This study audits representation-level support, not correctness against incident ground truth.

Inspection: Primary preprint methods, assumptions, supportability and evaluation; indexed journal abstract.

### [3] Advancing Network Monitoring with Packet-Level Records and Selective Flow Aggregation

Ina Berenice Fink, Ike Kunze, Pascal Hein, Jan Pennekamp, Benjamin Standaert, Klaus Wehrle, Jan Rüth. 2025. Primary conference research (IEEE/IFIP NOMS); author lab publication. [Source](https://www.comsys.rwth-aachen.de/publication/2025/2025_fink_advancing-network-monitoring-with/). Accessed 7 October 2026.

Verified support: HybridMon combines condensed packet records with selective flow aggregation and evaluates monitoring efficiency. Packet/flow trade-offs are established prior art.

Inspection: Author-lab abstract and indexed primary-paper method excerpt.

### [4] Introducing Packet-Level Analysis in Programmable Data Planes to Advance Network Intrusion Detection

Roberto Doriguzzi-Corin, Luis Augusto Dias Knob, Luca Mendozzi, Domenico Siracusa, Marco Savi. 2023; arXiv v4 revised 2024-01-04. Primary author preprint; associated Computer Networks publication. DOI: 10.48550/arXiv.2307.05936. [Source](https://arxiv.org/abs/2307.05936). Accessed 7 October 2026.

Verified support: P4DDLe selectively collects packet features under resource limits for NIDS detection; resource-aware selection is not new.

Inspection: Primary abstract and official authors' repository; publisher full text denied.

### [5] Rethinking Full Packet Capture Evaluating IDS-Triggered PCAP

Zachary Gaster. 2026. Primary practitioner white paper (SANS), abstract only reviewed. [Source](https://www.sans.org/white-papers/rethinking-full-packet-capture-evaluating-ids-triggered-pcap). Accessed 7 October 2026.

Verified support: A directly related study addresses alert-driven capture versus full capture and forensic usefulness. Its existence narrows any novelty claim; no numerical findings are used.

Inspection: Official title, author, publication date and abstract; full PDF not reviewed.

### [6] Sampling and Filtering Techniques for IP Packet Selection

Tanja Zseby et al.. 2009. IETF standard RFC 5475. DOI: 10.17487/RFC5475. [Source](https://www.rfc-editor.org/rfc/rfc5475.html). Accessed 7 October 2026.

Verified support: Sampling and deterministic property filtering are distinct; configured and attained packet selection fractions may differ.

Inspection: Official categories and attained selection fraction.

### [7] Specification of the IP Flow Information Export IPFIX Protocol for the Exchange of Flow Information

Benoit Claise, Brian Trammell, Paul Aitken. 2013. IETF standard RFC 7011. DOI: 10.17487/RFC7011. [Source](https://www.rfc-editor.org/rfc/rfc7011.html). Accessed 7 October 2026.

Verified support: IPFIX exports flow information using template and data records; it does not imply retention of original packet contents.

Inspection: Official protocol specification.

### [8] Suricata yaml Conditional PCAP logging

Open Information Security Foundation. Undated. Official software documentation, stable 8.0.1. [Source](https://docs.suricata.io/en/suricata-8.0.1/configuration/suricata-yaml.html). Accessed 7 October 2026.

Verified support: Suricata supports all, alerts and tag conditional PCAP logging. The MVP alert rule is illustrative and does not run Suricata.

Inspection: Conditional pcap-log section.

### [9] Common Logs and conn log

Zeek Project. Undated. Official software documentation. [Source](https://docs.zeek.org/en/current/reference/logs/index.html). Accessed 7 October 2026.

Verified support: Connection, DNS and HTTP logs provide structured monitoring records. Metadata availability is separate from preserved packet evidence.

Inspection: Official common-log list and connection-log tutorial.

### [10] Configure packet capture

ExtraHop. Undated. Official commercial documentation. [Source](https://docs.extrahop.com/current/configure-pcap-eda/). Accessed 7 October 2026.

Verified support: Precision capture via triggers and packet slicing are existing commercial mechanisms; no independent effectiveness result is inferred.

Inspection: Indexed official page; direct HTML access denied.

### [11] Introducing Endace

Endace Technology Limited. 2024. Official commercial product material. [Source](https://www.endace.com/introducing-endace.pdf). Accessed 7 October 2026.

Verified support: Endace offers continuous capture and discusses triggered capture trade-offs. Vendor claims are not independent benchmarks.

Inspection: Official indexed product material and capture-solution pages.

### [12] Guide to Integrating Forensic Techniques into Incident Response

Karen Kent, Suzanne Chevalier, Tim Grance, Hung Dang. 2006. Authoritative NIST SP 800-86 guidance. DOI: 10.6028/NIST.SP.800-86. [Source](https://csrc.nist.gov/pubs/sp/800/86/final). Accessed 7 October 2026.

Verified support: Network traffic is an incident-response data source; collection, examination, analysis and reporting require provenance and integrity controls.

Inspection: Official publication scope and forensic-process material.

### [13] PCAP Capture File Format

Guy Harris, Michael Richardson. 2025. IETF Internet-Draft draft-ietf-opsawg-pcap-05, work in progress. [Source](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap-05). Accessed 7 October 2026.

Verified support: Classic PCAP file header and record structure, byte order and timestamp resolution; this is a versioned draft rather than a final RFC.

Inspection: Official file and packet header layouts.

### [14] Feature-Sniffer Enabling IoT Forensics in OpenWrt based Wi-Fi Access Points

Fabio Palmese, Alessandro E. C. Redondi, Matteo Cesana. 2023; Preprint 2023; accepted at IEEE WF-IOT 2022. Primary author preprint. DOI: 10.48550/arXiv.2302.06991. [Source](https://arxiv.org/abs/2302.06991). Accessed 7 October 2026.

Verified support: Online feature extraction on OpenWrt avoids retaining large PCAP files; demonstrations concern IoT device/activity classification.

Inspection: Primary abstract.

### [15] Improving the Collection of Digital Evidence

Martin Novak, National Institute of Justice. 2021. Authoritative agency report on funded FileTSAR research (secondary project account). [Source](https://nij.ojp.gov/topics/articles/improving-collection-digital-evidence). Accessed 7 October 2026.

Verified support: FileTSAR includes capture, selective analysis and file reconstruction. Reconstruction tools do not by themselves establish a byte-budget retention optimizer. The agency account warns that the research software is not an operational release.

Inspection: Official agency article and indexed final-report excerpt; 30 MB final report could not be fetched.

### [16] IPv4 Address Blocks Reserved for Documentation

Jari Arkko, Michelle Cotton, Leo Vegoda. 2010. IETF informational RFC 5737. DOI: 10.17487/RFC5737. [Source](https://www.rfc-editor.org/rfc/rfc5737.html). Accessed 7 October 2026.

Verified support: 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are documentation ranges; the generator writes examples to disk only.

Inspection: Official reserved address ranges.

### [17] editcap

Wireshark Foundation. Undated. Official software manual. [Source](https://www.wireshark.org/docs/man-pages/editcap.html). Accessed 7 October 2026.

Verified support: editcap can convert capture containers using -F; converting PCAPNG does not add unsupported protocol analysis.

Inspection: Official capture-format conversion option.

### [18] Configure a Rule and Advanced Configurations

NetWitness. Undated. Official commercial technical documentation. [Source](https://community.netwitness.com/s/article/ConfigureaRule). Accessed 7 October 2026.

Verified support: Raw packets and parsed metadata may have separate retention periods. Product availability does not establish forensic utility superiority.

Inspection: Indexed official rule and retention configuration documentation.

