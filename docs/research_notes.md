# Research notes

Research date: 7 October 2026, Asia/Kolkata. Scope: selective capture, slicing, PSAMP sampling/filtering, flow export, event retention, forensic inference loss, storage trade-offs and reproducible network-forensic evaluation.

## Primary-source search record
Queries included "network forensics selective packet capture storage Time Machine", "forensic question coverage network evidence utility byte selective capture sampling", "packet capture forensic utility storage constrained 2022 2023 2024 2025 2026", and targeted official Suricata, Zeek, ExtraHop, Endace, NIST and IETF searches. A bounded discovery search is not an exhaustive systematic review; absence in results cannot establish absence in literature.

## Important correction to supplied analysis
The statement that forensic coverage is absent from academic literature is contradicted by Vaseghipanah et al. (2026). The supplied recommendation remains a reasonable topic choice, but its novelty ratings and imagined percentage examples are not results. No claim about Topic 1 or Topic 3 was needed or verified for this project.

## Access and verification ledger
Time Machine: inspected publisher abstract and the primary-paper design/evaluation sections.
Vaseghipanah et al.: inspected indexed publisher abstract and methods, assumptions, supportability and evaluation in the primary 28-page preprint with DOI 10.20944/preprints202601.0343.v1. Publisher HTML/XML returned HTTP 429. Preprint version differs from the final publication; cite the reviewed version and do not merge their numeric findings.
SANS Gaster: verified official date 28 September 2026, author, title and abstract. Full PDF behind an Egnyte download link was not reviewed. Use only abstract-level scope; no benchmark numbers are attributed to it.
RFCs: read official IETF/RFC Editor materials for sampling, flow export and documentation addresses.
Suricata: read stable 8.0.1 conditional PCAP documentation.
Zeek: read official log documentation.
ExtraHop: official indexed documentation describes precision capture and slicing; full page returned HTTP 403. Treat capability description as vendor documentation, not independent effectiveness evidence.
Endace and NetWitness: official product/technical material supports capture/metadata/retention capabilities; no vendor performance claim is used as a comparative experiment.
PCAP: read draft-ietf-opsawg-pcap-05. It is a versioned Internet-Draft, not a final RFC. The MVP intentionally limits container/protocol support.
Feature-Sniffer: read primary author abstract; 2023 preprint, accepted at WF-IOT 2022. Record these dates separately.
FileTSAR: inspected the official NIJ agency article and indexed final-report excerpts; the 30 MB full report could not be fetched. The agency account warns that the research tool is not an operational release. Selective analysis/reconstruction is distinct from optimizing storage selection.

## Categories used in every deliverable
Literature fact: cite a verified external source.
Design decision: team choice, such as eight equal-weight questions.
Hypothesis: expected comparison, not yet a conclusion.
Preliminary result: output of an actual command; keep manifest, source hash and full trial rows.

## Deferred verification
A final project should extend the review in IEEE/ACM bibliographic databases, inspect the SANS full paper, and review the final Network journal version before claiming publication novelty. Search evidence did not establish that this exact byte-budget/question-catalogue combination is globally new.
