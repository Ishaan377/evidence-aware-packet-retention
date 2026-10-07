# Preparing to explain the project

## A 60-second explanation

“Our project asks which packets should be kept when there is not enough storage to keep a complete capture. We compare random selection, a rule-based alert policy, a connection-prefix policy and an explainable evidence policy under the same byte cap. Instead of calling every retained packet useful, we define eight investigation questions and reconstruct their answers from the retained PCAP. The current prototype runs on labelled synthetic traffic. At a 5% cap it preserves seven of eight criteria, versus four for our alert baseline and an average of 0.2 for random selection. That is a preliminary observation on this scenario. Next we need independently annotated traffic and stronger baselines.”

Say “we have a working prototype and preliminary experiment,” not “we have proved the method works on all networks.”

## What problem are we solving?

Packet bytes accumulate with traffic volume and retention time. As arithmetic, continuously recording 1 Gbit/s produces 10.8 decimal TB/day before capture overhead. This is a unit calculation, not a measurement of our lab. Full retention also requires indexing, protection and a justified retention period.

Selective retention keeps a subset of the original capture. It saves selected-file bytes but risks losing the packets needed for an answer. A DNS response without its query or a TCP SYN without the other handshake packets may not satisfy a complete sequence criterion.

## What is evidence-aware about the approach?

The selector recognises observable structures: a scan fan-out group and its boundary packets, matched HTTP exchanges, matched DNS exchanges, and complete internal TCP handshakes. It treats these as candidate bundles rather than scoring every packet in isolation. Singleton packets remain available for volume and background evidence.

For each candidate, it calculates a configured evidence gain divided by the extra record bytes required. Already retained packets do not cost twice. Repeated categories receive diminishing gain so one type does not consume everything. It repeatedly chooses a fitting candidate with the best current ratio.

Weights are readable design choices in `config.json`, not probabilities, learned parameters or a proof of optimal selection. The heuristic knows protocol features and indicators, not generator labels, question answers or oracle packet IDs. However, we designed the questions and features together, so independent future test scenarios are essential.

## Why these comparisons?

Random packing tests what happens without evidence preferences. Repeated seeds show variability on the same trace. It shuffles whole packets and skips those that do not fit; this can favour smaller packets and is not unbiased probabilistic sampling.

Our alert policy keeps packets from flows flagged by configured rules. It tests what a straightforward alert-first preference preserves or misses. Chronological allocation favours early events; it is a deliberately simple, potentially weak baseline, not a benchmark of Suricata.

Connection prefixes test a well-established retention idea. Our 4,096 captured-byte whole-packet limit is inspired by Time Machine, without reproducing that system's traffic classes, indexes or architecture.

## What exactly is a forensic question?

An operational question is a criterion with packet witnesses and a pass/fail rule. For example: “Does the retained capture contain a DNS query for archive.example and its matched response mapping it to 203.0.113.9?” The transaction ID, endpoints and question must match. Merely remembering the full-input DNS log is not enough.

The eight criteria cover scan identity, exact observed scan count, observed scan interval endpoints, three HTTP rejection exchanges, one HTTP 200 exchange, an internal TCP handshake, a DNS mapping and at least 65,536 unique outbound TCP payload bytes on a nominated flow.

The catalogue explains every criterion and its inference limit. These are network-observation questions; they do not establish who operated a host or whether an attack succeeded.

## How are answers evaluated?

The generator stores reference answers separately from the PCAP. The evaluator re-parses each selected file and computes its observations. It then compares the observations with the relevant reference target/answer. The runner first requires the full capture to pass all eight criteria and verifies that the truth-file hash matches the PCAP.

Each question is scored 1 only when its complete implemented criterion succeeds. We do not use subjective partial credit. Several criteria can share packets; equal weights and eight questions are design decisions rather than statistically independent measures.

## What is the storage budget and coverage?

For input size S0 and configured fraction b, the cap is floor(b × S0). Retained size S includes the 24-byte PCAP header and each 16-byte packet record header plus captured bytes. S must not exceed the cap; packets remain whole and byte-preserved.

With A successful criteria out of Q=8, coverage C=A/Q. Actual retention r=S/S0. We also report packet retention, storage reduction, selection/evaluation time and:

- Normalized efficiency C/r, which is dimensionless.
- Question density A/(S/1,048,576), measured in questions per MiB.

The ratio alone can favour cheap questions and tiny subsets. Coverage curves and actual bytes are the primary evidence. All truth, full-input diagnostics, reports and the full source capture are outside the retained-PCAP cap.

## What is our gap and hypothesis?

Selective retention already exists: Time Machine, conditional capture tools and recent IDS-triggered PCAP work are related. Forensic coverage also already has explicit research formulations. We cannot claim either idea is new.

Our project contribution is a reproducible student-scale comparison of concrete answers reconstructed from actual retained packets under equal serialized-byte caps. Publication novelty remains provisional pending a wider search and full review of the closest recent papers.

Hypothesis: bundle preservation and category diversity will retain more of the selected sequence/count/boundary criteria at small budgets than random packet packing on the controlled scenario. The current results support that narrow hypothesis; they do not establish general superiority.

## What actually exists?

The offline generator, limited PCAP parser, feature extractor, four policies, strict subset writer, eight-question evaluator, metrics, manifests and HTML/SVG reporting all exist and have run.

Actual evidence: 165 primary trials, 1,188 supplementary trials, 15 passed unit tests, a clean environment reproducing the primary measurements, and independent Scapy packet/checksum/subset checks. Scapy and Matplotlib are optional QA tools; the core uses only the Python standard library.

The synopsis follows the supplied 16-section document with exact team details. This is generated work the team must read, understand and validate before claiming ownership of explanations.

## Likely questions and accurate answers

**What is your novelty?**  
“Our contribution is the transparent equal-byte-budget experiment and operational question evaluator. Selective retention and forensic coverage have prior art. We are not yet claiming an unprecedented method.”

**How is it different from ordinary sampling?**  
“The evidence policy keeps matched witnesses together and balances feature categories. Random selection has no such preference. Both still discard data; preservation is measured rather than assumed.”

**Why not retain all packets?**  
“If storage and policy permit it, full capture preserves the most observed packet evidence. Our experiment addresses the case where that is not affordable. The 100% control passes all criteria.”

**Why no machine learning?**  
“The immediate need is explainable selection and a reproducible evaluation. We lack justified training labels and a held-out real benchmark. ML would add complexity without resolving the current research question.”

**How do you know ground truth is correct?**  
“The generator knows what it wrote. The full capture must reproduce every criterion, unit tests remove or duplicate witnesses to check scoring, and Scapy independently checks protocol fields and checksums. Designed synthetic truth is still weaker than independently annotated real traffic.”

**Why these eight questions?**  
“They exercise different evidence costs: cheap identity/boundaries, complete transactions, exact counts and expensive volume. They are not a universal forensic checklist. Independent selection of future questions will reduce bias.”

**Why does evidence already get 87.5% at 1%?**  
“Seven criteria have compact witnesses and can share packets. The synthetic scan is only 40 small SYNs; all can fit. The final volume criterion requires at least 65,536 unique payload bytes, so it cannot fit into the 9,049-byte 1% cap. This makes the catalogue cost distribution important.”

**Does HTTP 200 mean a successful attack or login?**  
“No. It proves the matched request and HTTP 200 response were observed. Application semantics and a real outcome require additional evidence.”

**Does TCP 445 prove lateral movement, and does bulk traffic prove exfiltration?**  
“No. A matched internal handshake proves an observed connection sequence. A byte threshold proves a retained lower bound. Intent and compromise are outside these criteria.”

**What happens when the scorer misses an event?**  
“Relevant evidence may be lost. Removing the known destination indicator in the supplementary experiment loses Q8 even at 20%. The heuristic is fallible; evaluation must expose its blind spots.”

**Can it work on real traffic?**  
“The parser accepts its supported PCAP formats, but the current evaluator needs matching annotated targets/answers. It cannot automatically score an arbitrary capture using the demo truth. Real streams, encrypted protocols and capture loss require further work.”

**Is your alert baseline fair?**  
“It is clear and reproducible, but chronological packing can favour early events. We must add event-balanced and context-window baselines before making a strong comparison claim.”

**Is a hash a chain of custody?**  
“No. It detects changed bytes against a trusted manifest. It does not prove capture origin or stop someone replacing both the file and manifest.”

**How fast/scalable is the method?**  
“We record actual timings for this roughly 0.9 MB trace. Candidate search is suitable for the small demonstration. We have not established online throughput or large-capture scaling.”

**Why does the 100% control pass even for prefix/alert policies?**  
“The selectors deliberately bypass filtering when the whole input fits. It is a reference control, not evidence that ordinary alert or prefix rules naturally retain everything.”

**What comes next?**  
“Professor review of criteria and baseline fairness, independently annotated traffic, stronger baseline policies, broader supported evidence, scenario-level uncertainty and a final reproducible evaluation.”

## Read before presenting

Run the demo yourself. Trace one bundle decision from `evidence_b0.05_seed0.decisions.json`, inspect one question's witnesses in the report, and explain the 45,245-byte cap calculation. Read the limitations and closest-prior-art entries. Do not memorize unsupported percentage improvements or call the generated PCAP a real attack dataset.
