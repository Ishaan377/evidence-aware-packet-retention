# Operational forensic-question catalogue

This file documents the actual eight binary criteria in `src/evaluator.py`. Version: initial synthetic MVP, 7 October 2026. All eight have equal primary weight; some share witnesses.

“Preserved” means the implemented retained-packet criterion is correctly satisfied against the reference observed trace. It does not mean every possible investigation question is answerable.

| ID | Reference target / successful retained criterion | Required evidence | Inference limit |
|---|---|---|---|
| Q1 | 192.0.2.10 → 10.0.0.10, at least four distinct nominated scan ports | Retained SYNs to ports in the reference scan set | An observable fan-out witness, not actor attribution |
| Q2 | Exactly 40 distinct observed scan SYN attempts | All distinct (source port, destination port, TCP sequence) witnesses from that source/target scan set | Exact count relative to captured reference; no claim that uncaptured attempts did not exist |
| Q3 | Both reference first/last observed scan timestamps | Earliest and latest observed scan SYN witnesses | Observed interval endpoints, not proof that activity began/ended there in reality |
| Q4 | At least three distinct matched POST /login and HTTP 401 transactions between nominated hosts | Request/response matching by flow and request-end TCP acknowledgement | Rejection response observations, not verified password failures |
| Q5 | At least one matched POST /login and HTTP 200 transaction | Complete request/response pair | HTTP 200 witness, not proof of authentication or compromise |
| Q6 | 10.0.0.10 → 10.0.0.20:445 complete TCP three-way handshake | SYN, SYN-ACK and final ACK with sequence/ACK consistency | Observed internal connection sequence, not proof of lateral movement |
| Q7 | archive.example → 203.0.113.9 matched DNS A exchange | Query and response matching transaction ID, endpoints and qname | DNS mapping observation, not proof of malicious communication |
| Q8 | At least 65,536 unique outbound TCP payload bytes on 10.0.0.20:45000 → 203.0.113.9:9000 | Union of retained TCP payload sequence intervals | Lower bound, not original 300,000-byte reconstruction or proof of exfiltration |

The generator parameters alter scan count, interval and rejection count in supplementary cases; the truth file supplies the matching reference values. Q8's 65,536-byte threshold stays fixed. Packet sequence wrap is not supported.

## Scoring and oracle separation

Coverage C = successful criteria / 8. There is no partial credit. A query target identifies the observation being investigated; expected answers and generator event indices never enter the selectors. The evaluator receives reference truth and re-parses the selected PCAP before checking criteria.

A full-input feature CSV or event log is not a retained witness. Witness indices in question reports are positions in the re-parsed retained capture. The subset manifest separately records source packet indices.

The runner requires a matching PCAP SHA-256 and a passing full-capture control before any comparison. These controls catch accidental input/truth mismatch; they do not validate a real incident's ground truth or stop coordinated replacement of files/manifests.

## Expected cost differences and failure cases

Q1/Q3 can be cheap; Q2 requires the whole observed count; paired exchanges need multiple compatible packets. Q8 is deliberately expensive: a total cap below 65,536 payload bytes makes success impossible regardless of strategy. This catalogue distribution explains why seven questions can survive tiny synthetic budgets.

Removing an HTTP request must invalidate the corresponding response-pair criterion. Removing the final handshake ACK must invalidate Q6. Dropping a scan boundary invalidates Q3; dropping a distinct attempt invalidates Q2. Repeated identical payload must not inflate Q8. These negative cases are covered by the unit tests.

The questions and scorer were designed together. Future research must freeze questions before using independently selected/annotated traffic and examine unsupported or missed evidence, not merely add more similar synthetic cases.
