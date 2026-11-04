# Evidence-Based Retention (EBR)

EBR reduces a packet capture to a fixed storage budget while keeping the evidence an investigator needs. It decides from the traffic alone, using no signatures, labels or training data, so it can preserve attacks nobody had a rule for at capture time.

This document explains the algorithm, what is new about it, how it was tested and where it falls short. The code is in [final/ebr/](final/ebr/).

## The problem

Full packet capture is the best evidence a network can produce, and it is expensive to keep. Storage forces a choice, and the usual options each lose something:

| Approach | What goes wrong |
|---|---|
| Lossless compression (gzip) | Keeps everything, but on the test captures it still needed 51% of the original size, and up to 88% on ordinary traffic |
| Random sampling | Loses small flows, which is where exploits and command-and-control live |
| Flow cutoff (Time Machine) | Treats every connection alike, and loses commands sent late in a long session |
| Alert-triggered capture | Keeps only what a rule already recognised, so it cannot help with threats discovered later |

EBR asks a different question: **given a fixed number of bytes, which bytes would an investigator most regret losing?**

## Why the first version needed replacing

The project's earlier algorithm was honest work, and its own audit showed three problems:

1. A simple unweighted method beat it on several captures, so its scoring was not earning its keep.
2. It treated all sessions as equally important, so cheap scan traffic used up the budget.
3. It held every packet in Python memory. One 58 MB capture took 230 seconds, so a multi-gigabyte run was out of reach.

EBR is a redesign rather than a patch.

## How EBR works

```text
PCAP files
   │  Pass 1: stream every packet once
   ▼
Flows + fidelity tiers + protocol fingerprints
   ▼
Evidence value per flow, in bits   ← rarity, automation, pivoting, diminishing returns
   ▼
Multiple-choice knapsack            ← one fidelity level per flow, exact byte cap
   ▼
Reduced PCAP + flow ledger          ← Pass 2: copy chosen records byte for byte
```

### 1. Fidelity tiers: keep part of a flow

Older methods keep or drop whole packets or whole flows. EBR gives each packet a tier based on the role it plays:

| Tier | Contents | Why it matters |
|---|---|---|
| 0 Skeleton | SYN, FIN, RST, first and last packet | Proves the connection happened and when |
| 1 Head | First 1 KiB each way | Requests, banners and response headers |
| 2 Deep head | First 16 KiB each way | Longer headers and the start of transfers |
| 3 Turn heads | First 1 KiB of each later message | Commands sent late in a long session |
| 4 Bulk | Everything else | File bodies and encrypted data |

Tier 3 is what a plain connection prefix cannot do. Each change of speaker starts a new turn, so the fiftieth command in a remote shell still gets its opening bytes kept.

Position comes from TCP sequence numbers, so retransmissions land in the same tier as the data they repeat. Pure ACKs follow the data they acknowledge, which keeps the retained stream readable by a reassembling IDS.

### 2. Evidence value, measured in bits

A flow's value is how surprising it is under the capture's own baseline. A trait seen with probability P is worth -log₂ P bits, and five traits are measured: service, flow shape, client-server pair, client fingerprint and content skeleton.

The client fingerprint comes from the HTTP header layout and User-Agent, a hash of the TLS ClientHello, or the SSH banner. The content skeleton keeps a URL's punctuation and drops its words, so `/page?id=1' OR 1=1--` looks different from `/page?id=7`. Neither needs a rule that knows what SQL injection is.

**Good–Turing correction.** Plain frequency counting over-rates one-off values. If nearly every DNS name appears once, as in a spam bot's mail lookups, then one more new name is not surprising. EBR estimates P as `max(n/N, novelty/n)`, where `novelty` is the share of values seen exactly once. A one-off value only scores highly when one-offs are rare.

### 3. Automation

Rarity alone fails on floods, because a flood's traits become common. EBR adds a second signal: for each client-server-service group of `n` flows, `log₂(n)` bits, scaled by how machine-like the group looks. Near-identical sizes, regular timing and a high failure rate all count. A single client probing many endpoints is scored the same way.

### 4. Pivoting

An investigator who distrusts a host looks at everything it touched, and EBR does the same in two ways:

- Suspicion spreads from a host to all of its flows, including quiet ones that look harmless alone.
- A host that was attacked has its next connections to rare peers lifted for 30 minutes, because that is where a compromise shows up.

A host's suspicion is the mass of surprise it initiated, not its single oddest flow, so one unusual connection does not condemn it.

### 5. Diminishing returns

The ten-thousandth identical failed login adds almost nothing. Each flow's value is multiplied down by its rank inside its behaviour, at two strengths:

- **Repeats fall steeply:** the same message from the same client to the same server.
- **Variations fall gently:** new content or a new endpoint is a new indicator of compromise, so it keeps most of its value.

A flow with no payload holds nothing the ledger lacks, so it also falls steeply. A thousand-port scan therefore counts as one behaviour rather than a thousand.

The first 16 flows of each behaviour keep their full value, so rate-based IDS rules have an unbroken burst to fire on. The rest are visited in bit-reversed order, so any prefix of them covers the behaviour's whole time span.

### 6. Multiple-choice knapsack

Each flow chooses one level, from ledger-only up to complete. Each level has an exact byte cost and a value, so this is a multiple-choice knapsack problem. EBR reduces each flow's levels to their upper concave hull, sorts all hull segments by value per byte and takes them until the budget is spent. This is the standard greedy solution, and it is optimal for the fractional relaxation.

A flow earns value only for evidence it contains. A bare SYN has no head to keep, so it cannot outbid a real request just by being cheap.

### 7. The flow ledger

Every flow is recorded in a small compressed table with its endpoints, times, counts and application, whether or not any of its packets survive. When space is tight, low-value flows fold into grouped rows that keep exact totals. **The ledger is charged against the same byte budget as the packets**, so no comparator is disadvantaged.

### 8. A budget cap for scan flows

This is the main change in the second version. Flows with no payload are so cheap that a scan storm can outbid real evidence on price alone. On one red-team capture they took 186 MB of a 227 MB packet budget. Payload-free flows now get at most 30% of the budget, and anything content leaves unused goes back to them. Their value is unchanged, so a capture without a scan storm behaves as before.

The second version also treats SMB as readable, because it is not encrypted and is where human attackers move sideways. With the cap added, the knapsack has a second constraint, so its result is a good heuristic rather than the fractional optimum.

## What is new, and what is not

Selective retention is an established field. The honest position is that EBR's individual ideas have relatives, and its contribution is the combination and the formulation. The ablation results below show that one idea carries most of the benefit.

| Prior work | What it does | How EBR differs |
|---|---|---|
| [Time Machine](https://www.usenix.org/conference/imc-05/building-time-machine-efficient-recording-and-retrieval-high-volume-network) and [its NIDS-steered successor](https://www.icir.org/vern/papers/time-machine-sigcomm08.pdf) | A per-connection cutoff, with storage classes an IDS can adjust | Value-driven levels per flow, no IDS needed, an exact byte cap, and turn heads for late commands |
| [XNET](https://arxiv.org/abs/2608.18349) (Papastergiou et al., 2026) | Line-rate traffic categories, keeps rare destinations and DNS, header-only, uses external popularity feeds | Self-calibrating with no external feeds, content-aware, optimised against a byte budget, handles floods with exemplars. XNET works live at 100 Gbps, while EBR works offline |
| [Suricata conditional logging](https://docs.suricata.io/en/suricata-8.0.1/configuration/suricata-yaml.html), [Corelight Smart PCAP](https://corelight.com/platform/smart-pcap), [IDS-triggered PCAP (SANS)](https://www.sans.org/white-papers/rethinking-full-packet-capture-evaluating-ids-triggered-pcap) | Keep traffic that matches rules | No rules at retention time, so later detections remain possible |
| [TrimPCAP](https://netresec.com/?b=17Cf81f), [selective capping](https://dl.ifip.org/IFIP-LNCS-9053/hal-01411176v1) | Fixed trimming per session or packet | Trim depth varies per flow according to value |
| Patents on [value and entropy truncation](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11172055), [selective forensic retention](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10395331) and [ML storage priority](https://patents.google.com/patent/US10257214) | Value-based retention as a general concept | The idea of retaining by value is not new. These were seen through search summaries and not read in full, and they matter if this work is ever commercialised |

**A claim you can defend:** in a bounded literature search, no published method was found that combines signature-free surprisal with Good–Turing correction, two-level diminishing returns, per-flow fidelity selection as a knapsack, and a budget-charged ledger, or that verifies a reduction against an IDS and repairs it inside the same budget before deletion. The tests show that behaviour-aware diminishing returns is what makes retention work under a tight cap, and that pre-deletion repair adds a large, sealed-tested gain.

**A claim you should not make:** that this has never been done, that value-based retention is a new idea, or that EBR beats an IDS in general. A bounded search cannot establish the first, the patents above contradict the second, and two small tests with mixed instance-recall results cannot show the third.

## How it was tested

The evaluation was designed so that a good score would mean something:

- **An independent judge.** Suricata 7.0.3 with 52,778 ET Open rules decides what counts as detected. EBR never sees those rules.
- **Independent ground truth.** Attack times and addresses come from the dataset publisher.
- **A sealed test.** Algorithm, settings, comparators and scoring were hashed in [final/FREEZE.json](final/FREEZE.json) before any test capture was opened, and tuning used separate development cases.
- **Strong comparators.** The flow cutoff is fitted to every budget, and the IDS-triggered policy receives real alerts, an advantage EBR never gets.
- **A time-travel measure.** Alerts from rules published after the capture date could not have guided any IDS-triggered system at the time.
- **Equal budgets.** The cap counts every serialized byte, and EBR's ledger comes out of its own allowance.

There were three sealed tests. The first found a weakness. The second tested the fixed version on fresh captures, but those captures never triggered the fix. The third was pre-registered in [final/sealed3_plan.json](final/sealed3_plan.json) and frozen in [final/FREEZE_v3.json](final/FREEZE_v3.json) to test the fix and the verification loop on scan-heavy captures.

Attack signatures kept at a 5% cap, across all three:

| Test | Data | EBR alone | EBR with repair | IDS-triggered + fill |
|---|---|---:|---:|---:|
| First | 11.3 GB, CIC attacks and WRCCDC | 91.7% | not tested | 86.5% |
| Second | 7.0 GB, WRCCDC, CTU and CIC | 94.4% | not tested | 85.9% |
| Third | 6.1 GB, IoT botnets and WRCCDC | 84.7% | **99.6%** | 84.9% |

## Third sealed test: the scan cap and the repair loop

This test covered 6.1 GB of captures opened only after the plan was hashed. A blind screen, using packet headers and no detection, found that 7 of 9 captures were scan-heavy. Eight of the nine cases scored, because one IoT capture raised no attack alerts even when complete. The full [report](final/results/forensic/sealed3/report.html) has every table.

**Attack signatures preserved**, mean across scored cases:

| Method | 1% cap | 2% cap | 5% cap | 10% cap |
|---|---:|---:|---:|---:|
| **EBR with repair** | **87.1%** | **95.1%** | **99.6%** | **98.4%** |
| EBR alone | 55.0% | 72.7% | 84.7% | 92.4% |
| First version of EBR | 50.8% | 68.1% | 82.6% | 92.4% |
| IDS-triggered + fill | 82.2% | 82.2% | 84.9% | 85.7% |
| Tuned flow cutoff | 22.6% | 26.9% | 34.4% | 38.0% |
| Rare destinations | 12.9% | 13.3% | 14.1% | 14.4% |

**The pre-registered verdicts:**

| Hypothesis | Verdict | Evidence, in points |
|---|---|---|
| H1: the scan cap beats the first version on scan-heavy cases at 5% and 10% | **Not supported** | +2.8 at 5% and 0.0 at 10%, and the 5% interval reaches zero |
| H2: repair beats EBR alone at every cap | **Supported** | +32.1, +22.4, +14.9 and +7.6 |
| H3: repair beats IDS-triggered capture at every cap | **Not supported** | Clear at 2%, 5% and 10% (+12.9, +14.7, +12.7), but +4.8 at 1% with an interval of -14.4 to +21.4 |
| H4: repair costs later-published rules no more than 5 points on average | **Not supported** | -7.5 at 2%, from only four cases with such alerts |
| H5: the blind-spot estimate beats guessing | **Not scoreable** | 8 usable pairs, and the plan required 10. On those 8 it did worse than guessing: 24.5 points of error against 14.6 |

### Why it came out this way

- **The cap had little to protect on IoT captures.** A botnet host produces millions of scan flows but few flows with content, and that content usually fits anyway. The cap helped in 3 of 8 cases and did not lower signature recall in any. It is a safeguard against a rare failure, not a general improvement.
- **EBR alone missed login sprays.** On the Hide and Seek capture it lost 110 of 158 attack alert instances at a 10% cap, mostly telnet logins with known default passwords. Each attempt has the same size and shape, and the difference lies in the password, so diminishing returns treats them as repeats. This is a real blind spot in the idea that does most of EBR's work.
- **Repair struggles with rate-based rules.** At 5%, 249 of 2,041 usable alerts stayed lost, mostly scan rules that need many flows close together.

**What repair cost here.** It used 15.6%, 13.1%, 5.0% and 1.4% of the budget at the four caps, and it made 3 of 64 case comparisons worse. Lossless gzip reached 39.9% of the original size on these captures.

## Second sealed test: the fixed version

This test covered 7.0 GB and 15.1 million packets from captures neither version had seen: three WRCCDC events, two CTU networks with live infections, and an unused CIC DDoS day. The WRCCDC 2026 slice raised no attack alerts even when complete, so five cases are scored. The full [report](final/results/forensic/sealed2/report.html) has every table.

**Attack signatures preserved**, mean across scored cases:

| Policy | 1% cap | 2% cap | 5% cap | 10% cap |
|---|---:|---:|---:|---:|
| **EBR** | **89.6%** | **91.9%** | **94.4%** | **97.8%** |
| IDS-triggered + fill | 85.9% | 89.6% | 85.9% | 91.2% |
| Rare destinations | 63.7% | 72.6% | 79.9% | 85.8% |
| Tuned flow cutoff | 38.0% | 61.0% | 77.5% | 82.8% |

### What this supports

- **EBR led every method on signature recall at every cap.** Its lead over rare destinations clears the 95% interval at every cap. Its lead over IDS-triggered capture clears it at 5% and 10% (+8.5 and +6.5 points), but not at 1% and 2%. Against the tuned cutoff it clears at 1% and 2%, and reaches zero at 5% and 10%.
- **Alert instances are closer.** IDS-triggered capture keeps more at 1% and 2% (77.1% against 72.1% at 1%), and EBR keeps more at 5% and 10%. None of those differences clears the interval.
- **The one scoreable labelled attack was caught at every cap.** DDoS HOIC was caught at all four caps, and EBR's own ranking put the attackers first. This is a single attack, so it says little alone.

### What it does not support

**The test did not exercise the scan cap.** Payload-free flows would have taken at most 3.4% of the budget on these captures, against 82% on the capture that exposed the flaw, so the 30% cap never engaged. The two versions tie on signature recall in every case. The evidence for the cap is therefore not sealed: on the WRCCDC 2018 capture it raised signature recall from 60.7% to 96.4% at 5% and from 50.0% to 100% at 10%, and signature recall did not change on any of the other 12 earlier cases. That capture shaped the fix, so it is development evidence.

**The SMB change made no clear difference here.** With the cap idle, instance recall moved by -1.2, -1.6, -0.9 and +0.6 points at the four caps. That is within scan noise, so an earlier description of this as a small cost went further than the evidence. SMB showed a benefit only on data that was not sealed.

**Scan noise.** Scanning identical selections in two separate runs changed alert instance recall in 9 of 20 case and cap combinations, by 1.2 points on average and up to 4.5 on one case. The likely source is rate-based rules running across threads, and single-threaded scanning did not remove it. Signature recall did not move in those comparisons, but in the third test it moved by 0.4 points on average and 12.5 on one case with only 8 signatures. It is the steadier measure, not a noise-free one. Treat differences of a point or two as noise.

## Verify before delete: the first results

**The results in this section are not sealed.** They come from the first run of [final/ebr/verify.py](final/ebr/verify.py) and [final/verify_before_delete.py](final/verify_before_delete.py), on captures whose earlier outcomes were known. The loop's settings were fixed before the run and were not tuned afterwards. The sealed result is in the third test above.

Retention is usually treated as a blind bet, but the original still exists until the moment it is deleted. The loop reduces a capture with EBR, scans both copies, gives the flows behind any lost detection the top priority, and tries again up to twice. A repaired flow outbids everything else, so the byte cap still holds and the lowest-value evidence makes room.

Repair below used only rules published before each capture, the same knowledge given to IDS-triggered capture. Means cover 11 cases and exclude the WRCCDC 2026 slice, which raised no attack alerts.

| Measure | Method | 1% cap | 2% cap | 5% cap | 10% cap |
|---|---|---:|---:|---:|---:|
| Attack signatures | **EBR with repair** | **95.7%** | **98.7%** | **99.6%** | **100%** |
| | EBR alone | 88.6% | 91.8% | 96.2% | 98.7% |
| | IDS-triggered + fill | 84.8% | 86.5% | 86.2% | 91.6% |
| Alert instances | **EBR with repair** | 68.7% | 84.6% | **97.2%** | **97.1%** |
| | EBR alone | 59.8% | 76.8% | 90.2% | 92.9% |
| | IDS-triggered + fill | **85.1%** | **87.7%** | 85.1% | 89.3% |
| Later-rule alerts | **EBR with repair** | 50.3% | 75.7% | **94.6%** | **95.0%** |
| | EBR alone | 46.4% | 74.0% | 95.8% | 96.3% |
| | IDS-triggered + fill | **75.5%** | **77.1%** | 75.4% | 82.8% |

**What it gained.** With repair, EBR beat IDS-triggered capture on signature recall at every cap, by 8 to 13 points, with every 95% interval above zero and no case lost. Against EBR alone it gained 1 to 7 points of signature recall and lost none. Repair made no clear difference to later-rule alerts, so fixing known losses did not visibly hurt unknown ones overall.

**What it cost.**

- **Budget:** repaired flows used 9.3%, 6.2%, 2.7% and 0.9% of the budget at the four caps.
- **Time:** the original must be scanned before deletion, about 62 seconds per GB here. Each check of the reduced copy adds about 7% of that at a 5% cap.
- **Some cases got worse:** 6 of 88 case comparisons fell, by up to 15 points at a 1% cap, because repaired flows displace other evidence.
- **Some alerts stay lost:** 33 of 1,118 usable alerts at 5%, mostly rate-based rules that need many flows close together.
- **It does nothing for unknown threats directly.** Repair only protects what a rule can already see.

**The blind-spot estimate.** Hiding half the rule families from repair gives a daily estimate of how EBR handles threats with no rule. It predicted recall on later-published rules to within 9.1 points on average, against 26.8 for guessing the mean, with a correlation of 0.87 across 40 case and cap pairs. Its worst miss was 42 points. **It did not hold up in the third sealed test**, where it did worse than guessing on the few pairs available, so treat it as an unproven idea.

## First sealed test: the first version

One disclosure: the first frozen run stopped before anything was scored, because one 4.3 GB capture was PCAPNG. It was converted to classic PCAP, Scapy confirmed all 18,890,171 packets match with zero mismatches, and no frozen file changed.

The test covered 11.3 GB and 35.0 million packets across six cases: five days of CSE-CIC-IDS2018 attacks and a WRCCDC human red-team capture. The full [report](final/results/forensic/test/report.html) has every table.

**Labelled attacks still caught**, out of the 8 that Suricata detects on the complete capture:

| Policy | 1% cap | 2% cap | 5% cap | 10% cap |
|---|---:|---:|---:|---:|
| **EBR** | 5 | 7 | **8** | **8** |
| IDS-triggered + fill | 7 | 7 | 7 | 8 |
| Tuned flow cutoff | 0 | 2 | 5 | 7 |
| Rare destinations | 3 | 3 | 3 | 4 |
| Random flows (mean of 3 seeds) | 5.7 | 6.3 | 6.3 | 6.3 |
| Random packets (mean of 3 seeds) | 0 | 0.7 | 1.7 | 3 |

**Attack signatures preserved**, mean across cases:

| Policy | 1% cap | 2% cap | 5% cap | 10% cap |
|---|---:|---:|---:|---:|
| **EBR** | **87.7%** | **90.5%** | **91.7%** | 91.1% |
| IDS-triggered + fill | 83.9% | 83.9% | 86.5% | **91.9%** |
| Rare destinations | 57.9% | 62.8% | 69.2% | 74.8% |
| Tuned flow cutoff | 30.3% | 54.0% | 62.8% | 74.7% |

### What this supports

- **EBR beats the signature-free methods.** Against the tuned cutoff and rare destinations, the 95% interval on its advantage excludes zero at every cap.
- **It is level with an IDS given real rules.** EBR is ahead at 1–5% and behind at 10%, but every interval includes zero, so this test cannot separate them. That is still a strong result for a method that used no rules at all.
- **The flow ledger is accurate.** At a 5% cap it gave the attacker's exact flow count in all five labelled cases, including all 1,908,929 flows in the largest, with first and last times within a millisecond.

### What did not go EBR's way

- **Tight caps favour an IDS on alert instances.** At 1%, IDS-triggered capture keeps 91.7% of alert instances against EBR's 49.2%.
- **The time-travel hypothesis failed.** Rules published after the capture were expected to favour EBR. IDS-triggered capture still kept 92.9% of those alerts against EBR's 85.0% at 5%, because new rules mostly fire on flows that old rules had already flagged.
- **Human red-team traffic was the weak spot.** On WRCCDC, the first version kept 60.7% of attack signatures at 5% against 78.6%. Of the 11 signatures it never recovered, ten were SMB lateral movement or SMB exploits. Later experiments found the main cause was scan flows taking most of the budget, with the SMB discount as a smaller second cause.
- **More budget sometimes lost detections.** Three WRCCDC signatures present at a lower cap were gone at 10%. I first blamed gaps inside flows, and an experiment disproved that: the affected login flows alert at every fidelity level when scanned alone. The loss disappeared once scan flows were capped, which suggests retained scan traffic was interfering, but the exact mechanism inside the IDS was not established.
- **The suspect list is uneven.** The attacker ranked #1, #1 and #7 in three labelled cases, but did not appear at all for the bot and infiltration cases, where the attacker initiates little.

### What each component contributes

Each row removes one component. Scores are attack signature recall, followed by attacks caught.

| Variant | 1% | 2% | 5% | 10% | Attacks caught at 1 / 2 / 5 / 10% |
|---|---:|---:|---:|---:|---:|
| Full EBR | 87.7% | 90.5% | 91.7% | 91.1% | 5 / 7 / 8 / 8 |
| No diminishing returns | 51.5% | 67.3% | 77.8% | 77.8% | 2 / 5 / 6 / 8 |
| Tiers and knapsack only | 51.1% | 63.4% | 75.5% | 76.5% | 1 / 4 / 6 / 8 |
| No rarity score | 83.8% | 88.6% | 91.1% | 92.3% | 5 / 7 / 8 / 8 |
| No automation score | 87.1% | 89.9% | 90.5% | 91.7% | 5 / 7 / 8 / 8 |
| No pivoting | 87.7% | 90.5% | 91.7% | 91.1% | 5 / 7 / 8 / 8 |
| No turn heads | 87.7% | 90.5% | 91.7% | 91.1% | 5 / 7 / 8 / 8 |
| No ledger | 87.7% | 90.5% | 91.7% | 92.3% | 7 / 7 / 8 / 8 |

**Diminishing returns does most of the work.** Pivoting and turn heads made no measurable difference to signature recall here, and rarity and automation each changed it only slightly when removed alone. This study does not show that those parts are needed. The ledger costs detection at 1%, and that is the price of exact flow accounting.

### Compared with your original algorithm

| Mean signature recall on five small captures | 1% | 2% | 5% | 10% |
|---|---:|---:|---:|---:|
| EBR | 63.7% | 87.4% | 95.8% | 97.9% |
| Original evidence algorithm | 58.6% | 71.2% | 73.2% | 78.4% |
| Original unweighted bundles | 39.0% | 44.3% | 64.8% | 96.8% |

Four of those five captures are development data, so these margins flatter EBR. On the single held-out capture the two tie on signature recall at every cap, and the original keeps more alert instances at 1% and 2%. EBR's clear advantage over the original is scale: it processed the whole 11.3 GB test by streaming, while the original keeps every packet in memory and was run only on captures up to 58 MB here.

### The demonstration

[The demo](final/forensic_demo.py) now runs the current version at a 5% cap:

| Run | Reduced | Attack signatures kept | Labelled attacks caught |
|---|---|---:|---:|
| Default, labelled captures | 11.28 GB to 564.2 MB, 95.0% smaller | 143 of 147 | 8 of 8 |
| `--sealed`, unseen captures | 7.03 GB to 296.0 MB, 95.8% smaller | 82 of 87 | 1 of 1 |

The default captures helped shape the current version, so that run is a demonstration and not a clean test. Three labelled attacks in it raise no alert even on the complete capture, and their exact flow counts are in the ledger.

## Limits

- **EBR is not an intrusion detector.** Its suspect list is a triage aid, not proof of compromise.
- **Discarded data is gone.** Bulk file contents and most encrypted payload cannot be recovered from the reduced copy.
- **It works offline.** It makes two passes over a finished capture, and a live version is future work.
- **It reads classic PCAP.** PCAPNG files must be converted first with [final/pcapng_to_pcap.py](final/pcapng_to_pcap.py). One test capture needed this.
- **The scan cap was not confirmed.** It failed its pre-registered test. It helped a few cases and hurt none on signature recall, so treat it as a safeguard.
- **Login sprays look like repeats.** Diminishing returns cannot see that two identical-looking logins carry different passwords, so EBR alone loses them.
- **Rate-based rules are hard to repair.** They need many flows close together, which can cost more than the budget allows.
- **Low-and-slow attacks are harder.** A handful of quiet flows produce little surprise to work with.
- **The tests are small.** Each has only a few independent cases, so confidence intervals are wide, and many of the cases come from one generated lab dataset whose attackers are easy to separate. A signature's name is also not attribution: a "Ponmocup" alert here means a User-Agent rule matched, not that Ponmocup was present.
- **Some settings are design choices.** Tier weights and powers were tuned on development data and could suit other networks less well.
- **Hashes are not chain of custody.** They show the files have not changed, not that evidence would be admissible.

## Viva questions

**Is EBR better than everything else?** Not on its own. It led an IDS in the first two tests, but on scan-dominated captures it fell well behind at 1% and 2%. With the repair loop it beat the IDS method at 2%, 5% and 10% in a pre-registered sealed test, and the 1% result was inconclusive. The test cases are few, so this is strong evidence and not proof.

**Did your fix work?** Not as hoped. The scan cap fixed the capture that exposed the flaw, but it failed its pre-registered test on fresh scan-heavy captures. It helped 3 of 8 cases and hurt none on signature recall, so I keep it as a safeguard and do not claim it as a general improvement.

**Why pre-register?** I wrote the hypotheses and pass rule down, hashed them, and only then opened the data. That stops results being explained away afterwards. Only one of the five hypotheses passed in full, three failed and one could not be scored, and all of that is reported as it came out.

**What is verify before delete?** The original still exists until it is deleted, so the system scans both copies, restores what was lost, and only then deletes. It was the strongest idea tested, and it passed its main sealed test: at a 5% cap it kept 99.6% of attack signatures, against 84.7% for EBR alone.

**Doesn't that need an IDS, which EBR was meant to avoid?** The first selection needs no rules, so unknown threats still depend on EBR. The IDS only repairs what it can see, and it runs once per batch instead of steering capture live.

**Which part matters most?** Diminishing returns. Removing it cut signature recall at a 1% cap from 88% to 52%. Pivoting and turn heads showed no measurable benefit here, so a simpler version may do just as well.

**Why not just use gzip?** Gzip keeps everything, but it still needed 51% of the original size on the test captures. EBR reaches 1–10% by deciding what to give up, and the two can be combined.

**What does "evidence-based" mean here?** Each byte is kept according to how much evidence it adds, measured in bits of surprise and discounted for repetition.

**Why bits?** Rarity, automation and pivoting then share one unit, so they can be compared and combined without ad hoc weights between them.

**Isn't this just anomaly detection?** It uses anomaly signals, but the output is a retention decision. A false positive costs a few kilobytes of extra storage, not an analyst's time, so imperfect scores are affordable.

**Why does Good–Turing matter?** Without it, a spam bot's thousands of unique DNS names all look extremely rare and take the whole budget. It corrects for the fact that if most values are unique, a new unique value is expected.

**Why charge the ledger to the budget?** Otherwise EBR would be getting free storage that the comparators do not, and the comparison would be unfair.

**Why give the first 16 exemplars full value?** Rate-based IDS rules need several events close together. Evenly spaced exemplars would not trigger them.

**Is the knapsack solution optimal?** The greedy method is optimal for the fractional relaxation, and within one flow's final segment of the true integer optimum. The value model itself is a design choice, so optimal means optimal for that model.

**Did you tune it on the test data?** No. Tuning used development cases only, and the test captures were opened after the freeze was recorded.

**What was the most surprising finding?** The "FTP brute force" in the dataset is 192,300 refused connections, because the server was not listening. Keeping a small set of exemplars plus an exact count was the right forensic answer, and it exposed a flaw in my first evaluation metric.

**What went wrong during the project?** The time-travel hypothesis failed, SMB was misjudged as opaque, my first two explanations of the red-team failure were wrong or incomplete, a steeper discount looked like the fix until it damaged other captures, and the first frozen run crashed on a PCAPNG file. All of it is reported, because a result is only credible if its failures are visible.

**How did you find the real cause?** I tested each explanation. Isolating the login flows disproved the gap theory, and checking where the bytes went showed scan flows taking 82% of the budget. Testing a candidate on all 13 earlier cases then rejected the first fix.

**Does the blind-spot estimate work?** It looked promising on unsealed data, then did worse than guessing on the few usable pairs in the sealed test. Present it as an open idea, not a finding.

**What would you do next?** Make content comparison see credentials, so login sprays stop looking like repeats. Then retest the blind-spot estimate on captures with more later-published rules, try other networks, build a streaming version, and measure real analyst time on reduced evidence.
