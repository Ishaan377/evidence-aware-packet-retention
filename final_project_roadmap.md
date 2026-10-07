# Roadmap to the final project

Planning date: 7 October 2026. Dates are suggested working windows, not fabricated progress or guaranteed deadlines. Confirm the actual submission calendar with the guide.

## Current baseline

A working offline prototype and synthetic preliminary comparison are complete. The synopsis, experiment data, logs and professor notes are ready. Research conclusions are limited to the designed cases. The next stage is independent validation, not cosmetic expansion.

## Phases and exit checks

| Phase / suggested window | Tasks | Deliverables and completion check | Complexity | Depends on |
|---|---|---|---|---|
| 1. Team understanding and guide review / 8–12 October | Run demo individually; explain parser, scorer and criteria; review question relevance and weak baseline; confirm submission details | Team can reproduce the main result and trace a packet witness; guide feedback recorded as decisions | Low, 2–3 focused sessions | Existing MVP/docs |
| 2. Literature and evaluation freeze / 12–18 October | Obtain closest 2026 full papers; extend IEEE/ACM search; freeze question definitions, hypotheses, weights and held-out plan before examining final outcomes | Updated source ledger, predeclared protocol, clear novelty boundary and change history | Medium, about one week | Guide review |
| 3. Independent data / 19 October–1 November | Select licensed public capture with useful annotation or capture benign/controlled lab actions; document consent, scope, capture loss and clock; annotate expected observations separately | Data provenance/licence notes, hash manifest, independent reference answers, full-capture control passes supported criteria | High, one to two weeks | Frozen evaluation |
| 4. Stronger comparison policies / 26 October–8 November | Event-balanced alert allocation; pre/post-event context; prefix parameter sweep; add metadata-plus-packets only if both are budgeted | Reproducible policies with the same caps; allocation fairness documented; no policy receives oracle labels | Medium | Frozen evaluation and representative data |
| 5. Required technical extensions / 2–15 November | Add PCAPNG conversion/import or IPv6 as needed; TCP stream reassembly for actual split HTTP witnesses; improve DNS/transaction validation; explicit unsupported-case handling | Targeted tests for genuine missing evidence; independent parser comparison; old byte preservation/cap invariants still pass | High; limit to evidence actually needed | Independent-data inspection |
| 6. Final experiments / 16–29 November | Multiple independently varied scenarios; weight/indicator sensitivity; random repeats; held-out outcomes; runtime and memory by trace size; compare achieved bytes | Raw trial CSV/JSON, subset manifests, coverage/byte curves, scenario-level uncertainty and failure cases | High, one to two weeks | Data, policies, technical support |
| 7. Final report and demonstration / 30 November–6 December | Rewrite claims to match outcomes; relate closest prior art; explain negative cases; render submission artifacts; package code/data or documented download instructions | Final report, presentation, reproducible release, teammate clean-machine rerun and viva rehearsal | Medium | Final measurements |

Data and policy tasks can overlap after the evaluation protocol is fixed. Do not change weights after seeing held-out results without calling the change exploratory and reserving another held-out test.

## Research questions retained for the final study

1. Which exact counts, observed boundaries and protocol sequences survive different serialized-byte caps?
2. Does the proposed explainable policy preserve more question criteria than random and stronger alert/prefix policies?
3. Which costly or unrecognised evidence types remain weak?
4. Are conclusions stable across independently chosen scenarios, background volumes, indicator availability and parameter changes?

A result can be negative. If a stronger alert policy matches or beats the evidence policy, explain the evidence/cost trade-off rather than hiding it.

## Dataset plan and dependencies

Prefer an independently chosen dataset over simply multiplying the current generator. A public dataset must have a usable licence, packet contents and annotation adequate for the questions; an attack label alone may not supply exact packet-level reference answers.

A controlled lab capture should include real protocol transactions with independently logged actions and timestamps. Keep it within authorised systems. Document what the capture observes versus what endpoint logs establish. Unencrypted controlled HTTP is useful for the current parser; encrypted traffic needs different packet-supported questions rather than claims of invisible application outcomes.

Team annotation must be separate from selection development. If annotation cannot answer a criterion reliably, revise the catalogue before the final run or mark it unsupported; do not silently invent truth.

## Baseline fairness and budget scope

Strengthen chronological alert packing and compare context windows under the same serialized-byte cap. Report attained bytes and packet sizes. The current prefix policy is simplified; call it inspired by Time Machine until a faithful reproduction is implemented.

If a future method stores flow counts alongside packets, include metadata/index/container bytes in its budget. Decide whether the study remains offline subset retention or becomes online collection. An online system must additionally handle bounded state, packet arrival decisions, capture loss and sustained throughput; that is optional and substantially harder.

## Metrics and analysis

Keep binary primary coverage with explicitly published criteria. Present per-question outcomes, actual bytes and coverage curves before ratios. Report random variation within scenarios separately from uncertainty across independent scenarios. Do not treat 30 random seeds on one trace as 30 independent networks.

Measure preprocessing, selection, writing, evaluation and memory consistently. Study unsupported evidence and intentionally missing indicators. For a volume lower bound, de-duplicate retransmitted sequence intervals and either support sequence wrap or explicitly exclude it.

Question weights may be explored later, but disclose the impact of weights and correlated criteria. More questions do not automatically produce a better scientific metric.

## Team ownership, proposed

These are planned responsibilities, not claims that team members have already performed the work.

- Ishaan Suresh Mullya: integration, packet IO and reproduction checks.
- Shriya P Reddy: literature/source verification, annotation protocol and claim ledger.
- Om KB: baselines, experiments and figures.
- All members: review each other's decisions, learn the whole pipeline and rehearse the viva.

Change ownership to suit actual strengths. The guide is Dr. Adesh ND; the supplied academic year is 2026–2027.

## Minimum defensible final submission

Require one independently annotated capture/scenario collection, stronger alert comparison, frozen criteria, at least one held-out evaluation, real raw measurements, negative-case discussion and a teammate reproduction. Include the existing synthetic case as a controlled mechanism test.

Defer ML, a dashboard, a database and online deployment unless they solve an evidenced need. If time is limited, narrow protocol scope openly while completing independent evaluation. Do not replace validation with interface polish.

## Risks and practical responses

| Risk | Response |
|---|---|
| Closest prior art removes an apparent novelty claim | Reframe contribution as transparent reproducibility and a particular evidence/cost study |
| Public data lacks usable ground truth | Use independently recorded authorised lab transactions |
| Baseline improvement eliminates advantage | Report the outcome and analyse which witnesses each policy preserves |
| Reassembly/format work becomes too large | Support a documented subset and use suitable data; avoid unsupported conclusions |
| Selected-file savings mistaken for total deployment savings | State exact budget scope; include metadata only in a future unified-budget comparison |
| Results reflect question/scorer co-design | Freeze catalogue, use independent annotation and hold out scenarios |

Keep `logs/action_log.md` append-only and update `logs/continuation_notes.md` after each phase. Preserve current measurements as the preliminary baseline; write future experiments to new directories.
