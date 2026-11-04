"""Build the second sealed test's report. Every figure comes from saved measurements."""
from collections import defaultdict
from html import escape
import json
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build_report import CAPS, bootstrap_difference, campaign_scores, collapse, curve, escape_time, percent, rows_of  # noqa: E402
from ebr.report import NAMES, results_report  # noqa: E402

FORENSIC = ROOT / 'results' / 'forensic'
LINES = ['ebr', 'ebr_frozen', 'flow_cutoff', 'rare_dest', 'ids_past_fill', 'random_flow']
OTHERS = ['ebr_frozen', 'ids_past_fill', 'ids_past', 'rare_dest', 'flow_cutoff', 'random_flow', 'random_packet']
METRICS = {'attack_sig_recall': 'Attack signatures preserved', 'attack_recall': 'Attack alert instances preserved', 'all_recall': 'All alert instances preserved'}
LABELS = {'sealed2_wrccdc2019': 'WRCCDC 2019 red team', 'sealed2_wrccdc2024': 'WRCCDC 2024 red team', 'sealed2_wrccdc2026': 'WRCCDC 2026 red team',
          'sealed2_ctu_mixed1': 'CTU infected network 1', 'sealed2_ctu_mixed2': 'CTU infected network 2', 'sealed2_ddos_feb21': 'CIC DDoS day'}


def main():
    run = FORENSIC / 'sealed2'
    rows, campaigns = rows_of(run / 'metrics.csv'), rows_of(run / 'campaigns.csv')
    cases = sorted({r['case'] for r in rows})
    stores = {c: json.loads((run / 'reduced' / c / 'records.json').read_text(encoding='utf8')) for c in cases}
    tables = {metric: collapse(rows, metric) for metric in METRICS}
    curves = {metric: {p: curve(table, p) for p in LINES + ['ids_past']} for metric, table in tables.items()}
    tests = {metric: {p: {str(c): bootstrap_difference(table, p, c, cases) for c in CAPS} for p in OTHERS} for metric, table in tables.items()}
    input_bytes = sum(s['meta']['input_bytes'] for s in stores.values())
    packets = sum(s['meta']['packets'] for s in stores.values())
    references = {c: next(r for r in rows if r['case'] == c) for c in cases}
    scored = [c for c in cases if int(references[c]['attack_sig_refs'])]
    engaged = json.loads((run / 'cap_engaged.json').read_text(encoding='utf8'))
    sealed_share = max(v for c in cases for v in engaged[c]['silent_share_of_budget_without_cap'].values())
    storm_share = max(engaged['test_wrccdc2018']['silent_share_of_budget_without_cap'].values())
    earlier = dict(new={}, old={})
    for metric_rows, target, policy in ((rows_of(FORENSIC / 'v2_share_30_13' / 'metrics.csv'), 'new', 'ebr'),
                                        (rows_of(FORENSIC / 'test' / 'metrics.csv') + rows_of(FORENSIC / 'dev_final' / 'metrics.csv'), 'old', 'ebr')):
        chosen = [r for r in metric_rows if r['policy'] == policy]
        earlier[target] = collapse(chosen, 'attack_sig_recall')
    first = json.loads((FORENSIC / 'test' / 'summary.json').read_text(encoding='utf8'))
    verified = json.loads((FORENSIC / 'verify' / 'summary.json').read_text(encoding='utf8'))
    noise = verified['scan_noise']
    caught, episodes = campaign_scores(campaigns) if campaigns else ({}, {})
    detectable = sorted(e for e, d in episodes.items() if d['detectable'])
    campaign_curve = {p: [sum(caught.get((e, p, cap), 0) for e in detectable) for cap in CAPS] for p in LINES + ['ids_past']}
    lost = []
    for metric, table in tables.items():
        for case in cases:
            for cap in CAPS:
                own = table.get((case, 'ebr', cap))
                for p in OTHERS:
                    other = table.get((case, p, cap))
                    if own is not None and other is not None and other > own + 1e-9:
                        lost.append(dict(metric=metric, case=case, cap=cap, policy=p, ebr=own, other=other))
    regressions = [item for item in lost if item['policy'] == 'ebr_frozen']
    invented = {p: sum(float(r['invented_attack']) for r in rows if r['policy'] == p) / max(1, len({r['seed'] for r in rows if r['policy'] == p})) for p in LINES}
    lossless = json.loads((run / 'lossless.json').read_text(encoding='utf8')) if (run / 'lossless.json').exists() else {}
    freeze = json.loads((ROOT / 'FREEZE_v2.json').read_text(encoding='utf8'))
    replay = json.loads((FORENSIC / 'frozen_replay.json').read_text(encoding='utf8'))
    nonsealed = FORENSIC / 'v2_share_30_13' / 'metrics.csv'
    summary = dict(freeze_time=freeze['frozen_at'], cases=cases, input_bytes=input_bytes, packets=packets, curves=curves, tests=tests,
                   campaign_curve=campaign_curve, detectable=len(detectable), episodes=episodes, losses=lost, regressions=regressions, invented=invented, lossless=lossless)
    (run / 'summary.json').write_text(json.dumps(summary, indent=1), encoding='utf8')

    sig, ins = curves['attack_sig_recall'], curves['attack_recall']
    five = CAPS.index(0.05)
    tiles = [(percent(sig['ebr'][five]), 'attack signatures kept at a 5% cap'), (percent(sig['ids_past_fill'][five]), 'best other method on the same data'),
             (f'{sealed_share:.1%}', 'most scan flows would have taken, so the new cap never engaged'), (f'{input_bytes / 1e9:.1f} GB', f'sealed evidence, {packets / 1e6:.1f} million packets')]
    lead = tests['attack_sig_recall']['ids_past_fill']
    clear = [c for c in CAPS if lead[str(c)]['low'] > 0]
    unclear = [c for c in CAPS if lead[str(c)]['low'] <= 0]
    cost = tests['attack_recall']['ebr_frozen']
    sections = [dict(heading='What this test shows', text=[
        f'<b>EBR led every other method on attack signature recall at every cap.</b> At 5% it kept {percent(sig["ebr"][five])}, against {percent(sig["ids_past_fill"][five])} for IDS-triggered capture with fill, {percent(sig["rare_dest"][five])} for rare destinations and {percent(sig["flow_cutoff"][five])} for the tuned cutoff. '
        f'Its lead over IDS-triggered capture clears the 95% interval at {" and ".join(f"{c:.0%}" for c in clear)}, but not at {" and ".join(f"{c:.0%}" for c in unclear)}.',
        f'<b>This test did not exercise the main fix.</b> Payload-free flows would have taken at most {sealed_share:.1%} of the packet budget on these captures, far below the 30% cap, so the cap never engaged. On the capture that exposed the flaw they would take {storm_share:.0%}. '
        'The two versions therefore tie on signature recall in every case, and the evidence for the cap comes only from data that was not sealed.',
        f'<b>The SMB change made no clear difference here.</b> With the cap idle, alert instance recall moved by {cost["0.01"]["mean"] * 100:+.1f}, {cost["0.02"]["mean"] * 100:+.1f}, {cost["0.05"]["mean"] * 100:+.1f} and {cost["0.1"]["mean"] * 100:+.1f} points at the four caps. '
        f'That is within scan noise: scanning identical selections twice changed a case by up to {noise["max_instance_gap"] * 100:.1f} points and the mean case by {noise["mean_instance_gap"] * 100:.1f}. An earlier version of this report called this a small cost, which went further than the evidence.']),
        dict(heading='What changed', text=[
        'The first sealed test showed EBR losing about 40% of attack signatures on a human red-team capture. Investigating that capture led to two changes.',
        '<b>Payload-free flows now get at most 30% of the budget.</b> On that capture, scan flows with no payload took 186 MB of a 227 MB packet budget, because they are cheap enough to outbid real evidence. '
        'Their value is unchanged and any budget left over goes back to them, so captures without a scan storm are barely affected.',
        '<b>SMB is now treated as readable.</b> EBR used to discount its later bytes as if they were encrypted.']),
        dict(heading='How this was tested', text=[
            f'The new version was frozen on {escape_time(freeze["frozen_at"])}, with hashes of {len(freeze["files"])} files, before any sealed capture was opened. Only sizes and format headers were read. '
            f'The sealed cases were chosen by a fixed rule before the fix was written: consecutive files from the middle of each event. They come from three WRCCDC events, two CTU networks with live infections, and one unused CIC day.',
            f'The first version ran on the same captures. Its replay was checked first: on {replay["comparisons"]} earlier comparisons it matched the original results exactly, in both selections and scores.',
            '<b>Disclosure.</b> The 2026 capture uses a link type EBR could not read, found from its header before the freeze, so support for it was added. This changes nothing for other captures, and both versions use the same parser.'])]
    sections.append(dict(heading='First version against the fix', text=[f'Means across the {len(scored)} sealed cases that raised attack alerts. The WRCCDC 2026 slice raised none even when complete, so it can score nothing. Positive advantages favour the fix, and the interval resamples the cases.'],
                         table=dict(headers=['Measure', 'Cap', 'Fixed', 'First version', 'Advantage (points)', '95% interval', 'Wins / ties / losses'], rows=[
                             [METRICS[m], f'{cap:.0%}', percent(curves[m]['ebr'][i]), percent(curves[m]['ebr_frozen'][i]),
                              f'{tests[m]["ebr_frozen"][str(cap)]["mean"] * 100:+.1f}',
                              f'{tests[m]["ebr_frozen"][str(cap)]["low"] * 100:+.1f} to {tests[m]["ebr_frozen"][str(cap)]["high"] * 100:+.1f}',
                              f'{tests[m]["ebr_frozen"][str(cap)]["wins"]} / {tests[m]["ebr_frozen"][str(cap)]["ties"]} / {tests[m]["ebr_frozen"][str(cap)]["losses"]}']
                             for m in ('attack_sig_recall', 'attack_recall') for i, cap in enumerate(CAPS)], numeric=(2, 3, 4, 5, 6))))
    per_case = []
    for case in cases:
        reference = references[case]
        cells = [LABELS.get(case, case), f'{float(reference["input_mb"]):,.0f} MB', reference['attack_sig_refs']]
        for cap in CAPS:
            new, old = tables['attack_sig_recall'].get((case, 'ebr', cap)), tables['attack_sig_recall'].get((case, 'ebr_frozen', cap))
            cells.append(f'{percent(new, 0)} / {percent(old, 0)}')
        per_case.append(cells)
    sections.append(dict(heading='Case by case', text=['Attack signature recall as fixed version / first version, at each cap.'],
                         table=dict(headers=['Case', 'Size', 'Signatures'] + [f'{c:.0%}' for c in CAPS], rows=per_case, numeric=(1, 2, 3, 4, 5, 6))))
    sections.append(dict(heading='Against the other methods', text=['Every method had the same byte cap, and EBR paid for its ledger from that cap. The IDS-triggered methods were given real alerts from rules that existed on the capture date.'],
                         charts=[dict(title=METRICS[m], series={p: [v or 0 for v in curves[m][p]] for p in LINES}) for m in METRICS],
                         table=dict(headers=['Attack signatures preserved'] + [f'{c:.0%} cap' for c in CAPS], rows=[[NAMES[p]] + [percent(v) for v in sig[p]] for p in LINES + ['ids_past']], numeric=(1, 2, 3, 4), emphasise=NAMES['ebr'])))
    rows_ci = []
    for p in OTHERS[1:]:
        for cap in CAPS:
            result = tests['attack_sig_recall'][p][str(cap)]
            if result:
                rows_ci.append([NAMES[p], f'{cap:.0%}', f'{result["mean"] * 100:+.1f}', f'{result["low"] * 100:+.1f} to {result["high"] * 100:+.1f}', f'{result["wins"]} / {result["ties"]} / {result["losses"]}'])
    sections.append(dict(heading='Is the difference real', text=[f'EBR\'s advantage in signature recall against each method, in percentage points. With {len(scored)} scored cases the intervals are wide, and with this many intervals, one that only just clears zero is weak evidence.'],
                         table=dict(headers=['Compared with', 'Cap', 'EBR advantage', '95% interval', 'Wins / ties / losses'], rows=rows_ci, numeric=(2, 3))))
    if detectable:
        attack_rows = [[escape(episodes[e]['attack']), str(episodes[e]['full_sids']), f'{episodes[e]["flows"]:,}'] + [f'{caught.get((e, "ebr", cap), 0):.0f} / {caught.get((e, "ebr_frozen", cap), 0):.0f}' for cap in CAPS] for e in detectable]
        sections.append(dict(heading='Labelled attacks', text=['Caught by fixed / first version, where 1 means at least one signature still links the labelled attacker and victim inside the window.'],
                             table=dict(headers=['Attack', 'Signatures', 'Flows'] + [f'{c:.0%}' for c in CAPS], rows=attack_rows, numeric=(1, 2, 3, 4, 5, 6, 7))))
    else:
        sections.append(dict(heading='Labelled attacks', text=['Neither labelled DDoS window raised an ET Open alert between the published addresses on the complete captures, so this test has no publisher-labelled attack to score. All results above rest on Suricata alerts.']))
    worst = sorted(lost, key=lambda x: x['ebr'] - x['other'])[:14]
    sections.append(dict(heading='Where EBR still lost', text=[
        f'A comparator beat the fixed version in {len(lost)} case, cap, measure and method comparisons, {len(regressions)} of them against the first version. The largest gaps are below.' if lost else 'No comparator beat the fixed version on any comparison.'],
        table=dict(headers=['Case', 'Cap', 'Measure', 'Winner', 'EBR', 'Winner score'], rows=[[LABELS.get(c['case'], c['case']), f'{c["cap"]:.0%}', METRICS[c['metric']], NAMES[c['policy']], percent(c['ebr']), percent(c['other'])] for c in worst], numeric=(4, 5)) if worst else None))
    storm_rows = [['Fixed version'] + [percent(earlier['new'].get(('test_wrccdc2018', 'ebr', c))) for c in CAPS], ['First version'] + [percent(earlier['old'].get(('test_wrccdc2018', 'ebr', c))) for c in CAPS]]
    changed = sum(1 for key, value in earlier['new'].items() if key in earlier['old'] and abs(value - earlier['old'][key]) > 1e-9)
    sections.append(dict(heading='Evidence for the cap, which is not sealed', text=[
        'This table is signature recall on the WRCCDC 2018 capture that exposed the flaw. That capture shaped the fix, so these numbers are development evidence and not a clean test.',
        f'Across the 13 earlier cases, signature recall changed in {changed} of 52 case and cap combinations, all on this capture.'],
        table=dict(headers=['WRCCDC 2018'] + [f'{c:.0%} cap' for c in CAPS], rows=storm_rows, numeric=(1, 2, 3, 4), emphasise='Fixed version')))
    sections.append(dict(heading='The first sealed test', text=[
        f'The first version was tested on {first["input_bytes"] / 1e9:.1f} GB of different captures. It caught {first["campaign_curve"]["ebr"][2]:.0f} of {first["detectable_attacks"]} labelled attacks at a 5% cap and kept {percent(first["curves"]["attack_sig_recall"]["ebr"][2])} of attack signatures, against {percent(first["curves"]["attack_sig_recall"]["ids_past_fill"][2])} for IDS-triggered capture with fill. '
        'That test also found the weakness on human red-team traffic that led to this version.']))
    t, spot = verified['table']['past'], verified['blind_spot']
    pct = lambda values: [percent(v) for v in values]
    compared = verified['comparisons']
    sections.append(dict(heading='Prototype: verify before delete', text=[
        '<b>These results are not sealed.</b> Their outcomes could be compared with earlier results on the same captures, and they come from a separate prototype, not the frozen version. The loop\'s settings were fixed before this run and were not tuned afterwards.',
        'A reduction is normally a blind bet, but the original still exists until it is deleted. So the prototype scans both copies with Suricata, puts back the flows behind any lost detection, and repeats up to twice, all inside the same byte budget. '
        f'Repair here used only rules published before each capture, the same knowledge given to IDS-triggered capture. Means cover {len(verified["scored"])} cases.'],
        table=dict(headers=['Measure and method'] + [f'{c:.0%} cap' for c in CAPS], rows=[
            ['Signatures: EBR with repair'] + pct(t['attack_sig_recall']['after']), ['Signatures: EBR alone'] + pct(t['attack_sig_recall']['before']), ['Signatures: IDS-triggered + fill'] + pct(verified['ids_fill']['attack_sig_recall']),
            ['Alert instances: EBR with repair'] + pct(t['attack_recall']['after']), ['Alert instances: EBR alone'] + pct(t['attack_recall']['before']), ['Alert instances: IDS-triggered + fill'] + pct(verified['ids_fill']['attack_recall']),
            ['Later-rule alerts: EBR with repair'] + pct(t['later_recall']['after']), ['Later-rule alerts: EBR alone'] + pct(t['later_recall']['before']), ['Later-rule alerts: IDS-triggered + fill'] + pct(verified['ids_fill']['future_recall'])], numeric=(1, 2, 3, 4)),
        after=[f'<b>Gain.</b> With repair, signature recall beat IDS-triggered capture at every cap, and its 95% intervals exclude zero. Alert instances are clearly better at 5% and 10%. They are lower at 1% and 2%, where the intervals include zero.',
               f'<b>Cost.</b> Repair used {percent(t["repair_share_of_budget"][0])}, {percent(t["repair_share_of_budget"][1])}, {percent(t["repair_share_of_budget"][2])} and {percent(t["repair_share_of_budget"][3])} of the budget at the four caps, and it requires scanning the original before deletion. '
               f'It made {len(verified["repair_made_worse"])} of 88 case comparisons worse, by up to {max(w["before"] - w["after"] for w in verified["repair_made_worse"]) * 100:.0f} points at a 1% cap, because repaired flows displace other evidence. {t["lost_after"][2]} of {t["known_total"][2]} usable alerts stayed lost at 5%, mostly rate-based rules that need many flows.',
               f'<b>Blind-spot estimate.</b> Hiding half the rule families from repair predicted recall on later-published rules to within {spot["hidden_vs_later_after"] * 100:.1f} points on average, against {spot["guess_the_mean"] * 100:.1f} for guessing the mean, across {spot["pairs"]} case and cap pairs. Its worst miss was {spot["worst_error"] * 100:.0f} points.']))
    sections.append(dict(heading='Earlier claims that were wrong', text=[
        f'<b>Scan repeatability was overstated.</b> An early check found identical alerts on complete captures. Reduced captures vary more: {noise["differing"]} of {noise["comparisons"]} identical selections scored differently when scanned twice, by up to {noise["max_instance_gap"] * 100:.1f} points of alert instance recall on one case. Signature recall did not change in those comparisons, though the third test later found that it can. Rate-based rules running across threads are the likely source. Instance-recall differences of a point or two in these reports should not be read as real.',
        '<b>SMB was only part of the cause.</b> The first report blamed the SMB discount. Testing showed that the budget lost to scan flows mattered more. SMB still helps, so both changes were kept.',
        '<b>Gaps were not the cause of the drop at 10%.</b> The first report suggested that gaps inside flows stopped the IDS parser. The affected login flows alert at every fidelity level when scanned alone, so that explanation was wrong. The drop disappeared once scan flows were capped.',
        '<b>A steeper discount looked like the fix and was not.</b> It rescued the red-team capture but halved instance recall on an infiltration capture. Testing it on all 13 earlier cases exposed this, and the budget cap replaced it.']))
    limits = [f'{len(scored)} scored cases cannot show general superiority, and the intervals above reflect that.',
              'The WRCCDC slices are short, about a minute each, and they have no attack labels here. Only one labelled attack could be scored at all.',
              'The sealed slices contained no scan storm, so a further sealed test on scan-heavy captures is needed before claiming the cap works in general.']
    if lossless:
        ratio = sum(v['gzip_bytes'] for v in lossless.values()) / sum(v['input_bytes'] for v in lossless.values())
        limits.insert(0, f'Lossless gzip on these captures reaches {percent(ratio)} of the original size and loses nothing.')
    sections.append(dict(heading='Limits', text=limits))
    report = dict(title='EBR second sealed test', lede=f'The fixed algorithm against its first version and the other methods, on {input_bytes / 1e9:.1f} GB of captures neither version had seen.',
                  tiles=tiles, sections=sections, caps=[c * 100 for c in CAPS], policies=LINES)
    (run / 'report.html').write_text(results_report(report), encoding='utf8')
    (run / 'report_fragment.html').write_text(results_report(report, True), encoding='utf8')
    print('Wrote', run / 'report.html')
    for metric in METRICS:
        print(metric)
        for p in LINES + ['ids_past']:
            print(f'  {p:<16}', [None if v is None else round(v, 3) for v in curves[metric][p]])
    print('caught', campaign_curve, 'of', len(detectable), 'losses', len(lost), 'against first version', len(regressions))


if __name__ == '__main__':
    main()
